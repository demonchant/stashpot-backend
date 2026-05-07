import { Router }              from 'express';
import { verifyJwt, AuthRequest } from '../middleware/auth.js';
import { validate, requestLoanSchema, repayLoanSchema } from '../utils/validation.js';
import { requireIdempotency }   from '../utils/idempotency.js';
import { withUserLock }         from '../utils/dbLocks.js';
import { audit }                from '../utils/audit.js';
import { db }                   from '../models/db.js';
import { z }                    from 'zod';

const router = Router();
router.use(verifyJwt);

const LOAN_PARAMS: Record<string, { max: number; apr: number; coll: number; minScore: number }> = {
  A: { max: 10_000, apr:  800, coll: 1.50, minScore: 0   },
  B: { max:  5_000, apr: 1000, coll: 1.20, minScore: 500 },
  C: { max:  2_000, apr: 1200, coll: 1.10, minScore: 700 },
  D: { max:    500, apr: 1800, coll: 0,    minScore: 850 },
};

router.get('/eligible', async (req: AuthRequest, res, next) => {
  try {
    const s = await db.query(
      'SELECT composite, in_default FROM scores WHERE user_id=$1',
      [req.user!.id],
    );
    const score     = parseInt(s.rows[0]?.composite || '0', 10);
    const inDefault = s.rows[0]?.in_default || false;
    const active    = await db.query(
      `SELECT COUNT(*) c FROM loans WHERE user_id=$1 AND status='active'`,
      [req.user!.id],
    );
    const activeCount = parseInt(active.rows[0].c, 10);

    const eligible = Object.entries(LOAN_PARAMS)
      .filter(([, p]) => score >= p.minScore)
      .map(([type, p]) => ({
        type,
        max_amount:     p.max,
        apr_pct:        p.apr / 100,
        collateral_pct: p.coll * 100,
        can_borrow:     !inDefault && activeCount < 3,
      }));

    res.json({ eligible, score, in_default: inDefault, active_loans: activeCount });
  } catch (e) { next(e); }
});

router.get('/mine', async (req: AuthRequest, res, next) => {
  try {
    const r = await db.query(
      `SELECT * FROM loans WHERE user_id=$1 ORDER BY issued_at DESC`,
      [req.user!.id],
    );
    res.json(r.rows);
  } catch (e) { next(e); }
});

router.post(
  '/request',
  requireIdempotency,
  validate(requestLoanSchema),
  async (req: AuthRequest, res, next) => {
    try {
      const { loan_type, amount, duration_days } = req.body;
      const userId = req.user!.id;
      const p      = LOAN_PARAMS[loan_type];

      if (amount > p.max) {
        return res.status(400).json({ error: `Max for type ${loan_type} is $${p.max}` });
      }

      const loan = await withUserLock(userId, async (client) => {
        const s = await client.query(
          'SELECT composite, in_default FROM scores WHERE user_id=$1 FOR UPDATE',
          [userId],
        );
        const score = parseInt(s.rows[0]?.composite || '0', 10);
        if (score < p.minScore) {
          const err: any = new Error(`Score too low — need ${p.minScore}, have ${score}`);
          err.status = 403; throw err;
        }
        if (s.rows[0]?.in_default) {
          const err: any = new Error('In 90-day default period');
          err.status = 403; throw err;
        }

        const active = await client.query(
          `SELECT COUNT(*) c FROM loans WHERE user_id=$1 AND status='active'`,
          [userId],
        );
        if (parseInt(active.rows[0].c, 10) >= 3) {
          const err: any = new Error('Maximum 3 active loans');
          err.status = 400; throw err;
        }

        const collateral = amount * p.coll;
        const dueAt      = new Date(Date.now() + duration_days * 86_400_000);

        if (collateral > 0) {
          const bal = await client.query(
            'SELECT usdc FROM balances WHERE user_id=$1 FOR UPDATE',
            [userId],
          );
          if (parseFloat(bal.rows[0]?.usdc || '0') < collateral) {
            const err: any = new Error(`Need $${collateral.toFixed(2)} for collateral`);
            err.status = 400; throw err;
          }
          await client.query(
            'UPDATE balances SET usdc = usdc - $1 WHERE user_id=$2',
            [collateral, userId],
          );
        }

        await client.query(
          'UPDATE balances SET usdc = usdc + $1 WHERE user_id=$2',
          [amount, userId],
        );

        const inserted = await client.query(
          `INSERT INTO loans(user_id, loan_type, principal, apr_bps, collateral,
                             duration_days, score_at_issuance, due_at)
           VALUES($1, $2, $3, $4, $5, $6, $7, $8) RETURNING *`,
          [userId, loan_type, amount, p.apr, collateral, duration_days, score, dueAt],
        );
        return inserted.rows[0];
      });

      await audit({
        action: 'loan.issued',
        user_id: userId,
        target_id: loan.id,
        amount,
        status: 'success',
        ip: req.ip,
        metadata: { loan_type, duration_days, collateral: loan.collateral },
      });

      res.json(loan);
    } catch (e) {
      await audit({
        action: 'loan.issued', user_id: req.user?.id, status: 'failure',
        error: (e as Error).message, ip: req.ip,
      });
      next(e);
    }
  },
);

router.post(
  '/:id/repay',
  requireIdempotency,
  validate(z.object({ id: z.string().uuid() }), 'params'),
  validate(repayLoanSchema),
  async (req: AuthRequest, res, next) => {
    try {
      const { amount } = req.body;
      const userId     = req.user!.id;
      const loanId     = req.params.id;

      const result = await withUserLock(userId, async (client) => {
        const loan = await client.query(
          `SELECT * FROM loans WHERE id=$1 AND user_id=$2 AND status='active' FOR UPDATE`,
          [loanId, userId],
        );
        if (!loan.rows.length) {
          const err: any = new Error('Loan not found or not active');
          err.status = 404; throw err;
        }
        const l = loan.rows[0];

        const elapsed   = (Date.now() - new Date(l.issued_at).getTime()) / 86_400_000;
        const interest  = parseFloat(l.principal) * parseFloat(l.apr_bps) * elapsed / (365 * 10_000);
        const total     = parseFloat(l.principal) + interest;
        const paid      = parseFloat(l.total_repaid);
        const remaining = total - paid;

        if (amount > remaining + 0.01) {
          const err: any = new Error('Overpayment');
          err.status = 400; throw err;
        }

        const bal = await client.query(
          'SELECT usdc FROM balances WHERE user_id=$1 FOR UPDATE',
          [userId],
        );
        if (parseFloat(bal.rows[0]?.usdc || '0') < amount) {
          const err: any = new Error('Insufficient balance');
          err.status = 400; throw err;
        }

        const isFinal = paid + amount >= total - 0.001;

        await client.query(
          'UPDATE balances SET usdc = usdc - $1 WHERE user_id=$2',
          [amount, userId],
        );
        await client.query(
          `UPDATE loans SET total_repaid=$1, status=$2 WHERE id=$3`,
          [paid + amount, isFinal ? 'repaid' : 'active', l.id],
        );
        if (isFinal && parseFloat(l.collateral) > 0) {
          await client.query(
            'UPDATE balances SET usdc = usdc + $1 WHERE user_id=$2',
            [l.collateral, userId],
          );
        }
        return { is_final: isFinal, remaining: Math.max(0, remaining - amount) };
      });

      await audit({
        action: 'loan.repaid',
        user_id: userId,
        target_id: loanId,
        amount,
        status: 'success',
        ip: req.ip,
        metadata: { is_final: result.is_final },
      });

      res.json({ ok: true, ...result });
    } catch (e) { next(e); }
  },
);

export default router;
