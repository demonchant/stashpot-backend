import { Router }                from 'express';
import { verifyJwt, AuthRequest } from '../middleware/auth.js';
import { validate, fiatDepositSchema, mockConfirmSchema } from '../utils/validation.js';
import { requireIdempotency }     from '../utils/idempotency.js';
import { withUserLock }           from '../utils/dbLocks.js';
import { audit }                  from '../utils/audit.js';
import { db }                     from '../models/db.js';

const router = Router();
router.use(verifyJwt);

const YELLOW_CARD_ENV = process.env.YELLOW_CARD_ENV || 'sandbox';

const RATES: Record<string, number> = {
  NGN: 1620, GHS: 14.5, KES: 130, ZAR: 18.8, USD: 1,
};

router.get('/rates', async (_req, res) => {
  res.json({
    rates:      RATES,
    fee_pct:    1.5,
    provider:   'Yellow Card',
    updated_at: new Date().toISOString(),
  });
});

router.post(
  '/deposit/initiate',
  requireIdempotency,
  validate(fiatDepositSchema),
  async (req: AuthRequest, res, next) => {
    try {
      const { currency, fiat_amount, provider } = req.body;
      const usdcAmount = (fiat_amount / RATES[currency]) * (1 - 0.015);
      const ref        = `SP-${Date.now()}-${Math.random().toString(36).slice(2, 8).toUpperCase()}`;

      await db.query(
        `INSERT INTO fiat_transactions(user_id, provider, provider_ref, direction, fiat_amount, fiat_currency, usdc_amount)
         VALUES($1, $2, $3, 'deposit', $4, $5, $6)`,
        [req.user!.id, provider, ref, fiat_amount, currency, usdcAmount.toFixed(6)],
      );

      await audit({
        action: 'fiat.deposit_initiated',
        user_id: req.user!.id,
        target_id: ref,
        amount: usdcAmount,
        status: 'success',
        ip: req.ip,
        metadata: { currency, fiat_amount, provider },
      });

      const isDev = YELLOW_CARD_ENV !== 'production';
      res.json({
        reference:     ref,
        usdc_expected: usdcAmount.toFixed(6),
        instructions:  isDev
          ? { note: 'DEV MODE — call /api/fiat/deposit/mock-confirm with the reference.' }
          : {
              bank_name:       'Yellow Card Bank',
              account_number:  '0123456789',
              reference:       ref,
              amount:          fiat_amount,
              currency,
            },
      });
    } catch (e) { next(e); }
  },
);

// DEV/STAGING ONLY — hard blocked in production
router.post(
  '/deposit/mock-confirm',
  validate(mockConfirmSchema),
  async (req: AuthRequest, res, next) => {
    try {
      if (YELLOW_CARD_ENV === 'production') {
        return res.status(403).json({ error: 'Not available in production' });
      }

      const { reference } = req.body;

      const result = await withUserLock(req.user!.id, async (client) => {
        const tx = await client.query(
          `SELECT * FROM fiat_transactions
           WHERE provider_ref=$1 AND user_id=$2 AND status='pending' FOR UPDATE`,
          [reference, req.user!.id],
        );
        if (!tx.rows.length) {
          const err: any = new Error('Transaction not found or already settled');
          err.status = 404;
          throw err;
        }
        const t = tx.rows[0];

        await client.query(
          `UPDATE fiat_transactions SET status='completed', settled_at=NOW() WHERE provider_ref=$1`,
          [reference],
        );
        await client.query(
          `UPDATE balances SET usdc = usdc + $1, last_updated=NOW() WHERE user_id=$2`,
          [t.usdc_amount, req.user!.id],
        );
        await client.query(
          `INSERT INTO transactions(user_id, type, amount, meta)
           VALUES($1, 'fiat_deposit', $2, $3)`,
          [req.user!.id, t.usdc_amount, JSON.stringify({ ref: reference, currency: t.fiat_currency, mock: true })],
        );
        return t.usdc_amount;
      });

      await audit({
        action: 'fiat.deposit_completed',
        user_id: req.user!.id,
        target_id: reference,
        amount: parseFloat(result),
        status: 'success',
        ip: req.ip,
        metadata: { mock: true },
      });

      res.json({ ok: true, usdc_credited: result });
    } catch (e) { next(e); }
  },
);

router.get('/history', async (req: AuthRequest, res, next) => {
  try {
    const r = await db.query(
      `SELECT provider, direction, fiat_amount, fiat_currency, usdc_amount, status, created_at
       FROM fiat_transactions WHERE user_id=$1
       ORDER BY created_at DESC LIMIT 20`,
      [req.user!.id],
    );
    res.json(r.rows);
  } catch (e) { next(e); }
});

export default router;
