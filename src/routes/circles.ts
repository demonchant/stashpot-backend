import { Router }                from 'express';
import { verifyJwt, AuthRequest } from '../middleware/auth.js';
import { validate, createCircleSchema, contributeSchema } from '../utils/validation.js';
import { requireIdempotency }     from '../utils/idempotency.js';
import { withUserLock, withResourceLock } from '../utils/dbLocks.js';
import { audit }                  from '../utils/audit.js';
import { db }                     from '../models/db.js';
import { z }                      from 'zod';

const router = Router();
router.use(verifyJwt);

router.get('/', async (req: AuthRequest, res, next) => {
  try {
    const r = await db.query(
      `SELECT c.*, cm.slot_index,
              (SELECT COUNT(*) FROM circle_members cm2 WHERE cm2.circle_id = c.id) member_count
       FROM circles c
       JOIN circle_members cm ON cm.circle_id = c.id AND cm.user_id = $1
       ORDER BY c.created_at DESC`,
      [req.user!.id],
    );
    res.json(r.rows);
  } catch (e) { next(e); }
});

router.get('/public', async (_req, res, next) => {
  try {
    const r = await db.query(
      `SELECT c.id, c.name, c.max_members, c.contribution, c.cycle_days, c.started,
              (SELECT COUNT(*) FROM circle_members cm WHERE cm.circle_id = c.id) member_count
       FROM circles c WHERE c.started = FALSE
       ORDER BY c.created_at DESC LIMIT 20`,
    );
    res.json(r.rows);
  } catch (e) { next(e); }
});

router.post(
  '/',
  requireIdempotency,
  validate(createCircleSchema),
  async (req: AuthRequest, res, next) => {
    try {
      const { name, max_members, contribution, cycle_days } = req.body;
      const userId = req.user!.id;

      const result = await withUserLock(userId, async (client) => {
        const circleId = Date.now();
        const c = await client.query(
          `INSERT INTO circles(circle_id, name, admin_id, max_members, contribution, cycle_days)
           VALUES($1, $2, $3, $4, $5, $6) RETURNING id`,
          [circleId, name || 'Savings Circle', userId, max_members, contribution, cycle_days],
        );
        await client.query(
          `INSERT INTO circle_members(circle_id, user_id, slot_index) VALUES($1, $2, 0)`,
          [c.rows[0].id, userId],
        );
        return { id: c.rows[0].id, circle_id: circleId };
      });

      await audit({
        action: 'circle.created',
        user_id: userId,
        target_id: result.id,
        status: 'success',
        ip: req.ip,
        metadata: { max_members, contribution },
      });

      res.status(201).json(result);
    } catch (e) { next(e); }
  },
);

router.post(
  '/:id/join',
  validate(z.object({ id: z.string().uuid() }), 'params'),
  async (req: AuthRequest, res, next) => {
    try {
      const slot = await withResourceLock(`circle:${req.params.id}`, async (client) => {
        const circle = await client.query(
          `SELECT id, max_members FROM circles WHERE id=$1 AND started=FALSE FOR UPDATE`,
          [req.params.id],
        );
        if (!circle.rows.length) {
          const err: any = new Error('Circle not found or already started');
          err.status = 404; throw err;
        }

        const count = await client.query(
          'SELECT COUNT(*) c FROM circle_members WHERE circle_id=$1',
          [req.params.id],
        );
        const slotIndex = parseInt(count.rows[0].c, 10);
        if (slotIndex >= circle.rows[0].max_members) {
          const err: any = new Error('Circle is full');
          err.status = 400; throw err;
        }

        await client.query(
          `INSERT INTO circle_members(circle_id, user_id, slot_index) VALUES($1, $2, $3)
           ON CONFLICT DO NOTHING`,
          [req.params.id, req.user!.id, slotIndex],
        );
        return slotIndex;
      });

      await audit({
        action: 'circle.joined',
        user_id: req.user!.id,
        target_id: req.params.id,
        status: 'success',
        ip: req.ip,
        metadata: { slot_index: slot },
      });

      res.json({ ok: true, slot_index: slot });
    } catch (e) { next(e); }
  },
);

router.post(
  '/:id/contribute',
  requireIdempotency,
  validate(z.object({ id: z.string().uuid() }), 'params'),
  validate(contributeSchema),
  async (req: AuthRequest, res, next) => {
    try {
      const { amount } = req.body;
      const userId     = req.user!.id;

      const result = await withResourceLock(`circle:${req.params.id}`, async () => {
        return withUserLock(userId, async (client) => {
          const circle = await client.query(
            `SELECT * FROM circles WHERE id=$1 AND started=TRUE AND completed=FALSE`,
            [req.params.id],
          );
          if (!circle.rows.length) {
            const err: any = new Error('Circle not active');
            err.status = 404; throw err;
          }
          const c = circle.rows[0];

          if (Math.abs(amount - parseFloat(c.contribution)) > 0.001) {
            const err: any = new Error(`Contribution must be exactly $${c.contribution} USDC`);
            err.status = 400; throw err;
          }

          const dup = await client.query(
            `SELECT id FROM circle_contributions
             WHERE circle_id=$1 AND user_id=$2 AND cycle=$3`,
            [req.params.id, userId, c.current_cycle],
          );
          if (dup.rows.length) {
            const err: any = new Error('Already contributed this cycle');
            err.status = 409; throw err;
          }

          const bal = await client.query(
            'SELECT usdc FROM balances WHERE user_id=$1 FOR UPDATE',
            [userId],
          );
          if (parseFloat(bal.rows[0]?.usdc || '0') < amount) {
            const err: any = new Error('Insufficient balance');
            err.status = 400; throw err;
          }

          await client.query(
            'UPDATE balances SET usdc = usdc - $1 WHERE user_id=$2',
            [amount, userId],
          );
          await client.query(
            `INSERT INTO circle_contributions(circle_id, user_id, cycle, amount)
             VALUES($1, $2, $3, $4)`,
            [req.params.id, userId, c.current_cycle, amount],
          );
          return c.current_cycle;
        });
      });

      await audit({
        action: 'circle.contribution',
        user_id: userId,
        target_id: req.params.id,
        amount,
        status: 'success',
        ip: req.ip,
        metadata: { cycle: result },
      });

      res.json({ ok: true, cycle: result });
    } catch (e) { next(e); }
  },
);

export default router;
