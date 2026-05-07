/**
 * StashPot — Pool Routes (HARDENED)
 *
 * All fixes applied:
 *   [#2] verifyJwt on every route
 *   [#5] Zod validation on every request body
 *   [Missing #1] Idempotency-Key required on mutations
 *   [Missing #2] withUserLock on every balance mutation
 *   [Missing #3] Audit log on every mutation
 */

import { Router }                     from 'express';
import { verifyJwt, AuthRequest }     from '../middleware/auth.js';
import { validate, depositSchema, withdrawSchema } from '../utils/validation.js';
import { requireIdempotency }         from '../utils/idempotency.js';
import { withUserLock, withResourceLock } from '../utils/dbLocks.js';
import { audit }                       from '../utils/audit.js';
import { db }                          from '../models/db.js';
import { WeightService, PoolEntry }   from '../services/WeightService.js';

const router = Router();

// [Fix #2] Every route in this router requires a valid JWT
router.use(verifyJwt);

// ─── GET /api/pools — public pool stats ──────────────────────────────────────

router.get('/', async (_req, res, next) => {
  try {
    const rows = await Promise.all(['daily', 'weekly', 'monthly'].map(async pt => {
      const r = await db.query(
        `SELECT COALESCE(SUM(amount),0) bal, COUNT(*) participants
         FROM pool_entries WHERE pool_type=$1 AND active=TRUE`,
        [pt],
      );
      return {
        type:         pt,
        balance:      parseFloat(r.rows[0].bal),
        participants: parseInt(r.rows[0].participants, 10),
        blended_apy:  8.74,
        draws:        pt === 'daily' ? 'Every 24h' : pt === 'weekly' ? 'Every 7 days' : 'Every 30 days',
        prize_share:  pt === 'daily' ? '10%' : pt === 'weekly' ? '60%' : '30%',
      };
    }));
    res.json(rows);
  } catch (e) { next(e); }
});

// ─── GET /api/pools/my-odds ───────────────────────────────────────────────────

router.get('/my-odds', async (req: AuthRequest, res, next) => {
  try {
    const now    = Date.now();
    const result: any = {};
    for (const pt of ['daily', 'weekly', 'monthly']) {
      const all = await db.query(
        `SELECT user_id, amount, avg_balance, joined_at, early_exits
         FROM pool_entries
         WHERE pool_type=$1 AND active=TRUE AND prize_opted_in=TRUE`,
        [pt],
      );
      const drawAt = now + (pt === 'daily' ? 86_400_000 : pt === 'weekly' ? 604_800_000 : 2_592_000_000);
      const entries: PoolEntry[] = all.rows.map((r: any) => ({
        userId:           r.user_id,
        balance:          parseFloat(r.amount),
        joinedAt:         new Date(r.joined_at).getTime(),
        lastUpdateAt:     now,
        earlyWithdrawals: parseInt(r.early_exits || '0', 10),
        avgBalance:       parseFloat(r.avg_balance || r.amount),
      }));
      const table = WeightService.buildOddsTable(entries, drawAt);
      const mine  = table.find(e => e.userId === req.user!.id);
      const total = table.reduce((s, e) => s + e.weight, 0);
      result[pt] = {
        chance:    total > 0 && mine ? ((mine.weight / total) * 100).toFixed(4) + '%' : '0%',
        pool_size: all.rows.length,
        next_draw: new Date(drawAt),
      };
    }
    res.json(result);
  } catch (e) { next(e); }
});

// ─── POST /api/pools/deposit ──────────────────────────────────────────────────

router.post(
  '/deposit',
  requireIdempotency,                   // [Missing #1]
  validate(depositSchema),              // [Fix #5]
  async (req: AuthRequest, res, next) => {
    try {
      const { poolId, amount } = req.body;
      const userId = req.user!.id;

      // Serialize per-user + per-pool — prevents racing deposits & draws
      const result = await withResourceLock(`pool:${poolId}`, async () => {
        return withUserLock(userId, async (client) => {
          // Pool lock check under the lock
          const lock = await client.query(
            'SELECT locked FROM pool_draw_locks WHERE pool_type=$1',
            [poolId],
          );
          if (lock.rows[0]?.locked) {
            const err: any = new Error('Pool is locked during draw — try again in 30 seconds');
            err.status = 423;
            throw err;
          }

          // [v1.6] Per-account daily deposit cap.
          // Closes the residual sybil edge documented in SECURITY.md §6.6.1.
          // Cap is checked under the user lock so two concurrent deposits
          // can't both squeeze under it.
          const cap = parseFloat(process.env.DAILY_DEPOSIT_CAP_USDC || '50000');
          const todays = await client.query(
            `SELECT COALESCE(SUM(amount), 0) AS total
             FROM transactions
             WHERE user_id=$1 AND type='deposit'
               AND created_at > NOW() - INTERVAL '24 hours'`,
            [userId],
          );
          const alreadyToday = parseFloat(todays.rows[0].total);
          if (alreadyToday + amount > cap) {
            const err: any = new Error(
              `Daily deposit cap exceeded: $${alreadyToday.toFixed(2)} of $${cap} already deposited in last 24h`,
            );
            err.status = 429;
            throw err;
          }

          const bal = await client.query(
            'SELECT usdc FROM balances WHERE user_id=$1 FOR UPDATE',
            [userId],
          );
          if (!bal.rows.length || parseFloat(bal.rows[0].usdc) < amount) {
            const err: any = new Error('Insufficient balance');
            err.status = 400;
            throw err;
          }

          await client.query(
            'UPDATE balances SET usdc = usdc - $1, last_updated=NOW() WHERE user_id=$2',
            [amount, userId],
          );

          const existing = await client.query(
            `SELECT id, amount, avg_balance FROM pool_entries
             WHERE user_id=$1 AND pool_type=$2 AND active=TRUE FOR UPDATE`,
            [userId, poolId],
          );

          if (existing.rows.length) {
            const old    = existing.rows[0];
            const newBal = parseFloat(old.amount) + amount;
            const newAvg = WeightService.updateAvgBalance(
              parseFloat(old.avg_balance || old.amount),
              newBal,
            );
            await client.query(
              `UPDATE pool_entries SET amount=$1, avg_balance=$2, last_update_at=NOW() WHERE id=$3`,
              [newBal, newAvg, old.id],
            );
          } else {
            await client.query(
              `INSERT INTO pool_entries(user_id, pool_type, amount, avg_balance, joined_at)
               VALUES($1, $2, $3, $3, NOW())`,
              [userId, poolId, amount],
            );
          }

          await client.query(
            `INSERT INTO transactions(user_id, type, amount, meta)
             VALUES($1, 'deposit', $2, $3)`,
            [userId, amount, JSON.stringify({ pool: poolId })],
          );

          return { ok: true, pool: poolId, amount };
        });
      });

      await audit({
        action:    'pool.deposit',
        user_id:   userId,
        target_id: poolId,
        amount,
        status:    'success',
        ip:        req.ip,
      });

      res.json(result);
    } catch (e) {
      await audit({
        action:  'pool.deposit',
        user_id: req.user?.id,
        status:  'failure',
        error:   (e as Error).message,
        ip:      req.ip,
      });
      next(e);
    }
  },
);

// ─── POST /api/pools/withdraw ─────────────────────────────────────────────────

router.post(
  '/withdraw',
  requireIdempotency,
  validate(withdrawSchema),
  async (req: AuthRequest, res, next) => {
    try {
      const { poolId, amount } = req.body;
      const userId = req.user!.id;

      const result = await withResourceLock(`pool:${poolId}`, async () => {
        return withUserLock(userId, async (client) => {
          const lock = await client.query(
            'SELECT locked FROM pool_draw_locks WHERE pool_type=$1',
            [poolId],
          );
          if (lock.rows[0]?.locked) {
            const err: any = new Error('Pool is locked during draw');
            err.status = 423;
            throw err;
          }

          const entry = await client.query(
            `SELECT id, amount, joined_at FROM pool_entries
             WHERE user_id=$1 AND pool_type=$2 AND active=TRUE FOR UPDATE`,
            [userId, poolId],
          );
          if (!entry.rows.length) {
            const err: any = new Error('No active entry in this pool');
            err.status = 404;
            throw err;
          }
          const e = entry.rows[0];
          if (parseFloat(e.amount) < amount) {
            const err: any = new Error('Withdrawal exceeds pool balance');
            err.status = 400;
            throw err;
          }

          const heldMs  = Date.now() - new Date(e.joined_at).getTime();
          const isEarly = heldMs < 86_400_000;

          const newAmount = parseFloat(e.amount) - amount;
          if (newAmount < 0.01) {
            await client.query('UPDATE pool_entries SET active=FALSE WHERE id=$1', [e.id]);
          } else {
            await client.query(
              `UPDATE pool_entries SET amount=$1, early_exits=early_exits+$2 WHERE id=$3`,
              [newAmount, isEarly ? 1 : 0, e.id],
            );
          }

          await client.query(
            'UPDATE balances SET usdc = usdc + $1, last_updated=NOW() WHERE user_id=$2',
            [amount, userId],
          );
          await client.query(
            `INSERT INTO transactions(user_id, type, amount, meta)
             VALUES($1, 'withdraw', $2, $3)`,
            [userId, amount, JSON.stringify({ pool: poolId, early: isEarly })],
          );

          return { ok: true, withdrawn: amount, early_exit: isEarly };
        });
      });

      await audit({
        action:    'pool.withdraw',
        user_id:   userId,
        target_id: poolId,
        amount,
        status:    'success',
        ip:        req.ip,
      });

      res.json(result);
    } catch (e) {
      await audit({
        action:  'pool.withdraw',
        user_id: req.user?.id,
        status:  'failure',
        error:   (e as Error).message,
        ip:      req.ip,
      });
      next(e);
    }
  },
);

// ─── GET /api/pools/history ───────────────────────────────────────────────────

router.get('/history', async (req: AuthRequest, res, next) => {
  try {
    const r = await db.query(
      `SELECT pool_type, amount, round_index, distributed_at
       FROM pool_rewards WHERE winner_id=$1
       ORDER BY distributed_at DESC LIMIT 20`,
      [req.user!.id],
    );
    res.json(r.rows);
  } catch (e) { next(e); }
});

export default router;
