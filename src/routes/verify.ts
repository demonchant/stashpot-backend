/**
 * StashPot — Public Verifiability Endpoints
 *
 * Zero trust required — anyone can reproduce the winner selection
 * from on-chain data plus what these endpoints return.
 *
 * No auth. Cached via Redis.
 */

import { Router }                   from 'express';
import { validate, poolType, solanaPubkey } from '../utils/validation.js';
import { cached }                   from '../utils/cache.js';
import { db }                       from '../models/db.js';
import { WeightService, PoolEntry } from '../services/WeightService.js';
import { z }                        from 'zod';

const router = Router();

router.get(
  '/round/:roundId',
  validate(z.object({ roundId: z.string().regex(/^\d+$/).max(20) }), 'params'),
  validate(z.object({ pool_type: poolType.optional() }), 'query'),
  async (req, res, next) => {
    try {
      const { roundId } = req.params;
      const pt          = (req.query.pool_type as string) || 'weekly';

      const data = await cached(`verify:round:${pt}:${roundId}`, 300, async () => {
        const draw = await db.query(
          'SELECT * FROM pool_rewards WHERE round_index=$1 AND pool_type=$2',
          [roundId, pt],
        );
        if (!draw.rows.length) return null;
        const d = draw.rows[0];

        const participants = await db.query(
          `SELECT pe.user_id, pe.avg_balance, pe.amount, pe.joined_at, pe.early_exits, u.wallet
           FROM pool_entries pe JOIN users u ON u.id = pe.user_id
           WHERE pe.pool_type=$1 ORDER BY pe.user_id ASC`,
          [pt],
        );

        const drawAt = new Date(d.distributed_at).getTime();
        const entries: PoolEntry[] = participants.rows.map((r: any) => ({
          userId:           r.user_id,
          balance:          parseFloat(r.amount),
          joinedAt:         new Date(r.joined_at).getTime(),
          lastUpdateAt:     drawAt,
          earlyWithdrawals: parseInt(r.early_exits || '0', 10),
          avgBalance:       parseFloat(r.avg_balance || r.amount),
        }));

        const table       = WeightService.buildOddsTable(entries, drawAt);
        const totalWeight = table.reduce((s, e) => s + e.weight, 0);

        return {
          round_index:       roundId,
          pool_type:         pt,
          executed_at:       d.distributed_at,
          prize_amount:      d.amount,
          winner_user_id:    d.winner_id,
          total_weight:      totalWeight,
          participant_count: participants.rows.length,
          formula:           'W = avg_balance × log(1+avg_balance) × T_hours × e^{-0.15 × early_exits}',
          verification_steps: [
            '1. Fetch all UserAccount PDAs from yield_vault program',
            '2. Compute W for each using the formula above',
            '3. Normalize to get probabilities',
            '4. Verify Merkle root matches DrawRecord.merkle_root on-chain',
            '5. Read vrf_result from Switchboard VRF account',
            '6. random_value = vrf_result[0..16] as u128 % total_weight',
            '7. Walk sorted weight list — winner is first with cumulative > random_value',
          ],
          participants: participants.rows.map((r: any, i: number) => ({
            wallet:      r.wallet,
            avg_balance: parseFloat(r.avg_balance || r.amount),
            held_hours:  Math.floor((drawAt - new Date(r.joined_at).getTime()) / 3_600_000),
            early_exits: parseInt(r.early_exits || '0', 10),
            weight:      table[i]?.weight || 0,
            chance:      totalWeight > 0
              ? ((table[i]?.weight || 0) / totalWeight * 100).toFixed(4) + '%'
              : '0%',
          })),
        };
      });

      if (!data) return res.status(404).json({ error: 'Round not found' });
      res.set('Cache-Control', 'public, max-age=300');
      res.json(data);
    } catch (e) { next(e); }
  },
);

router.get(
  '/weights/:poolType',
  validate(z.object({ poolType }), 'params'),
  async (req, res, next) => {
    try {
      const { poolType: pt } = req.params;
      const now    = Date.now();
      const drawAt = now + 7 * 24 * 3_600_000;

      const rows = await db.query(
        `SELECT pe.user_id, pe.amount, pe.avg_balance, pe.joined_at, pe.early_exits, u.wallet
         FROM pool_entries pe JOIN users u ON u.id = pe.user_id
         WHERE pe.pool_type=$1 AND pe.active=TRUE AND pe.prize_opted_in=TRUE
         ORDER BY pe.user_id ASC`,
        [pt],
      );

      const entries: PoolEntry[] = rows.rows.map((r: any) => ({
        userId:           r.user_id,
        balance:          parseFloat(r.amount),
        joinedAt:         new Date(r.joined_at).getTime(),
        lastUpdateAt:     now,
        earlyWithdrawals: parseInt(r.early_exits || '0', 10),
        avgBalance:       parseFloat(r.avg_balance || r.amount),
      }));

      const table       = WeightService.buildOddsTable(entries, drawAt);
      const totalWeight = table.reduce((s, e) => s + e.weight, 0);

      const result = rows.rows.map((r: any, i: number) => ({
        wallet:      r.wallet,
        avg_balance: parseFloat(r.avg_balance || r.amount),
        held_hours:  Math.floor((now - new Date(r.joined_at).getTime()) / 3_600_000),
        early_exits: parseInt(r.early_exits || '0', 10),
        weight:      table[i]?.weight || 0,
        chance:      totalWeight > 0
          ? ((table[i]?.weight || 0) / totalWeight * 100).toFixed(4) + '%'
          : '0%',
      })).sort((a, b) => b.weight - a.weight);

      res.set('Cache-Control', 'public, max-age=60');
      res.json({
        pool_type:    pt,
        formula:      'W = avg_balance × log(1+avg_balance) × T_hours × e^{-0.15 × early_exits}',
        total_weight: totalWeight,
        participants: result.length,
        weights:      result,
      });
    } catch (e) { next(e); }
  },
);

router.get(
  '/odds/:wallet',
  validate(z.object({ wallet: solanaPubkey }), 'params'),
  async (req, res, next) => {
    try {
      const { wallet } = req.params;
      const user = await db.query('SELECT id FROM users WHERE wallet=$1', [wallet]);
      if (!user.rows.length) return res.status(404).json({ error: 'Wallet not found' });
      const userId = user.rows[0].id;
      const now    = Date.now();
      const result: any = {};

      for (const pt of ['daily', 'weekly', 'monthly']) {
        const pos = await db.query(
          `SELECT amount, avg_balance, joined_at, early_exits
           FROM pool_entries
           WHERE user_id=$1 AND pool_type=$2 AND active=TRUE`,
          [userId, pt],
        );
        if (!pos.rows.length) { result[pt] = { active: false }; continue; }

        const all = await db.query(
          `SELECT user_id, amount, avg_balance, joined_at, early_exits
           FROM pool_entries
           WHERE pool_type=$1 AND active=TRUE AND prize_opted_in=TRUE`,
          [pt],
        );
        const daysMap: Record<string, number> = { daily: 1, weekly: 7, monthly: 30 };
        const drawAt = now + daysMap[pt] * 86_400_000;
        const entries: PoolEntry[] = all.rows.map((r: any) => ({
          userId:           r.user_id,
          balance:          parseFloat(r.amount),
          joinedAt:         new Date(r.joined_at).getTime(),
          lastUpdateAt:     now,
          earlyWithdrawals: parseInt(r.early_exits || '0', 10),
          avgBalance:       parseFloat(r.avg_balance || r.amount),
        }));
        const table = WeightService.buildOddsTable(entries, drawAt);
        const mine  = table.find(e => e.userId === userId);
        const total = table.reduce((s, e) => s + e.weight, 0);
        result[pt] = {
          active:      true,
          balance:     parseFloat(pos.rows[0].amount),
          avg_balance: parseFloat(pos.rows[0].avg_balance),
          held_hours:  Math.floor((now - new Date(pos.rows[0].joined_at).getTime()) / 3_600_000),
          early_exits: parseInt(pos.rows[0].early_exits || '0', 10),
          weight:      mine?.weight || 0,
          chance:      total > 0 ? ((mine?.weight || 0) / total * 100).toFixed(4) + '%' : '0%',
          pool_size:   all.rows.length,
        };
      }

      res.json({ wallet, odds: result });
    } catch (e) { next(e); }
  },
);

export default router;
