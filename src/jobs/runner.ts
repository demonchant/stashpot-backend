/**
 * StashPot Automation Runner — HARDENED
 *
 * All draws serialized by withResourceLock — two workers can't run
 * the same draw simultaneously (even if you scale to multiple instances).
 * Every financial mutation is audited.
 */

import cron                  from 'node-cron';
import { db }                from '../models/db.js';
import { WeightService, PoolEntry } from '../services/WeightService.js';
import { withResourceLock, withUserLock, withDrawLock } from '../utils/dbLocks.js';
import { audit }             from '../utils/audit.js';
import { anchorAuditLog, verifyAgainstLastAnchor } from '../services/AuditAnchor.js';
import { log }               from '../utils/logger.js';

// ─── Daily draw ───────────────────────────────────────────────────────────────
cron.schedule('5 0 * * *', async () => {
  try { await runPoolDraw('daily', 0.10); }
  catch (e) { log.error('Daily draw failed', { err: (e as Error).message }); }
});

// ─── Weekly draw ──────────────────────────────────────────────────────────────
cron.schedule('10 0 * * 1', async () => {
  try { await runPoolDraw('weekly', 0.60); }
  catch (e) { log.error('Weekly draw failed', { err: (e as Error).message }); }
});

// ─── Monthly draw ─────────────────────────────────────────────────────────────
cron.schedule('15 0 1 * *', async () => {
  try { await runPoolDraw('monthly', 0.30); }
  catch (e) { log.error('Monthly draw failed', { err: (e as Error).message }); }
});

// ─── Loan default detection ───────────────────────────────────────────────────
cron.schedule('0 * * * *', async () => {
  try {
    const overdue = await db.query(
      `SELECT id, user_id, principal FROM loans
       WHERE status='active' AND due_at < NOW() - INTERVAL '72 hours'`,
    );
    for (const loan of overdue.rows) {
      try {
        await withUserLock(loan.user_id, async (client) => {
          await client.query(`UPDATE loans SET status='defaulted' WHERE id=$1`, [loan.id]);
          await client.query(
            `UPDATE scores SET in_default=TRUE,
             composite=GREATEST(composite-100,0)
             WHERE user_id=$1`,
            [loan.user_id],
          );
        });
        await audit({
          action: 'loan.defaulted',
          user_id: loan.user_id,
          target_id: loan.id,
          amount: parseFloat(loan.principal),
          status: 'success',
        });
      } catch (e) {
        log.error('Default mark failed', { loanId: loan.id, err: (e as Error).message });
      }
    }
  } catch (e) { log.error('Loan default check failed', { err: (e as Error).message }); }
});

// ─── Vault inactivity alerts ──────────────────────────────────────────────────
cron.schedule('0 */12 * * *', async () => {
  try {
    const expiring = await db.query(
      `SELECT v.user_id, v.inactivity_days, v.last_ping, u.fcm_token
       FROM vaults v JOIN users u ON u.id=v.user_id
       WHERE v.status='active'
         AND v.last_ping < NOW() - (v.inactivity_days::TEXT || ' days')::INTERVAL + INTERVAL '3 days'`,
    );
    log.info(`[vault] ${expiring.rows.length} vaults expiring within 3 days`);
  } catch (e) { log.error('Vault check failed', { err: (e as Error).message }); }
});

// ─── EMA balance updater (hourly) ─────────────────────────────────────────────
cron.schedule('30 * * * *', async () => {
  try {
    const entries = await db.query(
      `SELECT id, amount, avg_balance FROM pool_entries WHERE active=TRUE`,
    );
    for (const e of entries.rows) {
      const newAvg = WeightService.updateAvgBalance(
        parseFloat(e.avg_balance || '0'),
        parseFloat(e.amount),
        0.1,
      );
      await db.query(
        `UPDATE pool_entries SET avg_balance=$1, last_update_at=NOW() WHERE id=$2`,
        [newAvg, e.id],
      );
    }
    log.info(`[ema] Updated ${entries.rows.length} EMAs`);
  } catch (e) { log.error('EMA updater failed', { err: (e as Error).message }); }
});

// ─── Referral fraud sweep ─────────────────────────────────────────────────────
cron.schedule('0 */6 * * *', async () => {
  try {
    await db.query('DELETE FROM referrals WHERE referrer_id = referred_id');
    const hv = await db.query(
      `SELECT referrer_id, COUNT(*) c FROM referrals
       WHERE created_at > NOW()-INTERVAL '30 days'
       GROUP BY referrer_id HAVING COUNT(*) > 50`,
    );
    for (const r of hv.rows) {
      await db.query('UPDATE users SET is_banned=TRUE WHERE id=$1', [r.referrer_id]);
      await audit({
        action: 'security.suspicious_activity',
        user_id: r.referrer_id,
        status: 'success',
        metadata: { reason: 'high_velocity_referrals', count: parseInt(r.c, 10) },
      });
      log.warn('[fraud] Banned high-velocity referrer', { userId: r.referrer_id, count: r.c });
    }
  } catch (e) { log.error('Fraud sweep failed', { err: (e as Error).message }); }
});

// ─── Idempotency key cleanup ──────────────────────────────────────────────────
cron.schedule('0 2 * * *', async () => {
  try {
    await db.query(`DELETE FROM idempotency_keys WHERE created_at < NOW() - INTERVAL '24 hours'`);
    await db.query(`DELETE FROM webhook_deliveries WHERE received_at < NOW() - INTERVAL '30 days'`);
    await db.query(`DELETE FROM auth_nonces WHERE expires_at < NOW() - INTERVAL '1 hour'`);
  } catch (e) { log.error('Cleanup failed', { err: (e as Error).message }); }
});

// ─── Audit log external anchor (every 6 hours) ───────────────────────────────
// Snapshots the audit_log chain head, signs it, publishes externally.
// Backstop against deletion / truncation of audit_log.
cron.schedule('0 */6 * * *', async () => {
  try {
    await anchorAuditLog();
  } catch (e) {
    log.error('audit.anchor failed', { err: (e as Error).message });
  }
});

// ─── Anchor verification (every hour) ────────────────────────────────────────
// Detects audit log truncation early. If verification fails, alerts ops.
cron.schedule('30 * * * *', async () => {
  try {
    const result = await verifyAgainstLastAnchor();
    if (!result.ok) {
      log.error('audit.anchor.verify FAILED', { reason: result.reason });
      await audit({
        action: 'security.suspicious_activity',
        status: 'failure',
        error: `Audit log integrity violation: ${result.reason}`,
        metadata: { source: 'anchor_verification' },
      });
    }
  } catch (e) {
    log.error('audit.anchor.verify error', { err: (e as Error).message });
  }
});

// ─── Core draw engine (hardened with resource lock) ──────────────────────────

async function runPoolDraw(poolType: string, yieldShare: number) {
  const drawAt = Date.now();
  log.info('draw.start', { poolType });

  // Draw-namespace lock — won't collide with deposit/withdraw resource locks
  await withDrawLock(poolType, async (client) => {
    await client.query(
      `UPDATE pool_draw_locks SET locked=TRUE, locked_at=NOW(), draw_at=$1 WHERE pool_type=$2`,
      [new Date(drawAt), poolType],
    );

    try {
      const rows = await client.query(
        `SELECT pe.user_id, pe.amount, pe.avg_balance, pe.joined_at, pe.last_update_at, pe.early_exits
         FROM pool_entries pe
         WHERE pe.pool_type=$1 AND pe.active=TRUE AND pe.prize_opted_in=TRUE`,
        [poolType],
      );

      if (!rows.rows.length) {
        log.info('draw.skip', { poolType, reason: 'no entries' });
        return;
      }

      const entries: PoolEntry[] = rows.rows.map((r: any) => ({
        userId:           r.user_id,
        balance:          parseFloat(r.amount),
        joinedAt:         new Date(r.joined_at).getTime(),
        lastUpdateAt:     new Date(r.last_update_at || r.joined_at).getTime(),
        earlyWithdrawals: parseInt(r.early_exits || '0', 10),
        avgBalance:       parseFloat(r.avg_balance || r.amount),
      }));

      const totalDeposited = entries.reduce((s, e) => s + e.balance, 0);
      const blendedApy     = 0.0874;
      const days           = poolType === 'daily' ? 1 : poolType === 'weekly' ? 7 : 30;
      const prizeAmount    = parseFloat(
        (totalDeposited * blendedApy * (days / 365) * yieldShare).toFixed(6),
      );

      if (prizeAmount < 0.01) {
        log.info('draw.skip', { poolType, reason: 'prize too small', prizeAmount });
        return;
      }

      const winnerId = WeightService.selectWinner(entries, drawAt);
      if (!winnerId) return;

      const roundIndex = Math.floor(drawAt / 1000);

      await client.query(
        `INSERT INTO pool_rewards(pool_type, winner_id, amount, round_index, participants)
         VALUES($1, $2, $3, $4, $5)`,
        [poolType, winnerId, prizeAmount, roundIndex, entries.length],
      );
      await client.query(
        `UPDATE balances SET usdc = usdc + $1, last_updated=NOW() WHERE user_id=$2`,
        [prizeAmount, winnerId],
      );
      await client.query(
        `INSERT INTO transactions(user_id, type, amount, meta) VALUES($1, 'pool_win', $2, $3)`,
        [winnerId, prizeAmount, JSON.stringify({ pool: poolType, round: roundIndex })],
      );

      await audit({
        action: 'pool.draw_executed',
        user_id: winnerId,
        target_id: poolType,
        amount: prizeAmount,
        status: 'success',
        metadata: { round: roundIndex, participants: entries.length },
      });

      log.info('draw.success', {
        poolType, winnerId: winnerId.slice(0, 8),
        prize: prizeAmount, participants: entries.length,
      });
    } finally {
      await client.query(
        `UPDATE pool_draw_locks SET locked=FALSE WHERE pool_type=$1`,
        [poolType],
      );
    }
  });
}

log.info('runner.started', { env: process.env.NODE_ENV || 'dev' });
