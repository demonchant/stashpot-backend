/**
 * StashPot — Webhook Handlers (Fix #1: webhook security)
 *
 * Every webhook endpoint:
 *   1. Reads the RAW body (json-parser on /api/webhooks does verify+preserve)
 *   2. Validates provider HMAC signature with constant-time comparison
 *   3. Validates timestamp is within ±5 minutes (prevents replay)
 *   4. Records every event by provider_ref — duplicate deliveries become no-ops
 *   5. Never modifies balances without an existing pending fiat_transaction row
 *   6. Audits every receipt — accepted and rejected
 */

import express, { Router }      from 'express';
import crypto                   from 'crypto';
import { db }                   from '../models/db.js';
import { audit }                from '../utils/audit.js';
import { log }                  from '../utils/logger.js';
import { withUserLock }         from '../utils/dbLocks.js';

const router = Router();

// Raw-body parser for signature verification (must be before json())
const rawJson = express.raw({ type: 'application/json', limit: '256kb' });

// ─── HMAC verification helper ─────────────────────────────────────────────────

function verifyHmac(
  secret:    string,
  rawBody:   Buffer,
  signature: string,
): boolean {
  if (!secret || !signature) return false;
  try {
    // Accept "sha256=<hex>" format or bare hex
    const sigHex = signature.startsWith('sha256=') ? signature.slice(7) : signature;
    const expected = crypto.createHmac('sha256', secret).update(rawBody).digest('hex');

    if (expected.length !== sigHex.length) return false;
    return crypto.timingSafeEqual(
      Buffer.from(expected, 'hex'),
      Buffer.from(sigHex,   'hex'),
    );
  } catch (err) {
    log.warn('hmac verify failed', { err: (err as Error).message });
    return false;
  }
}

function timestampWithinWindow(ts: number | string | undefined, windowSecs = 300): boolean {
  if (ts === undefined || ts === null) return false;
  const tsNum = typeof ts === 'string' ? parseInt(ts, 10) : ts;
  if (!Number.isFinite(tsNum)) return false;
  const now = Math.floor(Date.now() / 1000);
  return Math.abs(now - tsNum) <= windowSecs;
}

// ─── Webhook idempotency via provider_ref ─────────────────────────────────────

/**
 * Atomic claim-this-delivery primitive.
 *
 * Returns true if THIS request is the one that successfully inserted the
 * row (i.e. won the race). Returns false if another request already
 * inserted it (duplicate or concurrent retry).
 *
 * Critical: this is a SINGLE STATEMENT. There is no time-of-check vs
 * time-of-use window. Two concurrent webhook deliveries with the same
 * event_id will both attempt the INSERT; exactly one succeeds (returns
 * a row), the other gets ON CONFLICT and returns 0 rows.
 *
 * This closes finding #3 from the advanced audit.
 */
async function claimDelivery(
  provider: string,
  eventId:  string,
  payload:  any,
): Promise<boolean> {
  const r = await db.query(
    `INSERT INTO webhook_deliveries(provider, event_id, payload)
     VALUES($1, $2, $3)
     ON CONFLICT (provider, event_id) DO NOTHING
     RETURNING id`,
    [provider, eventId, JSON.stringify(payload)],
  );
  return r.rowCount === 1;
}

// ─── Yellow Card ──────────────────────────────────────────────────────────────

router.post('/yellow-card', rawJson, async (req, res) => {
  const raw       = req.body as Buffer;
  const signature = (req.headers['x-yellowcard-signature'] as string) || '';
  const timestamp = req.headers['x-yellowcard-timestamp'] as string;
  const secret    = process.env.YELLOW_CARD_WEBHOOK_SECRET || '';

  const ip = (req.headers['x-forwarded-for'] as string) || req.ip || null;

  // [Fix #1.A] Require signature
  if (!signature) {
    await audit({
      action: 'webhook.rejected',
      status: 'failure',
      ip,
      metadata: { provider: 'yellow_card', reason: 'missing_signature' },
    });
    return res.status(401).json({ error: 'Missing signature' });
  }

  // [Fix #1.B] Verify HMAC
  if (!verifyHmac(secret, raw, signature)) {
    await audit({
      action: 'webhook.rejected',
      status: 'failure',
      ip,
      metadata: { provider: 'yellow_card', reason: 'invalid_signature' },
    });
    return res.status(401).json({ error: 'Invalid signature' });
  }

  // [Fix #1.C] Reject replay — timestamp must be fresh
  if (!timestampWithinWindow(timestamp)) {
    await audit({
      action: 'webhook.rejected',
      status: 'failure',
      ip,
      metadata: { provider: 'yellow_card', reason: 'stale_timestamp' },
    });
    return res.status(401).json({ error: 'Stale request' });
  }

  // Parse body only AFTER signature verification
  let body: any;
  try { body = JSON.parse(raw.toString('utf8')); }
  catch { return res.status(400).json({ error: 'Invalid JSON' }); }

  const eventId   = body.event_id || body.id;
  const eventType = body.event    || body.type;
  const data      = body.data     || body;

  if (!eventId || !eventType) {
    return res.status(400).json({ error: 'Missing event_id or event' });
  }

  // [Fix #1.D + #3] Atomic dedup — the INSERT-RETURNING is a single statement
  // so two concurrent retries can't both pass. Exactly one wins; the loser
  // returns the deduplicated response without touching balances.
  const wonRace = await claimDelivery('yellow_card', eventId, body);
  if (!wonRace) {
    log.info('webhook duplicate', { provider: 'yellow_card', eventId });
    return res.json({ ok: true, deduplicated: true });
  }

  await audit({
    action: 'webhook.received',
    status: 'success',
    ip,
    metadata: { provider: 'yellow_card', eventType, eventId },
  });

  if (eventType !== 'payment.completed') {
    return res.json({ ok: true });
  }

  // Process payment completion
  const reference = data.reference;
  if (!reference) return res.status(400).json({ error: 'Missing reference' });

  const tx = await db.query(
    `SELECT * FROM fiat_transactions WHERE provider_ref = $1 AND status = 'pending'`,
    [reference],
  );
  if (!tx.rows.length) {
    return res.json({ ok: true, note: 'Transaction not found or already settled' });
  }
  const t = tx.rows[0];

  // [Missing #2] Transaction lock — serialize credits to this user
  try {
    await withUserLock(t.user_id, async (client) => {
      // Re-check status under lock
      const again = await client.query(
        `SELECT status FROM fiat_transactions WHERE provider_ref = $1 FOR UPDATE`,
        [reference],
      );
      if (!again.rows.length || again.rows[0].status !== 'pending') return;

      await client.query(
        `UPDATE fiat_transactions SET status='completed', settled_at=NOW()
         WHERE provider_ref=$1 AND status='pending'`,
        [reference],
      );
      await client.query(
        'UPDATE balances SET usdc = usdc + $1, last_updated=NOW() WHERE user_id=$2',
        [t.usdc_amount, t.user_id],
      );
      await client.query(
        `INSERT INTO transactions(user_id, type, amount, meta)
         VALUES($1, 'fiat_deposit', $2, $3)`,
        [t.user_id, t.usdc_amount, JSON.stringify({ provider: 'yellow_card', ref: reference })],
      );
    });

    await audit({
      action:    'fiat.deposit_completed',
      user_id:   t.user_id,
      target_id: reference,
      amount:    parseFloat(t.usdc_amount),
      status:    'success',
      metadata:  { provider: 'yellow_card' },
    });
  } catch (err) {
    log.error('yellow-card webhook processing failed', { err: (err as Error).message, reference });
    return res.status(500).json({ error: 'Processing failed' });
  }

  res.json({ ok: true });
});

// ─── Transak ──────────────────────────────────────────────────────────────────

router.post('/transak', rawJson, async (req, res) => {
  const raw       = req.body as Buffer;
  const signature = (req.headers['x-transak-signature'] as string) || '';
  const timestamp = req.headers['x-transak-timestamp'] as string;
  const secret    = process.env.TRANSAK_WEBHOOK_SECRET || '';

  const ip = (req.headers['x-forwarded-for'] as string) || req.ip || null;

  if (!signature) {
    await audit({ action: 'webhook.rejected', status: 'failure', ip,
      metadata: { provider: 'transak', reason: 'missing_signature' } });
    return res.status(401).json({ error: 'Missing signature' });
  }

  if (!verifyHmac(secret, raw, signature)) {
    await audit({ action: 'webhook.rejected', status: 'failure', ip,
      metadata: { provider: 'transak', reason: 'invalid_signature' } });
    return res.status(401).json({ error: 'Invalid signature' });
  }

  if (!timestampWithinWindow(timestamp)) {
    await audit({ action: 'webhook.rejected', status: 'failure', ip,
      metadata: { provider: 'transak', reason: 'stale_timestamp' } });
    return res.status(401).json({ error: 'Stale request' });
  }

  let body: any;
  try { body = JSON.parse(raw.toString('utf8')); }
  catch { return res.status(400).json({ error: 'Invalid JSON' }); }

  const eventId = body.eventID || body.webhookData?.id;
  if (!eventId) return res.status(400).json({ error: 'Missing event id' });

  const wonRace = await claimDelivery('transak', eventId, body);
  if (!wonRace) {
    return res.json({ ok: true, deduplicated: true });
  }

  await audit({ action: 'webhook.received', status: 'success', ip,
    metadata: { provider: 'transak', eventId } });

  if (body.eventID !== 'ORDER_COMPLETED') return res.json({ ok: true });

  const orderId = body.webhookData?.id;
  const tx      = await db.query(
    `SELECT * FROM fiat_transactions WHERE provider_ref = $1 AND status = 'pending'`,
    [orderId],
  );
  if (!tx.rows.length) return res.json({ ok: true });
  const t = tx.rows[0];

  try {
    await withUserLock(t.user_id, async (client) => {
      const again = await client.query(
        `SELECT status FROM fiat_transactions WHERE provider_ref = $1 FOR UPDATE`,
        [orderId],
      );
      if (!again.rows.length || again.rows[0].status !== 'pending') return;

      await client.query(
        `UPDATE fiat_transactions SET status='completed', settled_at=NOW()
         WHERE provider_ref=$1 AND status='pending'`,
        [orderId],
      );
      await client.query(
        'UPDATE balances SET usdc = usdc + $1, last_updated=NOW() WHERE user_id=$2',
        [t.usdc_amount, t.user_id],
      );
      await client.query(
        `INSERT INTO transactions(user_id, type, amount, meta)
         VALUES($1, 'fiat_deposit', $2, $3)`,
        [t.user_id, t.usdc_amount, JSON.stringify({ provider: 'transak', ref: orderId })],
      );
    });

    await audit({
      action:    'fiat.deposit_completed',
      user_id:   t.user_id,
      target_id: orderId,
      amount:    parseFloat(t.usdc_amount),
      status:    'success',
      metadata:  { provider: 'transak' },
    });
  } catch (err) {
    log.error('transak webhook processing failed', { err: (err as Error).message, orderId });
    return res.status(500).json({ error: 'Processing failed' });
  }

  res.json({ ok: true });
});

export default router;
