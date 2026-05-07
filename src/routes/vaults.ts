import { Router }                from 'express';
import { verifyJwt, AuthRequest } from '../middleware/auth.js';
import { validate, createVaultSchema } from '../utils/validation.js';
import { requireIdempotency }     from '../utils/idempotency.js';
import { withUserLock }           from '../utils/dbLocks.js';
import { audit }                  from '../utils/audit.js';
import { db }                     from '../models/db.js';
import { z }                      from 'zod';

const router = Router();
router.use(verifyJwt);

router.get('/', async (req: AuthRequest, res, next) => {
  try {
    const r = await db.query(
      `SELECT v.*, COALESCE(json_agg(
         json_build_object('wallet', vb.wallet, 'pct', vb.pct, 'paid', vb.paid)
       ) FILTER (WHERE vb.id IS NOT NULL), '[]') AS beneficiaries
       FROM vaults v
       LEFT JOIN vault_beneficiaries vb ON vb.vault_id = v.id
       WHERE v.user_id = $1
       GROUP BY v.id
       ORDER BY v.created_at DESC`,
      [req.user!.id],
    );
    res.json(r.rows);
  } catch (e) { next(e); }
});

router.post(
  '/',
  requireIdempotency,
  validate(createVaultSchema),
  async (req: AuthRequest, res, next) => {
    try {
      const { inactivity_days, beneficiaries } = req.body;
      const sum = beneficiaries.reduce((s: number, b: any) => s + b.pct, 0);
      if (sum !== 100) {
        return res.status(400).json({ error: 'Beneficiary percentages must sum to exactly 100' });
      }

      const vaultId = await withUserLock(req.user!.id, async (client) => {
        const v = await client.query(
          `INSERT INTO vaults(user_id, inactivity_days) VALUES($1, $2) RETURNING id`,
          [req.user!.id, inactivity_days],
        );
        const id = v.rows[0].id;
        for (const b of beneficiaries) {
          await client.query(
            `INSERT INTO vault_beneficiaries(vault_id, wallet, pct) VALUES($1, $2, $3)`,
            [id, b.wallet, b.pct],
          );
        }
        return id;
      });

      await audit({
        action: 'vault.created',
        user_id: req.user!.id,
        target_id: vaultId,
        status: 'success',
        ip: req.ip,
        metadata: { beneficiary_count: beneficiaries.length, inactivity_days },
      });

      res.status(201).json({ id: vaultId });
    } catch (e) { next(e); }
  },
);

router.post(
  '/:id/ping',
  validate(z.object({ id: z.string().uuid() }), 'params'),
  async (req: AuthRequest, res, next) => {
    try {
      const r = await db.query(
        `UPDATE vaults SET last_ping=NOW()
         WHERE id=$1 AND user_id=$2 AND status='active' RETURNING id`,
        [req.params.id, req.user!.id],
      );
      if (!r.rows.length) return res.status(404).json({ error: 'Vault not found or not active' });
      await audit({
        action: 'vault.ping',
        user_id: req.user!.id,
        target_id: req.params.id,
        status: 'success',
        ip: req.ip,
      });
      res.json({ ok: true, last_ping: new Date() });
    } catch (e) { next(e); }
  },
);

router.delete(
  '/:id',
  validate(z.object({ id: z.string().uuid() }), 'params'),
  async (req: AuthRequest, res, next) => {
    try {
      const r = await db.query(
        `UPDATE vaults SET status='cancelled'
         WHERE id=$1 AND user_id=$2 AND status='active' RETURNING id`,
        [req.params.id, req.user!.id],
      );
      if (!r.rows.length) return res.status(404).json({ error: 'Vault not found' });
      await audit({
        action: 'vault.cancelled',
        user_id: req.user!.id,
        target_id: req.params.id,
        status: 'success',
        ip: req.ip,
      });
      res.json({ ok: true });
    } catch (e) { next(e); }
  },
);

export default router;
