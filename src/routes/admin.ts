/**
 * StashPot — Admin Routes
 *
 * Admin-only operations. Auth gated by JWT + admin-list check.
 * Use ADMIN_USER_IDS env var (comma-separated UUIDs) for a static
 * allowlist. In production this should be tied to a multisig.
 */

import { Router, Response, NextFunction } from 'express';
import { verifyJwt, AuthRequest }  from '../middleware/auth.js';
import { validate }                 from '../utils/validation.js';
import { setFeature, FeatureKey, publicFeatures } from '../config/features.js';
import { audit }                    from '../utils/audit.js';
import { z }                        from 'zod';

const router = Router();
router.use(verifyJwt);

// Admin allowlist — static for now, swap for multisig check in production.
const ADMIN_USER_IDS = (process.env.ADMIN_USER_IDS || '')
  .split(',').map(s => s.trim()).filter(Boolean);

function requireAdmin(req: AuthRequest, res: Response, next: NextFunction) {
  if (!req.user?.id || !ADMIN_USER_IDS.includes(req.user.id)) {
    return res.status(403).json({ error: 'Admin only' });
  }
  next();
}

router.use(requireAdmin);

// GET /api/admin/features — list all flags + state
router.get('/features', (_req, res) => {
  res.json(publicFeatures());
});

// POST /api/admin/features — toggle a flag (live, no restart)
const setFeatureSchema = z.object({
  feature: z.enum([
    'VAULT', 'DEPOSITS', 'WITHDRAWALS',
    'PRIZE_POOLS', 'INHERITANCE', 'CIRCLES',
    'LOANS', 'REFERRALS', 'FIAT', 'CARDS',
  ]),
  enabled: z.boolean(),
});

router.post(
  '/features',
  validate(setFeatureSchema),
  async (req: AuthRequest, res, next) => {
    try {
      const { feature, enabled } = req.body as { feature: FeatureKey; enabled: boolean };
      await setFeature(feature, enabled, req.user!.id);
      await audit({
        action:    'admin.feature_toggled',
        user_id:   req.user!.id,
        target_id: feature,
        status:    'success',
        ip:        req.ip,
        metadata:  { enabled },
      });
      res.json({ ok: true, feature, enabled });
    } catch (e) { next(e); }
  },
);

export default router;
