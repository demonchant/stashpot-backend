import { Router }                from 'express';
import { verifyJwt, AuthRequest } from '../middleware/auth.js';
import { validate, registerReferralSchema } from '../utils/validation.js';
import { audit }                  from '../utils/audit.js';
import { db }                     from '../models/db.js';

const router = Router();
router.use(verifyJwt);

const REFERRAL_REWARD = 2.00;

router.get('/stats', async (req: AuthRequest, res, next) => {
  try {
    const r = await db.query(
      `SELECT
         COUNT(*)                                        total,
         COUNT(*) FILTER (WHERE deposited=TRUE)         deposited,
         COUNT(*) FILTER (WHERE reward_paid=TRUE)       paid,
         COALESCE(SUM(CASE WHEN reward_paid THEN $2 END), 0) earned
       FROM referrals WHERE referrer_id=$1`,
      [req.user!.id, REFERRAL_REWARD],
    );
    const code = await db.query(
      'SELECT code FROM referrals WHERE referrer_id=$1 LIMIT 1',
      [req.user!.id],
    );
    res.json({ ...r.rows[0], code: code.rows[0]?.code || null });
  } catch (e) { next(e); }
});

router.post('/generate', async (req: AuthRequest, res, next) => {
  try {
    const existing = await db.query(
      `SELECT code FROM referrals WHERE referrer_id=$1 AND referred_id IS NULL LIMIT 1`,
      [req.user!.id],
    );
    if (existing.rows.length) return res.json({ code: existing.rows[0].code });

    const code = Math.random().toString(36).slice(2, 8).toUpperCase();
    await db.query(
      `INSERT INTO referrals(referrer_id, code) VALUES($1, $2)`,
      [req.user!.id, code],
    );
    res.json({ code });
  } catch (e) { next(e); }
});

router.post(
  '/register',
  validate(registerReferralSchema),
  async (req: AuthRequest, res, next) => {
    try {
      const { code } = req.body;

      const ref = await db.query(
        'SELECT id, referrer_id FROM referrals WHERE code=$1 AND referred_id IS NULL',
        [code],
      );
      if (!ref.rows.length) return res.status(404).json({ error: 'Invalid referral code' });
      if (ref.rows[0].referrer_id === req.user!.id) {
        return res.status(400).json({ error: 'Cannot refer yourself' });
      }

      const monthly = await db.query(
        `SELECT COUNT(*) c FROM referrals
         WHERE referrer_id=$1 AND created_at > NOW() - INTERVAL '30 days'`,
        [ref.rows[0].referrer_id],
      );
      if (parseInt(monthly.rows[0].c, 10) >= 50) {
        return res.status(400).json({ error: 'Referrer limit reached' });
      }

      await db.query(
        'UPDATE referrals SET referred_id=$1 WHERE id=$2',
        [req.user!.id, ref.rows[0].id],
      );

      await audit({
        action: 'referral.registered',
        user_id: req.user!.id,
        target_id: ref.rows[0].referrer_id,
        status: 'success',
        ip: req.ip,
      });

      res.json({ ok: true });
    } catch (e) { next(e); }
  },
);

router.get('/leaderboard', async (_req, res, next) => {
  try {
    const r = await db.query(
      `SELECT u.username, u.wallet,
              COUNT(*) FILTER (WHERE r.deposited) AS conversions
       FROM referrals r JOIN users u ON u.id=r.referrer_id
       GROUP BY u.id ORDER BY conversions DESC LIMIT 10`,
    );
    res.json(r.rows);
  } catch (e) { next(e); }
});

export default router;
