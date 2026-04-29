import { Router }              from 'express';
import { verifyJwt, AuthRequest } from '../middleware/auth.js';
import { validate, updateUserSchema, fcmTokenSchema } from '../utils/validation.js';
import { db }                   from '../models/db.js';

const router = Router();
router.use(verifyJwt); // [Fix #2] All user routes require auth

router.get('/me', async (req: AuthRequest, res, next) => {
  try {
    const r = await db.query(
      `SELECT u.id, u.wallet, u.username, u.email, u.created_at,
              b.usdc,
              s.composite, s.tier
       FROM users u
       LEFT JOIN balances b ON b.user_id = u.id
       LEFT JOIN scores   s ON s.user_id = u.id
       WHERE u.id = $1`,
      [req.user!.id],
    );
    if (!r.rows.length) return res.status(404).json({ error: 'User not found' });
    res.json(r.rows[0]);
  } catch (e) { next(e); }
});

router.patch(
  '/me',
  validate(updateUserSchema),
  async (req: AuthRequest, res, next) => {
    try {
      const { username, email } = req.body;
      if (username) {
        const taken = await db.query(
          'SELECT id FROM users WHERE username=$1 AND id!=$2',
          [username, req.user!.id],
        );
        if (taken.rows.length) return res.status(409).json({ error: 'Username taken' });
      }
      await db.query(
        `UPDATE users SET username = COALESCE($1, username), email = COALESCE($2, email) WHERE id = $3`,
        [username || null, email || null, req.user!.id],
      );
      res.json({ ok: true });
    } catch (e) { next(e); }
  },
);

router.post(
  '/fcm-token',
  validate(fcmTokenSchema),
  async (req: AuthRequest, res, next) => {
    try {
      await db.query('UPDATE users SET fcm_token=$1 WHERE id=$2', [req.body.token, req.user!.id]);
      res.json({ ok: true });
    } catch (e) { next(e); }
  },
);

router.get('/history', async (req: AuthRequest, res, next) => {
  try {
    const r = await db.query(
      `SELECT type, amount, meta, created_at FROM transactions
       WHERE user_id=$1 ORDER BY created_at DESC LIMIT 50`,
      [req.user!.id],
    );
    res.json(r.rows);
  } catch (e) { next(e); }
});

export default router;
