import { Router }                 from 'express';
import rateLimit                   from 'express-rate-limit';
import { generateNonce, verifySignature, issueJwt } from '../middleware/auth.js';
import { validate, authVerifySchema, solanaPubkey } from '../utils/validation.js';
import { audit }                   from '../utils/audit.js';
import { db }                      from '../models/db.js';
import { z }                       from 'zod';

const router = Router();

// Extra per-IP limit for nonce generation (prevents nonce flooding)
const nonceLimiter = rateLimit({
  windowMs: 60 * 1_000, max: 5,
  message: { error: 'Too many nonce requests' },
});

// GET /api/auth/nonce/:wallet
router.get(
  '/nonce/:wallet',
  nonceLimiter,
  validate(z.object({ wallet: solanaPubkey }), 'params'),
  async (req, res, next) => {
    try {
      const { wallet } = req.params;
      const nonce = await generateNonce(wallet);
      await audit({
        action: 'auth.nonce_issued',
        target_id: wallet,
        status: 'success',
        ip: req.ip,
      });
      res.json({ nonce });
    } catch (e) { next(e); }
  },
);

// POST /api/auth/verify — exchanges signed nonce for JWT
router.post(
  '/verify',
  validate(authVerifySchema),
  async (req, res, next) => {
    try {
      const { wallet, signature, nonce } = req.body;

      const valid = await verifySignature(wallet, signature, nonce);
      if (!valid) {
        await audit({
          action: 'auth.login',
          target_id: wallet,
          status: 'failure',
          error: 'Invalid signature',
          ip: req.ip,
        });
        return res.status(401).json({ error: 'Invalid signature' });
      }

      const result = await db.query(
        `INSERT INTO users(wallet) VALUES($1)
         ON CONFLICT(wallet) DO UPDATE SET last_seen_at=NOW()
         RETURNING id, wallet, username, is_banned`,
        [wallet],
      );
      const user = result.rows[0];

      if (user.is_banned) {
        await audit({
          action: 'auth.login',
          user_id: user.id,
          target_id: wallet,
          status: 'failure',
          error: 'Banned',
          ip: req.ip,
        });
        return res.status(403).json({ error: 'Account unavailable' });
      }

      await db.query(
        'INSERT INTO balances(user_id) VALUES($1) ON CONFLICT DO NOTHING',
        [user.id],
      );
      await db.query(
        'INSERT INTO scores(user_id) VALUES($1) ON CONFLICT DO NOTHING',
        [user.id],
      );

      const token = issueJwt(user.id, wallet);

      await audit({
        action: 'auth.login',
        user_id: user.id,
        target_id: wallet,
        status: 'success',
        ip: req.ip,
      });

      res.json({ token, user: { id: user.id, wallet: user.wallet, username: user.username } });
    } catch (e) { next(e); }
  },
);

export default router;
