/**
 * StashPot — Privy Auth Route
 *
 * Exchanges a Privy access token for a StashPot JWT.
 *
 * Privy is the primary auth provider — users sign in via email magic link,
 * Google, passkey, or any of 50+ Solana wallets through the Privy modal.
 *
 * Auth flow:
 *   1. Frontend calls usePrivy().getAccessToken() → ES256-signed JWT
 *   2. Frontend POSTs that token here
 *   3. Server calls privy.verifyAuthToken(token) → verified userId
 *   4. Server calls privy.getUser(userId) → full profile (email, wallets)
 *   5. Server upserts the StashPot user and issues a StashPot JWT
 *
 * Important: verifyAuthToken works on ACCESS tokens (the kind getAccessToken
 * returns). It does NOT work on identity tokens — for those you'd use
 * getUser({ idToken }) instead. We use access tokens because that's the
 * default flow with @privy-io/react-auth.
 */

import { Router, Request, Response, NextFunction } from 'express';
import rateLimit from 'express-rate-limit';
import { z } from 'zod';
import { PrivyClient } from '@privy-io/server-auth';
import { issueJwt } from '../../middleware/auth.js';
import { validate } from '../../utils/validation.js';
import { audit } from '../../utils/audit.js';
import { db } from '../../models/db.js';

const router = Router();

// ─── Privy client (singleton) ─────────────────────────────────────────────────
const privy = new PrivyClient(
  process.env.PRIVY_APP_ID || '',
  process.env.PRIVY_APP_SECRET || '',
);

// Rate limit auth attempts per IP (prevents brute force)
const authLimiter = rateLimit({
  windowMs: 60 * 1_000,
  max: 10,
  message: { error: 'Too many authentication attempts' },
});

// ─── Validation schema ────────────────────────────────────────────────────────
const privyVerifySchema = z.object({
  // Frontend sends "idToken" but it's actually the access token from
  // getAccessToken(). We accept it under that name for API stability.
  idToken: z.string().min(20).max(8192),
  walletAddress: z.string().optional(),
});

// ─── POST /api/auth/privy/verify ──────────────────────────────────────────────
router.post(
  '/verify',
  authLimiter,
  validate(privyVerifySchema),
  async (req: Request, res: Response, next: NextFunction) => {
    try {
      if (!process.env.PRIVY_APP_ID || !process.env.PRIVY_APP_SECRET) {
        console.error('[privy] PRIVY_APP_ID or PRIVY_APP_SECRET not set');
        return res.status(500).json({ error: 'Privy not configured' });
      }

      const { idToken, walletAddress } = req.body as {
        idToken: string;
        walletAddress?: string;
      };

      // ── 1. Verify the Privy access token ──────────────────────────────────
      // verifyAuthToken validates the JWT signature against Privy's public
      // keys and checks expiry. It returns the claims, including `userId`
      // (the Privy DID, e.g. "did:privy:abc...").
      let verified;
      try {
        verified = await privy.verifyAuthToken(idToken);
      } catch (err: any) {
        await audit({
          action: 'auth.privy_verify',
          status: 'failure',
          error: 'Invalid Privy auth token',
          ip: req.ip,
        });
        return res.status(401).json({ error: 'Invalid auth token' });
      }

      const privyDid = verified.userId;
      if (!privyDid) {
        return res.status(401).json({ error: 'Privy user ID missing' });
      }

      // ── 2. Fetch full Privy user profile ──────────────────────────────────
      // getUser(userId) hits Privy's API and returns linkedAccounts, email,
      // wallets, etc. This is the source of truth for the user's identity.
      let privyUser;
      try {
        privyUser = await privy.getUser(privyDid);
      } catch (err: any) {
        console.error('[privy] getUser failed:', err?.message);
        return res.status(500).json({ error: 'Could not fetch Privy user' });
      }

      const email = privyUser.email?.address?.toLowerCase() || null;

      // ── 3. Find a Solana wallet ───────────────────────────────────────────
      // Prefer the wallet the frontend reported (verified via Privy).
      // Fall back to scanning linkedAccounts for any Solana wallet.
      let solanaWallet: string | null = null;

      if (walletAddress) {
        // Confirm the reported wallet is actually linked to this Privy user
        const isLinked = privyUser.linkedAccounts?.some(
          (a: any) =>
            a.type === 'wallet' &&
            a.chainType === 'solana' &&
            a.address === walletAddress,
        );
        if (isLinked) solanaWallet = walletAddress;
      }

      if (!solanaWallet) {
        const linked = privyUser.linkedAccounts?.find(
          (a: any) => a.type === 'wallet' && a.chainType === 'solana',
        );
        if (linked && 'address' in linked) {
          solanaWallet = linked.address as string;
        }
      }

      if (!solanaWallet) {
        // Privy creates the embedded wallet asynchronously. Frontend will retry.
        return res.status(409).json({
          error: 'No Solana wallet linked yet. Please retry in a moment.',
          retry: true,
        });
      }

      // ── 4. Upsert the StashPot user ───────────────────────────────────────
      // The schema's users.wallet is UNIQUE — we dedupe on it.
      const result = await db.query(
        `INSERT INTO users (wallet, email, privy_did, last_seen_at)
         VALUES ($1, $2, $3, NOW())
         ON CONFLICT (wallet) DO UPDATE
           SET last_seen_at = NOW(),
               email        = COALESCE(users.email, EXCLUDED.email),
               privy_did    = COALESCE(users.privy_did, EXCLUDED.privy_did)
         RETURNING id, wallet, username, email, is_banned`,
        [solanaWallet, email, privyDid],
      );
      const user = result.rows[0];

      if (user.is_banned) {
        await audit({
          action: 'auth.privy_verify',
          user_id: user.id,
          target_id: solanaWallet,
          status: 'failure',
          error: 'Banned',
          ip: req.ip,
        });
        return res.status(403).json({ error: 'Account unavailable' });
      }

      // Initialize side tables (idempotent)
      await db.query(
        'INSERT INTO balances (user_id) VALUES ($1) ON CONFLICT DO NOTHING',
        [user.id],
      );
      await db.query(
        'INSERT INTO scores (user_id) VALUES ($1) ON CONFLICT DO NOTHING',
        [user.id],
      );

      // ── 5. Issue a StashPot JWT (same shape as the wallet-sig path) ──────
      const token = issueJwt(user.id, solanaWallet);

      await audit({
        action: 'auth.privy_verify',
        user_id: user.id,
        target_id: solanaWallet,
        metadata: { email_present: !!email, privy_did: privyDid },
        status: 'success',
        ip: req.ip,
      });

      res.json({
        token,
        user: {
          id: user.id,
          wallet: user.wallet,
          username: user.username,
          email: user.email,
        },
      });
    } catch (e) {
      next(e);
    }
  },
);

// ─── POST /api/auth/privy/link-wallet ─────────────────────────────────────────
// Links an additional Solana wallet to an existing StashPot account.
// Useful when an email-signup user later adds Phantom.
router.post(
  '/link-wallet',
  authLimiter,
  validate(privyVerifySchema),
  async (req: Request, res: Response, next: NextFunction) => {
    try {
      const { idToken, walletAddress } = req.body as {
        idToken: string;
        walletAddress?: string;
      };
      if (!walletAddress) {
        return res.status(400).json({ error: 'walletAddress required' });
      }

      let verified;
      try {
        verified = await privy.verifyAuthToken(idToken);
      } catch {
        return res.status(401).json({ error: 'Invalid Privy auth token' });
      }

      const privyUser = await privy.getUser(verified.userId);
      const isLinked = privyUser?.linkedAccounts?.some(
        (a: any) =>
          a.type === 'wallet' &&
          a.chainType === 'solana' &&
          a.address === walletAddress,
      );
      if (!isLinked) {
        return res.status(403).json({ error: 'Wallet not verified by Privy' });
      }

      // Update the user record (only if there's already a record matching this DID)
      const updated = await db.query(
        `UPDATE users SET wallet = $1
         WHERE privy_did = $2
         RETURNING id, wallet`,
        [walletAddress, verified.userId],
      );
      if (updated.rowCount === 0) {
        return res.status(404).json({ error: 'No StashPot account for this Privy user' });
      }

      await audit({
        action: 'auth.link_wallet',
        target_id: walletAddress,
        metadata: { privy_did: verified.userId },
        status: 'success',
        ip: req.ip,
      });

      res.json({ ok: true, wallet: walletAddress });
    } catch (e) {
      next(e);
    }
  },
);

export default router;
