/**
 * StashPot — Privy Auth Route
 *
 * Exchanges a Privy access token for a StashPot JWT.
 */
import { Router } from 'express';
import rateLimit from 'express-rate-limit';
import { z } from 'zod';
import { PrivyClient } from '@privy-io/server-auth';
import { issueJwt } from '../../middleware/auth.js';
import { validate } from '../../utils/validation.js';
import { db } from '../../models/db.js';
const router = Router();
// ─── Privy client ─────────────────────────────────────────────────────────────
const privy = new PrivyClient(process.env.PRIVY_APP_ID || '', process.env.PRIVY_APP_SECRET || '');
// Rate limit
const authLimiter = rateLimit({
    windowMs: 60 * 1_000,
    max: 10,
    message: { error: 'Too many authentication attempts' },
});
// ─── Validation ───────────────────────────────────────────────────────────────
const privyVerifySchema = z.object({
    idToken: z.string().min(20).max(8192),
    walletAddress: z.string().optional(),
});
// ─── POST /api/auth/privy/verify ──────────────────────────────────────────────
router.post('/verify', authLimiter, validate(privyVerifySchema), async (req, res, next) => {
    try {
        if (!process.env.PRIVY_APP_ID || !process.env.PRIVY_APP_SECRET) {
            console.error('[privy] PRIVY_APP_ID or PRIVY_APP_SECRET not set');
            return res.status(500).json({ error: 'Privy not configured' });
        }
        const { idToken, walletAddress } = req.body;
        // Verify Privy access token
        let verified;
        try {
            verified = await privy.verifyAuthToken(idToken);
        }
        catch (err) {
            console.error('[privy] verifyAuthToken failed:', err?.message);
            return res.status(401).json({ error: 'Invalid auth token' });
        }
        const privyDid = verified.userId;
        if (!privyDid) {
            return res.status(401).json({ error: 'Privy user ID missing' });
        }
        // Fetch full user profile
        let privyUser;
        try {
            privyUser = await privy.getUser(privyDid);
        }
        catch (err) {
            console.error('[privy] getUser failed:', err?.message);
            return res.status(500).json({ error: 'Could not fetch Privy user' });
        }
        const email = privyUser.email?.address?.toLowerCase() || null;
        // Find Solana wallet
        let solanaWallet = null;
        if (walletAddress) {
            const isLinked = privyUser.linkedAccounts?.some((a) => a.type === 'wallet' &&
                a.chainType === 'solana' &&
                a.address === walletAddress);
            if (isLinked)
                solanaWallet = walletAddress;
        }
        if (!solanaWallet) {
            const linked = privyUser.linkedAccounts?.find((a) => a.type === 'wallet' && a.chainType === 'solana');
            if (linked && 'address' in linked) {
                solanaWallet = linked.address;
            }
        }
        if (!solanaWallet) {
            return res.status(409).json({
                error: 'No Solana wallet linked yet. Please retry in a moment.',
                retry: true,
            });
        }
        // Upsert user
        const result = await db.query(`INSERT INTO users (wallet, email, privy_did, last_seen_at)
         VALUES ($1, $2, $3, NOW())
         ON CONFLICT (wallet) DO UPDATE
           SET last_seen_at = NOW(),
               email        = COALESCE(users.email, EXCLUDED.email),
               privy_did    = COALESCE(users.privy_did, EXCLUDED.privy_did)
         RETURNING id, wallet, username, email, is_banned`, [solanaWallet, email, privyDid]);
        const user = result.rows[0];
        if (user.is_banned) {
            return res.status(403).json({ error: 'Account unavailable' });
        }
        // Initialize side tables
        await db.query('INSERT INTO balances (user_id) VALUES ($1) ON CONFLICT DO NOTHING', [user.id]);
        await db.query('INSERT INTO scores (user_id) VALUES ($1) ON CONFLICT DO NOTHING', [user.id]);
        // Issue JWT
        const token = issueJwt(user.id, solanaWallet);
        res.json({
            token,
            user: {
                id: user.id,
                wallet: user.wallet,
                username: user.username,
                email: user.email,
            },
        });
    }
    catch (e) {
        next(e);
    }
});
// ─── POST /api/auth/privy/link-wallet ─────────────────────────────────────────
router.post('/link-wallet', authLimiter, validate(privyVerifySchema), async (req, res, next) => {
    try {
        const { idToken, walletAddress } = req.body;
        if (!walletAddress) {
            return res.status(400).json({ error: 'walletAddress required' });
        }
        let verified;
        try {
            verified = await privy.verifyAuthToken(idToken);
        }
        catch {
            return res.status(401).json({ error: 'Invalid Privy auth token' });
        }
        const privyUser = await privy.getUser(verified.userId);
        const isLinked = privyUser?.linkedAccounts?.some((a) => a.type === 'wallet' &&
            a.chainType === 'solana' &&
            a.address === walletAddress);
        if (!isLinked) {
            return res.status(403).json({ error: 'Wallet not verified by Privy' });
        }
        const updated = await db.query(`UPDATE users SET wallet = $1
         WHERE privy_did = $2
         RETURNING id, wallet`, [walletAddress, verified.userId]);
        if (updated.rowCount === 0) {
            return res.status(404).json({ error: 'No StashPot account for this Privy user' });
        }
        res.json({ ok: true, wallet: walletAddress });
    }
    catch (e) {
        next(e);
    }
});
export default router;
//# sourceMappingURL=privy.js.map