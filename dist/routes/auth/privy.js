import { Router } from 'express';
import { PrivyClient } from '@privy-io/server-auth';
import { db } from '../../models/db.js';
import { audit } from '../../utils/audit.js';
import { issueJwt } from '../../middleware/auth.js';
const router = Router();
const privy = new PrivyClient(process.env.PRIVY_APP_ID || '', process.env.PRIVY_APP_SECRET || '');
// POST /api/auth/privy/verify
router.post('/verify', async (req, res, next) => {
    try {
        const authHeader = req.headers.authorization;
        if (!authHeader?.startsWith('Bearer ')) {
            return res.status(401).json({ error: 'Missing authorization header' });
        }
        const token = authHeader.substring(7);
        // Verify the Privy token
        const claims = await privy.verifyAuthToken(token);
        // Get Privy user ID
        const privyUserId = claims.userId;
        // Create or update user in database (email will be null for now)
        const result = await db.query(`INSERT INTO users(privy_id, wallet)
       VALUES($1, NULL)
       ON CONFLICT(privy_id) DO UPDATE 
       SET last_seen_at = NOW()
       RETURNING id, privy_id, wallet, username, is_banned`, [privyUserId]);
        const user = result.rows[0];
        if (user.is_banned) {
            await audit({
                action: 'auth.login',
                user_id: user.id,
                target_id: privyUserId,
                status: 'failure',
                error: 'Banned',
                ip: req.ip || 'unknown',
            });
            return res.status(403).json({ error: 'Account unavailable' });
        }
        // Ensure user has balances and scores
        await db.query('INSERT INTO balances(user_id) VALUES($1) ON CONFLICT DO NOTHING', [user.id]);
        await db.query('INSERT INTO scores(user_id) VALUES($1) ON CONFLICT DO NOTHING', [user.id]);
        // Issue JWT
        const jwtToken = issueJwt(user.id, user.wallet || privyUserId);
        await audit({
            action: 'auth.login',
            user_id: user.id,
            target_id: privyUserId,
            status: 'success',
            ip: req.ip || 'unknown',
        });
        res.json({
            token: jwtToken,
            user: {
                id: user.id,
                wallet: user.wallet,
                username: user.username,
            },
        });
    }
    catch (error) {
        console.error('Privy verification error:', error);
        await audit({
            action: 'auth.login',
            status: 'failure',
            error: error.message,
            ip: req.ip || 'unknown',
        });
        res.status(401).json({
            error: 'Authentication failed',
            details: error.message
        });
    }
});
export default router;
//# sourceMappingURL=privy.js.map