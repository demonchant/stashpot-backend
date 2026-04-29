import { Request, Response, NextFunction } from 'express';
import jwt                from 'jsonwebtoken';
import { sign }           from 'tweetnacl';
import { PublicKey }      from '@solana/web3.js';
import bs58               from 'bs58';
import { db }             from '../models/db.js';

export interface AuthRequest extends Request {
  user?: { id: string; wallet: string };
}

const JWT_SECRET  = process.env.JWT_SECRET!;
const JWT_EXPIRY  = '30d';
const NONCE_TTL   = 5 * 60 * 1000; // 5 minutes

export function verifyJwt(req: AuthRequest, res: Response, next: NextFunction) {
  const header = req.headers['authorization'];
  if (!header?.startsWith('Bearer ')) {
    return res.status(401).json({ error: 'Missing authorization header' });
  }
  const token = header.slice(7);
  try {
    const payload = jwt.verify(token, JWT_SECRET) as { id: string; wallet: string };
    req.user = payload;
    next();
  } catch {
    return res.status(401).json({ error: 'Invalid or expired token' });
  }
}

export function issueJwt(id: string, wallet: string): string {
  return jwt.sign({ id, wallet }, JWT_SECRET, { expiresIn: JWT_EXPIRY });
}

/** Generate a nonce for wallet signing */
export async function generateNonce(wallet: string): Promise<string> {
  // Validate wallet is a valid Solana pubkey
  try { new PublicKey(wallet); } catch {
    throw new Error('Invalid wallet address');
  }

  const nonce     = `StashPot sign-in: ${Math.random().toString(36).slice(2)}.${Date.now()}`;
  const expiresAt = new Date(Date.now() + NONCE_TTL);

  // Invalidate old nonces for this wallet
  await db.query('UPDATE auth_nonces SET used=TRUE WHERE wallet=$1 AND used=FALSE', [wallet]);

  await db.query(
    'INSERT INTO auth_nonces(wallet, nonce, expires_at) VALUES($1,$2,$3)',
    [wallet, nonce, expiresAt]
  );
  return nonce;
}

/** Verify wallet signature against stored nonce */
export async function verifySignature(
  wallet:    string,
  signature: string,
  nonce:     string,
): Promise<boolean> {
  // Check nonce is valid and unused
  const row = await db.query(
    `SELECT id FROM auth_nonces
     WHERE wallet=$1 AND nonce=$2 AND used=FALSE AND expires_at > NOW()`,
    [wallet, nonce]
  );
  if (!row.rows.length) return false;

  // Mark nonce used immediately (replay protection)
  await db.query('UPDATE auth_nonces SET used=TRUE WHERE id=$1', [row.rows[0].id]);

  // Verify Ed25519 signature
  try {
    const pubkeyBytes  = new PublicKey(wallet).toBytes();
    const sigBytes     = bs58.decode(signature);
    const msgBytes     = new TextEncoder().encode(nonce);
    return sign.detached.verify(msgBytes, sigBytes, pubkeyBytes);
  } catch {
    return false;
  }
}
