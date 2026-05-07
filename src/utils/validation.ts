/**
 * StashPot — Request Validation Layer (Fix #5)
 *
 * ALL request bodies, query params, and URL params are validated with Zod
 * BEFORE hitting route handlers. Prevents:
 *   - SQL injection via malformed input
 *   - Logic manipulation (negative amounts, absurd values)
 *   - Overflow attacks (u64 max values)
 *   - Missing required fields
 *   - Wrong types (string where number expected)
 */

import { z }                        from 'zod';
import { Request, Response, NextFunction } from 'express';

// ─── Shared primitives ────────────────────────────────────────────────────────

/// Solana base58 pubkey: 32–44 chars, base58 alphabet only
export const solanaPubkey = z.string()
  .min(32).max(44)
  .regex(/^[1-9A-HJ-NP-Za-km-z]+$/, 'Must be valid Solana pubkey');

/// USDC amount: positive finite number, bounded
export const usdcAmount = z.number()
  .finite()
  .positive()
  .max(1_000_000, 'Amount exceeds $1M maximum per operation');

/// Minimum deposit
export const minUsdcAmount = usdcAmount.min(1, 'Minimum $1 USDC');

/// Pool type enum
export const poolType = z.enum(['daily', 'weekly', 'monthly']);

/// Loan type
export const loanType = z.enum(['A', 'B', 'C', 'D']);

/// Duration in days
export const durationDays = z.number().int().min(7).max(90);

/// UUID (for internal IDs)
export const uuid = z.string().uuid();

/// Idempotency key (optional on mutating endpoints)
export const idempotencyKey = z.string()
  .min(16).max(128)
  .regex(/^[a-zA-Z0-9_\-]+$/)
  .optional();

// ─── Route-specific schemas ───────────────────────────────────────────────────

export const authVerifySchema = z.object({
  wallet:    solanaPubkey,
  signature: z.string().min(64).max(128).regex(/^[1-9A-HJ-NP-Za-km-z]+$/),
  nonce:     z.string().min(10).max(200),
});

export const updateUserSchema = z.object({
  username: z.string().regex(/^[a-zA-Z0-9_]{3,32}$/).optional(),
  email:    z.string().email().max(255).optional(),
});

export const fcmTokenSchema = z.object({
  token: z.string().min(50).max(512),
});

export const depositSchema = z.object({
  poolId: poolType,
  amount: minUsdcAmount,
});

export const withdrawSchema = z.object({
  poolId: poolType,
  amount: usdcAmount,
});

export const createCircleSchema = z.object({
  name:         z.string().min(2).max(64).optional(),
  max_members:  z.number().int().min(2).max(12),
  contribution: minUsdcAmount,
  cycle_days:   z.number().int().min(1).max(90),
});

export const contributeSchema = z.object({
  amount: minUsdcAmount,
});

export const createVaultSchema = z.object({
  inactivity_days: z.number().int().min(7).max(3_650), // 7 days to 10 years
  beneficiaries:   z.array(
    z.object({
      wallet: solanaPubkey,
      pct:    z.number().int().min(1).max(100),
    })
  ).min(1).max(10),
});

export const requestLoanSchema = z.object({
  loan_type:     loanType,
  amount:        z.number().positive().min(10).max(10_000),
  duration_days: durationDays.optional().default(30),
});

export const repayLoanSchema = z.object({
  amount: usdcAmount,
});

export const fiatDepositSchema = z.object({
  currency:    z.enum(['NGN', 'GHS', 'KES', 'ZAR', 'USD']),
  fiat_amount: z.number().positive().max(10_000_000),
  provider:    z.enum(['yellow_card', 'transak']).optional().default('yellow_card'),
});

export const mockConfirmSchema = z.object({
  reference: z.string().min(5).max(64).regex(/^[A-Z0-9\-_]+$/i),
});

export const registerReferralSchema = z.object({
  code: z.string().min(4).max(16).regex(/^[A-Z0-9]+$/i),
});

// ─── Validation middleware factory ────────────────────────────────────────────

type Source = 'body' | 'query' | 'params';

/**
 * Creates an Express middleware that validates a request source against a Zod schema.
 * On failure: returns 400 with structured error. On success: replaces req[source] with parsed data.
 */
export function validate(schema: z.ZodTypeAny, source: Source = 'body') {
  return (req: Request, res: Response, next: NextFunction) => {
    const result = schema.safeParse(req[source]);
    if (!result.success) {
      const errors = result.error.errors.map(e => ({
        path: e.path.join('.') || '(root)',
        message: e.message,
      }));
      return res.status(400).json({
        error:  'Invalid request',
        source,
        issues: errors,
      });
    }
    // Overwrite with the parsed/coerced data — use validated values downstream
    (req as any)[source] = result.data;
    next();
  };
}
