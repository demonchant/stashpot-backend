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
import { z } from 'zod';
import { Request, Response, NextFunction } from 'express';
export declare const solanaPubkey: z.ZodString;
export declare const usdcAmount: z.ZodNumber;
export declare const minUsdcAmount: z.ZodNumber;
export declare const poolType: z.ZodEnum<["daily", "weekly", "monthly"]>;
export declare const loanType: z.ZodEnum<["A", "B", "C", "D"]>;
export declare const durationDays: z.ZodNumber;
export declare const uuid: z.ZodString;
export declare const idempotencyKey: z.ZodOptional<z.ZodString>;
export declare const authVerifySchema: z.ZodObject<{
    wallet: z.ZodString;
    signature: z.ZodString;
    nonce: z.ZodString;
}, "strip", z.ZodTypeAny, {
    signature: string;
    wallet: string;
    nonce: string;
}, {
    signature: string;
    wallet: string;
    nonce: string;
}>;
export declare const updateUserSchema: z.ZodObject<{
    username: z.ZodOptional<z.ZodString>;
    email: z.ZodOptional<z.ZodString>;
}, "strip", z.ZodTypeAny, {
    username?: string | undefined;
    email?: string | undefined;
}, {
    username?: string | undefined;
    email?: string | undefined;
}>;
export declare const fcmTokenSchema: z.ZodObject<{
    token: z.ZodString;
}, "strip", z.ZodTypeAny, {
    token: string;
}, {
    token: string;
}>;
export declare const depositSchema: z.ZodObject<{
    poolId: z.ZodEnum<["daily", "weekly", "monthly"]>;
    amount: z.ZodNumber;
}, "strip", z.ZodTypeAny, {
    amount: number;
    poolId: "daily" | "weekly" | "monthly";
}, {
    amount: number;
    poolId: "daily" | "weekly" | "monthly";
}>;
export declare const withdrawSchema: z.ZodObject<{
    poolId: z.ZodEnum<["daily", "weekly", "monthly"]>;
    amount: z.ZodNumber;
}, "strip", z.ZodTypeAny, {
    amount: number;
    poolId: "daily" | "weekly" | "monthly";
}, {
    amount: number;
    poolId: "daily" | "weekly" | "monthly";
}>;
export declare const createCircleSchema: z.ZodObject<{
    name: z.ZodOptional<z.ZodString>;
    max_members: z.ZodNumber;
    contribution: z.ZodNumber;
    cycle_days: z.ZodNumber;
}, "strip", z.ZodTypeAny, {
    max_members: number;
    contribution: number;
    cycle_days: number;
    name?: string | undefined;
}, {
    max_members: number;
    contribution: number;
    cycle_days: number;
    name?: string | undefined;
}>;
export declare const contributeSchema: z.ZodObject<{
    amount: z.ZodNumber;
}, "strip", z.ZodTypeAny, {
    amount: number;
}, {
    amount: number;
}>;
export declare const createVaultSchema: z.ZodObject<{
    inactivity_days: z.ZodNumber;
    beneficiaries: z.ZodArray<z.ZodObject<{
        wallet: z.ZodString;
        pct: z.ZodNumber;
    }, "strip", z.ZodTypeAny, {
        wallet: string;
        pct: number;
    }, {
        wallet: string;
        pct: number;
    }>, "many">;
}, "strip", z.ZodTypeAny, {
    inactivity_days: number;
    beneficiaries: {
        wallet: string;
        pct: number;
    }[];
}, {
    inactivity_days: number;
    beneficiaries: {
        wallet: string;
        pct: number;
    }[];
}>;
export declare const requestLoanSchema: z.ZodObject<{
    loan_type: z.ZodEnum<["A", "B", "C", "D"]>;
    amount: z.ZodNumber;
    duration_days: z.ZodDefault<z.ZodOptional<z.ZodNumber>>;
}, "strip", z.ZodTypeAny, {
    amount: number;
    loan_type: "D" | "A" | "B" | "C";
    duration_days: number;
}, {
    amount: number;
    loan_type: "D" | "A" | "B" | "C";
    duration_days?: number | undefined;
}>;
export declare const repayLoanSchema: z.ZodObject<{
    amount: z.ZodNumber;
}, "strip", z.ZodTypeAny, {
    amount: number;
}, {
    amount: number;
}>;
export declare const fiatDepositSchema: z.ZodObject<{
    currency: z.ZodEnum<["NGN", "GHS", "KES", "ZAR", "USD"]>;
    fiat_amount: z.ZodNumber;
    provider: z.ZodDefault<z.ZodOptional<z.ZodEnum<["yellow_card", "transak"]>>>;
}, "strip", z.ZodTypeAny, {
    currency: "NGN" | "GHS" | "KES" | "ZAR" | "USD";
    fiat_amount: number;
    provider: "yellow_card" | "transak";
}, {
    currency: "NGN" | "GHS" | "KES" | "ZAR" | "USD";
    fiat_amount: number;
    provider?: "yellow_card" | "transak" | undefined;
}>;
export declare const mockConfirmSchema: z.ZodObject<{
    reference: z.ZodString;
}, "strip", z.ZodTypeAny, {
    reference: string;
}, {
    reference: string;
}>;
export declare const registerReferralSchema: z.ZodObject<{
    code: z.ZodString;
}, "strip", z.ZodTypeAny, {
    code: string;
}, {
    code: string;
}>;
type Source = 'body' | 'query' | 'params';
/**
 * Creates an Express middleware that validates a request source against a Zod schema.
 * On failure: returns 400 with structured error. On success: replaces req[source] with parsed data.
 */
export declare function validate(schema: z.ZodTypeAny, source?: Source): (req: Request, res: Response, next: NextFunction) => Response<any, Record<string, any>> | undefined;
export {};
