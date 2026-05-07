/**
 * WeightService — Attack-Resistant Prize Weight Engine
 *
 * Formula: W = avg_balance × log(1+avg_balance) × T_hours × e^{-0.15 × early_exits}
 *
 * Defends against:
 *   Flash deposit sniping    → T_hours near zero → W ≈ 0
 *   Whale dominance          → log(1+A) flattens at scale
 *   Sybil wallet splitting   → log(total) > sum(log(splits))
 *   Exit farming             → early_exits penalty compounds
 *   Last-minute entry        → ENTRY_CUTOFF_SECS before draw gets weight = 0
 */
export interface PoolEntry {
    userId: string;
    balance: number;
    joinedAt: number;
    lastUpdateAt: number;
    earlyWithdrawals: number;
    avgBalance: number;
}
export declare class WeightService {
    static computeWeight(entry: PoolEntry, drawAt: number): number;
    static selectWinner(entries: PoolEntry[], drawAt: number, random?: number): string | null;
    static buildOddsTable(entries: PoolEntry[], drawAt: number): {
        chance: number;
        userId: string;
        weight: number;
    }[];
    static updateAvgBalance(current: number, newBalance: number, alpha?: number): number;
}
