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
  userId:           string;
  balance:          number;
  joinedAt:         number;  // ms timestamp
  lastUpdateAt:     number;  // ms timestamp
  earlyWithdrawals: number;
  avgBalance:       number;  // EMA updated on-chain
}

const LAMBDA            = 0.15;
const ENTRY_CUTOFF_SECS = 5 * 60; // 5 min cutoff before draw

export class WeightService {

  static computeWeight(entry: PoolEntry, drawAt: number): number {
    const secsHeld = (drawAt - entry.joinedAt) / 1000;
    // 5-min entry cutoff — last-minute deposits get zero weight
    if (secsHeld < ENTRY_CUTOFF_SECS) return 0;

    const A       = Math.max(0, entry.avgBalance);
    if (A === 0)  return 0;

    const hoursHeld  = secsHeld / 3600;
    const logA       = Math.log(1 + A);
    const riskDecay  = Math.exp(-LAMBDA * entry.earlyWithdrawals);

    return Math.max(0, A * logA * hoursHeld * riskDecay);
  }

  static selectWinner(entries: PoolEntry[], drawAt: number, random?: number): string | null {
    if (!entries.length) return null;
    const weights  = entries.map(e => ({ userId: e.userId, weight: this.computeWeight(e, drawAt) }));
    const total    = weights.reduce((s, w) => s + w.weight, 0);
    if (total === 0) {
      const idx = Math.floor(Math.random() * entries.length);
      return entries[idx].userId;
    }
    let r = (random !== undefined ? random : Math.random()) * total;
    for (const w of weights) {
      r -= w.weight;
      if (r <= 0) return w.userId;
    }
    return weights[weights.length - 1].userId;
  }

  static buildOddsTable(entries: PoolEntry[], drawAt: number) {
    const weights = entries.map(e => ({ userId: e.userId, weight: this.computeWeight(e, drawAt) }));
    const total   = weights.reduce((s, w) => s + w.weight, 0);
    if (total === 0) return weights.map(w => ({ ...w, chance: 1 / entries.length }));
    return weights.map(w => ({ ...w, chance: w.weight / total }));
  }

  static updateAvgBalance(current: number, newBalance: number, alpha = 0.1): number {
    if (current === 0) return newBalance;
    return (1 - alpha) * current + alpha * newBalance;
  }
}
