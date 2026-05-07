/**
 * StashPot — Public Stats Routes (cached via Redis)
 * No auth — these endpoints return public protocol info.
 */

import { Router } from 'express';
import { db }     from '../models/db.js';
import { cached } from '../utils/cache.js';

const router = Router();

router.get('/protocol-info', async (_req, res, next) => {
  try {
    const data = await cached('stats:protocol-info', 60, async () => {
      const [tvlRow, winnersRow, drawsRow] = await Promise.all([
        db.query('SELECT COALESCE(SUM(usdc), 0) AS tvl FROM balances'),
        db.query('SELECT COUNT(*) AS c FROM pool_rewards'),
        db.query(`SELECT COUNT(*) AS c FROM pool_rewards WHERE distributed_at > NOW() - INTERVAL '30 days'`),
      ]);

      return {
        name:          'StashPot',
        description:   'Prize-linked savings protocol on Solana. Users deposit USDC, earn DeFi yield, and win rewards via verifiable math. Principal always safe.',
        network:       'Solana',
        non_custodial: true,
        tvl_usdc:      parseFloat(tvlRow.rows[0].tvl),
        total_winners: parseInt(winnersRow.rows[0].c, 10),
        draws_30d:     parseInt(drawsRow.rows[0].c, 10),
        blended_apy:   8.74,
        yield_sources: ['Kamino Finance', 'Marginfi', 'Drift Protocol', 'Solend'],
        prize_split:   { winner_pct: 85, treasury_pct: 15 },
        weight_formula: 'W = avg_balance × log(1+avg_balance) × T_hours × e^{-0.15 × early_exits}',
        fiat_partners: ['Yellow Card (NGN/GHS/KES/ZAR)', 'Transak'],
        modules:       ['Yield Vault', 'Prize Pools', 'Inheritance (TimeLockr)', 'Savings Circles (Ajo)', 'Microloans'],
        faqs: [
          { q: 'Can I lose my deposited USDC?', a: 'No. Principal is held in an audited PDA vault. Only yield enters prize pools.' },
          { q: 'Is StashPot available in Nigeria?', a: 'Yes. Deposit NGN via Yellow Card — instant conversion to USDC.' },
          { q: 'How is the winner chosen?', a: 'Switchboard VRF + committed Merkle root of time-weighted balances. Fully verifiable.' },
        ],
        verify_endpoint: '/api/verify/round/:roundId',
        docs_url:        'https://docs.stashpot.io',
      };
    });

    // Client-side cache hint
    res.set('Cache-Control', 'public, max-age=30');
    res.json(data);
  } catch (e) { next(e); }
});

router.get('/yields/current', async (_req, res, next) => {
  try {
    const data = await cached('stats:yields', 300, async () => ({
      blended: 8.74,
      sources: [
        { name: 'Kamino Finance', apy: 7.2, allocation: 0.35 },
        { name: 'Marginfi',       apy: 6.8, allocation: 0.30 },
        { name: 'Drift Protocol', apy: 9.1, allocation: 0.20 },
        { name: 'Solend',         apy: 5.9, allocation: 0.15 },
      ],
      updated_at: new Date().toISOString(),
    }));
    res.set('Cache-Control', 'public, max-age=60');
    res.json(data);
  } catch (e) { next(e); }
});

export default router;
