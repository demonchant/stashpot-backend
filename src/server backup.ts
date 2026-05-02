/**
 * StashPot — Hardened API Server
 *
 * All 12 audit findings addressed:
 *   [Fix #1] Webhooks signature verification (in routes/webhooks.ts)
 *   [Fix #2] Auth middleware applied to ALL sensitive routes (via verifyJwt inside each router)
 *   [Fix #3] Feature guard + auth combined
 *   [Fix #4] Per-endpoint rate limits + per-user throttling
 *   [Fix #5] Zod validation on every request body (utils/validation.ts)
 *   [Fix #6] Strict CORS whitelist
 *   [Fix #7] Helmet CSP enabled with proper directives
 *   [Fix #8] Error handler redacts internal messages in production
 *   [Perf #9] 1mb JSON body limit
 *   [Perf #10] compression middleware
 *   [Perf #11] Redis cache layer (utils/cache.ts)
 *   [Perf #12] PG connection pool (models/db.ts)
 * Plus Critical Missing Concepts:
 *   [Missing #1] Idempotency-Key enforcement (utils/idempotency.ts)
 *   [Missing #2] Transaction locking via PG advisory locks (utils/dbLocks.ts)
 *   [Missing #3] Append-only hash-chained audit log (utils/audit.ts)
 *   [Missing #4] Deterministic reward engine (WeightService + on-chain Merkle commit)
 */

import express         from 'express';
import cors            from 'cors';
import helmet          from 'helmet';
import compression     from 'compression';
import rateLimit       from 'express-rate-limit';
import { json, Request, Response, NextFunction } from 'express';

import { featureGuard } from './middleware/featureGuard.js';
import { FEATURES, publicFeatures, startFeaturePoller } from './config/features.js';
import { log, newErrorId } from './utils/logger.js';
import { audit }       from './utils/audit.js';

// Routes
import authRoutes      from './routes/auth.js';
import userRoutes      from './routes/users.js';
import poolRoutes      from './routes/pools.js';
import circleRoutes    from './routes/circles.js';
import loanRoutes      from './routes/loans.js';
import fiatRoutes      from './routes/fiat.js';
import vaultRoutes     from './routes/vaults.js';
import referralRoutes  from './routes/referrals.js';
import statsRoutes     from './routes/stats.js';
import webhookRoutes   from './routes/webhooks.js';
import verifyRoutes    from './routes/verify.js';
import adminRoutes     from './routes/admin.js';

const app  = express();
const PORT = process.env.PORT || 4000;
const PROD = process.env.NODE_ENV === 'production';

// Required so rate-limit + ip detection work correctly behind nginx
app.set('trust proxy', 1);

// ─── [Fix #7] Helmet with CSP ENABLED ─────────────────────────────────────────
app.use(
  helmet({
    contentSecurityPolicy: {
      useDefaults: true,
      directives: {
        defaultSrc: ["'self'"],
        scriptSrc:  ["'self'"],
        styleSrc:   ["'self'", "'unsafe-inline'", 'https://fonts.googleapis.com'],
        fontSrc:    ["'self'", 'https://fonts.gstatic.com', 'data:'],
        imgSrc:     ["'self'", 'data:', 'blob:', 'https:'],
        connectSrc: [
          "'self'",
          'https://api.devnet.solana.com',
          'https://api.mainnet-beta.solana.com',
          'https://*.helius-rpc.com',
          'wss://*.helius-rpc.com',
        ],
        objectSrc:      ["'none'"],
        frameSrc:       ["'none'"],
        frameAncestors: ["'none'"],
        upgradeInsecureRequests: PROD ? [] : null,
      },
    },
    crossOriginEmbedderPolicy: false,
    strictTransportSecurity:   PROD
      ? { maxAge: 31_536_000, includeSubDomains: true, preload: true }
      : false,
  }),
);

// ─── [Perf #10] gzip/brotli compression ───────────────────────────────────────
app.use(compression({
  filter: (req, res) => {
    if (req.headers['x-no-compression']) return false;
    return compression.filter(req, res);
  },
  threshold: 1024,
}));

// ─── [Fix #6] Strict CORS whitelist ───────────────────────────────────────────
const ALLOWED_ORIGINS = (process.env.FRONTEND_URL || 'http://localhost:3000')
  .split(',').map(s => s.trim()).filter(Boolean);

// STRICT_CORS=true rejects requests with no Origin header (curl, server-to-server).
// Default is permissive (allows non-browser clients) for backward compat.
// Production browser-only deployments should set STRICT_CORS=true.
const STRICT_CORS = process.env.STRICT_CORS === 'true';

app.use(cors({
  origin: (origin, cb) => {
    if (!origin) {
      if (STRICT_CORS) {
        log.warn('CORS rejection (strict mode)', { reason: 'no origin header' });
        return cb(new Error('Origin header required'));
      }
      return cb(null, true);  // curl, same-origin, mobile SDK
    }
    if (ALLOWED_ORIGINS.includes(origin)) return cb(null, true);
    log.warn('CORS rejection', { origin, allowed: ALLOWED_ORIGINS });
    return cb(new Error('Not allowed by CORS'));
  },
  credentials:    true,
  maxAge:         600,
  methods:        ['GET', 'POST', 'PATCH', 'PUT', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization', 'Idempotency-Key', 'X-Requested-With'],
  exposedHeaders: ['X-Idempotent-Replay'],
}));

// ─── Body parser with strict JSON only, 1mb limit ────────────────────────────
app.use(json({ limit: '1mb', strict: true }));

// ─── [Fix #4] Rate limiters — multiple zones ──────────────────────────────────
const perUserOrIp = (req: any) => (req.user?.id || req.ip || 'anon');

// Global catch-all
app.use(rateLimit({
  windowMs:        15 * 60 * 1000,
  max:             200,
  standardHeaders: true,
  legacyHeaders:   false,
  keyGenerator:    perUserOrIp,
  message:         { error: 'Too many requests' },
}));

// Financial mutation limit — strict, per-user
const financialLimiter = rateLimit({
  windowMs:        60 * 1000,
  max:             20,
  standardHeaders: true,
  legacyHeaders:   false,
  keyGenerator:    perUserOrIp,
  skip:            (req) => req.method === 'GET',
  message:         { error: 'Too many financial operations — slow down' },
});

// Auth — tightest (per-IP, bots can't rotate)
const authLimiter = rateLimit({
  windowMs:        60 * 1000,
  max:             10,
  standardHeaders: true,
  legacyHeaders:   false,
  keyGenerator:    (req) => req.ip || 'anon',
  message:         { error: 'Too many authentication attempts' },
});

// Webhook limiter — per-IP (providers stay well under)
const webhookLimiter = rateLimit({
  windowMs:        60 * 1000,
  max:             60,
  standardHeaders: true,
  legacyHeaders:   false,
  keyGenerator:    (req) => req.ip || 'anon',
});

// ─── Structured request log (redacted) ───────────────────────────────────────
app.use((req, _res, next) => {
  log.debug('request', { method: req.method, path: req.path, ip: req.ip });
  next();
});

// ─── Health ────────────────────────────────────────────────────────────────────
app.get('/health', (_req, res) => res.json({ status: 'ok' }));

// ─── Public endpoints (no auth) ───────────────────────────────────────────────
app.get('/api/features', (_req, res) => res.json(publicFeatures()));
app.use('/api/auth',     authLimiter,    authRoutes);
app.use('/api/stats',                    statsRoutes);
app.use('/api/verify',                   verifyRoutes);
app.use('/api/webhooks', webhookLimiter, webhookRoutes); // HMAC verified in handler

// ─── [Fix #2, #3] Protected endpoints: auth + financial limit + feature guard ─
// Auth is applied INSIDE each route file via `router.use(verifyJwt)`
// so that every mutation is user-scoped at the route level.
app.use('/api/users',                                                                  userRoutes);
app.use('/api/admin',                                                                  adminRoutes);
app.use('/api/pools',     financialLimiter, featureGuard('PRIZE_POOLS'),               poolRoutes);
app.use('/api/circles',   financialLimiter, featureGuard('CIRCLES'),                   circleRoutes);
app.use('/api/loans',     financialLimiter, featureGuard('LOANS'),                     loanRoutes);
app.use('/api/fiat',      financialLimiter, featureGuard('FIAT'),                      fiatRoutes);
app.use('/api/vaults',    financialLimiter, featureGuard('INHERITANCE'),               vaultRoutes);
app.use('/api/referrals',                    featureGuard('REFERRALS'),                referralRoutes);

// ─── 404 ──────────────────────────────────────────────────────────────────────
app.use((_req, res) => res.status(404).json({ error: 'Not found' }));

// ─── [Fix #8] Error handler — NEVER leak internals to clients ────────────────
// eslint-disable-next-line @typescript-eslint/no-unused-vars
app.use((err: any, req: Request, res: Response, _next: NextFunction) => {
  const errorId = newErrorId();

  // Log full detail server-side only (redacted)
  log.error('unhandled error', {
    errorId,
    path:   req.path,
    method: req.method,
    msg:    err?.message,
    stack:  PROD ? undefined : err?.stack,
    code:   err?.code,
  });

  // Fire-and-forget audit
  audit({
    action:    'security.suspicious_activity',
    user_id:   (req as any).user?.id ?? null,
    ip:        (req.headers['x-forwarded-for'] as string || req.ip || null) as string | null,
    user_agent:(req.headers['user-agent'] as string || null),
    status:    'failure',
    metadata:  { path: req.path, method: req.method, errorId },
    error:     err?.message,
  }).catch(() => {});

  const status = err?.status || 500;

  // 4xx are user-input errors — message is safe to return
  if (status >= 400 && status < 500 && err?.message) {
    return res.status(status).json({ error: err.message, errorId });
  }

  // 5xx — generic message with traceable errorId
  return res.status(500).json({
    error:   'Something went wrong',
    errorId,
  });
});

// ─── Startup + graceful shutdown ──────────────────────────────────────────────
const server = app.listen(PORT, () => {
  // Start live feature-flag polling (10s default)
  startFeaturePoller();

  log.info(`StashPot API listening on :${PORT}`, {
    env:      process.env.NODE_ENV || 'dev',
    features: FEATURES,
    origins:  ALLOWED_ORIGINS,
  });
});

function shutdown(signal: string) {
  log.info(`Received ${signal} — shutting down`);
  server.close(() => { log.info('HTTP server closed'); process.exit(0); });
  setTimeout(() => process.exit(1), 10_000).unref();
}
process.on('SIGTERM', () => shutdown('SIGTERM'));
process.on('SIGINT',  () => shutdown('SIGINT'));

export default app;
