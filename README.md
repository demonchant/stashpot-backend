# StashPot Backend

Production-grade Node.js/Express backend for StashPot - a no-loss savings protocol on Solana.

## Overview

StashPot backend handles:
- User authentication (Privy integration)
- Solana smart contract interaction
- Yield calculation and distribution
- Prize draw execution
- User data persistence
- Transaction history tracking
- StashScore calculation (on-chain credit scoring)

**Stack:** Node.js 20, Express, TypeScript, PostgreSQL, Solana Web3.js, Anchor IDL

**Status:** Production-ready on Solana devnet, ready for mainnet deployment after audit

---

## Quick Start

### Prerequisites

- Node.js 20+
- PostgreSQL 13+
- Solana CLI (for keypair generation)
- Git

### Installation

```bash
# Clone repository
git clone https://github.com/demonchant/stashpot-backend.git
cd stashpot-backend

# Install dependencies
npm install

# Create .env.local (never commit this)
cp .env.example .env.local

# Add your actual values to .env.local
# See Environment Variables section below
```

### Environment Variables

Create `.env.local` with these values (NEVER commit to git):

```env
# Server
NODE_ENV=development
PORT=4000

# Database
DATABASE_URL=postgresql://user:password@localhost:5432/stashpot

# Solana
SOLANA_NETWORK=devnet
SOLANA_RPC_URL=https://api.devnet.solana.com
SOLANA_PRIVATE_KEY=base58_encoded_keypair

# Privy (Authentication)
PRIVY_APP_ID=your_privy_app_id
PRIVY_APP_SECRET=your_privy_app_secret

# Smart Contracts (from devnet deployment)
YIELD_VAULT_PROGRAM_ID=YLDxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
PRIZE_MODULE_PROGRAM_ID=PRZxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
INHERITANCE_PROGRAM_ID=INHxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
SAVINGS_CIRCLES_PROGRAM_ID=CRCxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
MICROLOANS_PROGRAM_ID=MLxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
GOVERNANCE_PROGRAM_ID=GOVxxxxxxxxxxxxxxxxxxxxxxxxxxxxx

# Yield Protocols (Devnet addresses)
KAMINO_PROGRAM_ID=
SAVE_PROGRAM_ID=
MARGINFI_PROGRAM_ID=
DRIFT_PROGRAM_ID=

# External APIs
SWITCHBOARD_NETWORK=devnet
CHAINLINK_FEED_ADDRESS=
YELLOW_CARD_API_KEY=your_key_here
TRANSAK_API_KEY=your_key_here

# JWT
JWT_SECRET=generate_with_crypto.randomBytes(32).toString('hex')

# Redis (for caching)
REDIS_URL=redis://localhost:6379

# Notifications
RESEND_API_KEY=your_resend_key
FIREBASE_PROJECT_ID=your_firebase_project
FIREBASE_SERVICE_ACCOUNT_JSON={"type":"service_account",...}

# Frontend
FRONTEND_URL=http://localhost:3000,http://localhost:5173,https://stashpot-frontendd.vercel.app
CORS_ORIGIN=http://localhost:3000,http://localhost:5173
```

### Development

```bash
# Start dev server
npm run dev

# Server runs on http://localhost:4000
```

### Build & Deploy

```bash
# Build TypeScript
npm run build

# Run production server
npm start

# Deploy to Render
git push origin main  # Automatically deploys on Render
```

---

## API Endpoints

### Authentication

**POST /api/auth/privy/verify**
```json
{
  "idToken": "privy_jwt_token",
  "walletAddress": "solana_wallet_address"
}
```
Returns: `{ token: "jwt", user: { id, email, wallet, ... } }`

**POST /api/auth/signature/verify**
```json
{
  "wallet": "solana_address",
  "signature": "base58_signature",
  "nonce": "nonce_string"
}
```
Returns: JWT token

**GET /api/auth/nonce/:wallet**
Returns: `{ nonce: "random_string" }`

**POST /api/auth/logout**
Clears JWT token

---

### User Profile

**GET /api/users/profile** (requires auth)
Returns: User profile with USDC balance, StashScore, tier

**PUT /api/users/profile** (requires auth)
Update username, email preferences, etc.

---

### Pools (Prize Pools)

**GET /api/pools**
Returns: All pools (daily, weekly, monthly)
```json
{
  "type": "weekly",
  "totalBalance": 50000,
  "participants": 234,
  "prizeShare": "8%",
  "nextDraw": "2026-05-17T00:00:00Z"
}
```

**GET /api/pools/:poolType/odds** (requires auth)
Returns: User's win probability and odds

**POST /api/pools/:poolType/deposit** (requires auth)
```json
{ "amount": 100 }
```
Returns: Transaction signature

**POST /api/pools/:poolType/withdraw** (requires auth)
```json
{ "amount": 100 }
```
Returns: Transaction signature

**GET /api/pools/history** (requires auth)
Returns: User's pool transaction history

---

### TimeLockr Vaults (Inheritance)

**POST /api/vaults/create** (requires auth)
```json
{
  "beneficiaries": [
    { "address": "solana_address", "percentage": 50 },
    { "address": "solana_address", "percentage": 50 }
  ],
  "unlockDate": "2027-05-17T00:00:00Z",
  "deadManSwitchDays": 90
}
```

**GET /api/vaults** (requires auth)
Returns: User's vaults

**POST /api/vaults/:vaultId/checkin** (requires auth)
Resets dead-man switch timer

**POST /api/vaults/:vaultId/withdraw** (requires auth, beneficiary only)
Withdraw from vault after unlock date

---

### Savings Circles

**GET /api/circles**
Returns: All available circles

**POST /api/circles/create** (requires auth)
```json
{
  "name": "Lagos Tech Savers",
  "description": "Monthly savings group",
  "monthlyContribution": 50000,
  "members": 10
}
```

**POST /api/circles/:circleId/join** (requires auth)
Join existing circle

**POST /api/circles/:circleId/contribute** (requires auth)
```json
{ "amount": 50000 }
```
Make monthly contribution

---

### Microloans

**POST /api/loans/apply** (requires auth)
```json
{
  "amount": 100,
  "duration": 90,
  "purpose": "Emergency"
}
```

**GET /api/loans** (requires auth)
Returns: User's loans and repayment status

**POST /api/loans/:loanId/repay** (requires auth)
```json
{ "amount": 50 }
```
Make loan repayment

---

### StashScore

**GET /api/stashscore** (requires auth)
Returns:
```json
{
  "score": 750,
  "tier": "Silver",
  "factors": {
    "totalSaved": 5000,
    "savingsConsistency": 95,
    "loanRepaymentHistory": 100,
    "circleParticipation": 85
  }
}
```

---

### On-Ramp (Fiat Conversion)

**GET /api/onramp/rates**
Returns: NGN/KES/GHS/ZAR to USDC conversion rates

**POST /api/onramp/initiate** (requires auth)
```json
{
  "currency": "NGN",
  "amount": 100000
}
```
Returns: YellowCard or Transak widget URL

**POST /api/onramp/webhook** (webhook from YellowCard/Transak)
Updates user USDC balance after successful conversion

---

## Database Schema

### Users Table
```sql
CREATE TABLE users (
  id UUID PRIMARY KEY,
  email VARCHAR(255) UNIQUE NOT NULL,
  wallet VARCHAR(255),
  privy_id VARCHAR(255) UNIQUE,
  usdc_balance DECIMAL(20, 6) DEFAULT 0,
  stash_score INT DEFAULT 0,
  tier VARCHAR(50) DEFAULT 'Bronze',
  created_at TIMESTAMP DEFAULT NOW(),
  updated_at TIMESTAMP DEFAULT NOW()
);
```

### Pool Deposits Table
```sql
CREATE TABLE pool_deposits (
  id UUID PRIMARY KEY,
  user_id UUID REFERENCES users(id),
  pool_type VARCHAR(50),
  amount DECIMAL(20, 6),
  tx_signature VARCHAR(255),
  status VARCHAR(50),
  created_at TIMESTAMP DEFAULT NOW()
);
```

### Transactions Table
```sql
CREATE TABLE transactions (
  id UUID PRIMARY KEY,
  user_id UUID REFERENCES users(id),
  type VARCHAR(50),
  amount DECIMAL(20, 6),
  tx_signature VARCHAR(255),
  status VARCHAR(50),
  created_at TIMESTAMP DEFAULT NOW()
);
```

Run migrations:
```bash
npm run migrate
```

---

## Smart Contract Interaction

### Anchor Programs Integrated

1. **Yield Vault Program** - Manages deposits and yield distribution
2. **Prize Module Program** - Handles weekly prize draws via Switchboard VRF
3. **Inheritance Program** - TimeLockr vault logic
4. **Savings Circles Program** - Circle management
5. **Microloans Program** - Loan underwriting and repayment
6. **Governance Program** - DAO parameter management

### IDL Files

All Anchor IDL files stored in `src/idl/`:
- `yield_vault.json`
- `prize_module.json`
- `inheritance.json`
- `savings_circles.json`
- `microloans.json`
- `governance.json`

Generate new IDL after smart contract updates:
```bash
anchor build
anchor idl init
anchor idl upgrade
```

---

## Testing

```bash
# Unit tests
npm test

# Integration tests (requires devnet)
npm run test:integration

# Load testing
npm run test:load
```

---

## Monitoring & Logging

Logs stored in `logs/` directory.

Real-time monitoring via:
- Sentry (error tracking)
- Datadog (performance metrics)
- Custom dashboards in `/admin/monitoring`

---

## Deployment

### Vercel (Recommended)

```bash
# Deploy automatically on push to main
git push origin main

# Manual deployment
vercel deploy
```

**Environment variables on Vercel:**
1. Go to Project Settings → Environment Variables
2. Add all .env variables
3. Redeploy

### Self-Hosted (Render)

```bash
# Connected to GitHub
# Auto-deploys on push to main
# Settings in render.yaml
```

---

## Troubleshooting

**Issue: Database connection fails**
