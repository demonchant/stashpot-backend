import { Pool } from 'pg';
console.log("DB URL INSIDE APP:", process.env.DATABASE_URL);
console.log("TYPE:", typeof process.env.DATABASE_URL);
export const db = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: {
    rejectUnauthorized: false,
    
  max:            20,
  idleTimeoutMillis: 30_000,
  connectionTimeoutMillis: 5_000,
});

db.on('error', (err) => {
  console.error('[db] Unexpected error on idle client:', err.message);
});
