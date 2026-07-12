import 'dotenv/config.js';
import { neon } from '@neondatabase/serverless';
import { drizzle } from 'drizzle-orm/neon-http';

// Validate environment variable
const connectionString = process.env.DATABASE_URL;

if (!connectionString) {
  throw new Error(
    '[DATABASE] Missing DATABASE_URL. Make sure it is set in your environment or .env file.'
  );
}

let sql;
try {
  sql = neon(connectionString);
} catch (err) {
  console.error('[DATABASE] Failed to initialize Neon client:');
  console.error(err);
  throw err; // Stop app from starting
}

let db: any;
try {
  db = drizzle(sql);
} catch (err) {
  console.error('[DATABASE] Failed to initialize Drizzle ORM:');
  console.error(err);
  throw err;
}

console.log('[DATABASE] Connected successfully.');

export { db, sql };
