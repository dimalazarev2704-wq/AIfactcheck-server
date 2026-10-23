// db.js: tiny data layer for accounts and daily usage (Postgres, e.g. Neon's free plan).
const { Pool } = require("pg");

let pool = null;
function getPool() {
  if (!pool) {
    pool = new Pool({
      connectionString: process.env.DATABASE_URL,
      ssl: { rejectUnauthorized: false },
      max: 5,
      idleTimeoutMillis: 30000
    });
    pool.on("error", (e) => console.error("Database pool error:", e.message));
  }
  return pool;
}

async function init() {
  const p = getPool();
  await p.query(`CREATE TABLE IF NOT EXISTS users (
    id SERIAL PRIMARY KEY,
    email TEXT UNIQUE NOT NULL,
    pw_salt TEXT NOT NULL,
    pw_hash TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
  )`);
  await p.query(`CREATE TABLE IF NOT EXISTS usage (
    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    day DATE NOT NULL,
    tokens INTEGER NOT NULL DEFAULT 0,
    checks INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (user_id, day)
  )`);
}

// Returns the new user, or null if the email is already taken.
async function createUser(email, salt, hash) {
  try {
    const r = await getPool().query(
      "INSERT INTO users (email, pw_salt, pw_hash) VALUES ($1, $2, $3) RETURNING id, email",
      [email, salt, hash]
    );
    return r.rows[0];
  } catch (e) {
    if (e.code === "23505") return null; // unique violation
    throw e;
  }
}

async function getUserByEmail(email) {
  const r = await getPool().query("SELECT id, email, pw_salt, pw_hash FROM users WHERE email = $1", [email]);
  return r.rows[0] || null;
}

async function getUserById(id) {
  const r = await getPool().query("SELECT id, email FROM users WHERE id = $1", [id]);
  return r.rows[0] || null;
}

// Tokens used today (UTC day).
async function getUsageToday(userId) {
  const r = await getPool().query(
    "SELECT tokens FROM usage WHERE user_id = $1 AND day = (now() AT TIME ZONE 'utc')::date",
    [userId]
  );
  return r.rows[0] ? r.rows[0].tokens : 0;
}

async function addUsage(userId, tokens) {
  await getPool().query(
    `INSERT INTO usage (user_id, day, tokens, checks)
     VALUES ($1, (now() AT TIME ZONE 'utc')::date, $2, 1)
     ON CONFLICT (user_id, day)
     DO UPDATE SET tokens = usage.tokens + EXCLUDED.tokens, checks = usage.checks + 1`,
    [userId, tokens]
  );
}

module.exports = { init, createUser, getUserByEmail, getUserById, getUsageToday, addUsage };
