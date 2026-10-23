// db.js: tiny data layer for accounts and daily usage (Postgres, e.g. Neon's free plan).
const { Pool } = require("pg");

// Neon's copied connection string ends with ?sslmode=require&channel_binding=require.
// We turn on encryption ourselves below and drop those two extras, which can make
// the connection fail with some Node versions.
function cleanConnectionString(url) {
  try {
    const u = new URL(url);
    u.searchParams.delete("channel_binding");
    u.searchParams.delete("sslmode");
    return u.toString();
  } catch (e) {
    return url;
  }
}

let pool = null;
function getPool() {
  if (!pool) {
    pool = new Pool({
      connectionString: cleanConnectionString(process.env.DATABASE_URL),
      ssl: { rejectUnauthorized: false },
      max: 5,
      idleTimeoutMillis: 10000, // drop idle connections quickly: Neon's free database sleeps when quiet
      connectionTimeoutMillis: 15000, // allow time for it to wake up
      keepAlive: true
    });
    pool.on("error", (e) => console.error("Database pool error:", e.message));
  }
  return pool;
}

// A connection that went stale while the database slept fails once; trying again
// opens a fresh one. Only used for harmless reads and setup, never for inserts.
function isTransient(e) {
  const msg = String((e && e.message) || "");
  return (
    /Connection terminated|terminating connection|ECONNRESET|ETIMEDOUT|EPIPE|timeout exceeded when trying to connect/i.test(msg) ||
    ["ECONNRESET", "ETIMEDOUT", "EPIPE", "57P01", "08006", "08003"].includes(e && e.code)
  );
}
async function q(text, params) {
  try {
    return await getPool().query(text, params);
  } catch (e) {
    if (isTransient(e)) return await getPool().query(text, params);
    throw e;
  }
}

async function init() {
  await q(`CREATE TABLE IF NOT EXISTS users (
    id SERIAL PRIMARY KEY,
    email TEXT UNIQUE NOT NULL,
    pw_salt TEXT NOT NULL,
    pw_hash TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
  )`);
  await q(`CREATE TABLE IF NOT EXISTS usage (
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
  const r = await q("SELECT id, email, pw_salt, pw_hash FROM users WHERE email = $1", [email]);
  return r.rows[0] || null;
}

async function getUserById(id) {
  const r = await q("SELECT id, email FROM users WHERE id = $1", [id]);
  return r.rows[0] || null;
}

// Tokens used today (UTC day).
async function getUsageToday(userId) {
  const r = await q(
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

module.exports = { cleanConnectionString, init, createUser, getUserByEmail, getUserById, getUsageToday, addUsage };
