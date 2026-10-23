// server.js: TruthCheck backend (runs on Render, code lives on GitHub).
// Accounts (email + password), a daily token limit per user, and the fact-checking itself.
// Search: Firecrawl Keyless (no account). LLM: Groq free tier. Database: Postgres (Neon free plan).

const express = require("express");
const cors = require("cors");
const rateLimit = require("express-rate-limit");
const crypto = require("crypto");
const { promisify } = require("util");
const db = require("./db");

const scrypt = promisify(crypto.scrypt);

const app = express();
app.set("trust proxy", 1); // Render sits behind a proxy; needed for per-IP rate limiting
app.use(cors());
app.use(express.json({ limit: "200kb" }));

// ---------- settings (all secrets come from Render's environment variables) ----------
const GROQ_URL = "https://api.groq.com/openai/v1/chat/completions";
const GROQ_MODELS_URL = "https://api.groq.com/openai/v1/models";
const FIRECRAWL_URL = "https://api.firecrawl.dev/v2/search";
const GROQ_KEY = process.env.GROQ_API_KEY;
const FIRECRAWL_KEY = process.env.FIRECRAWL_API_KEY; // optional
const JWT_SECRET = process.env.JWT_SECRET;
const HAS_DB = Boolean(process.env.DATABASE_URL);
// Tokens each person can use per day (UTC day). Change it with DAILY_TOKEN_LIMIT on Render.
const DAILY_TOKEN_LIMIT = Math.max(1000, parseInt(process.env.DAILY_TOKEN_LIMIT, 10) || 30000);
const SESSION_MS = 90 * 24 * 60 * 60 * 1000; // stay signed in for 90 days

const PREFERRED_MODELS = ["openai/gpt-oss-120b", "llama-3.3-70b-versatile", "openai/gpt-oss-20b", "llama-3.1-8b-instant"];
const VALID_VERDICTS = ["true", "false", "partially_true", "uncertain", "opinion"];

// ---------- accounts: passwords and session tokens ----------
async function hashPassword(password, salt) {
  return (await scrypt(password, salt, 64)).toString("hex");
}

function signToken(userId) {
  const payload = Buffer.from(JSON.stringify({ uid: userId, exp: Date.now() + SESSION_MS })).toString("base64url");
  const sig = crypto.createHmac("sha256", JWT_SECRET).update(payload).digest("base64url");
  return `${payload}.${sig}`;
}

function readToken(token) {
  if (!JWT_SECRET || typeof token !== "string") return null;
  const parts = token.split(".");
  if (parts.length !== 2 || !parts[0] || !parts[1]) return null;
  const expected = crypto.createHmac("sha256", JWT_SECRET).update(parts[0]).digest("base64url");
  const a = Buffer.from(parts[1]);
  const b = Buffer.from(expected);
  if (a.length !== b.length || !crypto.timingSafeEqual(a, b)) return null;
  try {
    const data = JSON.parse(Buffer.from(parts[0], "base64url").toString());
    if (!data.uid || !(data.exp > Date.now())) return null;
    return data;
  } catch (e) {
    return null;
  }
}

function nextResetIso() {
  const d = new Date();
  return new Date(Date.UTC(d.getUTCFullYear(), d.getUTCMonth(), d.getUTCDate() + 1)).toISOString();
}

let dbReady = null;
function ensureDb() {
  if (!dbReady) {
    dbReady = db.init().catch((e) => {
      dbReady = null;
      throw e;
    });
  }
  return dbReady;
}

async function needAccounts(req, res, next) {
  if (!HAS_DB || !JWT_SECRET) {
    return res.status(500).json({ error: "SERVER_MISCONFIGURED", detail: "DATABASE_URL or JWT_SECRET is missing on the server." });
  }
  try {
    await ensureDb();
  } catch (e) {
    console.error("Database init failed:", e.message);
    return res.status(503).json({ error: "DATABASE_UNAVAILABLE" });
  }
  next();
}

async function requireAuth(req, res, next) {
  const m = /^Bearer (.+)$/.exec(req.get("authorization") || "");
  const data = m && readToken(m[1]);
  if (!data) return res.status(401).json({ error: "NOT_SIGNED_IN" });
  try {
    const user = await db.getUserById(data.uid);
    if (!user) return res.status(401).json({ error: "NOT_SIGNED_IN" });
    req.user = user;
    next();
  } catch (e) {
    return res.status(503).json({ error: "DATABASE_UNAVAILABLE" });
  }
}

// ---------- rate limits ----------
const signupLimiter = rateLimit({
  windowMs: 60 * 60 * 1000,
  limit: 5,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: "RATE_LIMITED", detail: "Too many new accounts from this network. Try again in an hour." }
});
const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: 20,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: "RATE_LIMITED", detail: "Too many sign-in attempts. Try again in a few minutes." }
});
// Per person (not per network), so a family on one Wi-Fi doesn't share a limit.
const verifyLimiter = rateLimit({
  windowMs: 60 * 1000,
  limit: 8,
  standardHeaders: true,
  legacyHeaders: false,
  keyGenerator: (req) => `user-${req.user.id}`,
  message: { error: "RATE_LIMITED", detail: "Slow down a little. Try again in a minute." }
});

// ---------- routes: health and accounts ----------
app.get("/health", (req, res) =>
  res.json({ ok: true, hasKey: Boolean(GROQ_KEY), hasDatabase: HAS_DB, hasSecret: Boolean(JWT_SECRET) })
);

function cleanEmail(raw) {
  const email = String(raw || "").trim().toLowerCase();
  return email.length <= 254 && /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email) ? email : null;
}

app.post("/auth/signup", signupLimiter, needAccounts, async (req, res) => {
  const email = cleanEmail(req.body && req.body.email);
  const password = String((req.body && req.body.password) || "");
  if (!email) return res.status(400).json({ error: "INVALID_EMAIL" });
  if (password.length < 8 || password.length > 200) {
    return res.status(400).json({ error: "WEAK_PASSWORD", detail: "Use at least 8 characters." });
  }
  try {
    const salt = crypto.randomBytes(16).toString("hex");
    const user = await db.createUser(email, salt, await hashPassword(password, salt));
    if (!user) return res.status(409).json({ error: "EMAIL_TAKEN" });
    return res.json({ token: signToken(user.id), email: user.email });
  } catch (e) {
    console.error("Signup failed:", e.message);
    return res.status(503).json({ error: "DATABASE_UNAVAILABLE" });
  }
});

app.post("/auth/login", loginLimiter, needAccounts, async (req, res) => {
  const email = cleanEmail(req.body && req.body.email);
  const password = String((req.body && req.body.password) || "");
  try {
    const user = email ? await db.getUserByEmail(email) : null;
    // Always hash, so a wrong email takes as long as a wrong password.
    const hash = await hashPassword(password.slice(0, 200), user ? user.pw_salt : "0".repeat(32));
    const ok = user && crypto.timingSafeEqual(Buffer.from(hash, "hex"), Buffer.from(user.pw_hash, "hex"));
    if (!ok) return res.status(401).json({ error: "BAD_LOGIN" });
    return res.json({ token: signToken(user.id), email: user.email });
  } catch (e) {
    console.error("Login failed:", e.message);
    return res.status(503).json({ error: "DATABASE_UNAVAILABLE" });
  }
});

app.get("/me", needAccounts, requireAuth, async (req, res) => {
  try {
    const used = await db.getUsageToday(req.user.id);
    return res.json({ email: req.user.email, used, limit: DAILY_TOKEN_LIMIT, resetsAt: nextResetIso() });
  } catch (e) {
    return res.status(503).json({ error: "DATABASE_UNAVAILABLE" });
  }
});

// ---------- fact-checking ----------
const SYSTEM_PROMPT = `You are a fact-checking assistant embedded in a browser extension.
You will be given a passage of text (it may be an AI chatbot's answer, or text from any webpage) and a list of web search results gathered about it.

Your job:
1. Identify the concrete, checkable factual claims in the passage (names, dates, numbers, events, quotes, statistics, "who/what/when" statements).
2. Using ONLY the provided search results, judge whether those claims hold up. Do not invent sources - only cite from the list given to you.
3. If the passage is PURELY opinion or has no checkable factual content, say so.

Respond with ONLY a JSON object (no markdown fences, no commentary outside the JSON) in this exact shape:

{
  "hasFactualClaims": boolean,
  "verdict": "true" | "false" | "partially_true" | "uncertain" | "opinion",
  "confidence": number between 0 and 100 (a whole number like 85, never a fraction like 0.85),
  "summary": string,
  "corrections": string,
  "sources": [ { "title": string, "url": string } ]
}

If the search results don't clearly settle it, use "uncertain" rather than guessing.`;

let modelCache = { list: null, at: 0 };

async function getCandidateModels() {
  if (process.env.GROQ_MODEL) return [process.env.GROQ_MODEL];
  if (modelCache.list && Date.now() - modelCache.at < 60 * 60 * 1000) return modelCache.list;
  try {
    const r = await fetch(GROQ_MODELS_URL, {
      headers: { Authorization: `Bearer ${GROQ_KEY}` },
      signal: AbortSignal.timeout(8000)
    });
    if (r.ok) {
      const data = await r.json();
      const ids = ((data && data.data) || []).map((m) => m.id);
      const available = PREFERRED_MODELS.filter((id) => ids.includes(id));
      if (available.length) {
        modelCache = { list: available, at: Date.now() };
        return available;
      }
    }
  } catch (e) {
    // fall through to the built-in list
  }
  return PREFERRED_MODELS;
}

function callGroq(model, messages) {
  const body = {
    model,
    max_tokens: 2000, // reasoning models spend some of this thinking before they answer
    response_format: { type: "json_object" },
    messages
  };
  if (model.startsWith("openai/gpt-oss")) body.reasoning_effort = "low";
  return fetch(GROQ_URL, {
    method: "POST",
    headers: { "Content-Type": "application/json", Authorization: `Bearer ${GROQ_KEY}` },
    signal: AbortSignal.timeout(25000),
    body: JSON.stringify(body)
  });
}

async function searchWeb(query) {
  try {
    const headers = { "Content-Type": "application/json" };
    if (FIRECRAWL_KEY) headers.Authorization = `Bearer ${FIRECRAWL_KEY}`;
    const resp = await fetch(FIRECRAWL_URL, {
      method: "POST",
      headers,
      body: JSON.stringify({ query: query.slice(0, 300), limit: 5 }),
      signal: AbortSignal.timeout(10000)
    });
    if (!resp.ok) return [];
    const data = await resp.json();
    const web = (data && data.data && data.data.web) || [];
    return web.map((r) => ({ title: r.title, url: r.url, description: r.description }));
  } catch (e) {
    return [];
  }
}

app.post("/verify", needAccounts, requireAuth, verifyLimiter, async (req, res) => {
  if (!GROQ_KEY) return res.status(500).json({ error: "SERVER_MISSING_KEY" });

  const text = ((req.body && req.body.text) || "").toString().slice(0, 6000);
  if (!text.trim()) return res.status(400).json({ error: "BAD_REQUEST", detail: "No text provided." });

  // Daily limit: checked before any work is done.
  let used;
  try {
    used = await db.getUsageToday(req.user.id);
  } catch (e) {
    return res.status(503).json({ error: "DATABASE_UNAVAILABLE" });
  }
  if (used >= DAILY_TOKEN_LIMIT) {
    return res.status(429).json({ error: "DAILY_LIMIT_REACHED", used, limit: DAILY_TOKEN_LIMIT, resetsAt: nextResetIso() });
  }

  const results = await searchWeb(text);
  const context = results.length
    ? results.map((r, i) => `${i + 1}. ${r.title} (${r.url})\n${r.description || ""}`).join("\n\n")
    : '(NO SEARCH RESULTS WERE FOUND. You cannot verify anything. Use verdict "uncertain" unless the passage is purely opinion.)';

  try {
    const messages = [
      { role: "system", content: SYSTEM_PROMPT },
      { role: "user", content: `Passage to fact-check:\n"""${text}"""\n\nWeb search results:\n${context}` }
    ];
    const candidates = await getCandidateModels();
    let resp = null;
    for (const model of candidates) {
      resp = await callGroq(model, messages);
      if (resp.status !== 404) break; // 404 = this model no longer exists, try the next one
      modelCache = { list: null, at: 0 };
    }

    if (resp.status === 429) {
      return res.status(429).json({ error: "SERVICE_BUSY" });
    }
    if (!resp.ok) {
      const errText = (await resp.text()).slice(0, 300);
      return res.status(502).json({ error: "API_ERROR", detail: `${resp.status}: ${errText}` });
    }

    const data = await resp.json();
    const raw = (data.choices && data.choices[0] && data.choices[0].message && data.choices[0].message.content) || "";

    // Count what this check cost, as reported by Groq (or estimate if it isn't reported).
    let tokens = Number(data.usage && data.usage.total_tokens);
    if (!Number.isFinite(tokens) || tokens <= 0) tokens = Math.ceil((text.length + context.length + raw.length) / 4);
    tokens = Math.round(tokens);
    try {
      await db.addUsage(req.user.id, tokens);
    } catch (e) {
      console.error("Couldn't record usage:", e.message);
    }
    const usage = { used: used + tokens, limit: DAILY_TOKEN_LIMIT, resetsAt: nextResetIso() };

    const cleaned = raw.replace(/```json|```/g, "").trim();
    let parsed;
    try {
      parsed = JSON.parse(cleaned);
    } catch (e) {
      return res.status(502).json({ error: "PARSE_ERROR", raw: cleaned || "(empty response)", usage });
    }
    if (!parsed || typeof parsed !== "object") {
      return res.status(502).json({ error: "PARSE_ERROR", raw: cleaned.slice(0, 200), usage });
    }
    if (!VALID_VERDICTS.includes(parsed.verdict)) parsed.verdict = "uncertain";
    let conf = Number(parsed.confidence);
    if (!Number.isFinite(conf)) conf = 50;
    if (conf > 0 && conf <= 1) conf = conf * 100; // some models answer 0.9 instead of 90
    parsed.confidence = Math.max(0, Math.min(100, Math.round(conf)));
    if (!Array.isArray(parsed.sources)) parsed.sources = [];
    parsed.summary = String(parsed.summary || "");
    parsed.corrections = String(parsed.corrections || "");

    if (!results.length && parsed.verdict !== "opinion") {
      // No web sources came back, so don't let the model pass judgment from memory.
      parsed.verdict = "uncertain";
      parsed.confidence = Math.min(parsed.confidence, 30);
      parsed.summary = "Couldn't find web sources to check this. " + parsed.summary;
      parsed.corrections = "";
    }
    if (!parsed.sources.length && results.length) {
      parsed.sources = results.slice(0, 3).map((r) => ({ title: r.title, url: r.url }));
    }
    return res.json({ result: parsed, usage });
  } catch (e) {
    return res.status(500).json({ error: "NETWORK_ERROR", detail: String(e) });
  }
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`TruthCheck server listening on port ${PORT}`));
