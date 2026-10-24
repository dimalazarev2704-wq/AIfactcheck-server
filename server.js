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
// Behind Render's edge, req.ip can be a shared proxy address, which would lump many
// people into one limit. The edge passes the real visitor address in this header.
function clientIp(req) {
  return (req.get("cf-connecting-ip") || req.ip || "unknown").trim();
}

const signupLimiter = rateLimit({
  windowMs: 60 * 60 * 1000,
  limit: 10,
  standardHeaders: true,
  legacyHeaders: false,
  keyGenerator: clientIp,
  message: { error: "RATE_LIMITED", detail: "Too many new accounts from this network. Try again in an hour." }
});
const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: 20,
  standardHeaders: true,
  legacyHeaders: false,
  keyGenerator: clientIp,
  skipSuccessfulRequests: true, // only wrong passwords count against the limit
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

// ---------- public pages ----------
const CONTACT_EMAIL = (process.env.CONTACT_EMAIL || "").trim();
const MARK_PATH = "M7 2h10a5 5 0 0 1 5 5v7a5 5 0 0 1-5 5h-6l-4.2 3.4a.6.6 0 0 1-1-.47V19A5 5 0 0 1 2 14V7a5 5 0 0 1 5-5zM6.42 13.28 L10.51 17.38 L17.90 9.77 L16.10 8.03 L10.49 13.82 L8.18 11.52Z";
const POLICY_DATE = "October 24, 2026";

function escapeHtml(str) {
  return String(str).replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
}

function pageShell(title, body) {
  return `<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>${escapeHtml(title)}</title>
<style>
  :root { color-scheme: light dark; --ink:#1a1a1a; --muted:#5f5f5f; --line:#e6e6e6; --bg:#fff; }
  @media (prefers-color-scheme: dark) { :root { --ink:#ececec; --muted:#a8a8a8; --line:#333; --bg:#161616; } }
  * { box-sizing: border-box; }
  body { margin:0; background:var(--bg); color:var(--ink); font:16px/1.65 -apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,"Helvetica Neue",Arial,sans-serif; }
  main { max-width:680px; margin:0 auto; padding:48px 24px 72px; }
  header { display:flex; align-items:center; gap:12px; margin-bottom:32px; }
  header svg { width:32px; height:32px; }
  header strong { font-size:18px; }
  h1 { font-size:30px; line-height:1.2; margin:0 0 6px; letter-spacing:-0.01em; }
  h2 { font-size:18px; margin:36px 0 8px; }
  p, li { color:var(--ink); }
  .muted { color:var(--muted); font-size:14px; }
  ul { padding-left:22px; } li { margin:6px 0; }
  a { color:inherit; text-underline-offset:3px; }
  footer { margin-top:48px; padding-top:20px; border-top:1px solid var(--line); color:var(--muted); font-size:14px; }
</style></head>
<body><main>
<header><svg viewBox="0 0 24 24" aria-hidden="true"><path d="${MARK_PATH}" fill="currentColor" fill-rule="evenodd"/></svg><strong>TruthCheck</strong></header>
${body}
<footer><a href="/">TruthCheck</a> &middot; <a href="/privacy">Privacy policy</a></footer>
</main></body></html>`;
}

const contactLine = CONTACT_EMAIL
  ? `Email us at <a href="mailto:${escapeHtml(CONTACT_EMAIL)}">${escapeHtml(CONTACT_EMAIL)}</a>.`
  : "Use the support link on TruthCheck's store listing.";

const LANDING_HTML = pageShell("TruthCheck", `
<h1>Fact-check AI answers.</h1>
<p>TruthCheck is a browser extension that checks AI chatbot answers against live web search. Under each answer you choose what to check: the whole answer, only the text you highlight, or each factual claim, with the untrue ones flagged first.</p>
<p class="muted">This is the service behind the extension. Read the <a href="/privacy">privacy policy</a>.</p>`);

const PRIVACY_HTML = pageShell("TruthCheck privacy policy", `
<h1>Privacy policy</h1>
<p class="muted">Last updated ${POLICY_DATE}</p>
<p>TruthCheck checks AI answers and web text against live web search. This page explains what information it uses and why. We keep it short and plain on purpose.</p>

<h2>What we collect</h2>
<ul>
  <li><strong>Your account:</strong> your email address and a scrambled (hashed) version of your password. We can't read your password.</li>
  <li><strong>Your usage:</strong> how much of your daily limit you have used. We don't keep a list of what you checked.</li>
  <li><strong>A sign-in token:</strong> stored in your browser's extension storage so you stay signed in (for up to 90 days).</li>
  <li><strong>Your settings:</strong> for example whether the side window is collapsed. These stay in your browser.</li>
</ul>

<h2>The text you choose to check</h2>
<p>When you press a Check button, press Verify on highlighted text, or turn on automatic checking, the text is sent to our server. To do the check, the server passes it, and search terms taken from it, to the services listed below. We do not store the text or the results.</p>

<h2>What the extension reads on web pages</h2>
<ul>
  <li>On AI chat sites (ChatGPT, Claude and Gemini) it looks at the page, on your device, to show its Check bar under new answers and to read the answer you ask it to check.</li>
  <li>On other sites, it notices when you highlight text so it can offer a Verify button. The text stays on your device unless you press Verify.</li>
  <li>Nothing is sent anywhere until you choose to check something, unless you turn on automatic checking.</li>
  <li>We don't collect your browsing history, and we don't track you across sites.</li>
</ul>

<h2>Who helps us run TruthCheck</h2>
<p>These providers process data only to provide the service. Text you check is handled under their own terms and privacy policies.</p>
<ul>
  <li><strong>Groq</strong>: the AI model that judges claims.</li>
  <li><strong>Firecrawl</strong>: web search for sources.</li>
  <li><strong>Render</strong>: hosts our server.</li>
  <li><strong>Neon</strong>: hosts our account database.</li>
</ul>
<p>We do not sell your data, and we do not use it for advertising.</p>

<h2>Keeping and deleting your data</h2>
<p>We keep your account until you delete it. You can delete it any time in the extension: open TruthCheck, choose Delete account, and enter your password. This removes your email, your hashed password and your usage history. Copies may remain in our database provider's backups for a short time.</p>

<h2>Security</h2>
<p>Everything is sent over an encrypted connection. Passwords are hashed with scrypt before they are stored. No system is perfectly secure, but we take care to protect what we hold.</p>

<h2>Children</h2>
<p>TruthCheck is not directed at children under 13, and we don't knowingly collect their information.</p>

<h2>Changes</h2>
<p>If this policy changes, we will update the date at the top.</p>

<h2>Contact</h2>
<p>${contactLine}</p>`);

app.get("/", (req, res) => res.type("html").send(LANDING_HTML));
app.get("/privacy", (req, res) => res.type("html").send(PRIVACY_HTML));

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

app.post("/auth/delete", loginLimiter, needAccounts, requireAuth, async (req, res) => {
  const password = String((req.body && req.body.password) || "");
  try {
    const user = await db.getUserByEmail(req.user.email);
    const hash = await hashPassword(password.slice(0, 200), user ? user.pw_salt : "0".repeat(32));
    const ok = user && crypto.timingSafeEqual(Buffer.from(hash, "hex"), Buffer.from(user.pw_hash, "hex"));
    if (!ok) return res.status(401).json({ error: "BAD_LOGIN" });
    await db.deleteUser(user.id);
    return res.json({ ok: true });
  } catch (e) {
    console.error("Account deletion failed:", e.message);
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

async function searchWeb(query, limit) {
  try {
    const headers = { "Content-Type": "application/json" };
    if (FIRECRAWL_KEY) headers.Authorization = `Bearer ${FIRECRAWL_KEY}`;
    const resp = await fetch(FIRECRAWL_URL, {
      method: "POST",
      headers,
      body: JSON.stringify({ query: query.slice(0, 300), limit: limit || 5 }),
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

// ---------- shared helpers for both kinds of check ----------

// One request to Groq, trying the next model if one has been retired.
// Returns { ok, raw, tokens } or { ok: false, status, errText }.
async function groqRequest(messages) {
  const candidates = await getCandidateModels();
  let resp = null;
  for (const model of candidates) {
    resp = await callGroq(model, messages);
    if (resp.status !== 404) break; // 404 = this model no longer exists, try the next one
    modelCache = { list: null, at: 0 };
  }
  if (!resp.ok) return { ok: false, status: resp.status, errText: (await resp.text()).slice(0, 300) };
  const data = await resp.json();
  const raw = (data.choices && data.choices[0] && data.choices[0].message && data.choices[0].message.content) || "";
  // What this request cost, as reported by Groq (or an estimate if it isn't reported).
  let tokens = Number(data.usage && data.usage.total_tokens);
  if (!Number.isFinite(tokens) || tokens <= 0) tokens = Math.ceil((JSON.stringify(messages).length + raw.length) / 4);
  return { ok: true, raw, tokens: Math.round(tokens) };
}

function groqFailure(res, g) {
  if (g.status === 429) return res.status(429).json({ error: "SERVICE_BUSY" });
  return res.status(502).json({ error: "API_ERROR", detail: `${g.status}: ${g.errText}` });
}

function parseJsonObject(raw) {
  try {
    const o = JSON.parse(String(raw).replace(/```json|```/g, "").trim());
    return o && typeof o === "object" ? o : null;
  } catch (e) {
    return null;
  }
}

function normalizeConfidence(c) {
  let n = Number(c);
  if (!Number.isFinite(n)) n = 50;
  if (n > 0 && n <= 1) n = n * 100; // some models answer 0.9 instead of 90
  return Math.max(0, Math.min(100, Math.round(n)));
}

// 0-100, higher = more accurate. null when there's nothing to score.
function accuracyScore(verdict, conf) {
  if (verdict === "true") return conf;
  if (verdict === "false") return 100 - conf;
  if (verdict === "partially_true") return 50;
  return null;
}

async function recordUsage(userId, tokens) {
  try {
    await db.addUsage(userId, tokens);
  } catch (e) {
    console.error("Couldn't record usage:", e.message);
  }
}

// ---------- check 1: the whole answer (or a highlighted passage) ----------
async function checkWhole(req, res, text, used) {
  const results = await searchWeb(text);
  const context = results.length
    ? results.map((r, i) => `${i + 1}. ${r.title} (${r.url})\n${r.description || ""}`).join("\n\n")
    : '(NO SEARCH RESULTS WERE FOUND. You cannot verify anything. Use verdict "uncertain" unless the passage is purely opinion.)';

  const g = await groqRequest([
    { role: "system", content: SYSTEM_PROMPT },
    { role: "user", content: `Passage to fact-check:\n"""${text}"""\n\nWeb search results:\n${context}` }
  ]);
  if (!g.ok) return groqFailure(res, g);

  await recordUsage(req.user.id, g.tokens);
  const usage = { used: used + g.tokens, limit: DAILY_TOKEN_LIMIT, resetsAt: nextResetIso() };

  const parsed = parseJsonObject(g.raw);
  if (!parsed) return res.status(502).json({ error: "PARSE_ERROR", raw: String(g.raw).slice(0, 200) || "(empty response)", usage });

  if (!VALID_VERDICTS.includes(parsed.verdict)) parsed.verdict = "uncertain";
  parsed.confidence = normalizeConfidence(parsed.confidence);
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
}

// ---------- check 2: find the untrue claims inside an answer ----------
const MAX_CLAIMS = 4;

const CLAIMS_EXTRACT_PROMPT = `You pick out checkable factual claims from a passage so they can be fact-checked.
Return ONLY a JSON object (no markdown, no commentary) in this exact shape:
{ "claims": [ "claim one", "claim two" ] }

Rules:
- At most ${MAX_CLAIMS} claims. Choose the ones that matter most or are most likely to be wrong.
- Only concrete, checkable facts: names, dates, numbers, places, events, quotes, statistics, "who/what/when/where" statements.
- Skip opinions, advice, predictions and vague statements.
- Each claim must be one complete sentence that makes sense on its own: replace "it", "he", "they" and similar with the actual name.
- If there are no checkable claims, return { "claims": [] }.`;

const CLAIMS_JUDGE_PROMPT = `You are a fact-checker. You get several numbered claims, each with web search results.
Judge EACH claim using ONLY its own search results. Never invent sources: only cite results you were given.
Return ONLY a JSON object (no markdown, no commentary) in this exact shape:
{ "claims": [
  { "index": 1,
    "verdict": "true" | "false" | "partially_true" | "uncertain",
    "confidence": a whole number from 0 to 100 (never a fraction like 0.85),
    "explanation": "one short sentence",
    "correction": "if the claim is false or partly true, the correct information; otherwise an empty string",
    "sources": [ { "title": "...", "url": "..." } ] }
] }
If the results don't clearly settle a claim, use "uncertain" rather than guessing.`;

function claimsSummary(n, untrue, partial, good, unsure) {
  if (!untrue && !partial && !unsure) return n === 1 ? "The claim looks accurate." : `All ${n} claims look accurate.`;
  const parts = [];
  if (untrue) parts.push(`${untrue} of ${n} ${n === 1 ? "claim looks" : "claims look"} untrue.`);
  else if (!partial) parts.push("No untrue claims found.");
  if (partial) parts.push(`${partial} partly accurate.`);
  if (good) parts.push(`${good} ${good === 1 ? "looks" : "look"} accurate.`);
  if (unsure) parts.push(`${unsure} couldn't be confirmed.`);
  return parts.join(" ");
}

async function checkClaims(req, res, text, used) {
  // Step 1: pick out the checkable claims.
  const g1 = await groqRequest([
    { role: "system", content: CLAIMS_EXTRACT_PROMPT },
    { role: "user", content: `Passage:\n"""${text}"""` }
  ]);
  if (!g1.ok) return groqFailure(res, g1);
  let tokens = g1.tokens;
  const usageNow = () => ({ used: used + tokens, limit: DAILY_TOKEN_LIMIT, resetsAt: nextResetIso() });

  const extracted = parseJsonObject(g1.raw);
  if (!extracted || !Array.isArray(extracted.claims)) {
    await recordUsage(req.user.id, tokens);
    return res.status(502).json({ error: "PARSE_ERROR", raw: String(g1.raw).slice(0, 200) || "(empty response)", usage: usageNow() });
  }
  const claims = [...new Set(extracted.claims.map((c) => String(c || "").replace(/\s+/g, " ").trim().slice(0, 300)).filter((c) => c.length >= 8))].slice(0, MAX_CLAIMS);

  if (!claims.length) {
    await recordUsage(req.user.id, tokens);
    return res.json({
      result: {
        mode: "claims", verdict: "opinion", confidence: 70, score: null, claimCount: 0, untrueCount: 0,
        summary: "No specific factual claims were found to check in this text.", corrections: "", sources: [], claims: []
      },
      usage: usageNow()
    });
  }

  // Step 2: search the web for each claim (in parallel).
  const found = await Promise.all(claims.map((c) => searchWeb(c, 3)));

  // Step 3: judge every claim against its own results.
  const context = claims
    .map((c, i) => `Claim ${i + 1}: ${c}\nSearch results:\n` +
      (found[i].length ? found[i].map((r, j) => `${j + 1}. ${r.title} (${r.url})\n${r.description || ""}`).join("\n") : "(none found)"))
    .join("\n\n");
  const g2 = await groqRequest([
    { role: "system", content: CLAIMS_JUDGE_PROMPT },
    { role: "user", content: context }
  ]);
  if (!g2.ok) {
    await recordUsage(req.user.id, tokens);
    return groqFailure(res, g2);
  }
  tokens += g2.tokens;
  await recordUsage(req.user.id, tokens);

  const judged = parseJsonObject(g2.raw);
  if (!judged || !Array.isArray(judged.claims)) {
    return res.status(502).json({ error: "PARSE_ERROR", raw: String(g2.raw).slice(0, 200) || "(empty response)", usage: usageNow() });
  }

  const checked = claims.map((claim, i) => {
    const j = judged.claims.find((x) => x && Number(x.index) === i + 1) || judged.claims[i] || {};
    const results = found[i];
    let verdict = ["true", "false", "partially_true", "uncertain"].includes(j.verdict) ? j.verdict : "uncertain";
    let confidence = normalizeConfidence(j.confidence);
    let explanation = String(j.explanation || "").trim();
    let correction = String(j.correction || "").trim();
    if (!results.length) {
      // Nothing came back from the web, so don't let the model judge from memory.
      verdict = "uncertain";
      confidence = Math.min(confidence, 30);
      explanation = "Couldn't find web sources to check this.";
    }
    if (verdict === "true" || verdict === "uncertain") correction = "";
    // Only keep sources that really were in this claim's search results.
    const urls = new Set(results.map((r) => r.url));
    let sources = (Array.isArray(j.sources) ? j.sources : [])
      .filter((x) => x && urls.has(x.url))
      .map((x) => ({ title: String(x.title || ""), url: x.url }));
    if (!sources.length) sources = results.slice(0, 2).map((r) => ({ title: r.title, url: r.url }));
    return { claim, verdict, confidence, explanation, correction, sources };
  });

  // Untrue first, then partly true, can't-confirm, and accurate last.
  const rank = { false: 0, partially_true: 1, uncertain: 2, true: 3 };
  checked.sort((a, b) => rank[a.verdict] - rank[b.verdict]);

  const n = checked.length;
  const count = (v) => checked.filter((c) => c.verdict === v).length;
  const untrue = count("false"), partial = count("partially_true"), good = count("true"), unsure = count("uncertain");
  let verdict;
  if (untrue === n) verdict = "false";
  else if (untrue || partial) verdict = "partially_true";
  else if (good === n) verdict = "true";
  else verdict = "uncertain";
  const scores = checked.map((c) => accuracyScore(c.verdict, c.confidence)).filter((x) => x !== null);
  const score = scores.length ? Math.round(scores.reduce((a, b) => a + b, 0) / scores.length) : null;
  const confidence = Math.round(checked.reduce((a, c) => a + c.confidence, 0) / n);

  return res.json({
    result: {
      mode: "claims", verdict, confidence, score, claimCount: n, untrueCount: untrue,
      summary: claimsSummary(n, untrue, partial, good, unsure), corrections: "", sources: [], claims: checked
    },
    usage: usageNow()
  });
}

// ---------- the check endpoint ----------
app.post("/verify", needAccounts, requireAuth, verifyLimiter, async (req, res) => {
  if (!GROQ_KEY) return res.status(500).json({ error: "SERVER_MISSING_KEY" });

  const text = ((req.body && req.body.text) || "").toString().slice(0, 6000);
  if (!text.trim()) return res.status(400).json({ error: "BAD_REQUEST", detail: "No text provided." });
  const mode = req.body && req.body.mode === "claims" ? "claims" : "whole";

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

  try {
    return mode === "claims" ? await checkClaims(req, res, text, used) : await checkWhole(req, res, text, used);
  } catch (e) {
    console.error("Check failed:", e && e.message);
    const timedOut = e && (e.name === "TimeoutError" || e.name === "AbortError");
    return res.status(500).json({
      error: "NETWORK_ERROR",
      detail: timedOut ? "The check took too long. Try again." : "Something went wrong while checking. Try again."
    });
  }
});

// Bad or oversized requests get a short JSON answer, never a stack trace.
app.use((err, req, res, next) => {
  if (res.headersSent) return next(err);
  const tooBig = err && err.type === "entity.too.large";
  return res.status(tooBig ? 413 : 400).json({ error: "BAD_REQUEST", detail: tooBig ? "That text is too long." : "Bad request." });
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`TruthCheck server listening on port ${PORT}`));
