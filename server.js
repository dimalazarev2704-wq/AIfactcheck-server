// server.js — TruthCheck backend (runs on Render, code lives on GitHub).
// Keeps the Groq key secret on the server, so it is never shipped inside the extension.
// Search uses Firecrawl Keyless (no account/key). LLM uses Groq's free tier (no card).

const express = require("express");
const cors = require("cors");
const rateLimit = require("express-rate-limit");

const app = express();
app.set("trust proxy", 1); // Render sits behind a proxy; needed for per-IP rate limiting
app.use(cors());
app.use(express.json({ limit: "200kb" }));

const GROQ_URL = "https://api.groq.com/openai/v1/chat/completions";
const GROQ_MODEL = "llama-3.3-70b-versatile";
const FIRECRAWL_URL = "https://api.firecrawl.dev/v2/search";
const SHARED_KEY = process.env.GROQ_API_KEY;
// Optional: a free Firecrawl account key gives the server its own search allowance
// instead of the shared anonymous one. Leave unset to use keyless search.
const FIRECRAWL_KEY = process.env.FIRECRAWL_API_KEY;
const VALID_VERDICTS = ["true", "false", "partially_true", "uncertain", "opinion"];

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
  "confidence": number,
  "summary": string,
  "corrections": string,
  "sources": [ { "title": string, "url": string } ]
}

If the search results don't clearly settle it, use "uncertain" rather than guessing.`;

// Protects the shared free Groq quota from one heavy user.
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 40,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: "RATE_LIMITED", detail: "Too many checks - try again in a few minutes." }
});

app.get("/health", (req, res) => res.json({ ok: true, hasKey: Boolean(SHARED_KEY) }));

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

app.post("/verify", limiter, async (req, res) => {
  const ownKey = (req.get("x-user-groq-key") || "").trim();
  const key = ownKey || SHARED_KEY;
  const usingOwn = Boolean(ownKey);

  if (!key) {
    return res.status(500).json({ error: "SERVER_MISSING_KEY" });
  }
  const text = ((req.body && req.body.text) || "").toString().slice(0, 6000);
  if (!text.trim()) {
    return res.status(400).json({ error: "BAD_REQUEST", detail: "No text provided." });
  }

  const results = await searchWeb(text);
  const context = results.length
    ? results.map((r, i) => `${i + 1}. ${r.title} (${r.url})\n${r.description || ""}`).join("\n\n")
    : "(NO SEARCH RESULTS WERE FOUND. You cannot verify anything. Use verdict \"uncertain\" unless the passage is purely opinion.)";

  try {
    const resp = await fetch(GROQ_URL, {
      method: "POST",
      headers: { "Content-Type": "application/json", Authorization: `Bearer ${key}` },
      signal: AbortSignal.timeout(25000),
      body: JSON.stringify({
        model: GROQ_MODEL,
        max_tokens: 800,
        response_format: { type: "json_object" },
        messages: [
          { role: "system", content: SYSTEM_PROMPT },
          { role: "user", content: `Passage to fact-check:\n"""${text}"""\n\nWeb search results:\n${context}` }
        ]
      })
    });

    if (resp.status === 429) {
      return res.status(429).json({ error: usingOwn ? "OWN_KEY_RATE_LIMITED" : "SHARED_LIMIT_REACHED" });
    }
    if (!resp.ok) {
      const errText = (await resp.text()).slice(0, 300);
      return res.status(502).json({ error: "API_ERROR", detail: `${resp.status}: ${errText}` });
    }

    const data = await resp.json();
    const raw = (data.choices && data.choices[0] && data.choices[0].message && data.choices[0].message.content) || "";
    const cleaned = raw.replace(/```json|```/g, "").trim();

    let parsed;
    try {
      parsed = JSON.parse(cleaned);
    } catch (e) {
      return res.status(502).json({ error: "PARSE_ERROR", raw: cleaned || "(empty response)" });
    }
    if (!parsed || typeof parsed !== "object") {
      return res.status(502).json({ error: "PARSE_ERROR", raw: cleaned.slice(0, 200) });
    }
    if (!VALID_VERDICTS.includes(parsed.verdict)) parsed.verdict = "uncertain";
    let conf = Number(parsed.confidence);
    if (!Number.isFinite(conf)) conf = 50;
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
    return res.json({ result: parsed });
  } catch (e) {
    return res.status(500).json({ error: "NETWORK_ERROR", detail: String(e) });
  }
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`TruthCheck server listening on port ${PORT}`));
