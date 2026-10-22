# Deploy the TruthCheck server (GitHub + Render)

## 1. Get a free Groq key (no card)
Go to https://console.groq.com/keys, sign up with email, click "Create API Key", copy it.
Keep it private. It lives only on Render, never in the extension.

## 2. Put the code on GitHub
1. On github.com click New repository, name it `truthcheck-server`, create it.
2. Click "uploading an existing file", drag in everything from this folder (server.js, package.json, .gitignore, DEPLOY.md), commit.

## 3. Deploy on Render
1. render.com -> New + -> Web Service -> connect GitHub -> pick `truthcheck-server`.
2. Runtime: Node. Build command: `npm install`. Start command: `npm start`. Instance type: Free.
3. Environment Variables -> add `GROQ_API_KEY` = your Groq key.
4. Create Web Service. When it is live, copy the URL (like https://truthcheck-server-xxxx.onrender.com).
5. Open that URL + `/health` in a browser. You should see {"ok":true,"hasKey":true}.

## 4. Point the extension at it
Open the extension's `background.js` and replace the SERVER_URL line near the top with your Render URL. Then reload the extension.

## Notes
- Web search uses Firecrawl's anonymous free allowance, which is shared by everyone using your server (about 1,000 credits a month, and each check costs 2). If searches start coming back empty, make a free Firecrawl account and add its key on Render as `FIRECRAWL_API_KEY`; the server uses it automatically.
- Use a repo that contains ONLY these server files (not the extension files).
- Free Render services sleep when idle; the first check after a quiet period can take 20-30 seconds.
- If Render asks for card verification when you sign up, that is Render's own policy, not something this project needs.
- Users who hit the shared Groq limit can add their own free Groq key in the extension popup; the server then uses theirs instead.
