// ── Configuration ─────────────────────────────────────────────────────────────
const MAX_404S             = 3;
const WINDOW_SECS          = 60;
const CHALLENGE_TTL        = 600;
const VERIFIED_TTL         = 600;
const RECHECK_404S         = 10;
const RECHECK_WINDOW       = 60;
const TURNSTILE_SITE_KEY   = "0x4AAAAAADh3PNKr1tTTYgde";
const TURNSTILE_SECRET_KEY = "0x4AAAAAADh3PDOlVy3VvzfpgMpkbQgmfyM";

// ✅ Use a non-reserved path — /cdn-cgi/* is owned by Cloudflare
const VERIFY_PATH = "/check-human";
// ─────────────────────────────────────────────────────────────────────────────

const BAD_STATUSES = [403, 404, 499, 503];

export default {
  async fetch(request, env, ctx) {
    const ip  = request.headers.get("CF-Connecting-IP") || "unknown";
    const url = new URL(request.url);

    // ── Handle Turnstile callback POST ────────────────────────────────────────
    if (request.method === "POST" && url.pathname === VERIFY_PATH) {
      return handleTurnstileVerify(request, env, ip);
    }

    // ── 1. Already verified? ──────────────────────────────────────────────────
    const verified = await kvGet(env, `verified:${ip}`);
    if (verified) {
      console.log(`[VERIFIED] IP ${ip} — passing through`);
      const response = await fetch(request);
      const status   = response.status;
      if (BAD_STATUSES.includes(status)) {
        await incrementRecheckCounter(env, ctx, ip, status);
      }
      return response;
    }

    // ── 2. Currently challenged? ──────────────────────────────────────────────
    const challenged = await kvGet(env, `challenge:${ip}`);
    if (challenged) {
      console.warn(`[CHALLENGED] IP ${ip} — serving Turnstile challenge — ${url.pathname}`);
      return serveChallengeHTML(TURNSTILE_SITE_KEY, url.pathname);
    }

    // ── 3. Normal path — forward to origin ───────────────────────────────────
    const response = await fetch(request);
    const status   = response.status;

    console.log(`[ORIGIN] ${url.pathname} → ${status} — IP: ${ip}`);

    if (!BAD_STATUSES.includes(status)) {
      return response;
    }

    // ── 4. Bad status — update hit counter ───────────────────────────────────
    const countKey = `404:${ip}`;
    const now      = Math.floor(Date.now() / 1000);
    const stored   = await kvGet(env, countKey, { type: "json" });

    let count       = 1;
    let windowStart = now;

    if (stored) {
      const elapsed = now - stored.windowStart;
      if (elapsed <= WINDOW_SECS) {
        count       = stored.count + 1;
        windowStart = stored.windowStart;
      }
    }

    console.log(`[FOUND COUNTER] IP ${ip} — ${count}/${MAX_404S} errors (HTTP ${status}) — ${url.pathname}`);

    // ── 5. Threshold reached — set challenge flag ─────────────────────────────
    if (count >= MAX_404S) {
      ctx.waitUntil(kvPut(env, `challenge:${ip}`, "1", { expirationTtl: CHALLENGE_TTL }));
      ctx.waitUntil(kvDelete(env, countKey));
      console.warn(`[CHALLENGE-SET] IP ${ip} — flag written after ${count}x HTTP ${status}`);
      return response;
    }

    // Save updated counter
    ctx.waitUntil(kvPut(env, countKey, JSON.stringify({ count, windowStart }), { expirationTtl: 60 }));

    return response;
  },
};

// ── D1 helpers ────────────────────────────────────────────────────────────────
// Small shim that gives D1 the same get/put/delete-with-TTL shape the code
// was already written against, so the logic above barely had to change.
// Table: bot_state(key TEXT PRIMARY KEY, value TEXT, expires_at INTEGER)
// See schema.sql. Requires a D1 binding named "DB" (matches wrangler.json).

async function kvGet(env, key, opts = {}) {
  const row = await env.DB
    .prepare("SELECT value, expires_at FROM bot_state WHERE key = ?")
    .bind(key)
    .first();

  if (!row) return null;

  const now = Math.floor(Date.now() / 1000);
  if (row.expires_at !== null && row.expires_at <= now) {
    // Expired — D1 has no auto-expiry like KV, so clean up lazily on read.
    await kvDelete(env, key);
    return null;
  }

  if (opts.type === "json") {
    try {
      return JSON.parse(row.value);
    } catch {
      return null;
    }
  }
  return row.value;
}

async function kvPut(env, key, value, opts = {}) {
  const expiresAt = opts.expirationTtl
    ? Math.floor(Date.now() / 1000) + opts.expirationTtl
    : null;

  await env.DB
    .prepare(
      `INSERT INTO bot_state (key, value, expires_at)
       VALUES (?, ?, ?)
       ON CONFLICT(key) DO UPDATE SET
         value = excluded.value,
         expires_at = excluded.expires_at`
    )
    .bind(key, value, expiresAt)
    .run();
}

async function kvDelete(env, key) {
  await env.DB.prepare("DELETE FROM bot_state WHERE key = ?").bind(key).run();
}

// ── Serve Turnstile challenge page ────────────────────────────────────────────
function serveChallengeHTML(siteKey, returnPath) {
  const safeReturn = returnPath.replace(/"/g, "&quot;");
  const html = `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Security check</title>
  <script src="https://challenges.cloudflare.com/turnstile/v0/api.js" async defer></script>
  <style>
    *, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }
    body {
      font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
      background: #f6f6f6;
      display: flex; align-items: center; justify-content: center;
      min-height: 100vh; padding: 1rem;
    }
    .card {
      background: #fff; border-radius: 12px;
      box-shadow: 0 2px 16px rgba(0,0,0,0.08);
      padding: 2.5rem 2rem; text-align: center;
      max-width: 400px; width: 100%;
    }
    h1 { font-size: 1.25rem; font-weight: 600; color: #1a1a1a; margin-bottom: 0.5rem; }
    p  { font-size: 0.9rem; color: #666; margin-bottom: 1.5rem; line-height: 1.5; }
    .widget-wrap { display: flex; justify-content: center; margin-bottom: 1rem; }
    .ray { font-size: 0.75rem; color: #bbb; margin-top: 1.5rem; }
  </style>
</head>
<body>
  <div class="card">
    <h1>Security check</h1>
    <p>We noticed unusual activity from your IP address. Please verify you are human to continue.</p>
    <form method="POST" action="${VERIFY_PATH}">
      <input type="hidden" name="return_path" value="${safeReturn}">
      <div class="widget-wrap">
        <div class="cf-turnstile"
             data-sitekey="${siteKey}"
             data-callback="onSuccess"
             data-theme="light">
        </div>
      </div>
      <script>function onSuccess(token) { document.querySelector("form").submit(); }</script>
    </form>
    <p class="ray">Ray ID: ${crypto.randomUUID().split("-")[0].toUpperCase()}</p>
  </div>
</body>
</html>`;

  return new Response(html, {
    status: 403,
    headers: { "Content-Type": "text/html; charset=UTF-8" },
  });
}

// ── Handle Turnstile token verification ───────────────────────────────────────
async function handleTurnstileVerify(request, env, ip) {
  let returnPath = "/";
  try {
    const body   = await request.formData();
    const token  = body.get("cf-turnstile-response");
    returnPath   = body.get("return_path") || "/";

    console.log(`[TURNSTILE-POST] IP ${ip} — token present: ${!!token} — returning to: ${returnPath}`);

    if (!token) {
      return serveChallengeHTML(TURNSTILE_SITE_KEY, returnPath);
    }

    const verifyResp = await fetch("https://challenges.cloudflare.com/turnstile/v0/siteverify", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        secret:   TURNSTILE_SECRET_KEY,
        response: token,
        remoteip: ip,
      }),
    });

    const result = await verifyResp.json();
    console.log(`[TURNSTILE] IP ${ip} — success: ${result.success} — errors: ${JSON.stringify(result["error-codes"])}`);

    if (!result.success) {
      return serveChallengeHTML(TURNSTILE_SITE_KEY, returnPath);
    }

    // Delete challenge first, then write verified — both fully awaited
    await kvDelete(env, `challenge:${ip}`);
    await kvPut(env, `verified:${ip}`, "1", { expirationTtl: VERIFIED_TTL });

    console.log(`[VERIFIED] IP ${ip} — challenge cleared, redirecting to ${returnPath}`);

    const origin = new URL(request.url).origin;
    return Response.redirect(`${origin}${returnPath}`, 302);

  } catch (err) {
    console.error(`[ERROR] Turnstile verify failed for IP ${ip}: ${err.message}`);
    return serveChallengeHTML(TURNSTILE_SITE_KEY, returnPath);
  }
}

// ── Recheck counter for verified IPs ─────────────────────────────────────────
async function incrementRecheckCounter(env, ctx, ip, status) {
  const key    = `recheck:${ip}`;
  const now    = Math.floor(Date.now() / 1000);
  const stored = await kvGet(env, key, { type: "json" });

  let count       = 1;
  let windowStart = now;

  if (stored) {
    const elapsed = now - stored.windowStart;
    if (elapsed <= RECHECK_WINDOW) {
      count       = stored.count + 1;
      windowStart = stored.windowStart;
    }
  }

  console.log(`[RECHECK] Verified IP ${ip} — ${count}/${RECHECK_404S} new errors (HTTP ${status})`);

  if (count >= RECHECK_404S) {
    await Promise.all([
      kvPut(env, `challenge:${ip}`, "1", { expirationTtl: CHALLENGE_TTL }),
      kvDelete(env, `verified:${ip}`),
      kvDelete(env, key),
    ]);
    console.warn(`[RE-CHALLENGED] Verified IP ${ip} re-challenged after ${RECHECK_404S} errors`);
    return;
  }

  ctx.waitUntil(kvPut(env, key, JSON.stringify({ count, windowStart }), { expirationTtl: 60 }));
}
