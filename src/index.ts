// ── Configuration ─────────────────────────────────────────────────────────────

const MAX_404S        = 3;
const WINDOW_SECS     = 60;

const CHALLENGE_TTL   = 600;
const VERIFIED_TTL    = 600;

const RECHECK_404S    = 10;
const RECHECK_WINDOW  = 60;

const TURNSTILE_SITE_KEY   = "YOUR_TURNSTILE_SITE_KEY";
const TURNSTILE_SECRET_KEY = "YOUR_TURNSTILE_SECRET_KEY";

// ✅ Use a non-reserved path — /cdn-cgi/* is owned by Cloudflare
const VERIFY_PATH = "/check-human";

// ─────────────────────────────────────────────────────────────────────────────

const BAD_STATUSES = [403, 404, 499, 503];

interface BotBanState {
    ip: string;

    bad_count: number;
    bad_window_start: number;

    recheck_count: number;
    recheck_window_start: number;

    challenge_until: number;
    verified_until: number;

    updated_at: number;
}

interface CounterResult {
    count: number;
    challengeUntil: number;
}

function now() {
    return Math.floor(Date.now() / 1000);
}


// ── Worker ───────────────────────────────────────────────────────────────────

export default {
    async fetch(request, env, ctx) {

        const ip  = request.headers.get("CF-Connecting-IP") || "unknown";
        const url = new URL(request.url);

        // ── Handle Turnstile callback POST ────────────────────────────────────
        if (request.method === "POST" && url.pathname === VERIFY_PATH) {
            return handleTurnstileVerify(request, env, ip);
        }


        const currentTime = now();


        // ── 1. Check current state in D1 ──────────────────────────────────────

        const state = await getBotState(env, ip);


        // ── 2. Already verified? ──────────────────────────────────────────────

        if (state && state.verified_until > currentTime) {

            console.log(
                `[VERIFIED] IP ${ip} — passing through`
            );

            const response = await fetch(request);
            const status   = response.status;

            if (BAD_STATUSES.includes(status)) {

                await incrementRecheckCounter(
                    env,
                    ip,
                    status
                );
            }

            return response;
        }


        // ── 3. Currently challenged? ─────────────────────────────────────────

        if (state && state.challenge_until > currentTime) {

            console.warn(
                `[CHALLENGED] IP ${ip} — serving Turnstile challenge — ${url.pathname}`
            );

            return serveChallengeHTML(
                TURNSTILE_SITE_KEY,
                url.pathname
            );
        }


        // ── 4. Normal path — forward to origin ────────────────────────────────

        const response = await fetch(request);
        const status   = response.status;

        console.log(
            `[ORIGIN] ${url.pathname} → ${status} — IP: ${ip}`
        );


        if (!BAD_STATUSES.includes(status)) {
            return response;
        }


        // ── 5. Bad status — update D1 counter ────────────────────────────────

        const result = await incrementBadCounter(
            env,
            ip
        );

        console.log(
            `[COUNTER] IP ${ip} — ${result.count}/${MAX_404S} errors (HTTP ${status}) — ${url.pathname}`
        );


        // ── 6. Threshold reached — challenge ─────────────────────────────────

        if (result.challengeUntil > currentTime) {

            console.warn(
                `[CHALLENGE-SET] IP ${ip} — flag written after ${result.count}x HTTP ${status}`
            );

            return response;
        }


        return response;
    },
};


// ── Get current IP state ─────────────────────────────────────────────────────

async function getBotState(
    env: Env,
    ip: string
): Promise<BotBanState | null> {

    const state = await env.DB
        .prepare(`
            SELECT
                ip,
                bad_count,
                bad_window_start,
                recheck_count,
                recheck_window_start,
                challenge_until,
                verified_until,
                updated_at
            FROM bot_bans
            WHERE ip = ?
        `)
        .bind(ip)
        .first<BotBanState>();

    return state || null;
}


// ── Increment bad response counter ───────────────────────────────────────────
//
// This is an atomic D1 UPSERT.
//
// This is preferable to:
//   SELECT → increment in JavaScript → UPDATE
//
// because simultaneous requests from the same IP cannot simply overwrite
// each other's counter.

async function incrementBadCounter(
    env: Env,
    ip: string
): Promise<CounterResult> {

    const currentTime = now();

    const incrementStatement = env.DB
        .prepare(`
            INSERT INTO bot_bans (
                ip,
                bad_count,
                bad_window_start,
                updated_at
            )
            VALUES (?, 1, ?, ?)

            ON CONFLICT(ip) DO UPDATE SET

                bad_count =
                    CASE
                        WHEN
                            bot_bans.bad_window_start >=
                            excluded.bad_window_start - ?
                        THEN
                            bot_bans.bad_count + 1
                        ELSE
                            1
                    END,

                bad_window_start =
                    CASE
                        WHEN
                            bot_bans.bad_window_start >=
                            excluded.bad_window_start - ?
                        THEN
                            bot_bans.bad_window_start
                        ELSE
                            excluded.bad_window_start
                    END,

                challenge_until =
                    CASE
                        WHEN
                            (
                                CASE
                                    WHEN
                                        bot_bans.bad_window_start >=
                                        excluded.bad_window_start - ?
                                    THEN
                                        bot_bans.bad_count + 1
                                    ELSE
                                        1
                                END
                            ) >= ?
                        THEN
                            excluded.updated_at + ?
                        ELSE
                            bot_bans.challenge_until
                    END,

                recheck_count = 0,
                recheck_window_start = 0,

                updated_at = excluded.updated_at
        `)
        .bind(
            ip,
            currentTime,
            currentTime,

            WINDOW_SECS,
            WINDOW_SECS,
            WINDOW_SECS,

            MAX_404S,
            CHALLENGE_TTL
        );


    const selectStatement = env.DB
        .prepare(`
            SELECT
                bad_count,
                challenge_until
            FROM bot_bans
            WHERE ip = ?
        `)
        .bind(ip);


    const results = await env.DB.batch([
        incrementStatement,
        selectStatement,
    ]);


    const row = results[1].results?.[0] as
        | {
            bad_count: number;
            challenge_until: number;
        }
        | undefined;


    if (!row) {
        throw new Error(
            `Unable to retrieve updated D1 state for IP ${ip}`
        );
    }


    return {
        count: Number(row.bad_count),
        challengeUntil: Number(row.challenge_until),
    };
}


// ── Serve Turnstile challenge page ───────────────────────────────────────────

function serveChallengeHTML(
    siteKey: string,
    returnPath: string
) {

    const safeReturn = returnPath
        .replace(/"/g, "&quot;");

    const html = `<!DOCTYPE html>
<html lang="en">
<head>

    <meta charset="UTF-8">

    <meta
        name="viewport"
        content="width=device-width, initial-scale=1"
    >

    <title>Security check</title>

    <script
        src="https://challenges.cloudflare.com/turnstile/v0/api.js"
        async
        defer
    ></script>

    <style>

        *, *::before, *::after {
            box-sizing: border-box;
            margin: 0;
            padding: 0;
        }

        body {
            font-family:
                -apple-system,
                BlinkMacSystemFont,
                "Segoe UI",
                sans-serif;

            background: #f6f6f6;

            display: flex;
            align-items: center;
            justify-content: center;

            min-height: 100vh;

            padding: 1rem;
        }

        .card {
            background: #fff;

            border-radius: 12px;

            box-shadow:
                0 2px 16px rgba(0, 0, 0, 0.08);

            padding: 2.5rem 2rem;

            text-align: center;

            max-width: 400px;
            width: 100%;
        }

        h1 {
            font-size: 1.25rem;
            font-weight: 600;

            color: #1a1a1a;

            margin-bottom: 0.5rem;
        }

        p {
            font-size: 0.9rem;

            color: #666;

            margin-bottom: 1.5rem;

            line-height: 1.5;
        }

        .widget-wrap {
            display: flex;
            justify-content: center;

            margin-bottom: 1rem;
        }

        .ray {
            font-size: 0.75rem;

            color: #bbb;

            margin-top: 1.5rem;
        }

    </style>

</head>

<body>

    <div class="card">

        <h1>Security check</h1>

        <p>
            We noticed unusual activity from your IP address.
            Please verify you are human to continue.
        </p>

        <form
            method="POST"
            action="${VERIFY_PATH}"
        >

            <input
                type="hidden"
                name="return_path"
                value="${safeReturn}"
            >

            <div class="widget-wrap">

                <div
                    class="cf-turnstile"
                    data-sitekey="${siteKey}"
                    data-callback="onSuccess"
                    data-theme="light"
                ></div>

            </div>

            <script>
                function onSuccess(token) {
                    document.querySelector("form").submit();
                }
            </script>

        </form>

        <p class="ray">
            Ray ID:
            ${crypto.randomUUID().split("-")[0].toUpperCase()}
        </p>

    </div>

</body>
</html>`;

    return new Response(html, {
        status: 403,

        headers: {
            "Content-Type":
                "text/html; charset=UTF-8",
        },
    });
}


// ── Handle Turnstile verification ───────────────────────────────────────────

async function handleTurnstileVerify(
    request: Request,
    env: Env,
    ip: string
) {

    let returnPath = "/";

    try {

        const body = await request.formData();

        const token =
            body.get("cf-turnstile-response");

        returnPath =
            String(
                body.get("return_path") || "/"
            );


        console.log(
            `[TURNSTILE-POST] IP ${ip} — token present: ${!!token} — returning to: ${returnPath}`
        );


        if (!token) {

            return serveChallengeHTML(
                TURNSTILE_SITE_KEY,
                returnPath
            );
        }


        const verifyResp = await fetch(
            "https://challenges.cloudflare.com/turnstile/v0/siteverify",
            {
                method: "POST",

                headers: {
                    "Content-Type":
                        "application/json",
                },

                body: JSON.stringify({
                    secret:
                        TURNSTILE_SECRET_KEY,

                    response: token,

                    remoteip: ip,
                }),
            }
        );


        const result =
            await verifyResp.json();


        console.log(
            `[TURNSTILE] IP ${ip} — success: ${result.success} — errors: ${JSON.stringify(result["error-codes"])}`
        );


        if (!result.success) {

            return serveChallengeHTML(
                TURNSTILE_SITE_KEY,
                returnPath
            );
        }


        // ── Mark IP as verified in D1 ─────────────────────────────────────────

        const currentTime = now();

        await env.DB
            .prepare(`
                INSERT INTO bot_bans (
                    ip,
                    bad_count,
                    bad_window_start,
                    recheck_count,
                    recheck_window_start,
                    challenge_until,
                    verified_until,
                    updated_at
                )
                VALUES (
                    ?,
                    0,
                    0,
                    0,
                    0,
                    0,
                    ?,
                    ?
                )

                ON CONFLICT(ip) DO UPDATE SET

                    bad_count = 0,
                    bad_window_start = 0,

                    recheck_count = 0,
                    recheck_window_start = 0,

                    challenge_until = 0,

                    verified_until = excluded.verified_until,

                    updated_at = excluded.updated_at
            `)
            .bind(
                ip,
                currentTime + VERIFIED_TTL,
                currentTime
            )
            .run();


        console.log(
            `[VERIFIED] IP ${ip} — challenge cleared, redirecting to ${returnPath}`
        );


        const origin =
            new URL(request.url).origin;


        return Response.redirect(
            `${origin}${returnPath}`,
            302
        );

    } catch (err) {

        const message =
            err instanceof Error
                ? err.message
                : String(err);

        console.error(
            `[ERROR] Turnstile verify failed for IP ${ip}: ${message}`
        );


        return serveChallengeHTML(
            TURNSTILE_SITE_KEY,
            returnPath
        );
    }
}


// ── Increment recheck counter for verified IPs ───────────────────────────────

async function incrementRecheckCounter(
    env: Env,
    ip: string,
    status: number
) {

    const currentTime = now();


    const incrementStatement = env.DB
        .prepare(`
            INSERT INTO bot_bans (
                ip,
                recheck_count,
                recheck_window_start,
                updated_at
            )
            VALUES (?, 1, ?, ?)

            ON CONFLICT(ip) DO UPDATE SET

                recheck_count =
                    CASE
                        WHEN
                            bot_bans.recheck_window_start >=
                            excluded.recheck_window_start - ?
                        THEN
                            bot_bans.recheck_count + 1
                        ELSE
                            1
                    END,

                recheck_window_start =
                    CASE
                        WHEN
                            bot_bans.recheck_window_start >=
                            excluded.recheck_window_start - ?
                        THEN
                            bot_bans.recheck_window_start
                        ELSE
                            excluded.recheck_window_start
                    END,

                challenge_until =
                    CASE
                        WHEN
                            (
                                CASE
                                    WHEN
                                        bot_bans.recheck_window_start >=
                                        excluded.recheck_window_start - ?
                                    THEN
                                        bot_bans.recheck_count + 1
                                    ELSE
                                        1
                                END
                            ) >= ?
                        THEN
                            excluded.updated_at + ?
                        ELSE
                            bot_bans.challenge_until
                    END,

                verified_until =
                    CASE
                        WHEN
                            (
                                CASE
                                    WHEN
                                        bot_bans.recheck_window_start >=
                                        excluded.recheck_window_start - ?
                                    THEN
                                        bot_bans.recheck_count + 1
                                    ELSE
                                        1
                                END
                            ) >= ?
                        THEN
                            0
                        ELSE
                            bot_bans.verified_until
                    END,

                updated_at = excluded.updated_at
        `)
        .bind(
            ip,
            currentTime,
            currentTime,

            RECHECK_WINDOW,
            RECHECK_WINDOW,
            RECHECK_WINDOW,
            RECHECK_404S,
            CHALLENGE_TTL,

            RECHECK_WINDOW,
            RECHECK_404S
        );


    const selectStatement = env.DB
        .prepare(`
            SELECT
                recheck_count,
                challenge_until
            FROM bot_bans
            WHERE ip = ?
        `)
        .bind(ip);


    const results = await env.DB.batch([
        incrementStatement,
        selectStatement,
    ]);


    const row = results[1].results?.[0] as
        | {
            recheck_count: number;
            challenge_until: number;
        }
        | undefined;


    if (!row) {
        throw new Error(
            `Unable to retrieve updated D1 state for IP ${ip}`
        );
    }


    const count =
        Number(row.recheck_count);


    console.log(
        `[RECHECK] Verified IP ${ip} — ${count}/${RECHECK_404S} new errors (HTTP ${status})`
    );


    if (
        Number(row.challenge_until) >
        currentTime
    ) {

        console.warn(
            `[RE-CHALLENGED] Verified IP ${ip} re-challenged after ${RECHECK_404S} errors`
        );
    }
}
