CREATE TABLE IF NOT EXISTS bot_bans (
    ip TEXT PRIMARY KEY,

    bad_count INTEGER NOT NULL DEFAULT 0,
    bad_window_start INTEGER NOT NULL DEFAULT 0,

    recheck_count INTEGER NOT NULL DEFAULT 0,
    recheck_window_start INTEGER NOT NULL DEFAULT 0,

    challenge_until INTEGER NOT NULL DEFAULT 0,
    verified_until INTEGER NOT NULL DEFAULT 0,

    updated_at INTEGER NOT NULL DEFAULT 0
);

CREATE INDEX IF NOT EXISTS idx_bot_bans_updated_at
    ON bot_bans(updated_at);
