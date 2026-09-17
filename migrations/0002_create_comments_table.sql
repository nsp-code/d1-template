-- schema.sql
-- Replaces the BOT_BANS KV namespace with a single D1 table.
-- D1 has no built-in per-key TTL like KV, so expiry is tracked as a
-- plain unix-timestamp column and enforced in application code
-- (see kvGet() in index.js), with lazy cleanup on read.

CREATE TABLE IF NOT EXISTS bot_state (
  key        TEXT PRIMARY KEY,
  value      TEXT NOT NULL,
  expires_at INTEGER
);

-- Speeds up the optional periodic purge of expired rows.
CREATE INDEX IF NOT EXISTS idx_bot_state_expires_at ON bot_state (expires_at);
