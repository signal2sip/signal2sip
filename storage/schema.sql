-- signal2sip account/session storage schema.
--
-- Mirrors the field set of the Node prototype's per-account JSON files
-- (layer1/accountStore.js's saveAccount()/loadAccount(), confirmed against
-- the two real accounts already registered/linked this project:
-- +380000000001 standalone-registered, +380000000002 linked-as-device) and
-- protocolStores.js's sessions/identities file, byte-for-byte compatible in
-- meaning so existing accounts can be migrated in with a one-time import
-- script rather than re-registering.
--
-- One physical database file is now shared by every account the daemon
-- manages (see project decision: single-process multi-account, and the
-- shared-DB follow-up) - every table is namespaced by `account_name`
-- (the same free-form label used as the `[account.<name>]` config
-- section suffix) so two accounts' sessions/keys/identities never
-- collide even if they happen to reference the same remote serviceId.

PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS account (
    account_name            TEXT PRIMARY KEY,
    e164                    TEXT NOT NULL,
    aci                     TEXT NOT NULL,
    pni                     TEXT NOT NULL,
    device_id               INTEGER NOT NULL,
    password                TEXT NOT NULL,
    registration_id          INTEGER NOT NULL,
    pni_registration_id      INTEGER NOT NULL,
    flow                    TEXT,            -- 'standalone' | 'linked' | NULL
    account_entropy_pool     TEXT,            -- linked accounts only
    media_root_backup_key    BLOB,            -- linked accounts only
    profile_key             BLOB,
    registered_at            INTEGER,         -- unix seconds, standalone registration
    linked_at               INTEGER,         -- unix seconds, device-linking
    prekeys_refreshed_at     INTEGER,

    -- 2026-08-07: SIP/deployment config, moved here from signal2sip.conf's
    -- old [account.<name>] sections so it's editable live via
    -- `signal2sip-gendb <name> config set/get` (and eventually a TUI)
    -- instead of SSH+text-editing+restart. [global] (db_path/db_key and a
    -- few process-wide tuning knobs) is the only thing still read from the
    -- file - see Config.h. Field names/defaults mirror AccountConfig
    -- (Config.h) exactly; see that struct's own per-field doc comments for
    -- what each one means. `saveAccount()` (Storage.cpp) deliberately never
    -- touches these columns - only `saveAccountConfig()` does, so the
    -- daemon's own routine identity-bookkeeping writes (e.g.
    -- prekeys_refreshed_at) can never race with a concurrent
    -- `gendb config set` and clobber config_version.
    server_url               TEXT NOT NULL DEFAULT '',
    sip_host                 TEXT NOT NULL DEFAULT '',
    sip_extension             TEXT NOT NULL DEFAULT '',
    sip_password              TEXT NOT NULL DEFAULT '',
    sip_bridge_destination     TEXT NOT NULL DEFAULT '',
    sip_bridge_did            TEXT NOT NULL DEFAULT '',
    sip_srtp                 TEXT NOT NULL DEFAULT 'disabled', -- 'disabled' | 'optional' | 'mandatory'
    sip_transport             TEXT NOT NULL DEFAULT 'udp',      -- 'udp' | 'tls'
    sip_tls_ca_file            TEXT NOT NULL DEFAULT '',
    sip_tls_insecure          INTEGER NOT NULL DEFAULT 0,
    outgoing_call_target       TEXT NOT NULL DEFAULT '',
    -- "" (default) = no proxy, else "host" or "host:port" (default 443) -
    -- a transparent TCP/TLS relay to chat.signal.org, matching real
    -- Signal clients' manual "Proxy" setting (see AuthSocket.h's own doc
    -- comment / project memory: signal2sip-censorship-circumvention).
    signal_proxy              TEXT NOT NULL DEFAULT '',
    -- Matches real clients' separate "Censorship circumvention" toggle
    -- (automatic SNI domain fronting via Signal's own infrastructure) -
    -- independent of signal_proxy above.
    signal_censorship_circumvention INTEGER NOT NULL DEFAULT 0,
    -- Whether the daemon should set this account up at all - the DB-side
    -- replacement for "does a [account.<name>] section exist in the file".
    -- Flipped via `signal2sip-gendb <name> enable`/`disable`.
    enabled                  INTEGER NOT NULL DEFAULT 1,
    -- Bumped by saveAccountConfig() on every write (SQL-side
    -- `config_version = config_version + 1`, never trusted from the
    -- caller - avoids a read-then-write race). The running daemon
    -- remembers which version it last set an account up with (see
    -- AccountConfig::configVersion, Config.h) and rebuilds that one
    -- account (teardown+setup) when a poll/SIGHUP sees a mismatch - see
    -- main.cpp's reloadConfig().
    config_version            INTEGER NOT NULL DEFAULT 0,

    -- 2026-08-15: observed connection status, NOT admin-set config (unlike
    -- every other column above/below this comment) - the daemon writes
    -- these, never `gendb config set`. Set the moment AuthSocket reports
    -- isDeauthorized() (device unlinked/deleted elsewhere, or a future
    -- Registration Lock takeover attempt - see the website's Signal PIN
    -- doc page), cleared back to '' the moment a reconnect succeeds.
    -- Read via `signal2sip-gendb <name> status` or the TUI's account list.
    -- An empty value here does NOT by itself mean "currently connected" -
    -- it only means no *known, unrecoverable-without-admin-action*
    -- problem is outstanding (the daemon might simply not be running, or
    -- a plain drop might still be mid-retry).
    last_error                TEXT NOT NULL DEFAULT '',
    last_error_at              INTEGER NOT NULL DEFAULT 0
);

-- Identity keypairs: one row per (account_name, identity in {'aci','pni'}).
-- Private key never leaves this table/this process, matching the Node
-- prototype's aciIdentityKeyPair/pniIdentityKeyPair fields.
CREATE TABLE IF NOT EXISTS identity_keypair (
    account_name    TEXT NOT NULL REFERENCES account(account_name),
    identity        TEXT NOT NULL CHECK (identity IN ('aci', 'pni')),
    private_key     BLOB NOT NULL,
    public_key      BLOB NOT NULL,
    PRIMARY KEY (account_name, identity)
);

-- Current signed prekey per (account_name, identity). Only the most
-- recent one is ever needed (matches AccountSignedPreKeyStore's
-- single-record behavior in the Node prototype) - refreshing overwrites
-- the row rather than appending.
CREATE TABLE IF NOT EXISTS signed_prekey (
    account_name    TEXT NOT NULL REFERENCES account(account_name),
    identity        TEXT NOT NULL CHECK (identity IN ('aci', 'pni')),
    key_id          INTEGER NOT NULL,
    record          BLOB NOT NULL,          -- serialized SignedPreKeyRecord
    PRIMARY KEY (account_name, identity)
);

-- Last-resort Kyber (post-quantum) prekey per (account_name, identity) -
-- reusable by design, never marked "used" (matches AccountKyberPreKeyStore).
CREATE TABLE IF NOT EXISTS kyber_prekey (
    account_name    TEXT NOT NULL REFERENCES account(account_name),
    identity        TEXT NOT NULL CHECK (identity IN ('aci', 'pni')),
    key_id          INTEGER NOT NULL,
    record          BLOB NOT NULL,          -- serialized KyberPreKeyRecord
    PRIMARY KEY (account_name, identity)
);

-- Established sessions, keyed by (account_name, remote ProtocolAddress)
-- ("<serviceId>.<deviceId>", matching FileSessionStore's address.toString()
-- keys) so knownDeviceIdsFor()'s "scan the session-key namespace" query
-- becomes a simple LIKE prefix match (scoped to one account_name) instead
-- of a JSON key scan.
CREATE TABLE IF NOT EXISTS session (
    account_name    TEXT NOT NULL REFERENCES account(account_name),
    address         TEXT NOT NULL,          -- e.g. "<serviceId>.<deviceId>"
    record          BLOB NOT NULL,          -- serialized SessionRecord
    PRIMARY KEY (account_name, address)
);

-- Trusted remote identity keys (trust-on-first-use, matching
-- AccountIdentityStore.isTrustedIdentity's semantics exactly: absent means
-- "not yet seen, trust and record"; present means "must match exactly").
-- Namespaced per account_name too - two of our own accounts talking to the
-- same remote serviceId each keep their own trust-on-first-use record.
CREATE TABLE IF NOT EXISTS remote_identity (
    account_name    TEXT NOT NULL REFERENCES account(account_name),
    address         TEXT NOT NULL,          -- serviceId (not deviceId-qualified)
    public_key      BLOB NOT NULL,
    PRIMARY KEY (account_name, address)
);

-- Cached e164 -> ACI/PNI resolution results from real Contact Discovery
-- Service (CDSI) lookups - see native/signal/Cdsi.h. Avoids re-hitting
-- Signal's real, rate-limited CDS endpoint for the same outgoing_call_target
-- on every daemon (re)start. aci/pni are '' (not NULL) for a *resolved*
-- negative result (looked up, genuinely not on Signal) - distinct from no
-- row at all (never looked up yet). Kept per-account, like every other
-- table here, even though the real-world answer doesn't actually depend on
-- which of our accounts asked - simpler than a cross-account-shared table,
-- and CDS lookups are already rate-limited per-account regardless.
-- resolved_at has no automatic expiry (yet) - a stale row (e.g. the target
-- reassigned their old number) just means a wrong cached serviceId, not a
-- protocol-breaking one; revisit only if that turns out to matter live.
CREATE TABLE IF NOT EXISTS resolved_contact (
    account_name    TEXT NOT NULL REFERENCES account(account_name),
    e164            TEXT NOT NULL,
    aci             TEXT NOT NULL,          -- '' if not found on Signal at all
    pni             TEXT NOT NULL,          -- '' if aci is also ''
    resolved_at     INTEGER NOT NULL,       -- unix seconds
    PRIMARY KEY (account_name, e164)
);

-- Real contacts learned from this account's own StorageService sync (see
-- native/daemon/StorageServiceSync.h/.cpp) - unlike resolved_contact
-- (a CDS lookup, PNI-only for any e164 CDS treats as "cold"), this comes
-- straight from the account's real contact list, so aci is populated for
-- any genuinely mutual real contact regardless of CDS/PNP status. Only
-- meaningful for an account with a real account_entropy_pool (i.e. a
-- gendb-linked account, not a bare gendb-registered one with no real
-- contacts to sync in the first place).
--
-- Surrogate `id` PK, not (account_name, e164) as originally shipped - see
-- Storage.cpp's migrateSyncedContactPrimaryKeyIfNeeded() for the live-DB
-- migration this required. A real contact can have an aci with no e164 at
-- all (added via QR/username, no phone number ever shared), which the
-- original e164-keyed PK couldn't represent without every such contact
-- colliding on the same empty-string key. e164 and aci are each unique
-- per account only when non-empty (the two partial indexes below) - a
-- synced record can legitimately have either empty, just never both.
CREATE TABLE IF NOT EXISTS synced_contact (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    account_name    TEXT NOT NULL REFERENCES account(account_name),
    e164            TEXT NOT NULL,          -- '' if this contact has no phone number
    aci             TEXT NOT NULL,          -- '' if this contact record has none
    pni             TEXT NOT NULL,
    profile_key     BLOB NOT NULL,          -- empty if none
    given_name      TEXT NOT NULL DEFAULT '', -- ContactRecord.givenName, '' if unset
    family_name     TEXT NOT NULL DEFAULT '', -- ContactRecord.familyName, '' if unset
    synced_at       INTEGER NOT NULL        -- unix seconds
);
CREATE UNIQUE INDEX IF NOT EXISTS idx_synced_contact_e164
    ON synced_contact(account_name, e164) WHERE e164 != '';
CREATE UNIQUE INDEX IF NOT EXISTS idx_synced_contact_aci
    ON synced_contact(account_name, aci) WHERE aci != '';
