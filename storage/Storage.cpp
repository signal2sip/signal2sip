#include "Storage.h"

#include <sqlcipher/sqlite3.h>

#include <ctime>
#include <stdexcept>

#include "generated/schema_sql.h"

namespace signal2sip {

namespace {

// RAII wrapper around sqlite3_stmt so every early-return/throw below still
// finalizes the statement.
class Stmt {
public:
    Stmt(sqlite3* db, const char* sql) {
        if (sqlite3_prepare_v2(db, sql, -1, &stmt_, nullptr) != SQLITE_OK) {
            throw std::runtime_error(std::string("sqlite3_prepare_v2 failed: ") + sqlite3_errmsg(db));
        }
    }
    ~Stmt() { sqlite3_finalize(stmt_); }
    Stmt(const Stmt&) = delete;
    Stmt& operator=(const Stmt&) = delete;

    operator sqlite3_stmt*() const { return stmt_; }

private:
    sqlite3_stmt* stmt_ = nullptr;
};

void bindText(sqlite3_stmt* stmt, int index, const std::string& value) {
    sqlite3_bind_text(stmt, index, value.data(), static_cast<int>(value.size()), SQLITE_TRANSIENT);
}

void bindTextOpt(sqlite3_stmt* stmt, int index, const std::optional<std::string>& value) {
    if (value) bindText(stmt, index, *value);
    else sqlite3_bind_null(stmt, index);
}

void bindBlob(sqlite3_stmt* stmt, int index, const Bytes& value) {
    // An empty vector's .data() is commonly nullptr, and sqlite3_bind_blob
    // treats a NULL pointer as binding SQL NULL regardless of the length
    // argument - found live via a real NOT NULL constraint violation on
    // synced_contact.profile_key for a real contact with no cached profile
    // key. sqlite3_bind_zeroblob always produces an actual zero-length
    // blob (X''), immune to this pointer-nullness gotcha.
    if (value.empty()) {
        sqlite3_bind_zeroblob(stmt, index, 0);
        return;
    }
    sqlite3_bind_blob(stmt, index, value.data(), static_cast<int>(value.size()), SQLITE_TRANSIENT);
}

void bindBlobOpt(sqlite3_stmt* stmt, int index, const std::optional<Bytes>& value) {
    if (value) bindBlob(stmt, index, *value);
    else sqlite3_bind_null(stmt, index);
}

void bindInt64Opt(sqlite3_stmt* stmt, int index, const std::optional<int64_t>& value) {
    if (value) sqlite3_bind_int64(stmt, index, *value);
    else sqlite3_bind_null(stmt, index);
}

std::string columnText(sqlite3_stmt* stmt, int index) {
    const unsigned char* text = sqlite3_column_text(stmt, index);
    int len = sqlite3_column_bytes(stmt, index);
    return text ? std::string(reinterpret_cast<const char*>(text), len) : std::string();
}

std::optional<std::string> columnTextOpt(sqlite3_stmt* stmt, int index) {
    if (sqlite3_column_type(stmt, index) == SQLITE_NULL) return std::nullopt;
    return columnText(stmt, index);
}

Bytes columnBlob(sqlite3_stmt* stmt, int index) {
    const void* blob = sqlite3_column_blob(stmt, index);
    int len = sqlite3_column_bytes(stmt, index);
    const auto* bytes = static_cast<const uint8_t*>(blob);
    return blob ? Bytes(bytes, bytes + len) : Bytes();
}

std::optional<Bytes> columnBlobOpt(sqlite3_stmt* stmt, int index) {
    if (sqlite3_column_type(stmt, index) == SQLITE_NULL) return std::nullopt;
    return columnBlob(stmt, index);
}

std::optional<int64_t> columnInt64Opt(sqlite3_stmt* stmt, int index) {
    if (sqlite3_column_type(stmt, index) == SQLITE_NULL) return std::nullopt;
    return sqlite3_column_int64(stmt, index);
}

bool tableExists(sqlite3* db, const char* name) {
    Stmt stmt(db, "SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = ?");
    bindText(stmt, 1, name);
    return sqlite3_step(stmt) == SQLITE_ROW;
}

// 2026-08-07 caller-ID passthrough work replaced synced_contact's original
// PRIMARY KEY (account_name, e164) with a surrogate `id` (see schema.sql's
// own comment on that table for why - an e164-only PK structurally can't
// hold an ACI-only contact). Detects a database still on the old shape
// (table exists but has no `id` column) and renames it aside so the fresh
// CREATE TABLE IF NOT EXISTS in schema.sql creates the new shape; the
// caller copies the old rows across afterward (see the constructor). No-op
// on a brand-new database (table doesn't exist yet - kSchemaSql creates it
// directly in the new shape) or one already migrated.
void renameOldSyncedContactTableIfNeeded(sqlite3* db) {
    if (!tableExists(db, "synced_contact")) return;
    Stmt hasId(db, "SELECT 1 FROM pragma_table_info('synced_contact') WHERE name = 'id'");
    if (sqlite3_step(hasId) == SQLITE_ROW) return; // already migrated

    char* errmsg = nullptr;
    if (sqlite3_exec(db, "ALTER TABLE synced_contact RENAME TO synced_contact_old_pk_migration", nullptr, nullptr,
                      &errmsg) != SQLITE_OK) {
        std::string err = errmsg ? errmsg : "unknown error";
        sqlite3_free(errmsg);
        throw std::runtime_error("failed to rename old synced_contact table for migration: " + err);
    }
}

// Second half of the migration above - runs after kSchemaSql has created
// the new-shape synced_contact, copying every row across. given_name/
// family_name start empty for pre-existing rows (StorageServiceSync
// backfills them on this account's next periodic sync).
void copyOldSyncedContactDataIfPresent(sqlite3* db) {
    if (!tableExists(db, "synced_contact_old_pk_migration")) return;
    char* errmsg = nullptr;
    const char* sql =
        "INSERT INTO synced_contact (account_name, e164, aci, pni, profile_key, given_name, family_name, synced_at) "
        "SELECT account_name, e164, aci, pni, profile_key, '', '', synced_at FROM synced_contact_old_pk_migration;"
        "DROP TABLE synced_contact_old_pk_migration;";
    if (sqlite3_exec(db, sql, nullptr, nullptr, &errmsg) != SQLITE_OK) {
        std::string err = errmsg ? errmsg : "unknown error";
        sqlite3_free(errmsg);
        throw std::runtime_error("failed to migrate synced_contact data to new schema: " + err);
    }
}

// Generic additive-column migration: SQLite has no `ALTER TABLE ... ADD
// COLUMN IF NOT EXISTS` (confirmed live 2026-08-07 - it's a syntax error,
// unlike `DROP COLUMN IF EXISTS` which SQLite does support), so a plain
// unconditional ALTER TABLE in schema.sql would fail on every startup
// after the first once the column exists. Checked once per call via
// pragma_table_info before altering - safe to call unconditionally from
// the constructor on every startup, no-op once the column is there.
void addColumnIfMissing(sqlite3* db, const char* table, const char* column, const char* columnDefSql) {
    std::string checkSql = std::string("SELECT 1 FROM pragma_table_info('") + table + "') WHERE name = ?";
    Stmt check(db, checkSql.c_str());
    bindText(check, 1, column);
    if (sqlite3_step(check) == SQLITE_ROW) return; // already exists

    std::string alterSql = std::string("ALTER TABLE ") + table + " ADD COLUMN " + column + " " + columnDefSql;
    char* errmsg = nullptr;
    if (sqlite3_exec(db, alterSql.c_str(), nullptr, nullptr, &errmsg) != SQLITE_OK) {
        std::string err = errmsg ? errmsg : "unknown error";
        sqlite3_free(errmsg);
        throw std::runtime_error("failed to add column " + std::string(column) + " to " + table + ": " + err);
    }
}

// Live-migrates a database created before 2026-08-07's config-in-DB work:
// adds every new `account` column from schema.sql's own comment on that
// table (SIP/deployment config + enabled/config_version), each defaulting
// exactly as schema.sql specifies so a pre-existing row reads back as "no
// SIP config yet, enabled" - matching a fresh account row on a brand-new
// database (which gets these columns directly from CREATE TABLE instead).
void migrateAccountConfigColumnsIfNeeded(sqlite3* db) {
    addColumnIfMissing(db, "account", "server_url", "TEXT NOT NULL DEFAULT ''");
    addColumnIfMissing(db, "account", "sip_host", "TEXT NOT NULL DEFAULT ''");
    addColumnIfMissing(db, "account", "sip_extension", "TEXT NOT NULL DEFAULT ''");
    addColumnIfMissing(db, "account", "sip_password", "TEXT NOT NULL DEFAULT ''");
    addColumnIfMissing(db, "account", "sip_bridge_destination", "TEXT NOT NULL DEFAULT ''");
    addColumnIfMissing(db, "account", "sip_bridge_did", "TEXT NOT NULL DEFAULT ''");
    addColumnIfMissing(db, "account", "sip_srtp", "TEXT NOT NULL DEFAULT 'disabled'");
    addColumnIfMissing(db, "account", "sip_transport", "TEXT NOT NULL DEFAULT 'udp'");
    addColumnIfMissing(db, "account", "sip_tls_ca_file", "TEXT NOT NULL DEFAULT ''");
    addColumnIfMissing(db, "account", "sip_tls_insecure", "INTEGER NOT NULL DEFAULT 0");
    addColumnIfMissing(db, "account", "outgoing_call_target", "TEXT NOT NULL DEFAULT ''");
    addColumnIfMissing(db, "account", "signal_proxy", "TEXT NOT NULL DEFAULT ''");
    addColumnIfMissing(db, "account", "signal_censorship_circumvention", "INTEGER NOT NULL DEFAULT 0");
    addColumnIfMissing(db, "account", "enabled", "INTEGER NOT NULL DEFAULT 1");
    addColumnIfMissing(db, "account", "config_version", "INTEGER NOT NULL DEFAULT 0");
    // 2026-08-15: not config, but additive/nullable the same way - see
    // schema.sql's own comment on these two columns.
    addColumnIfMissing(db, "account", "last_error", "TEXT NOT NULL DEFAULT ''");
    addColumnIfMissing(db, "account", "last_error_at", "INTEGER NOT NULL DEFAULT 0");
}

} // namespace

Storage::Storage(const std::string& path, const std::string& key, const std::string& accountName)
    : accountName_(accountName) {
    if (sqlite3_open(path.c_str(), &db_) != SQLITE_OK) {
        std::string err = sqlite3_errmsg(db_);
        sqlite3_close(db_);
        db_ = nullptr;
        throw std::runtime_error("sqlite3_open failed: " + err);
    }

    // PRAGMA key must be the very first statement executed on this
    // connection (SQLCipher applies it lazily on first real access, but
    // ordering it first avoids ever touching an unencrypted temp state).
    // PRAGMA statements don't support bound parameters, so the key is
    // safely quoted as an SQL string literal via sqlite3_mprintf's %Q
    // instead (handles embedded quotes correctly).
    {
        char* sql = sqlite3_mprintf("PRAGMA key = %Q", key.c_str());
        char* errmsg = nullptr;
        int rc = sqlite3_exec(db_, sql, nullptr, nullptr, &errmsg);
        sqlite3_free(sql);
        if (rc != SQLITE_OK) {
            std::string err = errmsg ? errmsg : "unknown error";
            sqlite3_free(errmsg);
            sqlite3_close(db_);
            db_ = nullptr;
            throw std::runtime_error("PRAGMA key failed: " + err);
        }
    }

    // Cheapest way to confirm the key is actually correct: SQLCipher only
    // fails to decrypt on first real table access, not on PRAGMA key itself.
    char* errmsg = nullptr;
    if (sqlite3_exec(db_, "SELECT count(*) FROM sqlite_master", nullptr, nullptr, &errmsg) != SQLITE_OK) {
        std::string err = errmsg ? errmsg : "unknown error";
        sqlite3_free(errmsg);
        sqlite3_close(db_);
        db_ = nullptr;
        throw std::runtime_error("failed to open database (wrong key or corrupt file): " + err);
    }

    // Multiple accounts now share one physical file, each with its own
    // connection (see class doc comment) - the default rollback-journal
    // mode requires a writer to hold an exclusive file lock while
    // committing, which makes a DIFFERENT connection's concurrent read
    // fail with SQLITE_BUSY instead of just waiting. Found live: one
    // account's get_local_registration_id()/load_signed_pre_key() calls
    // failing with "no signed prekey on file"/similar during a real call
    // to another account, purely from lock contention, not missing data.
    // WAL mode lets readers and a writer proceed concurrently without
    // blocking each other; busy_timeout is defense-in-depth for the
    // remaining case of two writers landing at the same instant (WAL
    // still allows only one writer at a time).
    if (sqlite3_exec(db_, "PRAGMA journal_mode = WAL", nullptr, nullptr, &errmsg) != SQLITE_OK) {
        std::string err = errmsg ? errmsg : "unknown error";
        sqlite3_free(errmsg);
        sqlite3_close(db_);
        db_ = nullptr;
        throw std::runtime_error("PRAGMA journal_mode=WAL failed: " + err);
    }
    sqlite3_busy_timeout(db_, 5000);

    try {
        renameOldSyncedContactTableIfNeeded(db_);
    } catch (const std::exception& e) {
        sqlite3_close(db_);
        db_ = nullptr;
        throw;
    }

    if (sqlite3_exec(db_, kSchemaSql, nullptr, nullptr, &errmsg) != SQLITE_OK) {
        std::string err = errmsg ? errmsg : "unknown error";
        sqlite3_free(errmsg);
        sqlite3_close(db_);
        db_ = nullptr;
        throw std::runtime_error("failed to apply schema: " + err);
    }

    try {
        copyOldSyncedContactDataIfPresent(db_);
        migrateAccountConfigColumnsIfNeeded(db_);
    } catch (const std::exception& e) {
        sqlite3_close(db_);
        db_ = nullptr;
        throw;
    }
}

Storage::~Storage() {
    if (db_) sqlite3_close(db_);
}

bool Storage::hasAccount() {
    Stmt stmt(db_, "SELECT count(*) FROM account WHERE account_name = ?");
    bindText(stmt, 1, accountName_);
    sqlite3_step(stmt);
    return sqlite3_column_int(stmt, 0) > 0;
}

AccountRecord Storage::loadAccount() {
    Stmt stmt(db_,
        "SELECT e164, aci, pni, device_id, password, registration_id, pni_registration_id, "
        "flow, account_entropy_pool, media_root_backup_key, profile_key, "
        "registered_at, linked_at, prekeys_refreshed_at, "
        "server_url, sip_host, sip_extension, sip_password, sip_bridge_destination, sip_bridge_did, "
        "sip_srtp, sip_transport, sip_tls_ca_file, sip_tls_insecure, outgoing_call_target, "
        "signal_proxy, signal_censorship_circumvention, "
        "enabled, config_version, last_error, last_error_at "
        "FROM account WHERE account_name = ?");
    bindText(stmt, 1, accountName_);
    if (sqlite3_step(stmt) != SQLITE_ROW) {
        throw std::runtime_error("loadAccount: no account row present");
    }
    AccountRecord account;
    account.e164 = columnText(stmt, 0);
    account.aci = columnText(stmt, 1);
    account.pni = columnText(stmt, 2);
    account.device_id = sqlite3_column_int(stmt, 3);
    account.password = columnText(stmt, 4);
    account.registration_id = sqlite3_column_int64(stmt, 5);
    account.pni_registration_id = sqlite3_column_int64(stmt, 6);
    account.flow = columnTextOpt(stmt, 7);
    account.account_entropy_pool = columnTextOpt(stmt, 8);
    account.media_root_backup_key = columnBlobOpt(stmt, 9);
    account.profile_key = columnBlobOpt(stmt, 10);
    account.registered_at = columnInt64Opt(stmt, 11);
    account.linked_at = columnInt64Opt(stmt, 12);
    account.prekeys_refreshed_at = columnInt64Opt(stmt, 13);
    account.server_url = columnText(stmt, 14);
    account.sip_host = columnText(stmt, 15);
    account.sip_extension = columnText(stmt, 16);
    account.sip_password = columnText(stmt, 17);
    account.sip_bridge_destination = columnText(stmt, 18);
    account.sip_bridge_did = columnText(stmt, 19);
    account.sip_srtp = columnText(stmt, 20);
    account.sip_transport = columnText(stmt, 21);
    account.sip_tls_ca_file = columnText(stmt, 22);
    account.sip_tls_insecure = sqlite3_column_int(stmt, 23) != 0;
    account.outgoing_call_target = columnText(stmt, 24);
    account.signal_proxy = columnText(stmt, 25);
    account.signal_censorship_circumvention = sqlite3_column_int(stmt, 26) != 0;
    account.enabled = sqlite3_column_int(stmt, 27) != 0;
    account.config_version = sqlite3_column_int64(stmt, 28);
    account.last_error = columnText(stmt, 29);
    account.last_error_at = sqlite3_column_int64(stmt, 30);
    return account;
}

void Storage::setAccountLastError(const std::string& error, int64_t atEpochSeconds) {
    Stmt stmt(db_, "UPDATE account SET last_error = ?, last_error_at = ? WHERE account_name = ?");
    bindText(stmt, 1, error);
    sqlite3_bind_int64(stmt, 2, atEpochSeconds);
    bindText(stmt, 3, accountName_);
    if (sqlite3_step(stmt) != SQLITE_DONE) {
        throw std::runtime_error(std::string("setAccountLastError failed: ") + sqlite3_errmsg(db_));
    }
}

void Storage::clearAccountLastError() {
    setAccountLastError("", 0);
}

void Storage::saveAccountConfig(const AccountRecord& account) {
    Stmt stmt(db_,
        "UPDATE account SET server_url = ?, sip_host = ?, sip_extension = ?, sip_password = ?, "
        "sip_bridge_destination = ?, sip_bridge_did = ?, sip_srtp = ?, sip_transport = ?, "
        "sip_tls_ca_file = ?, sip_tls_insecure = ?, outgoing_call_target = ?, "
        "signal_proxy = ?, signal_censorship_circumvention = ?, enabled = ?, "
        "config_version = config_version + 1 "
        "WHERE account_name = ?");
    bindText(stmt, 1, account.server_url);
    bindText(stmt, 2, account.sip_host);
    bindText(stmt, 3, account.sip_extension);
    bindText(stmt, 4, account.sip_password);
    bindText(stmt, 5, account.sip_bridge_destination);
    bindText(stmt, 6, account.sip_bridge_did);
    bindText(stmt, 7, account.sip_srtp);
    bindText(stmt, 8, account.sip_transport);
    bindText(stmt, 9, account.sip_tls_ca_file);
    sqlite3_bind_int(stmt, 10, account.sip_tls_insecure ? 1 : 0);
    bindText(stmt, 11, account.outgoing_call_target);
    bindText(stmt, 12, account.signal_proxy);
    sqlite3_bind_int(stmt, 13, account.signal_censorship_circumvention ? 1 : 0);
    sqlite3_bind_int(stmt, 14, account.enabled ? 1 : 0);
    bindText(stmt, 15, accountName_);
    if (sqlite3_step(stmt) != SQLITE_DONE) {
        throw std::runtime_error(std::string("saveAccountConfig failed: ") + sqlite3_errmsg(db_));
    }
    if (sqlite3_changes(db_) == 0) {
        throw std::runtime_error("saveAccountConfig: no account row named '" + accountName_ + "' to update");
    }
}

void Storage::saveAccount(const AccountRecord& account) {
    Stmt stmt(db_,
        "INSERT INTO account (account_name, e164, aci, pni, device_id, password, registration_id, "
        "pni_registration_id, flow, account_entropy_pool, media_root_backup_key, profile_key, "
        "registered_at, linked_at, prekeys_refreshed_at) "
        "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?) "
        "ON CONFLICT (account_name) DO UPDATE SET "
        "e164 = excluded.e164, aci = excluded.aci, pni = excluded.pni, "
        "device_id = excluded.device_id, password = excluded.password, "
        "registration_id = excluded.registration_id, pni_registration_id = excluded.pni_registration_id, "
        "flow = excluded.flow, account_entropy_pool = excluded.account_entropy_pool, "
        "media_root_backup_key = excluded.media_root_backup_key, profile_key = excluded.profile_key, "
        "registered_at = excluded.registered_at, linked_at = excluded.linked_at, "
        "prekeys_refreshed_at = excluded.prekeys_refreshed_at");
    bindText(stmt, 1, accountName_);
    bindText(stmt, 2, account.e164);
    bindText(stmt, 3, account.aci);
    bindText(stmt, 4, account.pni);
    sqlite3_bind_int(stmt, 5, account.device_id);
    bindText(stmt, 6, account.password);
    sqlite3_bind_int64(stmt, 7, account.registration_id);
    sqlite3_bind_int64(stmt, 8, account.pni_registration_id);
    bindTextOpt(stmt, 9, account.flow);
    bindTextOpt(stmt, 10, account.account_entropy_pool);
    bindBlobOpt(stmt, 11, account.media_root_backup_key);
    bindBlobOpt(stmt, 12, account.profile_key);
    bindInt64Opt(stmt, 13, account.registered_at);
    bindInt64Opt(stmt, 14, account.linked_at);
    bindInt64Opt(stmt, 15, account.prekeys_refreshed_at);
    if (sqlite3_step(stmt) != SQLITE_DONE) {
        throw std::runtime_error(std::string("saveAccount failed: ") + sqlite3_errmsg(db_));
    }
}

void Storage::saveIdentityKeypair(const std::string& identity, const IdentityKeypairRecord& keypair) {
    Stmt stmt(db_,
        "INSERT INTO identity_keypair (account_name, identity, private_key, public_key) VALUES (?, ?, ?, ?) "
        "ON CONFLICT (account_name, identity) DO UPDATE SET "
        "private_key = excluded.private_key, public_key = excluded.public_key");
    bindText(stmt, 1, accountName_);
    bindText(stmt, 2, identity);
    bindBlob(stmt, 3, keypair.private_key);
    bindBlob(stmt, 4, keypair.public_key);
    if (sqlite3_step(stmt) != SQLITE_DONE) {
        throw std::runtime_error(std::string("saveIdentityKeypair failed: ") + sqlite3_errmsg(db_));
    }
}

std::optional<IdentityKeypairRecord> Storage::loadIdentityKeypair(const std::string& identity) {
    Stmt stmt(db_, "SELECT private_key, public_key FROM identity_keypair WHERE account_name = ? AND identity = ?");
    bindText(stmt, 1, accountName_);
    bindText(stmt, 2, identity);
    if (sqlite3_step(stmt) != SQLITE_ROW) return std::nullopt;
    IdentityKeypairRecord keypair;
    keypair.private_key = columnBlob(stmt, 0);
    keypair.public_key = columnBlob(stmt, 1);
    return keypair;
}

void Storage::saveSignedPrekey(const std::string& identity, const SignedPrekeyRecord& prekey) {
    Stmt stmt(db_,
        "INSERT INTO signed_prekey (account_name, identity, key_id, record) VALUES (?, ?, ?, ?) "
        "ON CONFLICT (account_name, identity) DO UPDATE SET key_id = excluded.key_id, record = excluded.record");
    bindText(stmt, 1, accountName_);
    bindText(stmt, 2, identity);
    sqlite3_bind_int64(stmt, 3, prekey.key_id);
    bindBlob(stmt, 4, prekey.record);
    if (sqlite3_step(stmt) != SQLITE_DONE) {
        throw std::runtime_error(std::string("saveSignedPrekey failed: ") + sqlite3_errmsg(db_));
    }
}

std::optional<SignedPrekeyRecord> Storage::loadSignedPrekey(const std::string& identity) {
    Stmt stmt(db_, "SELECT key_id, record FROM signed_prekey WHERE account_name = ? AND identity = ?");
    bindText(stmt, 1, accountName_);
    bindText(stmt, 2, identity);
    if (sqlite3_step(stmt) != SQLITE_ROW) return std::nullopt;
    SignedPrekeyRecord prekey;
    prekey.key_id = sqlite3_column_int64(stmt, 0);
    prekey.record = columnBlob(stmt, 1);
    return prekey;
}

void Storage::saveKyberPrekey(const std::string& identity, const KyberPrekeyRecord& prekey) {
    Stmt stmt(db_,
        "INSERT INTO kyber_prekey (account_name, identity, key_id, record) VALUES (?, ?, ?, ?) "
        "ON CONFLICT (account_name, identity) DO UPDATE SET key_id = excluded.key_id, record = excluded.record");
    bindText(stmt, 1, accountName_);
    bindText(stmt, 2, identity);
    sqlite3_bind_int64(stmt, 3, prekey.key_id);
    bindBlob(stmt, 4, prekey.record);
    if (sqlite3_step(stmt) != SQLITE_DONE) {
        throw std::runtime_error(std::string("saveKyberPrekey failed: ") + sqlite3_errmsg(db_));
    }
}

std::optional<KyberPrekeyRecord> Storage::loadKyberPrekey(const std::string& identity) {
    Stmt stmt(db_, "SELECT key_id, record FROM kyber_prekey WHERE account_name = ? AND identity = ?");
    bindText(stmt, 1, accountName_);
    bindText(stmt, 2, identity);
    if (sqlite3_step(stmt) != SQLITE_ROW) return std::nullopt;
    KyberPrekeyRecord prekey;
    prekey.key_id = sqlite3_column_int64(stmt, 0);
    prekey.record = columnBlob(stmt, 1);
    return prekey;
}

void Storage::saveSession(const std::string& address, const Bytes& record) {
    Stmt stmt(db_,
        "INSERT INTO session (account_name, address, record) VALUES (?, ?, ?) "
        "ON CONFLICT (account_name, address) DO UPDATE SET record = excluded.record");
    bindText(stmt, 1, accountName_);
    bindText(stmt, 2, address);
    bindBlob(stmt, 3, record);
    if (sqlite3_step(stmt) != SQLITE_DONE) {
        throw std::runtime_error(std::string("saveSession failed: ") + sqlite3_errmsg(db_));
    }
}

std::optional<Bytes> Storage::loadSession(const std::string& address) {
    Stmt stmt(db_, "SELECT record FROM session WHERE account_name = ? AND address = ?");
    bindText(stmt, 1, accountName_);
    bindText(stmt, 2, address);
    if (sqlite3_step(stmt) != SQLITE_ROW) return std::nullopt;
    return columnBlob(stmt, 0);
}

std::vector<int> Storage::knownDeviceIdsFor(const std::string& serviceId) {
    Stmt stmt(db_, "SELECT address FROM session WHERE account_name = ? AND address LIKE ?");
    bindText(stmt, 1, accountName_);
    std::string pattern = serviceId + ".%";
    bindText(stmt, 2, pattern);
    std::vector<int> deviceIds;
    while (sqlite3_step(stmt) == SQLITE_ROW) {
        std::string address = columnText(stmt, 0);
        auto dot = address.rfind('.');
        if (dot == std::string::npos) continue;
        try {
            deviceIds.push_back(std::stoi(address.substr(dot + 1)));
        } catch (...) {
            // not a plain integer suffix - ignore, matches the Node
            // prototype's Number.isInteger() filter.
        }
    }
    return deviceIds;
}

void Storage::saveRemoteIdentity(const std::string& address, const Bytes& publicKey) {
    Stmt stmt(db_,
        "INSERT INTO remote_identity (account_name, address, public_key) VALUES (?, ?, ?) "
        "ON CONFLICT (account_name, address) DO UPDATE SET public_key = excluded.public_key");
    bindText(stmt, 1, accountName_);
    bindText(stmt, 2, address);
    bindBlob(stmt, 3, publicKey);
    if (sqlite3_step(stmt) != SQLITE_DONE) {
        throw std::runtime_error(std::string("saveRemoteIdentity failed: ") + sqlite3_errmsg(db_));
    }
}

std::optional<Bytes> Storage::loadRemoteIdentity(const std::string& address) {
    Stmt stmt(db_, "SELECT public_key FROM remote_identity WHERE account_name = ? AND address = ?");
    bindText(stmt, 1, accountName_);
    bindText(stmt, 2, address);
    if (sqlite3_step(stmt) != SQLITE_ROW) return std::nullopt;
    return columnBlob(stmt, 0);
}

void Storage::saveResolvedContact(const std::string& e164, const std::string& aci, const std::string& pni) {
    Stmt stmt(db_,
        "INSERT INTO resolved_contact (account_name, e164, aci, pni, resolved_at) VALUES (?, ?, ?, ?, ?) "
        "ON CONFLICT (account_name, e164) DO UPDATE SET aci = excluded.aci, pni = excluded.pni, "
        "resolved_at = excluded.resolved_at");
    bindText(stmt, 1, accountName_);
    bindText(stmt, 2, e164);
    bindText(stmt, 3, aci);
    bindText(stmt, 4, pni);
    sqlite3_bind_int64(stmt, 5, static_cast<int64_t>(std::time(nullptr)));
    if (sqlite3_step(stmt) != SQLITE_DONE) {
        throw std::runtime_error(std::string("saveResolvedContact failed: ") + sqlite3_errmsg(db_));
    }
}

std::optional<ResolvedContactRecord> Storage::loadResolvedContact(const std::string& e164) {
    Stmt stmt(db_, "SELECT aci, pni, resolved_at FROM resolved_contact WHERE account_name = ? AND e164 = ?");
    bindText(stmt, 1, accountName_);
    bindText(stmt, 2, e164);
    if (sqlite3_step(stmt) != SQLITE_ROW) return std::nullopt;
    ResolvedContactRecord result;
    result.aci = columnText(stmt, 0);
    result.pni = columnText(stmt, 1);
    result.resolved_at = sqlite3_column_int64(stmt, 2);
    return result;
}

void Storage::saveSyncedContact(const std::string& e164, const std::string& aci, const std::string& pni,
                                const Bytes& profileKey, const std::string& givenName,
                                const std::string& familyName) {
    // Not a single ON CONFLICT upsert: this table now has two independent
    // partial-unique indexes (e164, aci - see schema.sql), and SQLite only
    // supports one ON CONFLICT target per statement. Manually find whichever
    // existing row (if any) this contact matches by e164 first, then aci,
    // and UPDATE that row; INSERT a fresh one otherwise.
    int64_t existingId = -1;
    if (!e164.empty()) {
        Stmt find(db_, "SELECT id FROM synced_contact WHERE account_name = ? AND e164 = ?");
        bindText(find, 1, accountName_);
        bindText(find, 2, e164);
        if (sqlite3_step(find) == SQLITE_ROW) existingId = sqlite3_column_int64(find, 0);
    }
    if (existingId < 0 && !aci.empty()) {
        Stmt find(db_, "SELECT id FROM synced_contact WHERE account_name = ? AND aci = ?");
        bindText(find, 1, accountName_);
        bindText(find, 2, aci);
        if (sqlite3_step(find) == SQLITE_ROW) existingId = sqlite3_column_int64(find, 0);
    }

    int64_t now = static_cast<int64_t>(std::time(nullptr));
    if (existingId >= 0) {
        Stmt update(db_, "UPDATE synced_contact SET e164 = ?, aci = ?, pni = ?, profile_key = ?, given_name = ?, "
                         "family_name = ?, synced_at = ? WHERE id = ?");
        bindText(update, 1, e164);
        bindText(update, 2, aci);
        bindText(update, 3, pni);
        bindBlob(update, 4, profileKey);
        bindText(update, 5, givenName);
        bindText(update, 6, familyName);
        sqlite3_bind_int64(update, 7, now);
        sqlite3_bind_int64(update, 8, existingId);
        if (sqlite3_step(update) != SQLITE_DONE) {
            throw std::runtime_error(std::string("saveSyncedContact (update) failed: ") + sqlite3_errmsg(db_));
        }
        return;
    }

    Stmt insert(db_, "INSERT INTO synced_contact (account_name, e164, aci, pni, profile_key, given_name, "
                     "family_name, synced_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)");
    bindText(insert, 1, accountName_);
    bindText(insert, 2, e164);
    bindText(insert, 3, aci);
    bindText(insert, 4, pni);
    bindBlob(insert, 5, profileKey);
    bindText(insert, 6, givenName);
    bindText(insert, 7, familyName);
    sqlite3_bind_int64(insert, 8, now);
    if (sqlite3_step(insert) != SQLITE_DONE) {
        throw std::runtime_error(std::string("saveSyncedContact (insert) failed: ") + sqlite3_errmsg(db_));
    }
}

namespace {
SyncedContactRecord readSyncedContactRow(sqlite3_stmt* stmt) {
    SyncedContactRecord result;
    result.e164 = columnText(stmt, 0);
    result.aci = columnText(stmt, 1);
    result.pni = columnText(stmt, 2);
    result.profile_key = columnBlob(stmt, 3);
    result.given_name = columnText(stmt, 4);
    result.family_name = columnText(stmt, 5);
    result.synced_at = sqlite3_column_int64(stmt, 6);
    return result;
}
} // namespace

std::optional<SyncedContactRecord> Storage::loadSyncedContact(const std::string& e164) {
    Stmt stmt(db_, "SELECT e164, aci, pni, profile_key, given_name, family_name, synced_at FROM synced_contact "
                   "WHERE account_name = ? AND e164 = ?");
    bindText(stmt, 1, accountName_);
    bindText(stmt, 2, e164);
    if (sqlite3_step(stmt) != SQLITE_ROW) return std::nullopt;
    return readSyncedContactRow(stmt);
}

std::optional<SyncedContactRecord> Storage::loadSyncedContactByAci(const std::string& aci) {
    Stmt stmt(db_, "SELECT e164, aci, pni, profile_key, given_name, family_name, synced_at FROM synced_contact "
                   "WHERE account_name = ? AND aci = ?");
    bindText(stmt, 1, accountName_);
    bindText(stmt, 2, aci);
    if (sqlite3_step(stmt) != SQLITE_ROW) return std::nullopt;
    return readSyncedContactRow(stmt);
}

void Storage::deleteAccount() {
    char* errmsg = nullptr;
    if (sqlite3_exec(db_, "BEGIN", nullptr, nullptr, &errmsg) != SQLITE_OK) {
        std::string err = errmsg ? errmsg : "unknown error";
        sqlite3_free(errmsg);
        throw std::runtime_error("deleteAccount: BEGIN failed: " + err);
    }

    // schema.sql has no ON DELETE CASCADE, so every table needs its own
    // explicit DELETE - order doesn't matter for correctness (no FK
    // enforcement is active here beyond PRAGMA foreign_keys=ON, which
    // SQLite only checks on INSERT/UPDATE of the referencing column, not
    // on deleting the referenced row), only the whole set needs to land
    // atomically.
    static const char* kTables[] = {
        "identity_keypair", "signed_prekey",   "kyber_prekey",    "session",
        "remote_identity",  "resolved_contact", "synced_contact", "account",
    };
    try {
        for (const char* table : kTables) {
            std::string sql = std::string("DELETE FROM ") + table + " WHERE account_name = ?";
            Stmt stmt(db_, sql.c_str());
            bindText(stmt, 1, accountName_);
            if (sqlite3_step(stmt) != SQLITE_DONE) {
                throw std::runtime_error(std::string("DELETE FROM ") + table + " failed: " + sqlite3_errmsg(db_));
            }
        }
    } catch (...) {
        sqlite3_exec(db_, "ROLLBACK", nullptr, nullptr, nullptr);
        throw;
    }

    if (sqlite3_exec(db_, "COMMIT", nullptr, nullptr, &errmsg) != SQLITE_OK) {
        std::string err = errmsg ? errmsg : "unknown error";
        sqlite3_free(errmsg);
        throw std::runtime_error("deleteAccount: COMMIT failed: " + err);
    }
}

std::vector<AccountSummary> listAllAccounts(const std::string& path, const std::string& key) {
    // Short-lived connection, not tied to any one account's Storage
    // instance (see this function's own doc comment in Storage.h) - same
    // open/key/schema sequence as Storage's constructor, minus the
    // account_name scoping this call doesn't need. Applies the schema too
    // (harmless no-op on an already-current database, and correctly
    // creates an empty-but-valid database on a brand-new path - matches
    // "zero accounts is a valid config").
    sqlite3* db = nullptr;
    if (sqlite3_open(path.c_str(), &db) != SQLITE_OK) {
        std::string err = sqlite3_errmsg(db);
        sqlite3_close(db);
        throw std::runtime_error("listAllAccounts: sqlite3_open failed: " + err);
    }
    char* errmsg = nullptr;
    {
        char* sql = sqlite3_mprintf("PRAGMA key = %Q", key.c_str());
        int rc = sqlite3_exec(db, sql, nullptr, nullptr, &errmsg);
        sqlite3_free(sql);
        if (rc != SQLITE_OK) {
            std::string err = errmsg ? errmsg : "unknown error";
            sqlite3_free(errmsg);
            sqlite3_close(db);
            throw std::runtime_error("listAllAccounts: PRAGMA key failed: " + err);
        }
    }
    if (sqlite3_exec(db, "SELECT count(*) FROM sqlite_master", nullptr, nullptr, &errmsg) != SQLITE_OK) {
        std::string err = errmsg ? errmsg : "unknown error";
        sqlite3_free(errmsg);
        sqlite3_close(db);
        throw std::runtime_error("listAllAccounts: failed to open database (wrong key or corrupt file): " + err);
    }
    if (sqlite3_exec(db, "PRAGMA journal_mode = WAL", nullptr, nullptr, &errmsg) != SQLITE_OK) {
        std::string err = errmsg ? errmsg : "unknown error";
        sqlite3_free(errmsg);
        sqlite3_close(db);
        throw std::runtime_error("listAllAccounts: PRAGMA journal_mode=WAL failed: " + err);
    }
    sqlite3_busy_timeout(db, 5000);
    try {
        renameOldSyncedContactTableIfNeeded(db);
    } catch (...) {
        sqlite3_close(db);
        throw;
    }
    if (sqlite3_exec(db, kSchemaSql, nullptr, nullptr, &errmsg) != SQLITE_OK) {
        std::string err = errmsg ? errmsg : "unknown error";
        sqlite3_free(errmsg);
        sqlite3_close(db);
        throw std::runtime_error("listAllAccounts: failed to apply schema: " + err);
    }
    try {
        copyOldSyncedContactDataIfPresent(db);
        migrateAccountConfigColumnsIfNeeded(db);
    } catch (...) {
        sqlite3_close(db);
        throw;
    }

    std::vector<AccountSummary> result;
    {
        Stmt stmt(db, "SELECT account_name, e164, enabled, config_version, last_error, last_error_at "
                       "FROM account ORDER BY account_name");
        while (sqlite3_step(stmt) == SQLITE_ROW) {
            AccountSummary summary;
            summary.account_name = columnText(stmt, 0);
            summary.e164 = columnText(stmt, 1);
            summary.enabled = sqlite3_column_int(stmt, 2) != 0;
            summary.config_version = sqlite3_column_int64(stmt, 3);
            summary.last_error = columnText(stmt, 4);
            summary.last_error_at = sqlite3_column_int64(stmt, 5);
            result.push_back(std::move(summary));
        }
    }
    sqlite3_close(db);
    return result;
}

} // namespace signal2sip
