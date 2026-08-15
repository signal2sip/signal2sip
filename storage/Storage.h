#pragma once

#include <cstdint>
#include <optional>
#include <string>
#include <vector>

struct sqlite3;

namespace signal2sip {

using Bytes = std::vector<uint8_t>;

// Field names/meaning match layer1/accountStore.js's saved JSON exactly -
// see schema.sql for the full mapping rationale.
struct AccountRecord {
    std::string e164, aci, pni, password;
    int device_id = 0;
    int64_t registration_id = 0;
    int64_t pni_registration_id = 0;
    std::optional<std::string> flow;
    std::optional<std::string> account_entropy_pool;
    std::optional<Bytes> media_root_backup_key;
    std::optional<Bytes> profile_key;
    std::optional<int64_t> registered_at;
    std::optional<int64_t> linked_at;
    std::optional<int64_t> prekeys_refreshed_at;

    // SIP/deployment config (schema.sql's own comment on the `account`
    // table has the full "why here, not the .conf file" rationale) -
    // field names/defaults/meaning mirror AccountConfig (daemon/Config.h)
    // exactly. Populated by loadAccount()'s SELECT, but saveAccount()
    // never writes these - only saveAccountConfig() does.
    std::string server_url;
    std::string sip_host, sip_extension, sip_password;
    std::string sip_bridge_destination, sip_bridge_did;
    std::string sip_srtp = "disabled";
    std::string sip_transport = "udp";
    std::string sip_tls_ca_file;
    bool sip_tls_insecure = false;
    std::string outgoing_call_target;
    std::string signal_proxy;
    bool signal_censorship_circumvention = false;
    bool enabled = true;
    int64_t config_version = 0;

    // Observed, not admin-set - see schema.sql's own comment on these two
    // columns. '' means "no known outstanding problem".
    std::string last_error;
    int64_t last_error_at = 0;
};

// Lightweight per-account summary for enumerating every account in the
// database without needing a full loadAccount() per row - used by the
// daemon (which accounts to run) and gendb's `list` command.
struct AccountSummary {
    std::string account_name;
    std::string e164;
    bool enabled = true;
    int64_t config_version = 0;
    std::string last_error;
    int64_t last_error_at = 0;
};

// Enumerates every account row in the database, regardless of which
// account any particular Storage instance is scoped to - opens its own
// short-lived connection (same path/key as Storage's constructor).
// Returns an empty vector for a brand-new/empty database (not an error -
// matches Config.cpp's "zero accounts is a valid config" comment).
std::vector<AccountSummary> listAllAccounts(const std::string& path, const std::string& key);

struct IdentityKeypairRecord {
    Bytes private_key;
    Bytes public_key;
};

struct SignedPrekeyRecord {
    int64_t key_id = 0;
    Bytes record;
};

struct KyberPrekeyRecord {
    int64_t key_id = 0;
    Bytes record;
};

// A cached CDSI lookup result (see native/signal/Cdsi.h) - aci/pni are ""
// for a resolved-but-not-found e164, distinct from no cache entry at all
// (see Storage::loadResolvedContact's own doc comment).
struct ResolvedContactRecord {
    std::string aci, pni;
    int64_t resolved_at = 0;
};

// A real contact learned from this account's own StorageService sync (see
// native/daemon/StorageServiceSync.h) - unlike ResolvedContactRecord (a
// CDS lookup, which for a cold/unknown e164 can only ever reveal PNI),
// this comes straight from the account's real contact list, so aci is
// populated whenever the contact record has one (i.e. for any genuinely
// mutual real contact, regardless of CDS/PNP status).
struct SyncedContactRecord {
    std::string e164; // '' if this contact has no phone number
    std::string aci, pni;
    Bytes profile_key;
    std::string given_name, family_name; // '' if unset/not synced
    int64_t synced_at = 0;
};

// Encrypted (SQLCipher) local storage, scoped to one Signal account via
// `accountName` - multiple Storage instances (one per account) can (and
// normally do) point at the same shared database file/path, each opening
// its own sqlite3 connection (SQLite/SQLCipher handle multiple
// connections to one file natively, same as any multi-process access).
// Every table is namespaced by account_name (see schema.sql) so two
// accounts' sessions/keys/identities never collide.
class Storage {
public:
    // Opens (creating if needed) the database at `path`, keyed with `key`
    // (passed to SQLCipher's `PRAGMA key`, which does its own KDF - callers
    // pass a human/config-supplied passphrase, not a raw derived key), and
    // ensures the schema exists. `accountName` scopes every row this
    // instance reads/writes - matches the `[account.<name>]` config
    // section suffix. Throws std::runtime_error on any failure, including
    // a wrong key against an existing database.
    Storage(const std::string& path, const std::string& key, const std::string& accountName);
    ~Storage();

    Storage(const Storage&) = delete;
    Storage& operator=(const Storage&) = delete;

    bool hasAccount();
    AccountRecord loadAccount();
    void saveAccount(const AccountRecord& account);

    // Writes ONLY the SIP/deployment-config + enabled columns (never the
    // Signal-identity ones saveAccount() owns) and bumps config_version by
    // 1 in the same statement (`config_version = config_version + 1` in
    // SQL - the passed-in account.config_version is never trusted/written,
    // avoiding a read-then-write race against a concurrent writer). The
    // account row must already exist (created via saveAccount() during
    // register/link/verify) - this is an UPDATE, not an upsert.
    void saveAccountConfig(const AccountRecord& account);

    // Observed connection status, not deployment config - see schema.sql's
    // own comment on the `account.last_error`/`last_error_at` columns.
    // Only the daemon calls these (main.cpp's socket watchdog); gendb only
    // ever reads them back via loadAccount()/listAllAccounts().
    void setAccountLastError(const std::string& error, int64_t atEpochSeconds);
    void clearAccountLastError();

    // identity in {"aci", "pni"}
    void saveIdentityKeypair(const std::string& identity, const IdentityKeypairRecord& keypair);
    std::optional<IdentityKeypairRecord> loadIdentityKeypair(const std::string& identity);

    void saveSignedPrekey(const std::string& identity, const SignedPrekeyRecord& prekey);
    std::optional<SignedPrekeyRecord> loadSignedPrekey(const std::string& identity);

    void saveKyberPrekey(const std::string& identity, const KyberPrekeyRecord& prekey);
    std::optional<KyberPrekeyRecord> loadKyberPrekey(const std::string& identity);

    // address is "<serviceId>.<deviceId>", matching FileSessionStore's
    // ProtocolAddress::toString() keys.
    void saveSession(const std::string& address, const Bytes& record);
    std::optional<Bytes> loadSession(const std::string& address);

    // Mirrors protocolStores.js's knownDeviceIdsFor(): every device id we
    // have a session with for the given serviceId.
    std::vector<int> knownDeviceIdsFor(const std::string& serviceId);

    // address is a bare serviceId (not device-qualified) - trust-on-first-
    // use store, matching AccountIdentityStore's semantics.
    void saveRemoteIdentity(const std::string& address, const Bytes& publicKey);
    std::optional<Bytes> loadRemoteIdentity(const std::string& address);

    // e164 must include the leading '+'. std::nullopt means "never looked
    // up" - distinct from a cached record with empty aci/pni, which means
    // "looked up, genuinely not on Signal".
    void saveResolvedContact(const std::string& e164, const std::string& aci, const std::string& pni);
    std::optional<ResolvedContactRecord> loadResolvedContact(const std::string& e164);

    // e164 may be "" (a contact with no phone number, e.g. added via
    // QR/username - see schema.sql's partial-unique-index comment), but
    // e164 and aci must not BOTH be "" (caller's responsibility - see
    // main.cpp's syncStorageContacts(), the only real caller). Upserts by
    // e164 if non-empty, else by aci - matches this row against whichever
    // of the two identifies it (StorageServiceSync's caller is expected to
    // just re-save every contact it fetches each time - a real contact's
    // own ACI/PNI/profileKey/name essentially never changes, but a wrong
    // stale cache is worse than a redundant write).
    void saveSyncedContact(const std::string& e164, const std::string& aci, const std::string& pni,
                           const Bytes& profileKey, const std::string& givenName, const std::string& familyName);
    std::optional<SyncedContactRecord> loadSyncedContact(const std::string& e164);

    // Same table as loadSyncedContact() but keyed by aci instead of e164 -
    // used to resolve an incoming Signal caller (RingRTC's remotePeerId,
    // always an ACI) back to their synced phone number/name for the
    // X-Signal-* SIP header passthrough (see main.cpp's startSipDial()).
    std::optional<SyncedContactRecord> loadSyncedContactByAci(const std::string& aci);

    // Deletes every row for this account across every table (identity
    // keypairs, prekeys, sessions, remote identities, resolved/synced
    // contacts, and the account row itself), in one transaction. Purely
    // local - does NOT contact Signal's servers, so it does not itself
    // unlink/deregister the real account. Safe to call even if
    // hasAccount() is false (a no-op transaction in that case).
    void deleteAccount();

private:
    sqlite3* db_ = nullptr;
    std::string accountName_;
};

} // namespace signal2sip
