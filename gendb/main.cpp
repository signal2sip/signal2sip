// signal2sip-gendb: standalone companion CLI for creating a brand-new
// Signal account - either Flow A (standalone SMS/voice registration) or
// Flow B (linking as a secondary device via QR) - mirrors tg2sip's
// gen_db.cpp (a companion binary doing the one-time interactive account
// setup the daemon itself never does, gated by the same "does the DB
// already have an account" check tg2sip's ConditionPathExists= expresses
// at the systemd level). C++ port of layer1/register-*.js and
// layer1/link-new-device.js, writing straight into the shared SQLCipher
// database signal2sip-daemon itself reads.
//
// Config file resolution matches signal2sip-daemon's own
// resolveConfigPath() exactly: --config <path>, else
// /etc/signal2sip/signal2sip.conf, else ./signal2sip.conf. Its
// [global] section (db_path/db_key) is bootstrapped automatically on a
// clean first run (missing file, or missing/empty db_path/db_key with no
// database file sitting at db_path yet) - see bootstrapGlobalConfigIfNeeded()
// below; a fresh db_key is only ever invented when there is provably no
// pre-existing encrypted database it could otherwise belong to. That's
// the ONLY thing this file contains now - 2026-08-07 moved every
// account's SIP/deployment config + enabled flag into the `account`
// table itself (see schema.sql's own comment on it), editable live via
// this CLI's `config`/`enable`/`disable` commands instead of hand-editing
// [account.<name>] sections. `register`/`link` can still target a
// brand-new account name with no existing database row at all - they
// just create one now, instead of also appending a config-file section.
//
// Usage:
//   signal2sip-gendb <account-name> register --e164 <e164> [sms|voice] [--config <path>]
//   signal2sip-gendb <account-name> register-captcha <token> [--config <path>]
//   signal2sip-gendb <account-name> verify <code> [--config <path>]
//   signal2sip-gendb <account-name> link [--config <path>]
//   signal2sip-gendb <account-name> enable|disable [--config <path>]
//   signal2sip-gendb <account-name> config get|set|list [field] [value] [--config <path>]
//   signal2sip-gendb list [--config <path>]

#include <curl/curl.h>
#include <openssl/rand.h>

#include <algorithm>
#include <csignal>
#include <cstdio>
#include <filesystem>
#include <fstream>
#include <functional>
#include <iostream>
#include <stdexcept>
#include <unistd.h>

#include <nlohmann/json.hpp>

#include "AccountFinisher.h"
#include "DeviceNameCipher.h"
#include "ProvisioningClient.h"
#include "RegistrationServiceClient.h"
#include "../daemon/Config.h"
#include "../signal/AuthSocket.h"
#include "../signal/FfiUtil.h"
#include "../storage/Storage.h"
#include "../util/Base64.h"
#include "../util/RegistrationClient.h"

using namespace signal2sip;
using json = nlohmann::json;

namespace {

// The name a linked device shows up as in the real Signal app's Linked
// Devices list (see DeviceNameCipher.h). Not user-configurable yet - every
// account this project links gets the same name, which is fine since
// there's currently no need to tell multiple linked signal2sip instances
// apart from within one real account's device list.
constexpr const char* kDeviceName = "signal2sip";

std::string base64NoPadding(const Bytes& data) {
    std::string s = base64Encode(data);
    while (!s.empty() && s.back() == '=') s.pop_back();
    return s;
}

Bytes randomBytes(size_t n) {
    Bytes out(n);
    if (RAND_bytes(out.data(), static_cast<int>(n)) != 1) throw std::runtime_error("RAND_bytes failed");
    return out;
}

std::string dirName(const std::string& path) {
    auto pos = path.find_last_of('/');
    return pos == std::string::npos ? std::string(".") : path.substr(0, pos);
}

std::string trim(const std::string& s) {
    size_t start = s.find_first_not_of(" \t\r\n");
    if (start == std::string::npos) return "";
    size_t end = s.find_last_not_of(" \t\r\n");
    return s.substr(start, end - start + 1);
}

// Tolerates the common ways a captcha token gets mangled when
// copy-pasted out of a browser's address bar/failed-navigation dialog:
// surrounding whitespace (a stray trailing newline is especially common
// from a terminal paste), the whole thing wrapped in quotes (some
// terminals/dialogs include them when you copy a URL), and either the
// full `signalcaptcha://<token>` redirect URL or just the bare token
// after it - both are accepted as-is.
std::string cleanCaptchaToken(std::string token) {
    token = trim(token);
    if (token.size() >= 2 && ((token.front() == '"' && token.back() == '"') ||
                              (token.front() == '\'' && token.back() == '\''))) {
        token = token.substr(1, token.size() - 2);
    }
    token = trim(token);
    const std::string prefix = "signalcaptcha://";
    if (token.rfind(prefix, 0) == 0) token = token.substr(prefix.size());
    while (!token.empty() && token.back() == '/') token.pop_back();
    return token;
}

// Session continuity between `register`/`register-captcha`/`verify`
// invocations (a captcha or SMS delay can separate them) - a small JSON
// file next to the shared DB, mirroring registrationSession.js's
// savePending/loadPending. Transient, pre-account state - not a schema
// change.
std::string pendingFilePath(const GlobalConfig& global, const std::string& accountName) {
    return dirName(global.dbPath) + "/." + accountName + ".gendb-pending.json";
}

struct PendingRegistration {
    std::string e164;
    std::string sessionId;
    std::string password;
    std::string transport;
};

void savePending(const GlobalConfig& global, const std::string& accountName, const PendingRegistration& p) {
    json j = {{"e164", p.e164}, {"sessionId", p.sessionId}, {"password", p.password}, {"transport", p.transport}};
    std::ofstream f(pendingFilePath(global, accountName));
    if (!f) throw std::runtime_error("cannot write pending-registration file");
    f << j.dump(2);
}

PendingRegistration loadPending(const GlobalConfig& global, const std::string& accountName) {
    std::ifstream f(pendingFilePath(global, accountName));
    if (!f) {
        throw std::runtime_error("no pending registration for account '" + accountName + "' - run 'register' first");
    }
    json j;
    f >> j;
    return PendingRegistration{j.at("e164").get<std::string>(), j.at("sessionId").get<std::string>(),
                               j.at("password").get<std::string>(), j.at("transport").get<std::string>()};
}

void deletePending(const GlobalConfig& global, const std::string& accountName) {
    std::remove(pendingFilePath(global, accountName).c_str());
}

// Matches Config.h's resolveConfigPath(argc, argv) fallback chain
// (--config override, else /etc/signal2sip/signal2sip.conf, else
// ./signal2sip.conf) without duplicating its file-exists logic.
std::string resolveGendbConfigPath(const std::string& explicitPath) {
    char prog[] = "signal2sip-gendb";
    if (!explicitPath.empty()) {
        char* argvOverride[2] = {prog, const_cast<char*>(explicitPath.c_str())};
        return resolveConfigPath(2, argvOverride);
    }
    char* argvDefault[1] = {prog};
    return resolveConfigPath(1, argvDefault);
}

constexpr const char* kDefaultDbPath = "/var/lib/signal2sip/signal2sip.db";

// Fills in a missing/incomplete [global] section on a clean first run -
// bootstraps db_path (default kDefaultDbPath) and/or a freshly generated
// db_key. Only ever invents db_key when there is provably no pre-existing
// database file at db_path yet - otherwise there'd be no way to know a
// fresh random passphrase actually opens whatever's really there, so it
// refuses instead and tells the user to set the real db_key by hand.
// Purely additive to the config file - never rewrites/touches an
// already-present db_path/db_key value.
void bootstrapGlobalConfigIfNeeded(const std::string& configPath) {
    GlobalConfig existing = loadGlobalConfigLenient(configPath);
    bool dbPathMissing = existing.dbPath.empty();
    bool dbKeyMissing = existing.dbKey.empty();
    if (!dbPathMissing && !dbKeyMissing) return; // already fully configured

    std::string dbPath = dbPathMissing ? kDefaultDbPath : existing.dbPath;

    if (dbKeyMissing && std::filesystem::exists(dbPath)) {
        throw std::runtime_error("[global] db_key is missing in " + configPath + " but " + dbPath +
                                 " already exists - refusing to invent a new passphrase for a database that "
                                 "might already hold real data; set the correct db_key by hand instead");
    }

    std::error_code ec;
    std::filesystem::create_directories(dirName(configPath), ec); // best-effort; the ofstream below reports failure

    std::ofstream f(configPath, std::ios::app);
    if (!f) throw std::runtime_error("cannot write to config file: " + configPath);

    std::string generatedKey;
    f << "\n[global]\n";
    if (dbPathMissing) f << "db_path=" << dbPath << "\n";
    if (dbKeyMissing) {
        generatedKey = base64NoPadding(randomBytes(32));
        f << "db_key=" << generatedKey << "\n";
    }
    f.close();

    std::cout << "[gendb] bootstrapped [global] in " << configPath << ":\n";
    if (dbPathMissing) std::cout << "  db_path=" << dbPath << "\n";
    if (dbKeyMissing) {
        std::cout << "  db_key=" << generatedKey << "\n";
        std::cout << "[gendb] IMPORTANT: back up this passphrase now (e.g. in a password manager) - it encrypts "
                     "every account's Signal keys in this database; losing it means losing every account's "
                     "identity/session state permanently, with no way to recover it.\n";
    }
}

struct ResolvedAccount {
    AccountConfig account;
    bool existedInDb = false;
};

ResolvedAccount resolveAccount(const DaemonConfig& config, const std::string& name) {
    for (const auto& a : config.accounts) {
        if (a.name == name) return ResolvedAccount{a, true};
    }
    AccountConfig fresh;
    fresh.name = name;
    return ResolvedAccount{fresh, false};
}

void requireNoExistingAccount(Storage& storage, const std::string& name) {
    if (storage.hasAccount()) {
        throw std::runtime_error("account '" + name +
                                  "' already has a saved account in the database - use a different "
                                  "[account.<name>] section for a new number");
    }
}

std::string serverHostFor(const AccountConfig& account) {
    return account.serverUrl.empty() ? "chat.signal.org" : account.serverUrl;
}

// Guards against registering/linking a real phone number that's already
// configured under a DIFFERENT [account.<name>] section in this same
// config - unlike an account-name collision (checked via
// requireNoExistingAccount()'s hasAccount() lookup), nothing else stops
// this: the real Signal server has no idea about our local names, and
// completing a second registration/link for a number some other account
// here already owns would re-register that number on the real server,
// most likely knocking the existing device off it.
void requireE164NotUsedByOtherAccount(const DaemonConfig& config, const std::string& accountName,
                                      const std::string& e164) {
    for (const auto& a : config.accounts) {
        if (a.name != accountName && a.e164 == e164) {
            throw std::runtime_error("e164 " + e164 + " is already configured under a different account ('" +
                                     a.name +
                                     "') in this config - registering/linking it again here would re-register "
                                     "that number on the real Signal server, likely kicking the existing device "
                                     "off it");
        }
    }
}

json capabilitiesJson() {
    // requireForNewDevices=true fields (spqr, usernameChangeSyncMessage)
    // plus the rest declared false for a brand-new account/device - see
    // link-new-device.js's own comment on DeviceCapability.
    return json{{"storage", false},
               {"versionedExpirationTimer", false},
               {"attachmentBackfill", false},
               {"spqr", true},
               {"usernameChangeSyncMessage", true}};
}

json signedPreKeyJson(const GeneratedSignedPreKey& key) {
    return json{{"keyId", key.wire.keyId},
               {"publicKey", base64NoPadding(key.wire.publicKey)},
               {"signature", base64NoPadding(key.wire.signature)}};
}

json kyberPreKeyJson(const GeneratedKyberPreKey& key) {
    return json{{"keyId", key.wire.keyId},
               {"publicKey", base64NoPadding(key.wire.publicKey)},
               {"signature", base64NoPadding(key.wire.signature)}};
}

// ---- Flow A: standalone SMS/voice registration ----

void cmdRegister(const DaemonConfig& config, const std::string& accountName, const std::string& e164Arg,
                 const std::string& transport) {
    if (transport != "sms" && transport != "voice") {
        throw std::runtime_error("transport must be \"sms\" or \"voice\"");
    }
    ResolvedAccount resolved = resolveAccount(config, accountName);
    AccountConfig account = resolved.account;
    if (!resolved.existedInDb) {
        if (e164Arg.empty()) {
            throw std::runtime_error("account '" + accountName +
                                     "' is not in the config yet - pass --e164 <e164> to register it");
        }
        account.e164 = e164Arg;
    } else if (!e164Arg.empty() && e164Arg != account.e164) {
        throw std::runtime_error("account '" + accountName + "' is already configured with e164=" + account.e164 +
                                 " - --e164 " + e164Arg + " does not match");
    }
    requireE164NotUsedByOtherAccount(config, account.name, account.e164);

    Storage storage(config.global.dbPath, config.global.dbKey, account.name);
    requireNoExistingAccount(storage, account.name);

    std::cout << "[register] creating verification session for " << account.e164 << "\n";
    RegistrationServiceClient client;
    RegistrationSessionState session = client.createSession(account.e164);
    std::cout << "[register] session created (id " << client.sessionId()
              << "), allowedToRequestCode=" << session.allowedToRequestCode << "\n";

    std::string ourPassword = base64NoPadding(randomBytes(18));

    // Saved right away, even if we can't request a code yet -
    // register-captcha needs this sessionId to resume instead of starting
    // a brand new session.
    savePending(config.global, account.name,
               PendingRegistration{account.e164, client.sessionId(), ourPassword, transport});

    const auto& requestedInformation = session.requestedInformation;
    bool needsCaptcha = std::find(requestedInformation.begin(), requestedInformation.end(), "captcha") !=
                       requestedInformation.end();
    if (needsCaptcha) {
        std::cout << "[register] BLOCKED: server requires a captcha (requestedInformation includes \"captcha\").\n";
        std::cout << "[register] Open this in a real browser and solve it:\n";
        std::cout << "  https://signalcaptchas.org/registration/generate.html\n";
        std::cout << "[register] It will try to redirect to signalcaptcha://<token> - that redirect will fail\n";
        std::cout << "[register] in a normal browser, but the token should still be visible. Then run:\n";
        std::cout << "  signal2sip-gendb " << account.name << " register-captcha <token>\n";
        return;
    }
    bool needsPushChallenge = std::find(requestedInformation.begin(), requestedInformation.end(), "pushChallenge") !=
                             requestedInformation.end();
    if (needsPushChallenge) {
        std::cout << "[register] FAIL: server requires a push challenge (no push token available headlessly).\n";
        return;
    }
    if (!session.allowedToRequestCode) {
        std::cout << "[register] FAIL: server says allowedToRequestCode=false, cannot proceed.\n";
        return;
    }

    std::cout << "[register] requesting " << transport << " verification code...\n";
    client.requestVerificationCode(transport);

    std::cout << "[register] PASS: code requested via " << transport << " - once received, run:\n";
    std::cout << "  signal2sip-gendb " << account.name << " verify <code>\n";
}

void cmdRegisterCaptcha(const DaemonConfig& config, const std::string& accountName, std::string token) {
    token = cleanCaptchaToken(token);
    if (token.empty()) throw std::runtime_error("captcha token is empty after cleanup");

    PendingRegistration pending = loadPending(config.global, accountName);

    std::cout << "[captcha] resuming session " << pending.sessionId << "\n";
    RegistrationServiceClient client;
    client.resumeSession(pending.sessionId, pending.e164);

    std::cout << "[captcha] submitting captcha token...\n";
    RegistrationSessionState session = client.submitCaptcha(token);
    if (!session.allowedToRequestCode) {
        std::cout << "[captcha] FAIL: still not allowed to request a code after captcha\n";
        return;
    }

    std::cout << "[captcha] captcha accepted, requesting " << pending.transport << " verification code...\n";
    client.requestVerificationCode(pending.transport);

    std::cout << "[captcha] PASS: code requested via " << pending.transport << " - once received, run:\n";
    std::cout << "  signal2sip-gendb " << accountName << " verify <code>\n";
}

void cmdVerify(const DaemonConfig& config, const std::string& accountName, const std::string& code) {
    Storage storage(config.global.dbPath, config.global.dbKey, accountName);
    requireNoExistingAccount(storage, accountName);

    ResolvedAccount resolved = resolveAccount(config, accountName);
    PendingRegistration pending = loadPending(config.global, accountName);
    AccountConfig account = resolved.account;
    // Not yet in the config (the common case - `register` only needed
    // --e164 once, already recorded in the pending file).
    if (account.e164.empty()) account.e164 = pending.e164;
    requireE164NotUsedByOtherAccount(config, accountName, account.e164);

    std::cout << "[verify] resuming session " << pending.sessionId << "\n";
    RegistrationServiceClient client;
    client.resumeSession(pending.sessionId, account.e164);

    std::cout << "[verify] submitting code...\n";
    bool verified = client.submitVerificationCode(code);
    if (!verified) {
        std::cout << "[verify] FAIL: session not marked verified after submitting code\n";
        return;
    }
    std::cout << "[verify] session confirmed verified, generating fresh identity + prekeys...\n";

    KeyPair aciIdentity = generateKeyPair();
    KeyPair pniIdentity = generateKeyPair();
    int64_t registrationId = randomRegistrationId();
    int64_t pniRegistrationId = randomRegistrationId();
    GeneratedPrekeys prekeys = generatePrekeys(aciIdentity.privateKey, pniIdentity.privateKey);

    std::cout << "[verify] registering account...\n";
    RegisteredAccount registered;
    try {
        registered = client.registerAccount(pending.password, registrationId, pniRegistrationId, aciIdentity,
                                            pniIdentity, prekeys);
    } catch (const std::exception& e) {
        std::cout << "[verify] FAIL: registration rejected: " << e.what() << "\n";
        return;
    }

    FinishedAccount finished;
    finished.e164 = account.e164;
    finished.aci = registered.aci;
    finished.pni = registered.pni;
    finished.password = pending.password;
    finished.deviceId = 1;
    finished.registrationId = registrationId;
    finished.pniRegistrationId = pniRegistrationId;
    finished.aciIdentity = aciIdentity;
    finished.pniIdentity = pniIdentity;
    finished.prekeys = prekeys;
    finished.flow = "standalone";
    saveFinishedAccount(storage, finished);
    deletePending(config.global, accountName);

    std::cout << "[verify] PASS: registered and saved account '" << accountName << "' (aci " << finished.aci
              << ")\n";
}

// ---- Flow B: device linking via QR ----

void cmdLink(const DaemonConfig& config, const std::string& accountName) {
    Storage storage(config.global.dbPath, config.global.dbKey, accountName);
    requireNoExistingAccount(storage, accountName);

    // Checked upfront, not just left to fail wherever it's first needed:
    // the QR-scan wait below takes up to ~90s, and the account's finishing
    // `PUT /v1/devices/link` (RegistrationClient, further down) is the one
    // remaining real consumer of this path (everything else - AuthSocket,
    // ProvisioningClient - gets its TLS pinning from libsignal-net-chat's
    // own Environment::Prod now). Better to fail immediately with a clear
    // reason than after the user has already scanned the code.
    std::string caCertPath = resolveCaCertPath();
    if (!std::filesystem::exists(caCertPath)) {
        throw std::runtime_error("Signal root CA cert not found at '" + caCertPath +
                                  "' - `link`'s finishing PUT /v1/devices/link request needs it. Check "
                                  "/etc/signal2sip/certs/signal-root-ca.pem or ./certs/signal-root-ca.pem.");
    }

    ResolvedAccount resolved = resolveAccount(config, accountName);
    AccountConfig account = resolved.account;

    ProvisioningClient provisioning;
    std::cout << "[link] connecting to provisioning socket...\n";
    ProvisionMessageResult provisioned = provisioning.waitForProvisionMessage();
    std::cout << "[link] decrypted provisioning message OK for " << provisioned.e164 << ", finishing linking...\n";

    // e164 comes straight from the scanned account's own ProvisionMessage
    // - no --e164 needed upfront for `link` at all, unlike `register`.
    std::string finalE164 = !account.e164.empty() ? account.e164 : provisioned.e164;
    if (!account.e164.empty() && !provisioned.e164.empty() && provisioned.e164 != account.e164) {
        std::cout << "[link] WARNING: linked number (" << provisioned.e164
                  << ") does not match this account's configured e164 (" << account.e164
                  << ") - saving under the configured e164 anyway; only the identity/keys come from the scan.\n";
        finalE164 = account.e164;
    }
    requireE164NotUsedByOtherAccount(config, accountName, finalE164);

    KeyPair aciIdentity{provisioned.aciIdentityKeyPrivate, provisioned.aciIdentityKeyPublic};
    KeyPair pniIdentity{provisioned.pniIdentityKeyPrivate, provisioned.pniIdentityKeyPublic};
    int64_t registrationId = randomRegistrationId();
    int64_t pniRegistrationId = randomRegistrationId();
    GeneratedPrekeys prekeys = generatePrekeys(aciIdentity.privateKey, pniIdentity.privateKey);
    // This device's own credentials for all future authenticated calls -
    // generated locally, sent as the Basic auth password on the finishing
    // PUT /v1/devices/link call, becoming this device's permanent password
    // from the server's point of view (matches link-new-device.js).
    std::string ourPassword = base64NoPadding(randomBytes(18));

    // Linked devices show up as "Unnamed device" in the real Signal app's
    // Linked Devices list without this - see project notes (device-name
    // investigation). Encrypted with the ACI identity private key we just
    // received above, matching DeviceNameUtil.encryptDeviceName() exactly.
    std::string encryptedDeviceName = encryptDeviceName(kDeviceName, aciIdentity.privateKey);

    json body = {
        {"verificationCode", provisioned.provisioningCode},
        {"accountAttributes",
        {{"fetchesMessages", true},
         {"registrationId", registrationId},
         {"pniRegistrationId", pniRegistrationId},
         {"name", encryptedDeviceName},
         {"capabilities", capabilitiesJson()}}},
        {"aciSignedPreKey", signedPreKeyJson(prekeys.aciSignedPreKey)},
        {"pniSignedPreKey", signedPreKeyJson(prekeys.pniSignedPreKey)},
        {"aciPqLastResortPreKey", kyberPreKeyJson(prekeys.aciKyberPreKey)},
        {"pniPqLastResortPreKey", kyberPreKeyJson(prekeys.pniKyberPreKey)},
        {"gcmToken", nullptr},
    };

    RegistrationClient client(serverHostFor(account));
    std::cout << "[link] PUT /v1/devices/link ...\n";
    HttpResponse resp = client.request("PUT", "/v1/devices/link", body.dump(), provisioned.aci, ourPassword);
    std::cout << "[link] response: " << resp.status << " " << resp.body << "\n";
    if (resp.status != 200) {
        std::cout << "[link] FAIL: linking rejected\n";
        return;
    }

    json parsed = json::parse(resp.body);
    FinishedAccount finished;
    finished.e164 = finalE164;
    finished.aci = parsed.at("uuid").get<std::string>();
    finished.pni = parsed.at("pni").get<std::string>();
    finished.password = ourPassword;
    finished.deviceId = parsed.at("deviceId").get<int>();
    finished.registrationId = registrationId;
    finished.pniRegistrationId = pniRegistrationId;
    finished.aciIdentity = aciIdentity;
    finished.pniIdentity = pniIdentity;
    finished.prekeys = prekeys;
    finished.flow = "linked";
    finished.profileKey = provisioned.profileKey;
    finished.accountEntropyPool = provisioned.accountEntropyPool;
    finished.mediaRootBackupKey = provisioned.mediaRootBackupKey;
    saveFinishedAccount(storage, finished);

    std::cout << "[link] PASS: linked and saved account '" << accountName << "' (aci " << finished.aci << ", device "
              << finished.deviceId << ")\n";
}

// ---- Local account removal ----

// Wipes every row for this account (identity keys, prekeys, sessions,
// remote identities, cached/synced contacts, the account row itself) from
// the shared local database. Purely local: does NOT contact Signal's
// servers, so it does not unlink/deregister the real account there -
// intended for cleaning up an account whose real-side registration is
// already gone (real unlink, real delete-account, or a local number that
// was never actually verified) so its dead key material doesn't linger
// and block reusing the account name (see requireNoExistingAccount()).
void cmdUnlink(const DaemonConfig& config, const std::string& accountName) {
    Storage storage(config.global.dbPath, config.global.dbKey, accountName);
    if (!storage.hasAccount()) {
        throw std::runtime_error("account '" + accountName + "' has no saved account in the database - nothing to unlink");
    }
    AccountRecord account = storage.loadAccount();
    storage.deleteAccount();
    std::cout << "[unlink] removed all local data for account '" << accountName << "' (e164=" << account.e164
              << ")\n";
    std::cout << "[unlink] this was LOCAL ONLY - it does not unlink or delete the account on Signal's real servers.\n";
    std::cout << "[unlink] this account's row (and its enabled flag) was also just wiped along with everything "
                 "else - re-run `register`/`link` to reuse this account name.\n";
}

// ---- Primary account lifecycle: deactivate (soft, alias: unregister) / reactivate ----

// PUT /v1/accounts/attributes/ over the account's own authenticated
// WebSocket (same call toggle_discoverability_test.cpp already proved
// live). Signal-Server's handler (AccountController.setAccountAttributes)
// unconditionally OVERWRITES capabilities/name/discoverableByPhoneNumber/
// unrestrictedUnidentifiedAccess with whatever this body sends - it does
// NOT merge against the account's current values - so every field below
// must always be resent, or it gets silently reset to a Java-default
// (false/null) rather than left alone. fetchesMessages is the only field
// that actually changes between deactivate and reactivate; the rest just
// re-assert the same values cmdVerify/cmdLink already set at account
// creation.
// `name` must match whatever cmdLink/cmdVerify already set: null for a
// standalone/primary account (no device name shown/expected there, by
// convention - matches every real client), or the encrypted device name
// for a linked account, re-derived fresh each call from the account's
// stored ACI identity private key + the fixed kDeviceName - no need to
// persist the plaintext name anywhere since it's always the same constant.
void putFetchesMessages(Storage& storage, const AccountRecord& account, bool fetchesMessages) {
    std::string username =
        account.device_id == 1 ? account.aci : (account.aci + "." + std::to_string(account.device_id));
    AuthSocket socket(username, account.password,
                      [](const std::string&, const std::string&, const Bytes&) {});
    socket.connect();

    json name = nullptr;
    if (account.flow == "linked") {
        auto aciKeypair = storage.loadIdentityKeypair("aci");
        if (aciKeypair) name = encryptDeviceName(kDeviceName, aciKeypair->private_key);
    }

    json body = {
        {"fetchesMessages", fetchesMessages},
        {"registrationId", account.registration_id},
        {"pniRegistrationId", account.pni_registration_id},
        {"name", name},
        {"capabilities", capabilitiesJson()},
        {"unrestrictedUnidentifiedAccess", true},
        {"discoverableByPhoneNumber", true},
    };
    std::string bodyStr = body.dump();
    Bytes bodyBytes(bodyStr.begin(), bodyStr.end());
    auto response = socket.request("PUT", "/v1/accounts/attributes/", &bodyBytes);
    socket.close();
    if (response.status / 100 != 2) {
        throw std::runtime_error("PUT /v1/accounts/attributes/ failed with status " +
                                 std::to_string(response.status));
    }
}

void cmdDeactivate(const DaemonConfig& config, const std::string& accountName) {
    Storage storage(config.global.dbPath, config.global.dbKey, accountName);
    if (!storage.hasAccount()) {
        throw std::runtime_error("account '" + accountName + "' has no saved account in the database");
    }
    AccountRecord account = storage.loadAccount();
    putFetchesMessages(storage, account, /*fetchesMessages=*/false);
    std::cout << "[deactivate] account '" << accountName << "' (e164=" << account.e164
              << ") is now dormant (fetchesMessages=false) - senders can no longer reach this number.\n";
    std::cout << "[deactivate] this is REVERSIBLE and purely a server-side flag flip - no local data or "
                 "registration/identity keys were touched. Run `reactivate` to bring it back.\n";
    std::cout << "[deactivate] if signal2sip-daemon is currently running this account, stop it (or run "
                 "`signal2sip-gendb " << accountName << " disable`) first - otherwise its already-open "
                 "connection may keep the account looking active until it next reconnects.\n";
}

void cmdReactivate(const DaemonConfig& config, const std::string& accountName) {
    Storage storage(config.global.dbPath, config.global.dbKey, accountName);
    if (!storage.hasAccount()) {
        throw std::runtime_error("account '" + accountName + "' has no saved account in the database");
    }
    AccountRecord account = storage.loadAccount();
    putFetchesMessages(storage, account, /*fetchesMessages=*/true);
    std::cout << "[reactivate] account '" << accountName << "' (e164=" << account.e164
              << ") is active again (fetchesMessages=true), no re-verification needed.\n";
    std::cout << "[reactivate] start (or SIGHUP-reload) signal2sip-daemon with this account in its config to "
                 "actually resume receiving.\n";
}

// ---- Primary account lifecycle: delete-account (hard, irreversible) ----

// Best-effort: DELETE /v1/accounts/registration_lock. Safe to call even
// if no lock is set (Signal-Server's removeRegistrationLock just sets the
// lock hash/salt to null unconditionally, see AccountController.java) -
// matches signal-cli's own AccountHelper.deleteAccount(), which does the
// same thing and only logs a warning on failure rather than aborting.
void disableRegistrationLockBestEffort(AuthSocket& socket) {
    try {
        auto response = socket.request("DELETE", "/v1/accounts/registration_lock");
        if (response.status / 100 != 2) {
            std::cout << "[delete-account] warning: DELETE /v1/accounts/registration_lock returned status "
                      << response.status << " - continuing anyway (matches real clients' best-effort handling)\n";
        }
    } catch (const std::exception& e) {
        std::cout << "[delete-account] warning: failed to clear registration lock: " << e.what()
                  << " - continuing anyway\n";
    }
}

// Real, irreversible DELETE /v1/accounts/me - frees the phone number
// entirely from Signal's servers, destroys the account and every linked
// device at once. libsignal-service-java's own doc comment on this
// endpoint (AccountApi.kt) says "204: Success, 4401: Success" - Signal's
// server can complete this request by closing the WebSocket with close
// code 4401 instead of returning a normal response frame. AuthSocket
// doesn't decode the actual close code yet (see project memory
// signal2sip-account-deletion-unlink's Gap 2), so from here a connection
// that closes before any response arrives is genuinely AMBIGUOUS - it
// could be that success-via-4401-closure, or an unrelated network drop.
// Given that ambiguity, this deliberately does NOT auto-wipe local data
// on an ambiguous outcome - only a clean 2xx response is treated as
// confirmed success.
void cmdDeleteAccount(const DaemonConfig& config, const std::string& accountName) {
    Storage storage(config.global.dbPath, config.global.dbKey, accountName);
    if (!storage.hasAccount()) {
        throw std::runtime_error("account '" + accountName + "' has no saved account in the database");
    }
    AccountRecord account = storage.loadAccount();

    std::string username =
        account.device_id == 1 ? account.aci : (account.aci + "." + std::to_string(account.device_id));
    AuthSocket socket(username, account.password,
                      [](const std::string&, const std::string&, const Bytes&) {});
    socket.connect();

    disableRegistrationLockBestEffort(socket);

    auto response = socket.request("DELETE", "/v1/accounts/me");
    socket.close();

    if (response.status / 100 == 2) {
        storage.deleteAccount();
        std::cout << "[delete-account] account '" << accountName << "' (e164=" << account.e164
                  << ") DELETED from Signal's real servers (status " << response.status
                  << ") - the phone number is now free for anyone to register. Local data wiped too.\n";
        return;
    }

    if (response.status == 0) {
        std::cout << "[delete-account] AMBIGUOUS: the connection closed before any response arrived for account '"
                  << accountName << "' (e164=" << account.e164
                  << "). Signal's own protocol documents this endpoint as sometimes completing via a WebSocket "
                     "close (code 4401) instead of a normal response - this MAY have succeeded. signal2sip's "
                     "AuthSocket does not yet decode the actual close code to tell that apart from a genuine "
                     "network failure (see project notes on detecting real-side unlink for the same gap).\n";
        std::cout << "[delete-account] local data was deliberately left untouched. Verify manually (e.g. try "
                     "registering this e164 fresh elsewhere, or re-run `delete-account` - a second delete of an "
                     "already-deleted account should fail auth outright, distinguishing the two cases), then run "
                     "`unlink` yourself once you've confirmed it.\n";
        return;
    }

    throw std::runtime_error("DELETE /v1/accounts/me failed with status " + std::to_string(response.status));
}

// ---- SIP/deployment config (2026-08-07: moved from signal2sip.conf's old
// [account.<name>] sections into the `account` table's own columns - see
// schema.sql's comment on that table and AccountConfig's doc comment in
// Config.h for the full "why") ----

std::string pidFilePath(const GlobalConfig& global) {
    return dirName(global.dbPath) + "/signal2sip.pid";
}

// Best-effort: if signal2sip-daemon is currently running (a live pidfile
// whose PID's /proc/<pid>/exe genuinely still resolves to a
// signal2sip-daemon binary, not some unrelated process that happens to
// have reused that PID after the daemon exited), send it SIGHUP so a
// config/enable/disable change this command just made takes effect
// immediately instead of waiting out GlobalConfig::configPollIntervalSec.
// Purely a convenience - silently does nothing if the daemon isn't
// running or the pidfile is stale; the periodic poll is the real
// guarantee this change gets picked up. Reads /proc/<pid>/exe (a symlink
// to the real binary path) rather than /proc/<pid>/comm - comm is
// truncated to 15 bytes by the kernel, which would silently and
// permanently mismatch "signal2sip-daemon" (18 bytes; confirmed live -
// comm reads back as "signal2sip-daem").
void signalDaemonBestEffort(const GlobalConfig& global) {
    std::ifstream pidFile(pidFilePath(global));
    if (!pidFile) return;
    long pid = 0;
    pidFile >> pid;
    if (pid <= 0) return;

    char exePath[4096];
    ssize_t len = ::readlink(("/proc/" + std::to_string(pid) + "/exe").c_str(), exePath, sizeof(exePath) - 1);
    if (len <= 0) return; // no such process
    std::string exe(exePath, len);
    // "signal2sip-daemon" is 17 characters (miscounted as 18 in an
    // earlier version of this check, live 2026-08-07 - that off-by-one
    // made the suffix compare() always fail on length alone regardless
    // of content, so this function silently never signaled anything).
    static const std::string kDaemonName = "signal2sip-daemon";
    if (exe.size() < kDaemonName.size() ||
        exe.compare(exe.size() - kDaemonName.size(), kDaemonName.size(), kDaemonName) != 0) {
        return; // stale pidfile - a different process now has this pid
    }

    if (::kill(static_cast<pid_t>(pid), SIGHUP) == 0) {
        std::cout << "[gendb] signaled running signal2sip-daemon (pid " << pid << ") to reload now\n";
    }
}

// One entry per editable SIP/deployment-config field - name (as used on
// the CLI and matching the old .conf key names exactly, for muscle-memory
// continuity) plus a get/set pair operating on the in-memory AccountRecord
// (set validates the same way Config.cpp's accountConfigFromRecord() does
// downstream, so a bad value is rejected here at write time rather than
// silently breaking the daemon's next reload).
struct ConfigField {
    std::string name;
    std::function<std::string(const AccountRecord&)> get;
    std::function<void(AccountRecord&, const std::string&)> set;
};

const std::vector<ConfigField>& configFields() {
    static const std::vector<ConfigField> fields = {
        {"server_url", [](const AccountRecord& a) { return a.server_url; },
         [](AccountRecord& a, const std::string& v) { a.server_url = v; }},
        {"sip_host", [](const AccountRecord& a) { return a.sip_host; },
         [](AccountRecord& a, const std::string& v) { a.sip_host = v; }},
        {"sip_extension", [](const AccountRecord& a) { return a.sip_extension; },
         [](AccountRecord& a, const std::string& v) { a.sip_extension = v; }},
        {"sip_password", [](const AccountRecord& a) { return a.sip_password; },
         [](AccountRecord& a, const std::string& v) { a.sip_password = v; }},
        {"sip_bridge_destination", [](const AccountRecord& a) { return a.sip_bridge_destination; },
         [](AccountRecord& a, const std::string& v) { a.sip_bridge_destination = v; }},
        {"sip_bridge_did", [](const AccountRecord& a) { return a.sip_bridge_did; },
         [](AccountRecord& a, const std::string& v) { a.sip_bridge_did = v; }},
        {"sip_srtp", [](const AccountRecord& a) { return a.sip_srtp; },
         [](AccountRecord& a, const std::string& v) {
             if (v != "disabled" && v != "optional" && v != "mandatory") {
                 throw std::runtime_error("sip_srtp must be disabled/optional/mandatory, got '" + v + "'");
             }
             a.sip_srtp = v;
         }},
        {"sip_transport", [](const AccountRecord& a) { return a.sip_transport; },
         [](AccountRecord& a, const std::string& v) {
             if (v != "udp" && v != "tls") {
                 throw std::runtime_error("sip_transport must be udp/tls, got '" + v + "'");
             }
             a.sip_transport = v;
         }},
        {"sip_tls_ca_file", [](const AccountRecord& a) { return a.sip_tls_ca_file; },
         [](AccountRecord& a, const std::string& v) { a.sip_tls_ca_file = v; }},
        {"sip_tls_insecure", [](const AccountRecord& a) { return a.sip_tls_insecure ? "yes" : "no"; },
         [](AccountRecord& a, const std::string& v) {
             a.sip_tls_insecure = (v == "yes" || v == "true" || v == "1");
         }},
        {"outgoing_call_target", [](const AccountRecord& a) { return a.outgoing_call_target; },
         [](AccountRecord& a, const std::string& v) { a.outgoing_call_target = v; }},
        {"signal_proxy", [](const AccountRecord& a) { return a.signal_proxy; },
         [](AccountRecord& a, const std::string& v) { a.signal_proxy = v; }},
        {"signal_censorship_circumvention",
         [](const AccountRecord& a) { return a.signal_censorship_circumvention ? "yes" : "no"; },
         [](AccountRecord& a, const std::string& v) {
             a.signal_censorship_circumvention = (v == "yes" || v == "true" || v == "1");
         }},
    };
    return fields;
}

const ConfigField& findConfigField(const std::string& name) {
    for (const auto& f : configFields()) {
        if (f.name == name) return f;
    }
    throw std::runtime_error(
        "unknown config field '" + name +
        "' - known fields: server_url, sip_host, sip_extension, sip_password, sip_bridge_destination, "
        "sip_bridge_did, sip_srtp, sip_transport, sip_tls_ca_file, sip_tls_insecure, outgoing_call_target, "
        "signal_proxy, signal_censorship_circumvention");
}

void cmdConfigGet(const DaemonConfig& config, const std::string& accountName, const std::string& field) {
    Storage storage(config.global.dbPath, config.global.dbKey, accountName);
    if (!storage.hasAccount()) {
        throw std::runtime_error("account '" + accountName + "' has no saved account in the database");
    }
    AccountRecord account = storage.loadAccount();
    if (!field.empty()) {
        std::cout << field << "=" << findConfigField(field).get(account) << "\n";
        return;
    }
    for (const auto& f : configFields()) std::cout << f.name << "=" << f.get(account) << "\n";
    std::cout << "enabled=" << (account.enabled ? "yes" : "no") << "\n";
    std::cout << "config_version=" << account.config_version << "\n";
}

void cmdConfigSet(const DaemonConfig& config, const std::string& accountName, const std::string& field,
                  const std::string& value) {
    Storage storage(config.global.dbPath, config.global.dbKey, accountName);
    if (!storage.hasAccount()) {
        throw std::runtime_error("account '" + accountName + "' has no saved account in the database");
    }
    AccountRecord account = storage.loadAccount();
    findConfigField(field).set(account, value);
    storage.saveAccountConfig(account);
    std::cout << "[config] " << accountName << ": " << field << "=" << value << "\n";
    signalDaemonBestEffort(config.global);
}

void cmdSetEnabled(const DaemonConfig& config, const std::string& accountName, bool enabled) {
    Storage storage(config.global.dbPath, config.global.dbKey, accountName);
    if (!storage.hasAccount()) {
        throw std::runtime_error("account '" + accountName + "' has no saved account in the database");
    }
    AccountRecord account = storage.loadAccount();
    account.enabled = enabled;
    storage.saveAccountConfig(account);
    std::cout << "[" << (enabled ? "enable" : "disable") << "] account '" << accountName << "' is now "
              << (enabled ? "enabled" : "disabled") << "\n";
    signalDaemonBestEffort(config.global);
}

// Unlike DaemonConfig::load()'s `accounts` (enabled=1 only, and silently
// skips an account whose config fails validation - see its own doc
// comment), this shows every account row regardless of enabled/validity,
// since the whole point of `list` is visibility into everything that
// exists.
void cmdListAccounts(const GlobalConfig& global) {
    std::vector<AccountSummary> accounts = listAllAccounts(global.dbPath, global.dbKey);
    if (accounts.empty()) {
        std::cout << "(no accounts)\n";
        return;
    }
    for (const AccountSummary& s : accounts) {
        std::cout << s.account_name << "\te164=" << s.e164 << "\t" << (s.enabled ? "enabled" : "disabled")
                  << "\tconfig_version=" << s.config_version << "\n";
    }
}

void printUsage() {
    std::cerr
        << "usage:\n"
          "  signal2sip-gendb <account-name> register --e164 <e164> [sms|voice] [--config <path>]\n"
          "  signal2sip-gendb <account-name> register-captcha <token> [--config <path>]\n"
          "  signal2sip-gendb <account-name> verify <code> [--config <path>]\n"
          "  signal2sip-gendb <account-name> link [--config <path>]\n"
          "  signal2sip-gendb <account-name> unlink [--config <path>]\n"
          "  signal2sip-gendb <account-name> deactivate [--config <path>]  (alias: unregister)\n"
          "  signal2sip-gendb <account-name> reactivate [--config <path>]\n"
          "  signal2sip-gendb <account-name> delete-account [--config <path>]\n"
          "  signal2sip-gendb <account-name> enable|disable [--config <path>]\n"
          "  signal2sip-gendb <account-name> config get [field] [--config <path>]\n"
          "  signal2sip-gendb <account-name> config set <field> <value> [--config <path>]\n"
          "  signal2sip-gendb list [--config <path>]\n"
          "\n"
          "`delete-account` is REAL and IRREVERSIBLE - it deletes the account from Signal's real servers\n"
          "(DELETE /v1/accounts/me) and frees the phone number for anyone to register, then wipes local data\n"
          "too on confirmed success. Unlike deactivate, there is no undo.\n"
          "\n"
          "`unlink` wipes this account's local data (keys, sessions, cached contacts, SIP/deployment config) from\n"
          "the database. It is LOCAL ONLY - it does not contact Signal's servers, so use it after the account is\n"
          "already gone on the real side (a real unlink/delete-account done elsewhere), not as a way to perform\n"
          "that unlink itself.\n"
          "\n"
          "`deactivate`/`reactivate` are the opposite: a REAL, reversible server-side flag flip\n"
          "(fetchesMessages) using the account's own stored credentials - senders can't reach a deactivated\n"
          "number until `reactivate` is run. Neither touches local data or requires re-verification. `unregister`\n"
          "still works as an alias for `deactivate`, for anything already scripted against the old name.\n"
          "\n"
          "`enable`/`disable` control whether signal2sip-daemon sets this account up at all - the running daemon\n"
          "picks up a change within 30s (configurable via [global] config_poll_interval_sec), or immediately if\n"
          "it finds the daemon's pid and can signal it (best-effort).\n"
          "\n"
          "`config get`/`config set` read/write this account's SIP/deployment settings (sip_host, sip_password,\n"
          "sip_bridge_destination, sip_bridge_did, sip_srtp, sip_transport, sip_tls_ca_file, sip_tls_insecure,\n"
          "outgoing_call_target, server_url) - these used to live in this file's own [account.<name>] sections,\n"
          "now they're in the database, live-editable the same way enable/disable is. `config get` with no field\n"
          "prints everything; `config set` picks up the running daemon the same way enable/disable does.\n"
          "\n"
          "Config file defaults to /etc/signal2sip/signal2sip.conf (else ./signal2sip.conf), same as\n"
          "signal2sip-daemon, and now only ever needs a [global] section (db_path/db_key) - bootstrapped\n"
          "automatically on a clean first run: db_path defaults to /var/lib/signal2sip/signal2sip.db, and db_key\n"
          "is freshly generated and printed once (back it up - it's the passphrase for every account's encrypted\n"
          "keys) - but only when no database file exists at db_path yet; otherwise gendb refuses rather than\n"
          "guess. `register --e164 ...`/`link` can target a brand-new account name with no existing database row\n"
          "at all - they just create one.\n";
}

struct ParsedArgs {
    std::string accountName;
    std::string command;
    std::vector<std::string> positional; // command-specific, in order (transport/token/code)
    std::string e164;
    std::string configPath;
};

ParsedArgs parseArgs(int argc, char** argv) {
    std::vector<std::string> rest;
    ParsedArgs result;
    for (int i = 1; i < argc; i++) {
        std::string arg = argv[i];
        if (arg == "--e164" && i + 1 < argc) {
            result.e164 = argv[++i];
        } else if (arg == "--config" && i + 1 < argc) {
            result.configPath = argv[++i];
        } else {
            rest.push_back(arg);
        }
    }
    // `list` is the one command with no <account-name> - it lists every
    // account, so there's nothing to scope it to.
    if (rest.size() == 1 && rest[0] == "list") {
        result.command = "list";
        return result;
    }
    if (rest.size() < 2) throw std::runtime_error("missing <account-name> <command>");
    result.accountName = rest[0];
    result.command = rest[1];
    result.positional.assign(rest.begin() + 2, rest.end());
    return result;
}

} // namespace

int main(int argc, char** argv) {
    // glibc only line-buffers stdout when it's a real terminal - piped
    // to anything else (a file, or another process's pipe), it silently
    // switches to full block buffering. Harmless for a normal terminal
    // run or for a caller like runGendb() that reads everything only
    // after the process exits, but it means `link`'s std::cout QR/status
    // output can sit unflushed indefinitely while the process blocks for
    // up to ~90s waiting for a scan - exactly the case signal2sip-tui's
    // Screen 5 needs to stream live. Force line buffering unconditionally
    // so a pipe behaves the same as a terminal here.
    ::setvbuf(stdout, nullptr, _IOLBF, 0);

    for (int i = 1; i < argc; i++) {
        std::string arg = argv[i];
        if (arg == "--help" || arg == "-h") {
            printUsage();
            return 0;
        }
    }

    curl_global_init(CURL_GLOBAL_DEFAULT);
    int exitCode = 0;
    ParsedArgs args;
    try {
        args = parseArgs(argc, argv);
    } catch (const std::exception& e) {
        std::cerr << "[gendb] error: " << e.what() << "\n";
        printUsage();
        curl_global_cleanup();
        return 1;
    }

    try {
        std::string configPath = resolveGendbConfigPath(args.configPath);
        bootstrapGlobalConfigIfNeeded(configPath);
        DaemonConfig config = DaemonConfig::load(configPath);

        if (args.command == "register") {
            std::string transport = args.positional.empty() ? "sms" : args.positional[0];
            cmdRegister(config, args.accountName, args.e164, transport);
        } else if (args.command == "register-captcha") {
            if (args.positional.empty()) throw std::runtime_error("register-captcha needs a <token>");
            cmdRegisterCaptcha(config, args.accountName, args.positional[0]);
        } else if (args.command == "verify") {
            if (args.positional.empty()) throw std::runtime_error("verify needs a <code>");
            cmdVerify(config, args.accountName, args.positional[0]);
        } else if (args.command == "link") {
            cmdLink(config, args.accountName);
        } else if (args.command == "unlink") {
            cmdUnlink(config, args.accountName);
        } else if (args.command == "deactivate" || args.command == "unregister") {
            cmdDeactivate(config, args.accountName);
        } else if (args.command == "reactivate") {
            cmdReactivate(config, args.accountName);
        } else if (args.command == "delete-account") {
            cmdDeleteAccount(config, args.accountName);
        } else if (args.command == "enable") {
            cmdSetEnabled(config, args.accountName, true);
        } else if (args.command == "disable") {
            cmdSetEnabled(config, args.accountName, false);
        } else if (args.command == "config") {
            if (args.positional.empty()) throw std::runtime_error("config needs a get/set subcommand");
            const std::string& sub = args.positional[0];
            if (sub == "get" || sub == "list") {
                std::string field = args.positional.size() > 1 ? args.positional[1] : "";
                cmdConfigGet(config, args.accountName, field);
            } else if (sub == "set") {
                if (args.positional.size() < 3) throw std::runtime_error("config set needs <field> <value>");
                cmdConfigSet(config, args.accountName, args.positional[1], args.positional[2]);
            } else {
                throw std::runtime_error("config: unknown subcommand '" + sub + "' - use get/set");
            }
        } else if (args.command == "list") {
            cmdListAccounts(config.global);
        } else {
            printUsage();
            exitCode = 1;
        }
    } catch (const std::exception& e) {
        std::cerr << "[gendb] error: " << e.what() << "\n";
        exitCode = 1;
    }

    curl_global_cleanup();
    return exitCode;
}
