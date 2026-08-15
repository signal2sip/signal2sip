#pragma once

// signal2sip.conf parser - minimal hand-rolled INI reader (no new
// dependency; matches this project's existing preference for small
// hand-rolled parsing over pulling in a library for something this simple
// - see AuthSocket.cpp/pjsip-gateway.cpp's own hand-rolled JSON field
// extraction). Section-and-key-value only, `;`/`#` comments - but ONLY as
// their own whole line. There is no inline/trailing-comment support: a
// line like `sip_extension=foo # my trunk` puts the literal text
// `foo # my trunk` (space, `#`, and all) into the value - found live as
// the actual cause of a PJSIP_EINVALIDURI failure (a commented-out
// annotation left on the same line as a real sip_extension= value). Put
// comments on their own line above the setting they refer to instead.
//
// 2026-08-07: this file now only ever contains one `[global]` section -
// every account's own config (SIP/deployment settings + enabled flag)
// moved into the `account` table (see schema.sql's own comment on it),
// editable live via `signal2sip-gendb <name> config set/enable/disable`
// instead of hand-editing `[account.<name>]` sections here. One process
// still serves N Signal accounts (each optionally with its own SIP
// trunk) from a single shared database (see GlobalConfig/Storage's own
// doc comments) - `<name>` (the account's key everywhere in the daemon:
// the accounts map, log-line prefixes, the `account_name` column
// scoping its rows) is just the database's account_name value now, same
// "purely arbitrary label, no relation to e164 required" meaning it
// always had.
//
// Was one account/one file per process (matching tg2sip-webrtc's own
// model) - deliberately reversed since tg2sip has no real
// in-process-multi-account precedent to mirror; see the project's memory
// for that decision.
//
// argv[1] -> /etc/signal2sip/signal2sip.conf -> ./signal2sip.conf,
// matching tg2sip/utils.cpp's resolve_config_path() exactly (same
// fallback order, same rationale: works both installed via systemd and
// run from a dev checkout).

#include <string>
#include <vector>

namespace signal2sip {

std::string resolveConfigPath(int argc, char** argv);

// Same fallback order as resolveConfigPath() above: /etc/signal2sip/... for
// an installed deployment, else a path relative to the current working
// directory for a dev checkout. Single source of truth for the CA cert
// every native TLS client in this project pins (AuthSocket, gendb,
// RegistrationClient) - was 8 separate hardcoded absolute paths before.
std::string resolveCaCertPath();

// [global] - one per file, shared by every account.
struct GlobalConfig {
    std::string dbPath;  // required - one SQLCipher file shared by all accounts
    std::string dbKey;   // required - SQLCipher passphrase

    // How long (seconds) a SIP account may sit unregistered before the
    // daemon forces a fresh registration attempt itself, regardless of
    // what PJSIP's own auto-retry would do. Needed because PJSIP only
    // auto-retries a short allowlist of "temporary" failure codes (408,
    // 500, 502, 503, 504, 480, 6xx - see pjsua_acc.c's regc_cb) - a 403
    // Forbidden (e.g. from a transient max_contacts collision after an
    // unclean process kill, confirmed live 08-04) is NOT on that list, so
    // without this watchdog the account would stay unregistered forever
    // until the whole daemon is restarted, which needlessly disrupts
    // every other account too. See main.cpp's registration-watchdog loop.
    unsigned sipRegWatchdogSec = 60;

    // How long (seconds) a cached e164->ACI/PNI resolution (see
    // ContactResolver.h / native/signal/Cdsi.h / the resolved_contact
    // table) is trusted before outgoing_call_target re-resolves it via a
    // real Contact Discovery Service lookup instead of reusing the cached
    // row. Real CDS lookups are rate-limited per account, so this isn't
    // just an optimization - too low defeats the point of caching at all.
    // Default 1 day: long enough that a normal outgoing_call_target
    // (checked once per account setup, not per call attempt) essentially
    // never re-resolves in practice, short enough that a target who
    // genuinely changed numbers (see project notes: PNI, unlike ACI,
    // changes with a real number change) doesn't stay wrong indefinitely.
    unsigned resolvedContactTtlSec = 86400;

    // How often (seconds) each account with a real account_entropy_pool
    // (i.e. gendb-linked, see StorageServiceSync.h) re-syncs its real
    // contact list from Signal's StorageService - see main.cpp's
    // storage-sync loop, right next to the registration watchdog above.
    // fetchStorageContacts() only ever ran once at startup before this
    // (2026-08-05) - a contact added/changed on the real primary device
    // afterward would never be picked up until the whole daemon
    // restarted. Default 12 hours: real contact lists change rarely, and
    // this hits Signal's real storage.signal.org host (not just a local
    // DB), so this shouldn't be aggressive - but also shouldn't need to
    // be as long as resolvedContactTtlSec above, since unlike a CDS
    // lookup this isn't separately rate-limited per-target.
    unsigned storageSyncIntervalSec = 43200;

    // How often (seconds) main()'s loop re-reads every account's SIP/
    // deployment config + enabled flag from the database (see
    // AccountConfig's own doc comment - 2026-08-07 moved these out of
    // this file's [account.<name>] sections into the `account` table,
    // editable live via `signal2sip-gendb <name> config set/enable/
    // disable`) and rebuilds any account whose config_version changed -
    // see main.cpp's reloadConfig(). Deliberately NOT on the same ~200ms
    // tick as the registration/socket watchdogs above - a config change
    // is a human running a CLI command, not a time-critical failure
    // condition, and polling every account's row that often at any real
    // account count would be pointless DB load for something that
    // changes maybe a few times a day. `gendb config set/enable/disable`
    // also sends the running daemon SIGHUP on a best-effort basis (see
    // gendb's own doc comment) for near-instant pickup without waiting
    // out this interval - this is just the fallback/floor.
    unsigned configPollIntervalSec = 30;

    // Optional external hook for an account-level problem the daemon
    // cannot recover from by itself (today: AuthSocket::isDeauthorized()
    // - device unlinked/deleted elsewhere, or a future Registration Lock
    // takeover attempt once SVR2 PIN support exists - see the website's
    // Signal PIN & Registration Lock doc page). Empty (default) means "no
    // hook" - the daemon still logs loudly to stderr (tagged for
    // journald's err priority) and persists `account.last_error` either
    // way; this is purely an extra, opt-in notification path, deliberately
    // NOT a specific channel like email/webhook so it can be pointed at
    // literally anything (ntfy.sh curl, a Telegram bot script, `mail`,
    // systemd's own escalation). Run as `/bin/sh -c '<value>' sh
    // <account_name> <e164> <error_type>` (see runAccountErrorHook() in
    // main.cpp) - account name/e164/error type arrive as $1/$2/$3 inside
    // the command, never string-concatenated into it. Fire-and-forget:
    // double-forked so the daemon's own main loop never blocks on it,
    // regardless of how long it takes to run.
    std::string onAccountErrorCmd;
};

// 2026-08-07: every field below except `name` now lives in the `account`
// table (see schema.sql's own comment on it), not a [account.<name>]
// section in this file anymore - DaemonConfig::load() builds these by
// querying the database (see Storage.h's listAllAccounts()/loadAccount()),
// filtered to enabled=true. `name` itself is still just the DB's
// account_name column value, same meaning as the old section-header
// label.
struct AccountConfig {
    // This account's key everywhere in the daemon (the accounts map,
    // log-line prefixes, Storage's account_name scoping) and to derive
    // PJSIP transport port defaults.
    std::string name;

    // The `account.config_version` value this AccountConfig was built
    // from (see Storage.h's own doc comment on that column) - main.cpp's
    // reloadConfig() compares this against a freshly re-loaded value on
    // each poll/SIGHUP to detect a `gendb config set` change and rebuild
    // just that one account. Not meaningful outside the daemon's own
    // in-memory bookkeeping (gendb doesn't read this field).
    int64_t configVersion = 0;

    // The account's REAL identity, not a label - the actual phone number
    // this Signal account is registered/linked under, in E.164 format
    // (leading '+', country code, e.g. "+380000000001"). Unlike `name`
    // above (an arbitrary label you pick), this value has no freedom:
    // Signal's own servers identify the account by this number (and its
    // derived ACI), so it must be the account's genuine registered
    // number, not a made-up placeholder.
    std::string e164;       // required
    std::string serverUrl;  // empty = production chat.signal.org

    // Entirely optional; an account with no sip_host never touches PJSIP
    // at all (Signal-only account).
    std::string sipHost;
    std::string sipExtension;
    std::string sipPassword;
    // What to dial out to when bridging an incoming Signal call to SIP -
    // e.g. "*43" for DPDZK's echo test, or a real destination extension.
    // Only meaningful when this account's PJSIP endpoint context on the
    // Asterisk/FreePBX side is "from-internal" (the usual FreePBX default
    // for a plain extension) - the dialed value is looked up as an
    // internal extension there, so it has to already BE one.
    std::string sipBridgeDestination;

    // Same underlying mechanic (see startSipBridge()'s destUri
    // construction - both fields end up dialed the exact same way, this
    // is purely about which one an account fills in), but for an account
    // whose PJSIP endpoint context is instead "from-pstn" (matching
    // tg2sip's own convention) - the dialed value there is a DID that
    // FreePBX's own Inbound Route (configured in the GUI, not here) uses
    // to decide the REAL destination: ring group, IVR, time conditions,
    // failover, all changeable without touching this config or
    // restarting the daemon. If both this and sipBridgeDestination are
    // set, this one wins - matches the corresponding Asterisk endpoint
    // only ever having ONE context, never both at once, so only one of
    // these two should realistically ever be set per account anyway.
    std::string sipBridgeDid;

    // Secure media transport (SDES-SRTP) for the RTP leg to Asterisk -
    // NOT the Signal-side call encryption (already independently handled
    // by RingRTC/libsignal regardless of this setting); purely about the
    // local PJSIP<->Asterisk hop. One of "disabled" (default - plain RTP,
    // this project's behavior before 08-03), "optional" (offers SRTP,
    // PJSIP falls back to plain RTP if the Asterisk endpoint doesn't have
    // media_encryption=sdes configured - safe to turn on unilaterally,
    // won't break an unprepared trunk), or "mandatory" (refuses plain RTP
    // - only enable once the Asterisk side is confirmed to negotiate SRTP,
    // or registration/calls on this account stop working). Verified live
    // 08-03 against DPDZK: real tone round-tripped with mandatory SRTP
    // negotiated (RTP/SAVP, AES_CM_128_HMAC_SHA1_80). By itself, the SDES
    // key exchange travels in the SDP over whatever SIP transport this
    // account uses (see sipTransport below) - over plain UDP that's in
    // the clear, protecting only against something that can see RTP but
    // not SIP signaling; pair with sip_transport=tls for the signaling to
    // be protected too.
    std::string sipSrtp = "disabled"; // "disabled" | "optional" | "mandatory"

    // SIP signaling transport to Asterisk for THIS account - "udp"
    // (default, current behavior) or "tls" (SIPS - idUri/registrarUri get
    // the sips: scheme instead of sip:). Every account gets its OWN
    // dedicated transport regardless of which (see main.cpp's
    // createAccountUdpTransport()/createAccountTlsTransport()) - PJSIP
    // can't reliably route an incoming call to the right account when
    // several accounts share one transport and the Request-URI doesn't
    // match any of their own identities (found live 2026-08-05: a real
    // SIP-triggered outgoing-call INVITE's Request-URI is the DIALED
    // NUMBER, not any account's own extension, so PJSIP fell back to
    // whatever account happened to be created first - wrong account,
    // wrong SRTP policy, spurious 488 Not Acceptable Here). TLS transports
    // additionally need to be separate because CaListFile/verifyServer are
    // configured once per transport factory and apply to every connection
    // made through it. If sip_host has no explicit ":port", tls defaults
    // it to ":5061" (Asterisk's usual TLS listener port) - see Config.cpp.
    std::string sipTransport = "udp"; // "udp" | "tls"

    // Only meaningful when sipTransport == "tls". Path to a PEM file
    // listing the certificate(s) to trust for THIS account's dedicated
    // TLS transport - pinning (trust exactly this certificate, not a real
    // CA bundle) is the right model for the common case of an internal
    // Asterisk box with a self-signed cert. Per-account, not [global],
    // because different accounts can legitimately point at different
    // Asterisk hosts with different certificates. Required unless
    // sipTlsInsecure is set instead.
    std::string sipTlsCaFile;

    // Explicit, loud opt-in to skip TLS server certificate verification
    // entirely for this account's TLS transport (the channel is still
    // encrypted - passive eavesdropping is still defeated - but the
    // server's identity isn't checked, so this doesn't protect against
    // interception by something that can also redirect/intercept the
    // connection on this network). Only takes effect if sipTlsCaFile is
    // empty; pinning wins if both are set. Default false - sip_transport=
    // tls with neither this nor sipTlsCaFile set is a config error (see
    // Config.cpp), not a silent insecure default.
    bool sipTlsInsecure = false;

    // The other account to place a test outgoing call to, if set - either
    // a ServiceId (ACI/PNI UUID, own ACI is logged at startup) or a plain
    // e164 phone number ('+' prefixed). An e164 is resolved to a real
    // ServiceId via CDSI (see ContactResolver.h/native/signal/Cdsi.h) the
    // first time it's used - GET /v2/keys/{e164}/* itself 404s on the
    // current Signal server, only a ServiceId works there, which is
    // exactly the problem CDSI resolution solves. Empty means this account
    // only answers incoming calls.
    std::string outgoingCallTarget;

    // See AuthSocket.h's own doc comment for what these mean - passed
    // straight through to AuthSocket's constructor.
    std::string signalProxy;
    bool signalCensorshipCircumvention = false;

    bool hasSip() const { return !sipHost.empty(); }
};

struct DaemonConfig {
    GlobalConfig global;
    std::vector<AccountConfig> accounts;

    // Reads [global] from `path` (still the only thing this file
    // contains), then queries the database at global.dbPath for every
    // account with enabled=1 and builds `accounts` from each one's stored
    // config (see AccountConfig's own doc comment) - applying the same
    // validation DaemonConfig::load() always has (sip_srtp/sip_transport
    // enum checks, the tls_ca_file/tls_insecure requirement, the :5061
    // default port). A single bad account's config no longer aborts the
    // whole load - see Config.cpp's own comment on why (this is now
    // called from a periodic poll, not just startup, and one account with
    // a bad config set via `gendb config set` shouldn't take every other
    // account down with it).
    static DaemonConfig load(const std::string& path);
};

// Reads only [global] db_path/db_key from `path`, tolerating a missing
// file or missing/empty fields (returns them as "" instead of throwing) -
// unlike DaemonConfig::load()'s validation, which signal2sip-daemon itself
// needs. Used by gendb (native/gendb/main.cpp) to detect what's missing
// before bootstrapping a brand-new [global] section on first run.
GlobalConfig loadGlobalConfigLenient(const std::string& path);

} // namespace signal2sip
