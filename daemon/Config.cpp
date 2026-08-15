#include "Config.h"

#include <cstdio>
#include <cstdlib>
#include <fstream>
#include <iostream>
#include <map>
#include <stdexcept>
#include <sys/stat.h>
#include <unistd.h>

#include "../storage/Storage.h"

namespace signal2sip {

namespace {

bool fileExists(const std::string& path) {
    struct stat st{};
    return ::stat(path.c_str(), &st) == 0;
}

std::string trim(const std::string& s) {
    size_t start = s.find_first_not_of(" \t\r\n");
    if (start == std::string::npos) return "";
    size_t end = s.find_last_not_of(" \t\r\n");
    return s.substr(start, end - start + 1);
}

// section -> key -> value
using IniMap = std::map<std::string, std::map<std::string, std::string>>;

IniMap parseIni(const std::string& path) {
    std::ifstream f(path);
    if (!f) throw std::runtime_error("cannot open config file: " + path);

    IniMap result;
    std::string section;
    std::string line;
    while (std::getline(f, line)) {
        std::string trimmed = trim(line);
        if (trimmed.empty() || trimmed[0] == ';' || trimmed[0] == '#') continue;
        if (trimmed.front() == '[' && trimmed.back() == ']') {
            section = trimmed.substr(1, trimmed.size() - 2);
            continue;
        }
        size_t eq = trimmed.find('=');
        if (eq == std::string::npos) continue;
        std::string key = trim(trimmed.substr(0, eq));
        std::string value = trim(trimmed.substr(eq + 1));
        result[section][key] = value;
    }
    return result;
}

std::string getOr(const IniMap& ini, const std::string& section, const std::string& key,
                   const std::string& fallback) {
    auto sec = ini.find(section);
    if (sec == ini.end()) return fallback;
    auto it = sec->second.find(key);
    if (it == sec->second.end() || it->second.empty()) return fallback;
    return it->second;
}

// Builds one account's AccountConfig from its database row (see
// Storage.h's AccountRecord/schema.sql's own comment on the `account`
// table for why these fields live there now, not a [account.<name>]
// section) - applies the exact same validation this project always has
// (sip_srtp/sip_transport enum checks, the tls_ca_file/tls_insecure
// requirement, the :5061 TLS default port). Throws std::runtime_error on
// an invalid config, same as before - the caller (DaemonConfig::load())
// catches this per-account so one account's bad config doesn't take every
// other account down with it.
AccountConfig accountConfigFromRecord(const std::string& name, const AccountRecord& record) {
    AccountConfig account;
    account.name = name;
    account.configVersion = record.config_version;

    account.e164 = record.e164;
    if (account.e164.empty()) {
        throw std::runtime_error("account '" + name + "': e164 is empty");
    }
    account.serverUrl = record.server_url;

    account.sipHost = record.sip_host;
    account.sipExtension = record.sip_extension;
    account.sipPassword = record.sip_password;
    account.sipBridgeDestination = record.sip_bridge_destination;
    account.sipBridgeDid = record.sip_bridge_did;

    account.sipSrtp = record.sip_srtp.empty() ? "disabled" : record.sip_srtp;
    if (account.sipSrtp != "disabled" && account.sipSrtp != "optional" && account.sipSrtp != "mandatory") {
        throw std::runtime_error("account '" + name + "': sip_srtp must be disabled/optional/mandatory, got '" +
                                 account.sipSrtp + "'");
    }

    account.sipTransport = record.sip_transport.empty() ? "udp" : record.sip_transport;
    if (account.sipTransport != "udp" && account.sipTransport != "tls") {
        throw std::runtime_error("account '" + name + "': sip_transport must be udp/tls, got '" +
                                 account.sipTransport + "'");
    }
    // sip_host with no explicit ":port" defaults to Asterisk's plain SIP
    // port implicitly (whatever sip:'s own resolution does) - but for
    // tls, default explicitly to 5061 (Asterisk's usual TLS listener
    // port, and this project's own DPDZK test setup) rather than leaving
    // it to chance.
    if (account.sipTransport == "tls" && !account.sipHost.empty() && account.sipHost.find(':') == std::string::npos) {
        account.sipHost += ":5061";
    }
    account.sipTlsCaFile = record.sip_tls_ca_file;
    account.sipTlsInsecure = record.sip_tls_insecure;
    if (account.sipTransport == "tls" && account.sipTlsCaFile.empty() && !account.sipTlsInsecure) {
        throw std::runtime_error(
            "account '" + name +
            "': sip_transport=tls needs either sip_tls_ca_file (pin the Asterisk server's certificate) or "
            "sip_tls_insecure=yes (skip verification entirely) - one of the two is required, not silently "
            "insecure by default");
    }

    account.outgoingCallTarget = record.outgoing_call_target;

    account.signalProxy = record.signal_proxy;
    account.signalCensorshipCircumvention = record.signal_censorship_circumvention;

    return account;
}

} // namespace

std::string resolveConfigPath(int argc, char** argv) {
    if (argc > 1 && argv[1][0] != '\0') return argv[1];
    if (fileExists("/etc/signal2sip/signal2sip.conf")) return "/etc/signal2sip/signal2sip.conf";
    return "./signal2sip.conf";
}

std::string resolveCaCertPath() {
    if (fileExists("/etc/signal2sip/certs/signal-root-ca.pem")) return "/etc/signal2sip/certs/signal-root-ca.pem";
    return "./certs/signal-root-ca.pem";
}

void refuseIfRunningAsRoot(const char* programName) {
    if (::geteuid() != 0) return;
    std::cerr << "[" << programName
               << "] refusing to start as root - create a dedicated non-root user (e.g. `signal2sip`), chown the "
                  "config file and database to it, and run this as that user instead. Running Signal/SIP-facing "
                  "network code as root is unnecessary privilege this project deliberately doesn't want.\n";
    std::exit(1);
}

void checkOwnerAndModeOrDie(const std::string& path, bool requireExactMode0600) {
    struct stat st{};
    if (::stat(path.c_str(), &st) != 0) return; // doesn't exist yet - nothing to check

    if (st.st_uid != ::getuid()) {
        std::cerr << "[config] refusing to use '" << path << "' - it's owned by uid " << st.st_uid
                   << ", not the user running this process (uid " << ::getuid()
                   << "). chown it to the right user first.\n";
        std::exit(1);
    }
    if (requireExactMode0600 && (st.st_mode & 07777) != 0600) {
        char modeStr[8];
        std::snprintf(modeStr, sizeof(modeStr), "%04o", st.st_mode & 07777);
        std::cerr << "[config] refusing to use '" << path << "' - its permissions are " << modeStr
                   << ", not exactly 0600 (it contains the database passphrase in plain text). `chmod 600 " << path
                   << "`.\n";
        std::exit(1);
    }
}

DaemonConfig DaemonConfig::load(const std::string& path) {
    IniMap ini = parseIni(path);

    DaemonConfig daemon;
    daemon.global.dbPath = getOr(ini, "global", "db_path", "");
    if (daemon.global.dbPath.empty()) {
        throw std::runtime_error("signal2sip.conf: [global] db_path is required");
    }
    daemon.global.dbKey = getOr(ini, "global", "db_key", "");
    if (daemon.global.dbKey.empty()) {
        throw std::runtime_error("signal2sip.conf: [global] db_key is required");
    }
    daemon.global.sipRegWatchdogSec =
        static_cast<unsigned>(std::stoul(getOr(ini, "global", "sip_reg_watchdog_sec", "60")));
    daemon.global.resolvedContactTtlSec =
        static_cast<unsigned>(std::stoul(getOr(ini, "global", "resolved_contact_ttl_sec", "86400")));
    daemon.global.storageSyncIntervalSec =
        static_cast<unsigned>(std::stoul(getOr(ini, "global", "storage_sync_interval_sec", "43200")));
    daemon.global.configPollIntervalSec =
        static_cast<unsigned>(std::stoul(getOr(ini, "global", "config_poll_interval_sec", "30")));
    daemon.global.onAccountErrorCmd = getOr(ini, "global", "on_account_error_cmd", "");

    // Every account's SIP/deployment config + enabled flag now lives in
    // the database (see AccountConfig's own doc comment) - zero accounts
    // is still a valid config (gendb needs to load a config that has
    // [global] but no accounts registered yet, to add the very first
    // one).
    for (const AccountSummary& summary : listAllAccounts(daemon.global.dbPath, daemon.global.dbKey)) {
        if (!summary.enabled) continue;
        try {
            Storage storage(daemon.global.dbPath, daemon.global.dbKey, summary.account_name);
            AccountRecord record = storage.loadAccount();
            daemon.accounts.push_back(accountConfigFromRecord(summary.account_name, record));
        } catch (const std::exception& e) {
            std::cerr << "[config] skipping account '" << summary.account_name << "': " << e.what() << "\n";
        }
    }

    return daemon;
}

GlobalConfig loadGlobalConfigLenient(const std::string& path) {
    GlobalConfig global;
    if (!fileExists(path)) return global;
    IniMap ini = parseIni(path);
    global.dbPath = getOr(ini, "global", "db_path", "");
    global.dbKey = getOr(ini, "global", "db_key", "");
    return global;
}

} // namespace signal2sip
