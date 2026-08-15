// signal2sip-tui: curses-style account manager - see the design writeup
// (project memory project_signal2sip_tui_future.md /
// project_signal2sip_config_in_db.md's own "TUI" note) for the full
// rationale. Deliberately reads the shared SQLCipher database directly
// (same Storage class signal2sip-daemon/signal2sip-gendb already use),
// never talks to a running daemon over any socket - this is a
// non-realtime account/config manager, not a call/connection monitor.
// Every mutating action shells out to the already-built signal2sip-gendb
// binary instead of reimplementing its logic here, so validation and
// error handling stay in exactly one place.
//
// This cut implements all 5 planned screens: Screen 1 (account list),
// Screen 2 (account detail), Screen 3 (confirmation dialogs, wired to
// real signal2sip-gendb subprocess calls), Screen 4 (SIP config editor),
// and Screen 5 (new-account wizard - register or link). Two confirmation
// severities, matching the concept's own distinction: a plain y/n with
// the real consequence spelled out for reversible-but-impactful actions
// (disable/enable/deactivate), and a type-the-account-name confirmation
// for the one truly irreversible action (delete-account) - mirrors
// GitHub's own repo-delete pattern. Screen 4 edits are written one
// changed field at a time via `signal2sip-gendb <name> config set
// <field> <value>` (never straight to the database), reusing exactly
// the same validation Config.cpp's accountConfigFromRecord() applies at
// daemon-load time, so a value rejected here would have been rejected
// there too. Screen 5's register path (Flow A) is three ordinary
// synchronous gendb calls; its link path (Flow B) runs gendb in a
// background thread instead, since linking prints an in-terminal QR
// code and then blocks for up to ~90s waiting for a phone to scan it -
// see startLinkThread()'s own comment for why that specific step can't
// use the same batch-collect-then-show helper every other action does.
//
// Status color rules (deliberately NOT symmetric - see the concept
// discussion this was built from):
//   - red is reserved for "enabled but not actually connected" - a real
//     problem. `disabled` is never red, it's a deliberate state.
//   - media encryption is binary per call (either encrypted or not), so
//     there is no "half-encrypted" indicator: sip_srtp=mandatory is the
//     ONLY state that's a genuine guarantee (green); optional and
//     disabled are both shown identically amber, since neither
//     guarantees anything about any specific call - only their labels
//     differ.
// 2026-08-15: the "daemon periodically writes its own last-known status"
// mechanism this comment used to say was a prerequisite now exists -
// account.last_error/last_error_at (schema.sql), written by the daemon's
// socket watchdog the moment AuthSocket::isDeauthorized() fires, cleared
// on the next successful connect (always after a restart - see
// setupAccount()'s and the watchdog's own comments in daemon/main.cpp for
// why a deauthorized account can't recover without one). This build DOES
// read it now (see ViewAccount::last_error / enabledCell()) and shows
// red. It's still not a live SIP-registration monitor, though - only
// Signal-side deauthorization is tracked this way so far, not a plain
// SIP registration drop (which stays purely in the running daemon's
// memory, same as before).
//
// All user-facing display text goes through i18n.h's tr()/format1(),
// which picks a language from LC_ALL/LC_MESSAGES/LANG at startup (see
// that header's own top comment) - config field identifiers and gendb
// CLI arg values (sip_srtp/sip_transport/sip_tls_insecure/wizTransport)
// are deliberately left untranslated, since those are real values sent
// to signal2sip-gendb, not display text.

#include <algorithm>
#include <atomic>
#include <csignal>
#include <cstdlib>
#include <ctime>
#include <iostream>
#include <map>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

#include <sys/wait.h>
#include <unistd.h>

#include <ftxui/component/component.hpp>
#include <ftxui/component/component_options.hpp>
#include <ftxui/component/screen_interactive.hpp>
#include <ftxui/dom/elements.hpp>

#include "daemon/Config.h"
#include "storage/Storage.h"
#include "tui/i18n.h"

using namespace ftxui;
using namespace signal2sip;
using namespace signal2sip::i18n;

namespace {

// Palette lifted straight from the concept mockup (same hex values) so
// the real thing matches what was agreed on, not a reinterpretation.
const Color kBg = Color::RGB(0x0f, 0x12, 0x18);
const Color kBgAlt = Color::RGB(0x17, 0x1b, 0x22);
const Color kBorder = Color::RGB(0x2b, 0x32, 0x3d);
const Color kFg = Color::RGB(0xda, 0xdd, 0xe3);
// +~15% over the concept mockup's original 0x6d/0x75/0x85 - that value
// was barely legible on a plain terminal with no fancy theme. Applies
// only to static UI chrome (nav hints, column headers, field labels) -
// never to actual account data, which already uses kFg/status colors.
const Color kDim = Color::RGB(0x7e, 0x87, 0x99);
const Color kAccent = Color::RGB(0xe8, 0xa3, 0x3d);
const Color kGood = Color::RGB(0x5c, 0xc9, 0xa7);
const Color kBad = Color::RGB(0xe8, 0x68, 0x7a);
const Color kLinked = Color::RGB(0x9e, 0xa6, 0xc9);

// Footer/hint-bar key-binding renderer - "[KEY]" (bracketed, upper-case,
// accent-colored) followed by its (already-translated) description in
// dim text, e.g. keyHint("esc", tr(Key::FooterCancel)). Upper-casing is
// purely cosmetic - key handling elsewhere in this file matches on
// lower-case Event::Character (FTXUI reports the actual case typed),
// unaffected by this.
Element keyHint(const std::string& key, const std::string& desc, Color keyColor = kAccent) {
    std::string upper = key;
    std::transform(upper.begin(), upper.end(), upper.begin(), ::toupper);
    return hbox({text("[" + upper + "]") | color(keyColor), text(" " + desc + "  ") | color(kDim)});
}

struct ViewAccount {
    std::string name;
    std::string e164;
    std::string flow;  // "standalone" | "linked" | "" (unknown/never registered)
    bool enabled = true;
    std::string sip_host;
    std::string sip_transport;
    std::string sip_srtp;
    // Written by the running daemon, never by this TUI or gendb - see
    // schema.sql's own comment on account.last_error/last_error_at. Empty
    // means "no known outstanding problem", not a live "currently
    // connected" guarantee (see this file's own top comment on why a red
    // status previously couldn't be shown at all).
    std::string last_error;
};

std::vector<ViewAccount> loadAccounts(const GlobalConfig& global, std::string& errorOut) {
    std::vector<ViewAccount> result;
    try {
        for (const AccountSummary& summary : listAllAccounts(global.dbPath, global.dbKey)) {
            ViewAccount view;
            view.name = summary.account_name;
            view.e164 = summary.e164;
            view.enabled = summary.enabled;
            view.last_error = summary.last_error;
            try {
                Storage storage(global.dbPath, global.dbKey, summary.account_name);
                AccountRecord record = storage.loadAccount();
                view.flow = record.flow.value_or("");
                view.sip_host = record.sip_host;
                view.sip_transport = record.sip_transport;
                view.sip_srtp = record.sip_srtp;
            } catch (const std::exception&) {
                // Leave the rest of the row blank rather than dropping the
                // account entirely - a summary-only row is still useful.
            }
            result.push_back(std::move(view));
        }
    } catch (const std::exception& e) {
        errorOut = e.what();
    }
    return result;
}

// Encryption status - see this file's own top comment for why
// optional/disabled render identically (amber, "not guaranteed") while
// only mandatory is green ("guaranteed"), and neither is ever red.
Element mediaCell(const ViewAccount& a) {
    if (a.sip_host.empty()) return text("—") | color(kDim);
    if (a.sip_srtp == "mandatory") return text(std::string("✓ ") + tr(Key::SrtpMandatory)) | color(kGood);
    if (a.sip_srtp == "optional") return text(std::string("⚠ ") + tr(Key::SrtpOptional)) | color(kAccent);
    return text(std::string("⚠ ") + tr(Key::StatusDisabled)) | color(kAccent);
}

Element enabledCell(const ViewAccount& a) {
    // Only ever red for enabled+problem - matches this file's own top
    // comment ("red is reserved for 'enabled but not actually connected'
    // - a real problem. disabled is never red"). A disabled account can
    // still have a stale last_error from before it was disabled; that's
    // not shown here since it's not actionable while disabled.
    if (a.enabled && !a.last_error.empty()) {
        return hbox({text("● ") | color(kBad), text(tr(Key::StatusError))}) | color(kBad);
    }
    if (a.enabled) return hbox({text("● ") | color(kGood), text(tr(Key::StatusEnabled))}) | color(kFg);
    return hbox({text("● ") | color(kBorder), text(tr(Key::StatusDisabled))}) | color(kDim);
}

Element typeCell(const ViewAccount& a) {
    if (a.flow == "linked") return text(tr(Key::TypeLinked)) | color(kLinked);
    if (a.flow == "standalone") return text(tr(Key::TypePrimary)) | color(kFg);
    return text("?") | color(kDim);
}

std::string formatDate(const std::optional<int64_t>& epochSeconds) {
    if (!epochSeconds) return "—";
    std::time_t t = static_cast<std::time_t>(*epochSeconds);
    std::tm tm{};
    gmtime_r(&t, &tm);
    char buf[16];
    std::strftime(buf, sizeof(buf), "%Y-%m-%d", &tm);
    return buf;
}

// Detail-screen versions of the same encryption rule Screen 1 uses (see
// this file's top comment) - kept as separate small helpers rather than
// generalizing over AccountRecord/ViewAccount, since the two structs
// don't share a common type and forcing one would cost more than the
// ~10 lines of duplication does.
Element signalingRow(const AccountRecord& a) {
    if (a.sip_host.empty()) return text("—") | color(kDim);
    if (a.sip_transport == "tls") return text("✓ TLS (sips:)") | color(kGood);
    return text(tr(Key::SignalingUdpInsecure)) | color(kAccent);
}

Element mediaRow(const AccountRecord& a) {
    if (a.sip_host.empty()) return text("—") | color(kDim);
    if (a.sip_srtp == "mandatory") return text(std::string("✓ SRTP ") + tr(Key::SrtpMandatory)) | color(kGood);
    std::string word = (a.sip_srtp == "optional") ? tr(Key::SrtpOptional) : tr(Key::StatusDisabled);
    std::string prefix = tr(Key::MediaSrtpNotGuaranteedPrefix);
    return text(prefix + "(" + word + ")") | color(kAccent);
}

// Screen 4 (SIP config editor) field list - `key` matches gendb's own
// `config set <field>` names exactly (native/gendb/main.cpp's
// configFields()), so edits round-trip through the same names on both
// sides without a translation table to keep in sync. `label` is
// deliberately identical to `key`, and deliberately NOT run through
// tr() - these are real field identifiers used with `signal2sip-gendb
// config set`, not display text (see i18n.h's own top comment).
struct ConfigFieldDef {
    std::string key;
    std::string label;
    enum class Kind { Text, Masked, Enum, Bool } kind;
    std::vector<std::string> options; // Enum only
};

// server_url is deliberately NOT in this list - it isn't a SIP setting
// at all (it's Signal-side), so it lives in Screen 6 (renderSignalConfig
// below) instead. See openSignalConfig()'s own comment.
const std::vector<ConfigFieldDef> kConfigFields = {
    {"sip_host", "sip_host", ConfigFieldDef::Kind::Text, {}},
    {"sip_extension", "sip_extension", ConfigFieldDef::Kind::Text, {}},
    {"sip_password", "sip_password", ConfigFieldDef::Kind::Masked, {}},
    {"sip_bridge_destination", "sip_bridge_destination", ConfigFieldDef::Kind::Text, {}},
    {"sip_bridge_did", "sip_bridge_did", ConfigFieldDef::Kind::Text, {}},
    {"sip_srtp", "sip_srtp", ConfigFieldDef::Kind::Enum, {"disabled", "optional", "mandatory"}},
    {"sip_transport", "sip_transport", ConfigFieldDef::Kind::Enum, {"udp", "tls"}},
    {"sip_tls_ca_file", "sip_tls_ca_file", ConfigFieldDef::Kind::Text, {}},
    {"sip_tls_insecure", "sip_tls_insecure", ConfigFieldDef::Kind::Bool, {}},
    {"outgoing_call_target", "outgoing_call_target", ConfigFieldDef::Kind::Text, {}},
};

// Screen 6 (Signal account settings) field list - same ConfigFieldDef/
// gendb-key-as-label convention as kConfigFields above, just the Signal-
// side settings that don't belong in Screen 4's SIP editor. signal_proxy
// and signal_censorship_circumvention added 2026-08-12 alongside the
// AuthSocket libsignal-net-chat migration (see project memory:
// signal2sip-censorship-circumvention / signal2sip-authsocket-ffi-migration).
const std::vector<ConfigFieldDef> kSignalConfigFields = {
    {"server_url", "server_url", ConfigFieldDef::Kind::Text, {}},
    {"signal_proxy", "signal_proxy", ConfigFieldDef::Kind::Text, {}},
    {"signal_censorship_circumvention", "signal_censorship_circumvention", ConfigFieldDef::Kind::Bool, {}},
};

// "SIP is being configured for this account at all" - true once any of
// the three identity fields has something in it. Drives the required-
// field markers (concept mockup: "обозначать обязательные поля").
bool sipFieldsInUse(const std::map<std::string, std::string>& v) {
    return !(v.at("sip_host").empty() && v.at("sip_extension").empty() && v.at("sip_password").empty());
}

// Same two rules Config.cpp's accountConfigFromRecord() enforces at
// daemon-load time (sip_host/extension/password all required together,
// sip_transport=tls needs a CA file or an explicit insecure opt-in) -
// checked here too so the TUI can refuse to even attempt the gendb
// calls, rather than sending a value gendb's own `config set` would
// accept (it validates one field in isolation) but the daemon would
// then reject wholesale on its next reload.
std::vector<std::string> configErrors(const std::map<std::string, std::string>& v) {
    std::vector<std::string> errs;
    if (sipFieldsInUse(v)) {
        if (v.at("sip_host").empty()) errs.push_back(tr(Key::ErrSipHostRequired));
        if (v.at("sip_extension").empty()) errs.push_back(tr(Key::ErrSipExtensionRequired));
        if (v.at("sip_password").empty()) errs.push_back(tr(Key::ErrSipPasswordRequired));
    }
    if (v.at("sip_transport") == "tls" && v.at("sip_tls_ca_file").empty() && v.at("sip_tls_insecure") != "yes") {
        errs.push_back(tr(Key::ErrTlsRequiresCa));
    }
    return errs;
}

// Soft warning, not blocking - see Config.h's own comment on
// sipBridgeDid: if both are set, sipBridgeDid silently wins, so having
// both filled in is almost certainly an operator mistake worth flagging
// even though it won't break anything.
std::vector<std::string> configWarnings(const std::map<std::string, std::string>& v) {
    std::vector<std::string> warns;
    if (!v.at("sip_bridge_destination").empty() && !v.at("sip_bridge_did").empty()) {
        warns.push_back(tr(Key::WarnBridgeBothSet));
    }
    return warns;
}

// Locates the companion signal2sip-gendb binary - prefers the copy next
// to this executable (the normal deployment layout, e.g. both in
// /opt/signal2sip/) over relying on $PATH, since the TUI is meant to work
// the same way whether run from an installed location or a dev build
// directory where nothing is on PATH at all.
std::string findGendbPath() {
    char exe[4096];
    ssize_t len = readlink("/proc/self/exe", exe, sizeof(exe) - 1);
    if (len > 0) {
        std::string path(exe, static_cast<size_t>(len));
        auto slash = path.find_last_of('/');
        if (slash != std::string::npos) {
            std::string candidate = path.substr(0, slash + 1) + "signal2sip-gendb";
            if (::access(candidate.c_str(), X_OK) == 0) return candidate;
        }
    }
    return "signal2sip-gendb"; // fall back to $PATH
}

struct GendbResult {
    int exitCode = -1;
    std::string output; // combined stdout+stderr
};

// Runs `gendbPath <args...>` and captures its output - via fork/exec/pipe
// with an explicit argv array, NOT popen()/system() with a concatenated
// command string, since these arguments can include real account fields
// (e.g. a SIP password from a future config-edit screen) that must never
// pass through a shell's own parsing. Blocks the whole TUI (and its
// screen redraws) until the subprocess exits - acceptable for now since
// every wired action here is a single fast gendb call, not a long-running
// operation; revisit with a background thread + screen.PostEvent() if a
// slower action is ever added.
GendbResult runGendb(const std::string& gendbPath, const std::vector<std::string>& args) {
    int pipefd[2];
    if (::pipe(pipefd) != 0) return {-1, "pipe() failed"};

    pid_t pid = ::fork();
    if (pid < 0) return {-1, "fork() failed"};

    if (pid == 0) {
        ::close(pipefd[0]);
        ::dup2(pipefd[1], STDOUT_FILENO);
        ::dup2(pipefd[1], STDERR_FILENO);
        ::close(pipefd[1]);

        std::vector<char*> argv;
        argv.push_back(const_cast<char*>(gendbPath.c_str()));
        for (const auto& a : args) argv.push_back(const_cast<char*>(a.c_str()));
        argv.push_back(nullptr);
        ::execvp(gendbPath.c_str(), argv.data());
        ::_exit(127); // only reached if execvp itself failed
    }

    ::close(pipefd[1]);
    GendbResult result;
    char buf[4096];
    ssize_t n;
    while ((n = ::read(pipefd[0], buf, sizeof(buf))) > 0) {
        result.output.append(buf, static_cast<size_t>(n));
    }
    ::close(pipefd[0]);
    int status = 0;
    ::waitpid(pid, &status, 0);
    result.exitCode = WIFEXITED(status) ? WEXITSTATUS(status) : -1;
    return result;
}

} // namespace

int main(int argc, char** argv) {
    std::string configPath = resolveConfigPath(argc, argv);
    GlobalConfig global = loadGlobalConfigLenient(configPath);
    if (global.dbPath.empty() || global.dbKey.empty()) {
        std::cerr << "signal2sip-tui: " << configPath << tr(Key::StartupNoDbConfig);
        return 1;
    }

    std::vector<ViewAccount> accounts;
    std::string loadError;
    int selected = 0;
    bool quit = false;

    auto reload = [&] {
        accounts = loadAccounts(global, loadError);
        if (selected >= static_cast<int>(accounts.size())) {
            selected = accounts.empty() ? 0 : static_cast<int>(accounts.size()) - 1;
        }
    };
    reload();

    // 0 = list, 1 = detail, 2 = confirmation dialog, 3 = SIP config
    // editor, 4 = new-account wizard - see the top-level Renderer/
    // CatchEvent below for why this is a plain int dispatched by hand
    // rather than any FTXUI container construct.
    int screenIndex = 0;
    AccountRecord detail;
    std::string detailName;
    std::string detailError;
    // Shared by Screens 3, 4 and 5 - all shell out to it.
    const std::string gendbPath = findGendbPath();
    // Declared this early (rather than next to screen.Loop() at the
    // bottom, where every other FTXUI setup call lives) because Screen
    // 5's background link-watcher thread (below) needs to call
    // screen.PostEvent() from inside a lambda defined well before that -
    // a lambda can only reference a variable already in scope at its own
    // definition point, not one declared later in the same function.
    auto screen = ScreenInteractive::Fullscreen();

    auto openDetail = [&] {
        if (accounts.empty()) return;
        detailName = accounts[selected].name;
        detailError.clear();
        try {
            Storage storage(global.dbPath, global.dbKey, detailName);
            detail = storage.loadAccount();
        } catch (const std::exception& e) {
            detailError = e.what();
        }
        screenIndex = 1;
    };

    // Screen 4: SIP config editor. `editValues`/`originalValues` are both
    // keyed by ConfigFieldDef::key; `originalValues` is a snapshot taken
    // the moment the screen opens so saveConfig() only sends the fields
    // that actually changed to gendb, instead of re-sending all 10 (which
    // would also mean 10 separate config_version bumps / daemon reloads
    // for a single-field edit).
    std::map<std::string, std::string> editValues;
    std::map<std::string, std::string> originalValues;
    int editField = 0;
    bool configSaveDone = false;
    std::string configSaveOutput;
    bool configSaveOk = true;

    auto openConfig = [&] {
        editValues.clear();
        editValues["sip_host"] = detail.sip_host;
        editValues["sip_extension"] = detail.sip_extension;
        editValues["sip_password"] = detail.sip_password;
        editValues["sip_bridge_destination"] = detail.sip_bridge_destination;
        editValues["sip_bridge_did"] = detail.sip_bridge_did;
        editValues["sip_srtp"] = detail.sip_srtp.empty() ? "disabled" : detail.sip_srtp;
        editValues["sip_transport"] = detail.sip_transport.empty() ? "udp" : detail.sip_transport;
        editValues["sip_tls_ca_file"] = detail.sip_tls_ca_file;
        editValues["sip_tls_insecure"] = detail.sip_tls_insecure ? "yes" : "no";
        editValues["outgoing_call_target"] = detail.outgoing_call_target;
        originalValues = editValues;
        editField = 0;
        configSaveDone = false;
        configSaveOutput.clear();
        screenIndex = 3;
    };

    // Blocked entirely (no gendb calls at all) if configErrors() is
    // non-empty - matches the concept's "проверять на совместимость
    // параметры" ask: catch it here, not after a partial write.
    auto saveConfig = [&] {
        if (!configErrors(editValues).empty()) return;
        std::string combined;
        bool allOk = true;
        for (const auto& f : kConfigFields) {
            if (editValues[f.key] == originalValues[f.key]) continue;
            GendbResult res =
                runGendb(gendbPath, {"--config", configPath, detailName, "config", "set", f.key, editValues[f.key]});
            combined += res.output;
            if (res.exitCode != 0) allOk = false;
        }
        if (combined.empty()) combined = tr(Key::NoChanges);
        configSaveOutput = combined;
        configSaveOk = allOk;
        configSaveDone = true;
    };

    // Screen 6: Signal account settings - deliberately separate from
    // Screen 4's SIP config editor (none of kSignalConfigFields are SIP
    // settings), and the natural future home for SVR2 PIN management once
    // that's built. Same field-list/cursor/save-only-changed-fields
    // pattern as Screen 4 (kConfigFields/editValues/editField/saveConfig
    // above), just against kSignalConfigFields instead.
    std::map<std::string, std::string> signalEditValues;
    std::map<std::string, std::string> signalOriginalValues;
    int signalEditField = 0;
    bool signalSaveDone = false;
    std::string signalSaveOutput;
    bool signalSaveOk = true;

    auto openSignalConfig = [&] {
        signalEditValues["server_url"] = detail.server_url;
        signalEditValues["signal_proxy"] = detail.signal_proxy;
        signalEditValues["signal_censorship_circumvention"] = detail.signal_censorship_circumvention ? "yes" : "no";
        signalOriginalValues = signalEditValues;
        signalEditField = 0;
        signalSaveDone = false;
        signalSaveOutput.clear();
        screenIndex = 5;
    };

    auto saveSignalConfig = [&] {
        std::string combined;
        bool allOk = true;
        for (const auto& f : kSignalConfigFields) {
            if (signalEditValues[f.key] == signalOriginalValues[f.key]) continue;
            GendbResult res = runGendb(
                gendbPath, {"--config", configPath, detailName, "config", "set", f.key, signalEditValues[f.key]});
            combined += res.output;
            if (res.exitCode != 0) allOk = false;
        }
        if (combined.empty()) combined = tr(Key::NoChanges);
        signalSaveOutput = combined;
        signalSaveOk = allOk;
        signalSaveDone = true;
    };

    // Screen 5: new-account wizard. Flow A (register/register-captcha/
    // verify) is 3 fast, single-round-trip HTTP calls - each just runs
    // synchronously through the same blocking runGendb() Screens 3/4
    // already use, storing its result in `wizResult` for whichever
    // "*Result" step follows. Flow B (link) is fundamentally different:
    // ProvisioningClient::waitForProvisionMessage() (see its own doc
    // comment) prints the QR *and then blocks for up to ~90s waiting for
    // a phone to scan it - a batch-collect-then-show helper like
    // runGendb() would mean the QR never appears until the whole wait is
    // already over. So link runs its own gendb subprocess in a
    // background thread, streaming stdout into `linkOutput` (behind
    // `linkMutex`) chunk by chunk and waking the render loop after each
    // one via screen.PostEvent(Event::Custom) - the standard FTXUI
    // pattern for a background job feeding the UI.
    enum class WizardStep {
        ChooseType,
        RegisterForm,
        RegisterResult,
        CaptchaForm,
        CaptchaResult,
        VerifyForm,
        VerifyResult,
        LinkWaiting,
        LinkResult,
    };
    WizardStep wizardStep = WizardStep::ChooseType;
    int wizField = 0; // which of the current step's (at most 2) fields is active
    std::string wizName;
    bool wizLink = false; // false = register (Flow A), true = link (Flow B)
    std::string wizE164;
    std::string wizTransport = "sms"; // "sms" | "voice"
    std::string wizCaptchaToken;
    std::string wizVerifyCode;
    std::optional<GendbResult> wizResult;
    std::string wizError;

    std::mutex linkMutex;
    std::string linkOutput;
    std::atomic<bool> linkDone{false};
    int linkExitCode = -1;
    pid_t linkPid = -1;
    std::thread linkThread;

    auto openWizard = [&] {
        wizardStep = WizardStep::ChooseType;
        wizField = 0;
        wizName.clear();
        wizLink = false;
        wizE164.clear();
        wizTransport = "sms";
        wizCaptchaToken.clear();
        wizVerifyCode.clear();
        wizResult.reset();
        wizError.clear();
        screenIndex = 4;
    };

    // Deliberately NOT built on runGendb() - that helper only returns
    // once the whole subprocess has exited, which is exactly wrong here
    // (see this section's own top comment). Same fork/exec/pipe shape as
    // runGendb() otherwise, just read incrementally instead of drained
    // once at the end.
    auto startLinkThread = [&](const std::string& name) {
        linkOutput.clear();
        linkDone = false;
        linkExitCode = -1;
        linkPid = -1;
        if (linkThread.joinable()) linkThread.join(); // shouldn't happen, but never leak a thread handle

        linkThread = std::thread([&, name] {
            int pipefd[2];
            if (::pipe(pipefd) != 0) {
                std::lock_guard<std::mutex> lock(linkMutex);
                linkOutput = "pipe() failed";
                linkDone = true;
                screen.PostEvent(Event::Custom);
                return;
            }
            pid_t pid = ::fork();
            if (pid < 0) {
                std::lock_guard<std::mutex> lock(linkMutex);
                linkOutput = "fork() failed";
                linkDone = true;
                screen.PostEvent(Event::Custom);
                return;
            }
            if (pid == 0) {
                ::close(pipefd[0]);
                ::dup2(pipefd[1], STDOUT_FILENO);
                ::dup2(pipefd[1], STDERR_FILENO);
                ::close(pipefd[1]);
                std::vector<std::string> argsStr = {"--config", configPath, name, "link"};
                std::vector<char*> argv;
                argv.push_back(const_cast<char*>(gendbPath.c_str()));
                for (auto& a : argsStr) argv.push_back(const_cast<char*>(a.c_str()));
                argv.push_back(nullptr);
                ::execvp(gendbPath.c_str(), argv.data());
                ::_exit(127);
            }
            {
                std::lock_guard<std::mutex> lock(linkMutex);
                linkPid = pid;
            }
            ::close(pipefd[1]);
            char buf[4096];
            ssize_t n;
            while ((n = ::read(pipefd[0], buf, sizeof(buf))) > 0) {
                {
                    std::lock_guard<std::mutex> lock(linkMutex);
                    linkOutput.append(buf, static_cast<size_t>(n));
                }
                screen.PostEvent(Event::Custom);
            }
            ::close(pipefd[0]);
            int status = 0;
            ::waitpid(pid, &status, 0);
            {
                std::lock_guard<std::mutex> lock(linkMutex);
                linkExitCode = WIFEXITED(status) ? WEXITSTATUS(status) : -1;
            }
            linkDone = true;
            screen.PostEvent(Event::Custom);
        });
    };

    // SIGTERM (no handler installed in gendb, so this is fatal to it) -
    // the reader loop's blocking read() then gets EOF once the pipe's
    // write end closes with the process, so the thread unwinds and this
    // join() returns quickly rather than waiting out the rest of the 90s.
    auto cancelLinkThread = [&] {
        pid_t pidToKill = -1;
        {
            std::lock_guard<std::mutex> lock(linkMutex);
            pidToKill = linkPid;
        }
        if (pidToKill > 0) ::kill(pidToKill, SIGTERM);
        if (linkThread.joinable()) linkThread.join();
    };

    // Screen 3: confirmation dialogs. `pending` is which action is being
    // confirmed; `typedConfirm` accumulates the account-name the user is
    // typing for the delete-account variant; `lastResult` is set once the
    // gendb subprocess has actually run, switching the same screen from
    // "confirm?" to "here's what happened" (dismissed by any key).
    enum class PendingAction { None, Enable, Disable, Deactivate, DeleteAccount };
    PendingAction pending = PendingAction::None;
    std::string typedConfirm;
    std::optional<GendbResult> lastResult;

    auto openConfirm = [&](PendingAction action) {
        pending = action;
        typedConfirm.clear();
        lastResult.reset();
        screenIndex = 2;
    };

    auto runPendingAction = [&] {
        std::vector<std::string> args = {"--config", configPath, detailName};
        switch (pending) {
            case PendingAction::Enable: args.push_back("enable"); break;
            case PendingAction::Disable: args.push_back("disable"); break;
            case PendingAction::Deactivate: args.push_back("deactivate"); break;
            case PendingAction::DeleteAccount: args.push_back("delete-account"); break;
            case PendingAction::None: return;
        }
        lastResult = runGendb(gendbPath, args);
    };

    // Deliberately NOT ftxui::Container::Tab (tried first, reverted): its
    // OnEvent inherits ContainerBase's `if (!Focused()) return false;`
    // gate, and nothing in this plain Renderer+CatchEvent tree (no
    // Input/Button/Menu leaf) ever becomes Focused() - so no keyboard
    // event ever reached either screen's handler once nested inside a
    // Tab container, confirmed live (arrows/Enter did nothing). A single
    // top-level Renderer+CatchEvent branching on `screenIndex` itself
    // sidesteps FTXUI's focus model entirely, matching how Screen 1
    // alone already worked before Screen 2 was added.
    auto renderList = [&]() -> Element {
        Elements rows;
        rows.push_back(hbox({
                            text("") | size(WIDTH, EQUAL, 2),
                            text(tr(Key::ColName)) | size(WIDTH, EQUAL, 18),
                            text("E.164") | size(WIDTH, EQUAL, 16),
                            text(tr(Key::ColType)) | size(WIDTH, EQUAL, 9),
                            text(tr(Key::ColStatus)) | size(WIDTH, EQUAL, 12),
                            text(tr(Key::ColMedia)) | flex,
                        }) |
                        color(kDim));
        rows.push_back(separator() | color(kBorder));

        if (!loadError.empty()) {
            rows.push_back(text(tr(Key::DbReadError) + loadError) | color(kBad));
        } else if (accounts.empty()) {
            rows.push_back(text(tr(Key::NoAccounts)) | color(kDim));
        }

        for (int i = 0; i < static_cast<int>(accounts.size()); i++) {
            const ViewAccount& a = accounts[i];
            bool sel = (i == selected);
            Element cursor = text(sel ? "▸ " : "  ") | color(kAccent);
            Element name = text(a.name) | size(WIDTH, EQUAL, 18) | color(sel ? kAccent : kFg);
            Element e164 = text(a.e164) | size(WIDTH, EQUAL, 16) | color(kFg);
            Element type = typeCell(a) | size(WIDTH, EQUAL, 9);
            Element status = enabledCell(a) | size(WIDTH, EQUAL, 12);
            Element media = mediaCell(a) | flex;
            Element row = hbox({cursor, name, e164, type, status, media});
            if (sel) row = row | bgcolor(Color::RGB(0x1c, 0x22, 0x2c));
            rows.push_back(row);
        }

        Element body = vbox(std::move(rows)) | color(kFg);

        Element titlebar = hbox({
                                text("● ") | color(kBorder),
                                text("● ") | color(kBorder),
                                text("● ") | color(kBorder),
                                text("  signal2sip-tui — " + global.dbPath) | color(kDim),
                            }) |
                            bgcolor(kBgAlt);

        // hflow (not hbox) for every footer/hint row in this file - a
        // panel capped at kMaxPanelWidth (see the top-level Renderer)
        // can be too narrow to fit every hint on one line, and hbox just
        // clips instead of wrapping.
        Element footer = hflow({
                              text(" "),
                              keyHint("↑↓", tr(Key::FooterSelect)),
                              keyHint("↵", tr(Key::FooterDetails)),
                              keyHint("n", tr(Key::FooterNew)),
                              keyHint("r", tr(Key::FooterRefresh)),
                              keyHint("q", tr(Key::FooterQuit)),
                          }) |
                          bgcolor(kBgAlt);

        return vbox({
                   titlebar,
                   separator() | color(kBorder),
                   body | flex | size(HEIGHT, GREATER_THAN, 3) | bgcolor(kBg) | color(kFg),
                   separator() | color(kBorder),
                   footer,
               }) |
               border | color(kBorder) | bgcolor(kBg);
    };

    auto renderDetail = [&]() -> Element {
        Elements idRows, statusRows;

        auto kv = [](const std::string& label, Element value) {
            return hbox({text(label) | size(WIDTH, EQUAL, 16) | color(kDim), value});
        };

        idRows.push_back(kv("E.164", text(detail.e164) | color(kFg)));
        idRows.push_back(kv("ACI", text(detail.aci) | color(kDim)));
        idRows.push_back(kv(tr(Key::ColType), detail.flow == "linked" ? text(tr(Key::TypeLinked)) | color(kLinked)
                                    : detail.flow == "standalone" ? text(tr(Key::TypePrimary)) | color(kFg)
                                                                   : text("?") | color(kDim)));
        idRows.push_back(kv(detail.flow == "linked" ? tr(Key::DetailLinkedAt) : tr(Key::DetailRegisteredAt),
                            text(formatDate(detail.flow == "linked" ? detail.linked_at : detail.registered_at)) |
                                color(kFg)));

        statusRows.push_back(
            kv(tr(Key::DetailEnabled), detail.enabled ? hbox({text("● ") | color(kGood), text(tr(Key::YesWord))}) |
                                                             color(kFg)
                                                       : hbox({text("● ") | color(kBorder), text(tr(Key::NoWord))}) |
                                                             color(kDim)));
        if (detail.sip_host.empty()) {
            statusRows.push_back(kv("SIP", text(tr(Key::DetailSipNone)) | color(kDim)));
        } else {
            statusRows.push_back(kv("SIP", text(detail.sip_extension + "@" + detail.sip_host) | color(kFg)));
            statusRows.push_back(kv(tr(Key::DetailSignaling), signalingRow(detail)));
            statusRows.push_back(kv(tr(Key::DetailMedia), mediaRow(detail)));
        }

        Elements body;
        if (!detailError.empty()) {
            body.push_back(text(tr(Key::AccountReadError) + detailError) | color(kBad));
        } else {
            body.push_back(text(tr(Key::SectionIdentity)) | color(kDim));
            body.push_back(vbox(std::move(idRows)));
            body.push_back(text(""));
            body.push_back(text(tr(Key::SectionStatus)) | color(kDim));
            body.push_back(vbox(std::move(statusRows)));
        }

        Element titlebar = hbox({
                                text("● ") | color(kBorder),
                                text("● ") | color(kBorder),
                                text("● ") | color(kBorder),
                                text(tr(Key::DetailTitlebar) + detailName) | color(kDim),
                            }) |
                            bgcolor(kBgAlt);

        Element footer = hflow({
                              text(" "),
                              keyHint("c", tr(Key::FooterConfigureSip)),
                              keyHint("s", tr(Key::FooterSignalSettings)),
                              keyHint("d", detail.enabled ? tr(Key::FooterDisable) : tr(Key::FooterEnable)),
                              keyHint("u", "deactivate"),
                          }) |
                          bgcolor(kBgAlt);
        Element footer2 = hflow({text(" "),
                                hbox({text("[X]") | color(kBad), text(std::string(" ") + tr(Key::FooterDeleteAccount)) |
                                                                      color(kBad)}),
                                keyHint("esc", tr(Key::FooterBack))}) |
                          bgcolor(kBgAlt);

        return vbox({
                   titlebar,
                   separator() | color(kBorder),
                   vbox(std::move(body)) | flex | size(HEIGHT, GREATER_THAN, 3) | bgcolor(kBg) | color(kFg),
                   separator() | color(kBorder),
                   footer,
                   footer2,
               }) |
               border | color(kBorder) | bgcolor(kBg);
    };

    // Text describing the real consequence of each mild action, straight
    // from the wording gendb itself already prints after running these
    // commands (native/gendb/main.cpp) - not reworded here, so the
    // warning shown BEFORE confirming matches what actually happens.
    auto actionTitle = [&](PendingAction action) -> std::string {
        switch (action) {
            case PendingAction::Enable: return format1(Key::ActionEnableTitle, detailName);
            case PendingAction::Disable: return format1(Key::ActionDisableTitle, detailName);
            case PendingAction::Deactivate: return format1(Key::ActionDeactivateTitle, detailName);
            case PendingAction::DeleteAccount: return format1(Key::ActionDeleteTitle, detailName);
            case PendingAction::None: return "";
        }
        return "";
    };
    auto actionBody = [&](PendingAction action) -> std::string {
        switch (action) {
            case PendingAction::Enable: return tr(Key::ActionEnableBody);
            case PendingAction::Disable: return tr(Key::ActionDisableBody);
            case PendingAction::Deactivate: return tr(Key::ActionDeactivateBody);
            case PendingAction::DeleteAccount: return tr(Key::ActionDeleteBody);
            case PendingAction::None: return "";
        }
        return "";
    };

    auto renderConfirm = [&]() -> Element {
        bool severe = pending == PendingAction::DeleteAccount;
        Elements body;

        if (lastResult) {
            body.push_back(text(lastResult->exitCode == 0 ? tr(Key::ResultDone)
                                                            : format1(Key::ResultError, lastResult->exitCode)) |
                           color(lastResult->exitCode == 0 ? kGood : kBad));
            body.push_back(text(""));
            std::string out = lastResult->output;
            if (out.size() > 2000) out = out.substr(0, 2000) + "…"; // keep the dialog on-screen
            body.push_back(paragraphAlignLeft(out) | color(kDim));
            body.push_back(text(""));
            body.push_back(text(tr(Key::AnyKeyToList)) | color(kDim));
        } else {
            body.push_back(paragraphAlignLeft(actionBody(pending)) | color(kFg));
            if (severe) {
                body.push_back(text(""));
                body.push_back(hbox({text(tr(Key::TypeAccountName)) | color(kDim),
                                     text(typedConfirm) | color(kAccent),
                                     text("█") | color(kAccent)}));
            }
        }

        Element dialogHead = text(" " + (lastResult ? (tr(Key::ConfirmAccountLabel) + detailName)
                                                     : actionTitle(pending))) |
                              color(severe ? kBad : kAccent) | bgcolor(kBgAlt);

        Element dialogFooter;
        if (lastResult) {
            dialogFooter = text(std::string(" ") + tr(Key::AnyKeyToList) + " ") | color(kDim) | bgcolor(kBgAlt);
        } else if (severe) {
            bool ready = typedConfirm == detailName;
            dialogFooter = hflow({text(" "), keyHint("esc", tr(Key::FooterCancel)),
                                 ready ? keyHint("enter", tr(Key::EnterDelete), kBad)
                                       : text(tr(Key::TypeNameInFull)) | color(kDim)}) |
                           bgcolor(kBgAlt);
        } else {
            dialogFooter = hflow({text(" "), keyHint("esc", tr(Key::FooterCancel)),
                                 keyHint("y", tr(Key::FooterConfirm))}) |
                           bgcolor(kBgAlt);
        }

        Element dialog = vbox({
                              dialogHead,
                              separator() | color(kBorder),
                              vbox(std::move(body)) | size(WIDTH, EQUAL, 60),
                              separator() | color(kBorder),
                              dialogFooter,
                          }) |
                          border | color(severe ? kBad : kBorder) | bgcolor(kBg);

        return dialog | center | bgcolor(kBgAlt);
    };

    // Screen 4: SIP config editor. One field "active" at a time
    // (`editField`), navigated with ↑↓/Tab; Text/Masked fields take raw
    // character input + Backspace directly (no FTXUI Input() - see this
    // file's Container::Tab postmortem above for why nothing here uses
    // FTXUI's own focus-based widgets), Enum/Bool fields cycle on Enter.
    // Errors/warnings are computed and shown live on every keystroke, not
    // only on save - matches the concept's "проверять на совместимость"
    // ask.
    auto renderConfig = [&]() -> Element {
        bool sipInUse = sipFieldsInUse(editValues);
        std::vector<std::string> errs = configErrors(editValues);
        std::vector<std::string> warns = configWarnings(editValues);

        Elements rows;
        for (int i = 0; i < static_cast<int>(kConfigFields.size()); i++) {
            const ConfigFieldDef& f = kConfigFields[i];
            bool active = (i == editField);
            bool required = sipInUse && (f.key == "sip_host" || f.key == "sip_extension" || f.key == "sip_password");
            bool missing = required && editValues.at(f.key).empty();

            std::string display = editValues.at(f.key);
            if (f.kind == ConfigFieldDef::Kind::Masked && !display.empty()) {
                display = std::string(display.size(), '*');
            }
            if (display.empty()) display = "—";
            if (active) display += "█";

            Element marker = text(required ? "* " : "  ") | color(missing ? kBad : kDim);
            Element label = text(f.label) | size(WIDTH, EQUAL, 24) | color(kDim);
            Element value = text(display) | color(active ? kAccent : kFg);

            Element row = hbox({text(active ? "▸ " : "  ") | color(kAccent), marker, label, value});
            if (active) row = row | bgcolor(Color::RGB(0x1c, 0x22, 0x2c));
            rows.push_back(row);
        }

        Elements body;
        body.push_back(vbox(std::move(rows)));
        if (!errs.empty()) {
            body.push_back(text(""));
            for (const auto& e : errs) body.push_back(text("✗ " + e) | color(kBad));
        }
        if (!warns.empty()) {
            body.push_back(text(""));
            for (const auto& w : warns) body.push_back(text("⚠ " + w) | color(kAccent));
        }
        if (configSaveDone) {
            body.push_back(text(""));
            body.push_back(text(configSaveOk ? tr(Key::ConfigSaved) : tr(Key::ConfigSaveError)) |
                           color(configSaveOk ? kGood : kBad));
            std::string out = configSaveOutput;
            if (out.size() > 1500) out = out.substr(0, 1500) + "…";
            body.push_back(paragraphAlignLeft(out) | color(kDim));
            body.push_back(text(""));
            body.push_back(text(tr(Key::AnyKeyBackToAccount)) | color(kDim));
        }

        Element titlebar = hbox({
                                text("● ") | color(kBorder),
                                text("● ") | color(kBorder),
                                text("● ") | color(kBorder),
                                text(tr(Key::ConfigTitlebar) + detailName) | color(kDim),
                            }) |
                            bgcolor(kBgAlt);

        Element footer = hflow({
                              text(" "),
                              keyHint("↑↓/tab", tr(Key::FooterField)),
                              text(tr(Key::FooterTextType)) | color(kDim),
                              keyHint("↵", tr(Key::FooterListCycles)),
                              keyHint("^o", tr(Key::FooterSave)),
                              keyHint("esc", tr(Key::FooterBack)),
                          }) |
                          bgcolor(kBgAlt);

        return vbox({
                   titlebar,
                   separator() | color(kBorder),
                   vbox(std::move(body)) | flex | size(HEIGHT, GREATER_THAN, 3) | bgcolor(kBg) | color(kFg),
                   separator() | color(kBorder),
                   footer,
               }) |
               border | color(errs.empty() ? kBorder : kBad) | bgcolor(kBg);
    };

    // Screen 6: Signal account settings - see openSignalConfig()'s own
    // comment on why this is a separate screen from Screen 4's SIP
    // editor. Same multi-field visual language as Screen 4's renderConfig().
    auto renderSignalConfig = [&]() -> Element {
        Elements rows;
        for (int i = 0; i < static_cast<int>(kSignalConfigFields.size()); i++) {
            const ConfigFieldDef& f = kSignalConfigFields[i];
            bool active = (i == signalEditField);
            std::string display = signalEditValues.at(f.key);
            if (display.empty()) display = "—";
            if (active) display += "█";

            Element label = text(f.label) | size(WIDTH, EQUAL, 32) | color(kDim);
            Element value = text(display) | color(active ? kAccent : kFg);
            Element row = hbox({text(active ? "▸ " : "  ") | color(kAccent), label, value});
            if (active) row = row | bgcolor(Color::RGB(0x1c, 0x22, 0x2c));
            rows.push_back(row);
        }

        Elements body;
        body.push_back(vbox(std::move(rows)));
        if (signalSaveDone) {
            body.push_back(text(""));
            body.push_back(text(signalSaveOk ? tr(Key::ConfigSaved) : tr(Key::ConfigSaveError)) |
                           color(signalSaveOk ? kGood : kBad));
            std::string out = signalSaveOutput;
            if (out.size() > 1500) out = out.substr(0, 1500) + "…";
            body.push_back(paragraphAlignLeft(out) | color(kDim));
            body.push_back(text(""));
            body.push_back(text(tr(Key::AnyKeyBackToAccount)) | color(kDim));
        }

        Element titlebar = hbox({
                                text("● ") | color(kBorder),
                                text("● ") | color(kBorder),
                                text("● ") | color(kBorder),
                                text(tr(Key::SignalConfigTitlebar) + detailName) | color(kDim),
                            }) |
                            bgcolor(kBgAlt);

        Element footer = hflow({
                              keyHint("↑↓/tab", tr(Key::FooterField)),
                              text(tr(Key::SignalConfigTypeText)) | color(kDim),
                              keyHint("↵", tr(Key::FooterListCycles)),
                              keyHint("^o", tr(Key::FooterSave)),
                              keyHint("esc", tr(Key::FooterBack)),
                          }) |
                          bgcolor(kBgAlt);

        return vbox({
                   titlebar,
                   separator() | color(kBorder),
                   vbox(std::move(body)) | flex | size(HEIGHT, GREATER_THAN, 3) | bgcolor(kBg) | color(kFg),
                   separator() | color(kBorder),
                   footer,
               }) |
               border | color(kBorder) | bgcolor(kBg);
    };

    // Screen 5: new-account wizard. One small field-row helper shared by
    // every form step (ChooseType/RegisterForm/CaptchaForm/VerifyForm),
    // same visual language as Screen 4's rows (▸ cursor, highlighted
    // background on the active field, trailing block cursor while
    // editing).
    auto renderWizard = [&]() -> Element {
        auto fieldRow = [&](const std::string& label, const std::string& value, bool active) {
            Element v = text(value + (active ? "█" : "")) | color(active ? kAccent : kFg);
            Element l = text(label) | size(WIDTH, EQUAL, 20) | color(kDim);
            Element row = hbox({text(active ? "▸ " : "  ") | color(kAccent), l, v});
            if (active) row = row | bgcolor(Color::RGB(0x1c, 0x22, 0x2c));
            return row;
        };
        // ProvisioningClient::printQrAscii() wraps the QR in raw ANSI SGR
        // codes (explicit black-on-white, overriding whatever theme the
        // terminal has - see its own comment on why) for operators running
        // gendb directly in a terminal. Piped through a subprocess and
        // rendered via FTXUI's text() those escape bytes would just show up
        // as garbage instead of being interpreted, so strip them here and
        // reproduce the same black-on-white explicitly at the FTXUI layer
        // instead, for the same reason (a phone camera scanning this out of
        // our own dark-themed TUI needs real dark-on-light, not
        // light-on-dark inherited from kBg/kFg).
        auto stripAnsi = [](const std::string& in) {
            std::string out;
            out.reserve(in.size());
            for (size_t i = 0; i < in.size(); i++) {
                if (in[i] == '\x1b' && i + 1 < in.size() && in[i + 1] == '[') {
                    size_t j = i + 2;
                    while (j < in.size() && in[j] != 'm') j++;
                    i = j;
                    continue;
                }
                out += in[i];
            }
            return out;
        };
        // Display-column count of a UTF-8 string built only from the
        // block-drawing glyphs printQrAscii() uses (all single-column,
        // none wide/combining) plus plain ASCII spaces - counts codepoints
        // (bytes that aren't UTF-8 continuation bytes), not raw
        // std::string::size() bytes, since each block glyph is a 3-byte
        // UTF-8 sequence but occupies exactly one terminal column.
        auto utf8ColumnWidth = [](const std::string& s) {
            int n = 0;
            for (unsigned char c : s) {
                if ((c & 0xC0) != 0x80) n++;
            }
            return n;
        };
        auto emitPlainLines = [&](Elements& body, const std::string& segment) {
            std::string clean = stripAnsi(segment);
            size_t pos = 0;
            while (pos <= clean.size()) {
                size_t nl = clean.find('\n', pos);
                std::string line = (nl == std::string::npos) ? clean.substr(pos) : clean.substr(pos, nl - pos);
                body.push_back(text(line) | color(kFg));
                if (nl == std::string::npos) break;
                pos = nl + 1;
            }
        };
        // ASCII QR from ProvisioningClient is a fixed character grid
        // (half-block glyphs, two QR module rows per printed line) -
        // paragraphAlignLeft's word-wrap would scramble it, so link output
        // is always split into one text() per line instead. An earlier cut
        // of this decided which lines were "QR" by whether they contained
        // an actual glyph, which silently excluded the QR's own blank
        // quiet-zone rows (all spaces, no glyph) from the white
        // background - a real bug, live-reported: the QR's top/bottom
        // edges had no true quiet zone, blending straight into the TUI's
        // own dark theme. Fixed by trusting the exact boundary gendb's own
        // ANSI markers already draw (`\x1b[30;107m` ... `\x1b[0m` around
        // the whole block, quiet zone included - see ProvisioningClient's
        // printQrAscii()) instead of re-guessing it from content.
        auto pushLines = [&](Elements& body, const std::string& rawOut) {
            static const std::string kQrStart = "\x1b[30;107m";
            static const std::string kQrEnd = "\x1b[0m";
            size_t qrStart = rawOut.find(kQrStart);
            size_t qrEnd = (qrStart == std::string::npos) ? std::string::npos
                                                           : rawOut.find(kQrEnd, qrStart + kQrStart.size());
            if (qrStart == std::string::npos || qrEnd == std::string::npos) {
                emitPlainLines(body, rawOut); // no marker (e.g. non-link output) - render as-is
                return;
            }
            emitPlainLines(body, rawOut.substr(0, qrStart));
            std::string qrBlock = rawOut.substr(qrStart + kQrStart.size(), qrEnd - (qrStart + kQrStart.size()));
            size_t pos = 0;
            while (pos <= qrBlock.size()) {
                size_t nl = qrBlock.find('\n', pos);
                std::string line = (nl == std::string::npos) ? qrBlock.substr(pos) : qrBlock.substr(pos, nl - pos);
                // Cap the white background to the QR's own rendered width
                // instead of the default vbox behavior of stretching a
                // text() child to the full panel width - otherwise the
                // white quiet-zone box trails off into a wide rectangle
                // past the code's right edge. The rest of the row then
                // falls through to the surrounding vbox's own bgcolor(kBg)
                // below, giving a square white box on the dark background.
                body.push_back(text(line) | color(Color::Black) | bgcolor(Color::White) |
                               size(WIDTH, EQUAL, utf8ColumnWidth(line)));
                if (nl == std::string::npos) break;
                pos = nl + 1;
            }
            emitPlainLines(body, rawOut.substr(qrEnd + kQrEnd.size()));
        };

        Elements body;
        std::string titleSuffix;
        Element footer;

        switch (wizardStep) {
            case WizardStep::ChooseType:
                titleSuffix = tr(Key::WizardNewAccount);
                body.push_back(fieldRow(tr(Key::FieldAccountName), wizName, wizField == 0));
                body.push_back(fieldRow(tr(Key::FieldMethod), wizLink ? "link (QR)" : tr(Key::MethodRegister),
                                        wizField == 1));
                body.push_back(text(""));
                body.push_back(text(tr(Key::WizardNameHint)) | color(kDim));
                if (!wizError.empty()) {
                    body.push_back(text(""));
                    body.push_back(text("✗ " + wizError) | color(kBad));
                }
                footer = hflow({text(" "), keyHint("↑↓", tr(Key::FooterField)), keyHint("↵", tr(Key::FooterToggleMethod)),
                              keyHint("^o", tr(Key::FooterNext)), keyHint("esc", tr(Key::FooterCancel))}) |
                        bgcolor(kBgAlt);
                break;

            case WizardStep::RegisterForm:
                titleSuffix = tr(Key::WizardRegistration) + wizName;
                body.push_back(fieldRow("e164 (+...)", wizE164, wizField == 0));
                body.push_back(fieldRow(tr(Key::FieldCodeMethod), wizTransport, wizField == 1));
                if (!wizError.empty()) {
                    body.push_back(text(""));
                    body.push_back(text("✗ " + wizError) | color(kBad));
                }
                footer = hflow({text(" "), keyHint("↑↓", tr(Key::FooterField)),
                              keyHint("↵", tr(Key::FooterToggleCodeMethod)), keyHint("^o", tr(Key::FooterRegister)),
                              keyHint("esc", tr(Key::FooterCancel))}) |
                        bgcolor(kBgAlt);
                break;

            case WizardStep::RegisterResult:
            case WizardStep::CaptchaResult:
                titleSuffix = tr(Key::WizardResult) + wizName;
                if (wizResult) {
                    body.push_back(text(wizResult->exitCode == 0 ? tr(Key::ResultDone)
                                                                  : format1(Key::ResultError, wizResult->exitCode)) |
                                   color(wizResult->exitCode == 0 ? kGood : kBad));
                    body.push_back(text(""));
                    body.push_back(paragraphAlignLeft(wizResult->output) | color(kFg));
                }
                footer = wizardStep == WizardStep::RegisterResult
                             ? hflow({text(" "), keyHint("g", "captcha"), keyHint("v", tr(Key::FooterEnterCode)),
                                    keyHint("esc", tr(Key::FooterToList))}) |
                                   bgcolor(kBgAlt)
                             : hflow({text(" "), keyHint("v", tr(Key::FooterEnterCode)),
                                    keyHint("esc", tr(Key::FooterToList))}) |
                                   bgcolor(kBgAlt);
                break;

            case WizardStep::CaptchaForm:
                titleSuffix = std::string("captcha: ") + wizName;
                body.push_back(paragraphAlignLeft(tr(Key::CaptchaInstructions)) | color(kDim));
                body.push_back(text(""));
                body.push_back(fieldRow(tr(Key::FieldToken), wizCaptchaToken, true));
                footer = hflow({text(tr(Key::FooterTypeToken)) | color(kDim), keyHint("^o", tr(Key::FooterSubmit)),
                              keyHint("esc", tr(Key::FooterCancel))}) |
                        bgcolor(kBgAlt);
                break;

            case WizardStep::VerifyForm:
                titleSuffix = tr(Key::WizardVerify) + wizName;
                body.push_back(fieldRow(tr(Key::FieldSmsCode), wizVerifyCode, true));
                footer = hflow({text(tr(Key::FooterTypeCode)) | color(kDim), keyHint("^o", tr(Key::FooterConfirm)),
                              keyHint("esc", tr(Key::FooterCancel))}) |
                        bgcolor(kBgAlt);
                break;

            case WizardStep::VerifyResult:
                titleSuffix = tr(Key::WizardResult) + wizName;
                if (wizResult) {
                    body.push_back(text(wizResult->exitCode == 0 ? tr(Key::ResultDone)
                                                                  : format1(Key::ResultError, wizResult->exitCode)) |
                                   color(wizResult->exitCode == 0 ? kGood : kBad));
                    body.push_back(text(""));
                    body.push_back(paragraphAlignLeft(wizResult->output) | color(kFg));
                }
                footer = text(std::string(" ") + tr(Key::AnyKeyToList) + " ") | color(kDim) | bgcolor(kBgAlt);
                break;

            case WizardStep::LinkWaiting: {
                titleSuffix = tr(Key::WizardLinking) + wizName;
                body.push_back(text(tr(Key::LinkWaitingInstructions)) | color(kDim));
                body.push_back(text(""));
                std::string out;
                {
                    std::lock_guard<std::mutex> lock(linkMutex);
                    out = linkOutput;
                }
                pushLines(body, out);
                footer = hflow({text(" "), keyHint("esc", tr(Key::FooterCancelWaiting))}) | bgcolor(kBgAlt);
                break;
            }

            case WizardStep::LinkResult:
                titleSuffix = tr(Key::WizardLinking) + wizName;
                if (wizResult) {
                    body.push_back(text(wizResult->exitCode == 0
                                             ? tr(Key::ResultDone)
                                             : format1(Key::ResultErrorCancelled, wizResult->exitCode)) |
                                   color(wizResult->exitCode == 0 ? kGood : kBad));
                    body.push_back(text(""));
                    pushLines(body, wizResult->output);
                }
                footer = text(std::string(" ") + tr(Key::AnyKeyToList) + " ") | color(kDim) | bgcolor(kBgAlt);
                break;
        }

        Element titlebar = hbox({
                                text("● ") | color(kBorder),
                                text("● ") | color(kBorder),
                                text("● ") | color(kBorder),
                                text(tr(Key::WizardTitlebar) + titleSuffix) | color(kDim),
                            }) |
                            bgcolor(kBgAlt);

        return vbox({
                   titlebar,
                   separator() | color(kBorder),
                   vbox(std::move(body)) | flex | size(HEIGHT, GREATER_THAN, 3) | bgcolor(kBg) | color(kFg),
                   separator() | color(kBorder),
                   footer,
               }) |
               border | color(kBorder) | bgcolor(kBg);
    };

    // Cap the panel's own width on very large terminals instead of
    // stretching a curses-style account manager edge to edge across a
    // whole wide monitor - same idea as most TUI tools (htop, etc)
    // staying a fixed comfortable width and just centering with blank
    // space on either side once the terminal's wider than that. Screen 2
    // (confirm dialog) already centers/caps itself via its own fixed-
    // width dialog box, so it's excluded here to avoid double-centering
    // it inside an even narrower column.
    constexpr int kMaxPanelWidth = 110;
    Component root = Renderer([&] {
        Element content;
        if (screenIndex == 0) content = renderList();
        else if (screenIndex == 1) content = renderDetail();
        else if (screenIndex == 2) return renderConfirm();
        else if (screenIndex == 3) content = renderConfig();
        else if (screenIndex == 5) content = renderSignalConfig();
        else content = renderWizard();
        return hbox({filler(), content | size(WIDTH, LESS_THAN, kMaxPanelWidth), filler()}) | bgcolor(kBg);
    });

    root = CatchEvent(root, [&](Event event) {
        if (screenIndex == 4) {
            if (wizardStep == WizardStep::LinkWaiting) {
                if (event == Event::Custom) {
                    // Our own wake-up ping from startLinkThread()'s
                    // background thread - not a real keypress. Every
                    // stdout chunk fires one of these (see that lambda's
                    // own comment), so the redraw this naturally triggers
                    // is what actually gets the QR/status on screen as it
                    // streams in.
                    if (linkDone.load()) {
                        std::lock_guard<std::mutex> lock(linkMutex);
                        wizResult = GendbResult{linkExitCode, linkOutput};
                        if (linkThread.joinable()) linkThread.join();
                        wizardStep = WizardStep::LinkResult;
                    }
                    return true;
                }
                if (event == Event::Escape) {
                    cancelLinkThread();
                    screenIndex = 0;
                    reload();
                    return true;
                }
                return false; // nothing else is meaningful while waiting
            }

            if (wizardStep == WizardStep::VerifyResult || wizardStep == WizardStep::LinkResult) {
                // Terminal either way (pass or fail) - any key returns to
                // the list. reload() unconditionally: a successful verify
                // or link just created a real account row.
                screenIndex = 0;
                reload();
                return true;
            }

            if (event == Event::Escape) {
                screenIndex = 0;
                reload();
                return true;
            }

            // Ctrl+O ("next"/"submit") - same portable control byte as
            // Screen 4's save key, checked before the free-text branches
            // below for the same reason (see Screen 4's own comment on
            // why F2 was abandoned).
            bool ctrlO = event == Event::Special(std::string(1, static_cast<char>(15)));

            if (wizardStep == WizardStep::ChooseType) {
                if (ctrlO) {
                    if (wizName.empty()) {
                        wizError = tr(Key::ErrEnterAccountName);
                        return true;
                    }
                    bool taken = std::any_of(accounts.begin(), accounts.end(),
                                             [&](const ViewAccount& a) { return a.name == wizName; });
                    if (taken) {
                        wizError = tr(Key::ErrAccountExists);
                        return true;
                    }
                    wizError.clear();
                    if (wizLink) {
                        startLinkThread(wizName);
                        wizardStep = WizardStep::LinkWaiting;
                    } else {
                        wizField = 0;
                        wizardStep = WizardStep::RegisterForm;
                    }
                    return true;
                }
                if (event == Event::ArrowDown || event == Event::Tab || event == Event::ArrowUp ||
                    event == Event::TabReverse) {
                    wizField = 1 - wizField;
                    return true;
                }
                if (wizField == 1) {
                    if (event == Event::Return) {
                        wizLink = !wizLink;
                        return true;
                    }
                    return false;
                }
                if (event == Event::Backspace) {
                    if (!wizName.empty()) wizName.pop_back();
                    wizError.clear();
                    return true;
                }
                if (event.is_character()) {
                    wizName += event.character();
                    wizError.clear();
                    return true;
                }
                return false;
            }

            if (wizardStep == WizardStep::RegisterForm) {
                if (ctrlO) {
                    if (wizE164.empty()) {
                        wizError = tr(Key::ErrEnterE164);
                        return true;
                    }
                    wizError.clear();
                    wizResult = runGendb(
                        gendbPath, {"--config", configPath, wizName, "register", "--e164", wizE164, wizTransport});
                    wizardStep = WizardStep::RegisterResult;
                    return true;
                }
                if (event == Event::ArrowDown || event == Event::Tab || event == Event::ArrowUp ||
                    event == Event::TabReverse) {
                    wizField = 1 - wizField;
                    return true;
                }
                if (wizField == 1) {
                    if (event == Event::Return) {
                        wizTransport = (wizTransport == "sms") ? "voice" : "sms";
                        return true;
                    }
                    return false;
                }
                if (event == Event::Backspace) {
                    if (!wizE164.empty()) wizE164.pop_back();
                    wizError.clear();
                    return true;
                }
                if (event.is_character()) {
                    wizE164 += event.character();
                    wizError.clear();
                    return true;
                }
                return false;
            }

            if (wizardStep == WizardStep::RegisterResult) {
                if (event == Event::Character('g')) {
                    wizardStep = WizardStep::CaptchaForm;
                    return true;
                }
                if (event == Event::Character('v')) {
                    wizardStep = WizardStep::VerifyForm;
                    return true;
                }
                return false;
            }

            if (wizardStep == WizardStep::CaptchaForm) {
                if (ctrlO) {
                    wizResult =
                        runGendb(gendbPath, {"--config", configPath, wizName, "register-captcha", wizCaptchaToken});
                    wizardStep = WizardStep::CaptchaResult;
                    return true;
                }
                if (event == Event::Backspace) {
                    if (!wizCaptchaToken.empty()) wizCaptchaToken.pop_back();
                    return true;
                }
                if (event.is_character()) {
                    wizCaptchaToken += event.character();
                    return true;
                }
                return false;
            }

            if (wizardStep == WizardStep::CaptchaResult) {
                if (event == Event::Character('v')) {
                    wizardStep = WizardStep::VerifyForm;
                    return true;
                }
                return false;
            }

            if (wizardStep == WizardStep::VerifyForm) {
                if (ctrlO) {
                    wizResult = runGendb(gendbPath, {"--config", configPath, wizName, "verify", wizVerifyCode});
                    wizardStep = WizardStep::VerifyResult;
                    return true;
                }
                if (event == Event::Backspace) {
                    if (!wizVerifyCode.empty()) wizVerifyCode.pop_back();
                    return true;
                }
                if (event.is_character()) {
                    wizVerifyCode += event.character();
                    return true;
                }
                return false;
            }

            return false;
        }

        if (screenIndex == 3) {
            if (configSaveDone) {
                // Any key dismisses back to the detail screen - re-read
                // the account since config/enabled likely changed, and
                // reload() the list too (config_version, sip_host, ...
                // all feed Screen 1's own columns).
                configSaveDone = false;
                screenIndex = 1;
                try {
                    Storage storage(global.dbPath, global.dbKey, detailName);
                    detail = storage.loadAccount();
                } catch (const std::exception& e) {
                    detailError = e.what();
                }
                reload();
                return true;
            }
            if (event == Event::Escape) {
                // Discards unsaved edits - editValues is rebuilt fresh
                // from the database next time openConfig() runs, no
                // separate "discard?" confirmation for a routine settings
                // form (unlike Screen 3's destructive actions).
                screenIndex = 1;
                return true;
            }
            // Ctrl+O (ASCII 15, "shift-in") for save, not an F-key: F-keys
            // send a multi-byte escape sequence whose exact bytes vary by
            // terminal/terminfo entry, and F2 was confirmed live to not
            // fire at all under tmux's default terminfo - a real instance
            // of the cross-terminal risk raised when this TUI was first
            // scoped. A bare control byte has no such ambiguity. Also not
            // Ctrl+S/Ctrl+Q (XON/XOFF software flow control - can freeze
            // the whole terminal) or Ctrl+C/Z/\ (SIGINT/SIGTSTP/SIGQUIT).
            if (event == Event::Special(std::string(1, static_cast<char>(15)))) {
                saveConfig();
                return true;
            }
            if (event == Event::ArrowDown || event == Event::Tab) {
                editField = (editField + 1) % static_cast<int>(kConfigFields.size());
                return true;
            }
            if (event == Event::ArrowUp || event == Event::TabReverse) {
                editField = (editField - 1 + static_cast<int>(kConfigFields.size())) %
                            static_cast<int>(kConfigFields.size());
                return true;
            }

            const ConfigFieldDef& f = kConfigFields[editField];
            std::string& value = editValues[f.key];
            if (f.kind == ConfigFieldDef::Kind::Enum) {
                if (event == Event::Return) {
                    auto it = std::find(f.options.begin(), f.options.end(), value);
                    size_t idx = (it == f.options.end())
                                     ? 0
                                     : (static_cast<size_t>(it - f.options.begin()) + 1) % f.options.size();
                    value = f.options[idx];
                    return true;
                }
                return false;
            }
            if (f.kind == ConfigFieldDef::Kind::Bool) {
                if (event == Event::Return) {
                    value = (value == "yes") ? "no" : "yes";
                    return true;
                }
                return false;
            }
            // Text / Masked
            if (event == Event::Backspace) {
                if (!value.empty()) value.pop_back();
                return true;
            }
            if (event.is_character()) {
                value += event.character();
                return true;
            }
            return false;
        }

        if (screenIndex == 5) {
            if (signalSaveDone) {
                // Same dismiss-and-refresh pattern as Screen 4's save
                // result - any key returns to the detail screen with a
                // freshly re-read account (server_url may have changed).
                signalSaveDone = false;
                screenIndex = 1;
                try {
                    Storage storage(global.dbPath, global.dbKey, detailName);
                    detail = storage.loadAccount();
                } catch (const std::exception& e) {
                    detailError = e.what();
                }
                reload();
                return true;
            }
            if (event == Event::Escape) {
                screenIndex = 1; // discard edits, same as Screen 4
                return true;
            }
            if (event == Event::Special(std::string(1, static_cast<char>(15)))) {
                saveSignalConfig();
                return true;
            }
            if (event == Event::ArrowDown || event == Event::Tab) {
                signalEditField = (signalEditField + 1) % static_cast<int>(kSignalConfigFields.size());
                return true;
            }
            if (event == Event::ArrowUp || event == Event::TabReverse) {
                signalEditField = (signalEditField - 1 + static_cast<int>(kSignalConfigFields.size())) %
                                   static_cast<int>(kSignalConfigFields.size());
                return true;
            }

            const ConfigFieldDef& sf = kSignalConfigFields[signalEditField];
            std::string& sValue = signalEditValues[sf.key];
            if (sf.kind == ConfigFieldDef::Kind::Bool) {
                if (event == Event::Return) {
                    sValue = (sValue == "yes") ? "no" : "yes";
                    return true;
                }
                return false;
            }
            if (event == Event::Backspace) {
                if (!sValue.empty()) sValue.pop_back();
                return true;
            }
            if (event.is_character()) {
                sValue += event.character();
                return true;
            }
            return false;
        }

        if (screenIndex == 2) {
            if (lastResult) {
                // Any key dismisses the result and returns to the list -
                // reload() since a completed action almost always changed
                // something reload() needs to reflect (enabled flag,
                // account existing at all after delete-account, ...).
                pending = PendingAction::None;
                lastResult.reset();
                screenIndex = 0;
                reload();
                return true;
            }
            if (event == Event::Escape) {
                pending = PendingAction::None;
                screenIndex = 1;
                return true;
            }
            bool severe = pending == PendingAction::DeleteAccount;
            if (severe) {
                if (event == Event::Backspace) {
                    if (!typedConfirm.empty()) typedConfirm.pop_back();
                    return true;
                }
                if (event == Event::Return) {
                    if (typedConfirm == detailName) runPendingAction();
                    return true;
                }
                if (event.is_character()) {
                    typedConfirm += event.character();
                    return true;
                }
                return false;
            }
            if (event == Event::Character('y')) {
                runPendingAction();
                return true;
            }
            return false;
        }

        if (screenIndex == 0) {
            if (event == Event::ArrowDown || event == Event::Character('j')) {
                if (!accounts.empty()) selected = std::min(selected + 1, static_cast<int>(accounts.size()) - 1);
                return true;
            }
            if (event == Event::ArrowUp || event == Event::Character('k')) {
                if (!accounts.empty()) selected = std::max(selected - 1, 0);
                return true;
            }
            if (event == Event::Return) {
                openDetail();
                return true;
            }
            if (event == Event::Character('n')) {
                openWizard();
                return true;
            }
            if (event == Event::Character('r')) {
                reload();
                return true;
            }
            if (event == Event::Character('q') || event == Event::Escape) {
                quit = true;
                screen.ExitLoopClosure()();
                return true;
            }
            return false;
        }

        // screenIndex == 1 (detail)
        if (event == Event::Escape) {
            screenIndex = 0;
            return true;
        }
        if (event == Event::Character('d')) {
            openConfirm(detail.enabled ? PendingAction::Disable : PendingAction::Enable);
            return true;
        }
        if (event == Event::Character('u')) {
            openConfirm(PendingAction::Deactivate);
            return true;
        }
        if (event == Event::Character('x')) {
            openConfirm(PendingAction::DeleteAccount);
            return true;
        }
        if (event == Event::Character('c')) {
            openConfig();
            return true;
        }
        if (event == Event::Character('s')) {
            openSignalConfig();
            return true;
        }
        return false;
    });

    screen.Loop(root);
    (void)quit;
    // Defensive only - every real exit path (Escape from LinkWaiting,
    // or the LinkResult transition once the subprocess finishes on its
    // own) already joins linkThread; this just guarantees no thread
    // handle is ever left dangling if some other exit path is added
    // later without remembering to do the same.
    if (linkThread.joinable()) {
        pid_t pidToKill = -1;
        {
            std::lock_guard<std::mutex> lock(linkMutex);
            pidToKill = linkPid;
        }
        if (pidToKill > 0) ::kill(pidToKill, SIGTERM);
        linkThread.join();
    }
    // ScreenInteractive::Fullscreen() doesn't use the terminal's alternate
    // screen buffer, so without this the last-drawn frame (borders, QR,
    // whatever screen was open) just sits there after quitting instead of
    // leaving a clean terminal behind. Plain ANSI clear + cursor-home -
    // deliberately not also clearing scrollback (`\x1b[3J`), only what's
    // currently visible.
    std::cout << "\x1b[2J\x1b[H" << std::flush;
    return 0;
}
