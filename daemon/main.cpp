// signal2sip-daemon: one process serving N Signal accounts at once (each
// optionally with its own SIP trunk), driven entirely by real
// incoming/outgoing Signal calls - no IPC, no Node. Real Signal Protocol
// send/receive, RingRTC calling, and the PJSIP ring-buffer bridge, all
// per-account.
//
// Was one process per account (mirroring tg2sip-webrtc's own model) -
// deliberately reversed to single-process-multi-account; see the
// project's own memory for that decision and Config.h's doc comment for
// the resulting config file shape.
//
// Two roles a given account can take, inferred from its own config
// section (not an explicit mode flag):
//   - Incoming Signal call + [sip.<name>] bridge_destination configured:
//     answers automatically and bridges the call's audio to a real SIP
//     call via RingRtcSipBridge (native/voip/), same pattern
//     pjsip_ringrtc_echo_test.cpp's peerB proved live against DPDZK's *43.
//   - [other.<name>] outgoing_call_target configured: places an outgoing
//     Signal call and pushes/pulls raw audio directly (no SIP leg) - a
//     test probe, measuring RMS to confirm the round trip through the
//     other account's SIP bridge actually carried real audio. Mirrors
//     pjsip_ringrtc_echo_test.cpp's peerA.
//
// Concurrent calls across DIFFERENT accounts are fully supported (each
// account has its own AuthSocket/ProtocolStores/RingRTC CallManager/
// PJSIP Account) now that ringrtc's AUDIO_TRANSPORT global was made
// per-instance (see ../webrtc/ringrtc/rffi/src/audio_device.cc, a sibling checkout of ../ringrtc)
// - two calls on two accounts no longer risk crossing audio.

#include <algorithm>
#include <atomic>
#include <cerrno>
#include <chrono>
#include <cmath>
#include <condition_variable>
#include <csignal>
#include <cstring>
#include <deque>
#include <fstream>
#include <functional>
#include <future>
#include <iostream>
#include <map>
#include <memory>
#include <mutex>
#include <regex>
#include <set>
#include <sstream>
#include <thread>
#include <unistd.h>
#include <sys/wait.h>

#include <curl/curl.h>
#include <nlohmann/json.hpp>
#include <pjmedia/resample.h>
#include <pjsua-lib/pjsua.h>
#include <pjsua2.hpp>

#include "CallSignaling.h"
#include "Config.h"
#include "ContactResolver.h"
#include "StorageServiceSync.h"
#include "../ringrtc/signal2sip_ringrtc.h"
#include "../signal/AuthSocket.h"
#include "../signal/Crypto.h"
#include "../signal/FfiUtil.h"
#include "../signal/PreKeys.h"
#include "../signal/ProtocolStores.h"
#include "../storage/Storage.h"
#include "../util/Base64.h"
#include "../voip/ringrtc_sip_bridge.h"
#include "SignalService.pb.h"

using namespace signal2sip;
using json = nlohmann::json;

namespace {

// Generates and uploads fresh signed+Kyber prekeys for both identities,
// saving them to Storage too - matches refresh_prekeys_test.cpp exactly,
// except it also persists locally (that test only uploads, proving the
// server accepts them, since it has no Storage to persist into). Real
// Signal clients do this periodically; this daemon does it once at
// startup, which also fixes a real gap found live: the two test
// accounts' migrated-from-JSON prekeys had drifted from whatever the
// server was actually advertising (stale snapshots from different
// points in time), so a fresh outgoing call's PreKey message failed to
// decrypt on the receiving end ("invalid PreKey message: decryption
// failed") even though the account data itself was otherwise fine.
void refreshPrekeys(Storage& storage, AuthSocket& socket, const AccountRecord& account) {
    int64_t keyId = static_cast<int64_t>(
        std::chrono::duration_cast<std::chrono::seconds>(std::chrono::system_clock::now().time_since_epoch())
            .count() %
        0xfffffe);

    auto refreshOne = [&](const char* identity, const Bytes& identityPrivateKey) {
        GeneratedSignedPreKey signedPreKey = generateSignedPreKey(identityPrivateKey, keyId);
        GeneratedKyberPreKey kyberPreKey = generateKyberPreKey(identityPrivateKey, keyId);
        storage.saveSignedPrekey(identity, signedPreKey.stored);
        storage.saveKyberPrekey(identity, kyberPreKey.stored);

        json body = {
            {"preKeys", json::array()},
            {"signedPreKey",
             {{"keyId", signedPreKey.wire.keyId},
              {"publicKey", base64Encode(signedPreKey.wire.publicKey)},
              {"signature", base64Encode(signedPreKey.wire.signature)}}},
            {"pqLastResortPreKey",
             {{"keyId", kyberPreKey.wire.keyId},
              {"publicKey", base64Encode(kyberPreKey.wire.publicKey)},
              {"signature", base64Encode(kyberPreKey.wire.signature)}}},
            {"pqPreKeys", json::array()},
        };
        std::string bodyStr = body.dump();
        Bytes bodyBytes(bodyStr.begin(), bodyStr.end());
        auto response = socket.request("PUT", std::string("/v2/keys?identity=") + identity, &bodyBytes);
        std::cout << "[daemon] PUT /v2/keys?identity=" << identity << " -> " << response.status << "\n";
    };

    auto aciKeypair = storage.loadIdentityKeypair("aci");
    auto pniKeypair = storage.loadIdentityKeypair("pni");
    if (aciKeypair) refreshOne("aci", aciKeypair->private_key);
    if (pniKeypair) refreshOne("pni", pniKeypair->private_key);
}

// PUT /v1/accounts/attributes/ once per setupAccount() - same call
// gendb's putFetchesMessages()/toggle_discoverability_test.cpp already
// proved live, just fired here automatically instead of only on a manual
// `deactivate`/`reactivate`. Exists to close a suspected gap behind
// project memory project_signal2sip_cds_discoverability.md: a real
// client keeps re-sending this attributes body periodically
// (RefreshAttributesJob), giving Signal-Server's CDS DynamoDB-stream
// filter repeated chances to see a clean event with the PNI field
// present; a `gendb register`-created account that's never connected a
// real client only ever got the ONE (possibly racy) insert event from
// registration and then went silent forever. Firing this once per daemon
// startup/account-(re)init is a cheap, harmless approximation of that
// periodic re-assertion - unverified whether it actually fixes CDS
// discoverability, this is the experiment.
//
// capabilitiesJson() is intentionally duplicated from gendb/main.cpp
// (not shared via a header) - keep the two in sync if either changes;
// not worth a new shared target for five lines of static JSON that two
// binaries with otherwise-disjoint link graphs would both need to link.
//
// Scoped to flow=="standalone" (Flow A / gendb `register`) only - a
// "linked" (Flow B) account's `name` field must be the encrypted device
// name (see gendb's putFetchesMessages()), which needs DeviceNameCipher
// from signal2sip_gendb, not linked into signal2sip-daemon; sending
// name=null for a linked account would silently blank its shown device
// name (setAccountAttributes overwrites, doesn't merge - see
// putFetchesMessages()'s own comment). The confirmed CDS anomaly is
// specifically about `gendb register`-created (standalone) accounts
// anyway, so linked accounts are out of scope for this fix, not just
// skipped for convenience.
void refreshAccountAttributes(AuthSocket& socket, const AccountRecord& account) {
    if (account.flow != "standalone") return;

    json body = {
        {"fetchesMessages", true},
        {"registrationId", account.registration_id},
        {"pniRegistrationId", account.pni_registration_id},
        {"name", nullptr},
        {"capabilities",
         json{{"storage", false},
              {"versionedExpirationTimer", false},
              {"attachmentBackfill", false},
              {"spqr", true},
              {"usernameChangeSyncMessage", true}}},
        {"unrestrictedUnidentifiedAccess", true},
        {"discoverableByPhoneNumber", true},
    };
    std::string bodyStr = body.dump();
    Bytes bodyBytes(bodyStr.begin(), bodyStr.end());
    auto response = socket.request("PUT", "/v1/accounts/attributes/", &bodyBytes);
    std::cout << "[daemon] PUT /v1/accounts/attributes/ (refresh, CDS-anomaly experiment) -> " << response.status
               << "\n";
}

// Ordered, off-service-thread dispatch for work triggered by onPush() -
// incoming CallMessage handling and DecryptionErrorMessage replies. Both
// used to be a raw `std::thread(...).detach()` per envelope: that
// avoided running on AuthSocket's single service thread (necessary - see
// ProtocolStores::mutex()'s doc comment for the self-deadlock that
// causes), but had three real problems found live: (1) no ordering
// between envelopes, so a same-call ICE-candidate envelope's thread could
// finish before an earlier Offer envelope's thread, and RingRTC would
// drop the ICE candidate for a call it doesn't know about yet; (2)
// unbounded thread creation under a burst/flood of envelopes; (3) nothing
// tracked these threads, so a detached thread could still be running
// when main() destroyed the objects it dereferences, a genuine
// use-after-free on shutdown. A single worker thread with a FIFO queue
// fixes all three: one thread total, strict arrival order, and something
// concrete for shutdown to join. One instance per account (not shared) -
// keeps each account's ordering/shutdown guarantees independent, with
// zero new cross-account interaction to reason about.
class EnvelopeDispatchQueue {
public:
    void start() {
        state_ = std::make_shared<State>();
        worker_ = std::thread([state = state_] { run(state); });
    }

    void push(std::function<void()> work) {
        {
            std::lock_guard<std::mutex> lock(state_->mutex);
            state_->queue.push_back(std::move(work));
        }
        state_->cv.notify_one();
    }

    // Drains whatever's queued, stops, and joins the worker - call once
    // from main()'s shutdown sequence, before destroying anything queued
    // work might reference.
    //
    // Bounded: run()'s loop only checks stopping *between* work items, so
    // if the in-flight item is itself blocked (e.g. a network call inside a
    // reconnect handler, observed live 2026-08-07 stalling shutdown for a
    // full 30s until systemd SIGKILLed the whole daemon), an unbounded
    // join() here blocks teardownAccount() for every account queued behind
    // this one, and with enough accounts configured that alone can exceed
    // systemd's TimeoutStopSec. If the worker hasn't finished within
    // kJoinTimeout, give up on joining it and return anyway - the worker
    // will still exit whenever its stuck call eventually returns.
    //
    // State is heap-allocated and kept alive via shared_ptr (captured by
    // value in both the worker's and the waiter's lambdas) specifically so
    // an abandoned join is memory-safe on *this* object's own bookkeeping:
    // the caller is free to destroy this EnvelopeDispatchQueue (and the
    // AccountState that owns it) right after stopAndJoin() returns, even
    // though the worker thread may still be running - it keeps its own
    // reference to State alive and touches nothing here once detached. The
    // join itself happens on a dedicated waiter thread that takes ownership
    // of worker_ by move, rather than racing worker_.join()/detach() from
    // two threads against the same std::thread object, which would be UB.
    //
    // What this does NOT make safe: the in-flight work() item itself may
    // still reference other AccountState fields (bridge, socket, storage)
    // that teardownAccount() destroys right after this returns. That
    // residual use-after-free risk, only reachable if a work item is still
    // stuck past kJoinTimeout, is accepted as the lesser evil versus a
    // guaranteed process-wide SIGKILL.
    void stopAndJoin() {
        {
            std::lock_guard<std::mutex> lock(state_->mutex);
            state_->stopping = true;
        }
        state_->cv.notify_one();
        if (!worker_.joinable()) return;

        static constexpr auto kJoinTimeout = std::chrono::seconds(5);
        std::promise<void> joined;
        std::future<void> joinedFuture = joined.get_future();
        std::thread waiter([w = std::move(worker_), joined = std::move(joined)]() mutable {
            w.join();
            joined.set_value();
        });
        waiter.detach();

        if (joinedFuture.wait_for(kJoinTimeout) != std::future_status::ready) {
            std::cerr << "[daemon] envelope dispatch: worker still busy after "
                      << kJoinTimeout.count() << "s, abandoning join to avoid blocking shutdown\n";
        }
    }

private:
    struct State {
        std::mutex mutex;
        std::condition_variable cv;
        std::deque<std::function<void()>> queue;
        bool stopping = false;
    };

    static void run(const std::shared_ptr<State>& state) {
        while (true) {
            std::function<void()> work;
            {
                std::unique_lock<std::mutex> lock(state->mutex);
                state->cv.wait(lock, [&state] { return state->stopping || !state->queue.empty(); });
                if (state->queue.empty()) {
                    if (state->stopping) return;
                    continue;
                }
                work = std::move(state->queue.front());
                state->queue.pop_front();
            }
            try {
                work();
            } catch (const std::exception& e) {
                std::cerr << "[daemon] envelope dispatch: unhandled exception: " << e.what() << "\n";
            } catch (...) {
                std::cerr << "[daemon] envelope dispatch: unhandled non-standard exception\n";
            }
        }
    }

    std::shared_ptr<State> state_;
    std::thread worker_;
};

// Everything one account's C-ABI callbacks (plain function pointers, no
// captures - RingRTC's Signal2sipCallbacks::context carries the pointer
// back to the right instance instead) need. One of these per configured
// account, owned by g_accounts below - replaces what used to be a single
// global DaemonState (one process = one account, pre-refactor).
struct AccountState {
    AccountConfig config;
    std::unique_ptr<Storage> storage;
    std::unique_ptr<ProtocolStores> stores;
    AccountRecord account;
    std::string localServiceId; // == account.aci
    std::unique_ptr<AuthSocket> socket;
    std::unique_ptr<CallMessageSender> sender;
    Signal2sipCallManagerHandle* handle = nullptr;

    // Set once a call is active - the far end's serviceId, used because
    // RingRTC's callbacks give us remote_peer_id already, but call_state
    // doesn't, and we need it to know who to bridge/probe against.
    std::atomic<uint64_t> activeCallId{0};
    std::atomic<bool> isCallee{false};
    std::string remotePeerId;

    // Only ever one of these is non-null at a time (this project's
    // one-call-at-a-time-per-account scope, matching RingRTC's own
    // single-active-call-per-CallManager design) - a second account can
    // still have its own call active concurrently, see this file's
    // top-of-file comment.
    std::unique_ptr<voip::RingRtcSipBridge> bridge;
    pj::Call* sipCall = nullptr; // BridgeCall - we're bridging OUT to the PBX

    // IncomingSipCall - a real SIP INVITE arrived FROM the PBX and we're
    // placing/running an outgoing Signal call in response (opposite
    // direction from sipCall above; still only one of the two at a time,
    // same one-call-per-account scope).
    pj::Call* incomingSipCall = nullptr;

    // Guards remotePeerId + sipCall + incomingSipCall together (one
    // call's identity, always changes as a unit) - needed once
    // something reads them from a thread other than RingRTC's own
    // callback thread. Added for DTMF-over-text (onPush() reads all
    // three, on a libsignal-net-chat worker thread, to decide where to
    // forward a matching text message): a bare pointer read here isn't
    // like onIncomingCall()'s existing unlocked `if (acct.sipCall)`
    // truthiness check (harmless if stale) - DTMF actually dereferences
    // the pointer (`call->dialDtmf(...)`), and stopSipBridge()/
    // stopIncomingSipCall() do `delete call;` BEFORE `acct.sipCall =
    // nullptr;`, unlocked - an unsynchronized read in that exact window
    // would be a real use-after-free, not just a stale value. Take this
    // only around the actual pointer/string mutation (or the DTMF
    // check+send) - never around hangup()'s own up-to-5s
    // disconnect-poll loop, so a hangup in progress never blocks
    // message handling for seconds.
    std::mutex callHandoffMutex;

    EnvelopeDispatchQueue dispatchQueue;

    // Epoch-ms of the last StorageService sync attempt (success or
    // failure - see main()'s own storage-sync loop, right next to the
    // registration watchdog) - 0 means never attempted yet this process
    // lifetime (setupAccount()'s own initial sync sets this too, so the
    // periodic loop doesn't immediately redo it on the next tick).
    int64_t lastStorageSyncMs = 0;

    // Signal WebSocket watchdog bookkeeping (main()'s loop, right next to
    // the registration watchdog) - see AuthSocket::isConnected()'s own doc
    // comment. socketConnected mirrors the last isConnected() reading, so
    // the watchdog only logs/acts on the down->up and up->down edges
    // instead of every 200ms tick; starts true since setupAccount() only
    // ever returns after a successful connect().
    bool socketConnected = true;
    int64_t lastSocketReconnectAttemptMs = 0;

    // Set once the watchdog has logged the loud "give up, needs manual
    // re-link" message for this account (see AuthSocket::isDeauthorized())
    // - keeps that message from repeating every kSocketReconnectIntervalMs
    // once we've already stopped retrying. Reset on a fresh successful
    // reconnect (defensive - in practice a deauthorized account never
    // reaches that branch again without a process restart, since the
    // watchdog skips reconnect() entirely once this is true).
    bool deauthorizedAlerted = false;
};

std::map<std::string, std::unique_ptr<AccountState>> g_accounts; // keyed by AccountConfig::name

// How often main()'s loop retries a dropped Signal WebSocket - see the
// watchdog next to the SIP registration watchdog. A plain constant (not a
// GlobalConfig knob like sipRegWatchdogSec) - reconnecting a dead socket
// every few seconds is cheap enough that this doesn't need to be tunable.
constexpr int64_t kSocketReconnectIntervalMs = 5000;

// Only a gendb-linked account (a real device linked into a real,
// already-in-use Signal account) has a meaningful contact list to sync at
// all - a bare gendb-registered account has no real contacts, and no
// account_entropy_pool to derive the storage service key from either.
// Always updates lastStorageSyncMs (success or failure) so callers on a
// periodic timer don't retry a persistently-failing sync every tick - see
// GlobalConfig::storageSyncIntervalSec's own doc comment. Non-fatal on
// failure either way: resolveOutgoingTarget() just falls back to its
// existing CDS-only path (PNI-only for a cold e164) - see
// StorageServiceSync.h's own doc comment for the full "why" this exists.
void syncStorageContacts(AccountState& acct) {
    acct.lastStorageSyncMs = std::chrono::duration_cast<std::chrono::milliseconds>(
                                 std::chrono::steady_clock::now().time_since_epoch())
                                 .count();
    if (!acct.account.account_entropy_pool || acct.account.account_entropy_pool->empty()) return;
    try {
        std::vector<StorageContact> contacts = fetchStorageContacts(*acct.socket, *acct.account.account_entropy_pool);
        int cachedCount = 0;
        for (const auto& contact : contacts) {
            // e164-less contacts (added via QR/username) are still worth
            // caching by aci alone - see schema.sql's synced_contact
            // comment - only a contact with neither identifier is truly
            // unkeyable.
            if (contact.e164.empty() && contact.aci.empty()) continue;
            try {
                acct.storage->saveSyncedContact(contact.e164, contact.aci, contact.pni, contact.profileKey,
                                                contact.givenName, contact.familyName);
                cachedCount++;
            } catch (const std::exception& e) {
                // One bad row (e.g. a real DB constraint issue) shouldn't
                // lose every contact after it in this batch - found live
                // 2026-08-06: this loop had no per-contact handling at
                // all, so a single failure silently discarded the rest of
                // a real account's contact list.
                std::cerr << "[daemon][" << acct.config.name << "] saveSyncedContact(" << contact.e164
                           << ") failed (non-fatal): " << e.what() << "\n";
            }
        }
        std::cout << "[daemon][" << acct.config.name << "] StorageService sync: " << contacts.size() << " contact(s), "
                   << cachedCount << " cached (had an e164 and/or aci)\n";
    } catch (const std::exception& e) {
        std::cerr << "[daemon][" << acct.config.name << "] StorageService sync failed (non-fatal): " << e.what()
                   << "\n";
    }
}

// --- RingRTC -> Signal CallMessage (send side) ---

// RingRTC (Rust) invokes these directly and synchronously - a C++
// exception unwinding out of one of them crosses into Rust stack frames,
// which Rust cannot handle ("Rust cannot catch foreign exceptions") and
// hard-aborts the whole process instead of failing just this one call.
// Found live: a transient send failure (e.g. a rate-limited /v2/keys
// fetch inside sendCallMessage's session-establishment fallback) took
// the entire daemon down instead of just that one signaling message.
// Every callback RingRTC calls into must therefore catch everything
// itself (including non-std::exception types - the boundary contract is
// "nothing ever crosses it", not just the common case); on failure,
// simply not calling signal2sip_call_message_sent() leaves RingRTC to
// retry/timeout the call on its own (it has its own ~60s per-call
// timeout independent of this), same as if the message had been lost in
// transit.
template <typename F>
void safeCallback(const char* name, F&& f) {
    try {
        f();
    } catch (const std::exception& e) {
        std::cerr << "[daemon] " << name << " failed: " << e.what() << "\n";
    } catch (...) {
        std::cerr << "[daemon] " << name << " failed: unknown exception\n";
    }
}

void onSendOffer(void* context, const char* remotePeerId, uint64_t callId, int32_t mediaType, const uint8_t* opaque,
                   size_t opaqueLen) {
    auto& acct = *static_cast<AccountState*>(context);
    std::cout << "[daemon][" << acct.config.name << "] send_offer -> " << remotePeerId << "\n";
    safeCallback("send_offer", [&] {
        acct.sender->sendOffer(remotePeerId, callId, mediaType, opaque, opaqueLen);
        signal2sip_call_message_sent(acct.handle, callId);
    });
}

void onSendAnswer(void* context, const char* remotePeerId, uint64_t callId, const uint8_t* opaque, size_t opaqueLen) {
    auto& acct = *static_cast<AccountState*>(context);
    std::cout << "[daemon][" << acct.config.name << "] send_answer -> " << remotePeerId << "\n";
    safeCallback("send_answer", [&] {
        acct.sender->sendAnswer(remotePeerId, callId, opaque, opaqueLen);
        signal2sip_call_message_sent(acct.handle, callId);
    });
}

void onSendIce(void* context, const char* remotePeerId, uint64_t callId, bool hasReceiverDeviceId,
                uint32_t receiverDeviceId, const uint8_t* opaque, size_t opaqueLen) {
    auto& acct = *static_cast<AccountState*>(context);
    safeCallback("send_ice", [&] {
        acct.sender->sendIce(remotePeerId, callId, hasReceiverDeviceId, receiverDeviceId, opaque, opaqueLen);
        signal2sip_call_message_sent(acct.handle, callId);
    });
}

void onSendHangup(void* context, const char* remotePeerId, uint64_t callId, int32_t hangupType,
                   uint32_t hangupDeviceId) {
    auto& acct = *static_cast<AccountState*>(context);
    std::cout << "[daemon][" << acct.config.name << "] send_hangup -> " << remotePeerId << "\n";
    safeCallback("send_hangup", [&] {
        acct.sender->sendHangup(remotePeerId, callId, hangupType, hangupDeviceId);
        signal2sip_call_message_sent(acct.handle, callId);
    });
}

// --- SIP bridging (mirrors pjsip_ringrtc_echo_test.cpp's BridgeCall) ---

// Shared by BridgeCall and IncomingSipCall's onCallMediaState - identical
// resample-port wiring regardless of which direction the SIP leg is
// going. Non-resampling PJSIP conference bridge in this build - see
// pjsip_ringrtc_echo_test.cpp's onCallMediaState for the full story
// (real 488 Not Acceptable Here forcing 48kHz against DPDZK's *43, this
// resample-port approach is the fix that works for any call regardless
// of negotiated codec).
void wireBridgeAudio(pj::Call& call, voip::RingRtcSipBridge& bridge) {
    // onCallMediaState() (this function's only caller) can fire more than
    // once for the same call (renegotiation, hold/resume, ...) - without
    // this guard a second firing would wire up a SECOND pair of resample
    // ports into the same downstream ports (double audio delivery) and
    // leak the first pair, since SetResamplePorts() below only has room
    // for one. Found alongside the real SIGSEGV this function's other
    // change here fixes - see RingRtcSipBridge::SetResamplePorts()'s own
    // doc comment.
    if (bridge.HasResamplePorts()) return;

    pj::CallInfo ci = call.getInfo();
    for (unsigned i = 0; i < ci.media.size(); i++) {
        if (ci.media[i].type != PJMEDIA_TYPE_AUDIO || !call.getMedia(i)) continue;
        auto* aud = static_cast<pj::AudioMedia*>(call.getMedia(i));
        unsigned callRate = aud->getPortInfo().format.clockRate;
        std::cout << "[daemon][sip] call clock rate: " << callRate << "\n";

        // PJMEDIA_RESAMPLE_DONT_DESTROY_DN: the default (0) behavior is
        // for a resample port to destroy its OWN downstream port when
        // it's itself destroyed - which here would be
        // bridge.InputPjmediaPort()/OutputPjmediaPort(), whose lifetime
        // SoftwareAudioInput/SoftwareAudioOutput already separately own
        // and destroy (audio_bridge.cpp) - without this flag, whichever
        // side destroys its port first leaves the other with a dangling
        // pointer/double-free.
        pj_pool_t* pool = pjsua_pool_create("resample", 2048, 512);
        pjmedia_port* inResample = nullptr;
        pjmedia_resample_port_create(pool, bridge.InputPjmediaPort(), callRate,
                                      PJMEDIA_RESAMPLE_DONT_DESTROY_DN, &inResample);
        pjsua_conf_port_id inResampleId = PJSUA_INVALID_ID;
        pjsua_conf_add_port(pool, inResample, &inResampleId);
        pjsua_conf_connect(aud->getPortId(), inResampleId);

        pjmedia_port* outResample = nullptr;
        pjmedia_resample_port_create(pool, bridge.OutputPjmediaPort(), callRate,
                                      PJMEDIA_RESAMPLE_DONT_DESTROY_DN, &outResample);
        pjsua_conf_port_id outResampleId = PJSUA_INVALID_ID;
        pjsua_conf_add_port(pool, outResample, &outResampleId);
        pjsua_conf_connect(outResampleId, aud->getPortId());

        // Record these so ~RingRtcSipBridge() can tear them down before
        // it destroys the ports they wrap - found live 2026-08-06: a real
        // SIGSEGV (resample_put_frame() called into freed memory) from
        // PJMEDIA's own clock_thread still driving these resample ports
        // after audio_input_/audio_output_ had already been destroyed by
        // stopSipBridge()/stopIncomingSipCall(), since nothing previously
        // retained these ids/pool anywhere to ever remove them.
        bridge.SetResamplePorts(pool, inResampleId, outResampleId);

        std::cout << "[daemon][sip] audio wired to RingRtcSipBridge via resample ports\n";
        bridge.Start();
    }
}

class BridgeCall : public pj::Call {
public:
    // `acct` lets onCallState() reach back into the Signal-side call (see
    // its own doc comment below) - only meaningful for an incoming-bridge
    // BridgeCall (startSipDial()'s caller), not for any future
    // outgoing-direction use of this class.
    BridgeCall(pj::Account& acc, voip::RingRtcSipBridge& bridge, AccountState& acct)
        : pj::Call(acc), bridge_(bridge), acct_(acct) {}

    void onCallState(pj::OnCallStateParam&) override {
        pj::CallInfo ci = getInfo();
        std::cout << "[daemon][sip] call state=" << ci.stateText << " (" << ci.state << ")\n";
        // This is the actual moment the PBX side (a real extension/queue/
        // IVR) picked up - only now do we take over the Signal call. See
        // startSipDial()'s doc comment for why this is deliberately late
        // (not right after Signal's own Ringing) - the whole point is to
        // let a real linked device win the race if a human answers it
        // first, and only "steal" the call once the PBX side has
        // genuinely answered. acceptSent_ guards against PJSIP possibly
        // reporting CONFIRMED more than once for the same dialog.
        if (ci.state == PJSIP_INV_STATE_CONFIRMED && !acceptSent_.exchange(true)) {
            std::cout << "[daemon][" << acct_.config.name
                       << "][sip] PBX answered - accepting the Signal call\n";
            signal2sip_call_accept(acct_.handle, acct_.activeCallId.load());
        }
        if (ci.state == PJSIP_INV_STATE_DISCONNECTED) {
            // If we'd actually taken over the Signal call (acceptSent_)
            // and this disconnect wasn't us hanging up first (weHungUp_,
            // set by stopSipBridge() right before its own call->hangup())
            // then the PBX side hung up on its own - found live 2026-08-05:
            // without this, ending the call on the PBX side left the
            // Signal call sitting CONNECTED forever on the caller's
            // Android, since nothing ever told RingRTC this side was
            // done. hangup() ends whatever call_manager's current active
            // call is; the ENDED/CONCLUDED event it triggers is what runs
            // stopSipBridge()'s normal teardown (bridge_.Stop(), deleting
            // this BridgeCall) - so no separate cleanup is needed here.
            if (acceptSent_.load() && !weHungUp_.load()) {
                std::cout << "[daemon][" << acct_.config.name
                           << "][sip] PBX hung up - ending the Signal call\n";
                signal2sip_call_hangup(acct_.handle);
            }
            disconnected_ = true;
        }
    }

    void onCallMediaState(pj::OnCallMediaStateParam&) override { wireBridgeAudio(*this, bridge_); }

    std::atomic<bool> disconnected_{false};
    std::atomic<bool> weHungUp_{false}; // set by stopSipBridge() before its own hangup()

private:
    voip::RingRtcSipBridge& bridge_;
    AccountState& acct_;
    std::atomic<bool> acceptSent_{false};
};

// Handles the opposite direction from BridgeCall: a real SIP INVITE
// arriving AT the daemon (from Asterisk/the PBX) that should place a real
// outgoing Signal call - see BridgeAccount::onIncomingCall's own doc
// comment for how the destination number and originating account get
// picked. Not answered (200 OK) until the outgoing Signal call actually
// reaches CONNECTED (see onCallState's own CONNECTED handler) - kept
// Ringing until then so the caller sees real call progress instead of an
// instant, possibly-wrong answer.
class IncomingSipCall : public pj::Call {
public:
    IncomingSipCall(pj::Account& acc, int callId, voip::RingRtcSipBridge& bridge, AccountState& acct)
        : pj::Call(acc, callId), bridge_(bridge), acct_(acct) {}

    void onCallState(pj::OnCallStateParam&) override {
        pj::CallInfo ci = getInfo();
        std::cout << "[daemon][sip] incoming call state=" << ci.stateText << " (" << ci.state << ")\n";
        if (ci.state == PJSIP_INV_STATE_DISCONNECTED) {
            // Mirrors BridgeCall's own DISCONNECTED handling in the
            // opposite direction: if the PBX/caller hung up or cancelled
            // and this wasn't us hanging up first (weHungUp_, set by
            // stopIncomingSipCall() before its own hangup()), end
            // whatever the outgoing Signal call attempt is doing too -
            // otherwise a caller hanging up before the Signal side ever
            // answers would leave that outgoing call ringing forever.
            if (!weHungUp_.exchange(true)) {
                signal2sip_call_hangup(acct_.handle);
            }
            disconnected_ = true;
        }
    }

    void onCallMediaState(pj::OnCallMediaStateParam&) override { wireBridgeAudio(*this, bridge_); }

    std::atomic<bool> disconnected_{false};
    std::atomic<bool> weHungUp_{false}; // set by stopIncomingSipCall() before its own hangup()

private:
    voip::RingRtcSipBridge& bridge_;
    AccountState& acct_;
};

class BridgeAccount : public pj::Account {
public:
    std::atomic<bool> registered{false};

    // The dedicated transport createAccountUdpTransport()/
    // createAccountTlsTransport() made for this account (see
    // AccountConfig::sipTransport's own doc comment for why every
    // account needs its own). teardownAccount() closes it explicitly via
    // this - found live 2026-08-07 (config-in-DB testing, repeated
    // rebuild cycles): PJSIP transport IDs are a small fixed-size table
    // that's NEVER auto-reclaimed just because the pj::Account/transport
    // C++ wrapper objects using them were destroyed; only an explicit
    // Endpoint::transportClose() actually frees the slot. Without this,
    // every reload-triggered rebuild (config change, enable/disable)
    // permanently leaked one transport slot until the whole process was
    // restarted - confirmed live: real accounts hit "Too many objects of
    // the specified type (PJ_ETOOMANY)" and silently lost SIP entirely
    // after only a handful of rebuilds.
    pj::TransportId transportId = PJSUA_INVALID_ID;

    // Set right after construction in setupAccount(), before this account
    // can possibly receive any real SIP traffic - lets onIncomingCall()
    // (defined out-of-line below, after g_global's declaration) know
    // which Signal identity received the INVITE, so it knows which
    // account to originate the resulting outgoing Signal call from.
    AccountState* acctState = nullptr;

    // Defined out-of-line after g_global (needed for
    // resolvedContactTtlSec) - see its own doc comment there for the
    // full "why".
    void onIncomingCall(pj::OnIncomingCallParam& iprm) override;

    // Epoch-ms timestamp of the most recent transition into "not
    // registered" (0 while currently registered) - read by the
    // registration watchdog in main()'s loop to decide when PJSIP's own
    // retry has had enough time and it's worth forcing another attempt
    // ourselves. Not just a bool: PJSIP only auto-retries a short
    // allowlist of "temporary" failure codes (see pjsua_acc.c's regc_cb -
    // 408/500/502/503/504/480/6xx); a 403 Forbidden is not on that list
    // and would otherwise never retry again on its own, confirmed live
    // 08-04 (a stale-contact 403 during testing left the account dead
    // until the whole process was restarted).
    std::atomic<int64_t> unregisteredSinceMs{0};

    void onRegState(pj::OnRegStateParam&) override {
        pj::AccountInfo ai = getInfo();
        std::cout << "[daemon][sip] reg state active=" << ai.regIsActive << "\n";
        // Must mirror regIsActive both ways - PJSIP's own regc retries
        // registration automatically (default 300s interval) after a
        // failure/outage, but until that retry succeeds this flag is
        // startSipDial()'s only signal that the account isn't actually
        // usable right now. Only ever setting it true (never back to
        // false) meant a Signal call arriving mid-outage would still
        // attempt a real INVITE through a dead registration instead of
        // failing cleanly.
        registered = ai.regIsActive;
        if (ai.regIsActive) {
            unregisteredSinceMs = 0;
        } else if (unregisteredSinceMs.load() == 0) {
            unregisteredSinceMs = std::chrono::duration_cast<std::chrono::milliseconds>(
                                      std::chrono::steady_clock::now().time_since_epoch())
                                      .count();
        }
    }
};

// One shared PJSIP Endpoint for the whole process (pjsua2/PJSIP itself is
// a process-wide singleton - only one Endpoint is possible per process).
// Every account still gets its OWN dedicated transport off of this one
// Endpoint though (see createAccountUdpTransport()/
// createAccountTlsTransport()) - PJSIP can't reliably route an incoming
// call to the right account when several accounts share one transport
// and the Request-URI doesn't match any of their own identities (see
// AccountConfig::sipTransport's own doc comment for the live bug this
// caused). Created lazily (see ensureSharedEndpoint()) the first time any
// account needs it - either at startup or via a later SIGHUP reload - and
// never destroyed until process exit. Read (never written after
// creation) from startSipDial()'s libRegisterThread() call.
pj::Endpoint* g_ep = nullptr;
std::map<std::string, std::unique_ptr<BridgeAccount>> g_sipAccounts; // keyed by AccountConfig::name

// Ground truth for "which account does this incoming SIP call actually
// belong to" - keyed by the actual local UDP/TLS port each account's own
// dedicated transport is bound to (see createAccountUdpTransport()/
// createAccountTlsTransport(), populated right after each is created).
// BridgeAccount::onIncomingCall() cannot just trust `this->acctState`
// (i.e. trust that pjsua2 invoked the callback on the "right" Account
// object) - found live 2026-08-06: a real INVITE whose Request-URI
// (`sip:+123456789001@192.168.16.79:39445;ob`) and CDR both unambiguously
// showed it physically arrived on 123456789003's own dedicated port
// (39445) still fired onIncomingCall() on 123456789002's BridgeAccount
// instead - pjsua's internal account-matching for an incoming call tries
// to match the Request-URI against each account's own registered AOR,
// and none of them match a bare phone number like "+123456789001", so it
// falls back to some other (apparently unreliable, observed live to be
// wrong) heuristic instead of the transport the packet actually arrived
// on. Cross-checking against the real receiving transport's own local
// port - which this project controls and knows unambiguously, unlike
// pjsua's internal matching - sidesteps the whole question.
std::map<int, AccountState*> g_portToAccount;

// sipBridgeDid wins if both are somehow set - see AccountConfig's own doc
// comment for why that shouldn't realistically happen (the matching
// Asterisk endpoint only ever has one context, from-internal or
// from-pstn, never both). Empty means this account doesn't bridge
// incoming calls to SIP at all.
const std::string& bridgeTarget(const AccountConfig& config) {
    return config.sipBridgeDid.empty() ? config.sipBridgeDestination : config.sipBridgeDid;
}

// True only if this account both has a bridge target configured AND its
// SIP registration is actually up right now - checked here, BEFORE ever
// answering on the Signal side (see onCallState's INCOMING_AUDIO
// handler), not just inside startSipDial() itself. Confirmed live
// 08-04 that the earlier version of this check (target configured, full
// stop) still steals the Accept from this account's other real devices
// even when Asterisk/the SIP registration is unreachable - the call gets
// answered here, then startSipDial() discovers it can't actually bridge
// and just logs an error, by which point the real devices have already
// lost the race for nothing.
bool canBridgeToSip(const AccountConfig& config) {
    if (bridgeTarget(config).empty()) return false;
    auto it = g_sipAccounts.find(config.name);
    return it != g_sipAccounts.end() && it->second->registered.load();
}

// PJSUA2 requires every thread that calls into it to be registered with
// PJLIB first (Endpoint::libRegisterThread()), unless it's the thread
// that originally initialized the library (main()'s thread, which called
// ep.libCreate()/libInit()/libStart()) or one of PJSIP's own worker
// threads. Every function here that calls into pjsua2 from RingRTC's own
// callback thread (onCallState() and anything it calls, e.g.
// stopSipBridge()/stopIncomingSipCall() from the ENDED/CONCLUDED branch)
// needs this, once per OS thread - found live in startSipDial() first:
// without it, makeCall() still sent a real INVITE (the transport layer
// tolerated the unregistered thread fine), but PJSIP's automatic
// 401-challenge auto-retry - which relies on the dialog's thread-local
// auth session state - never fired, so a real call to DPDZK's *43 got
// exactly one INVITE, one 401, and then silently never connected.
//
// Found live again 2026-08-05, a second time: stopIncomingSipCall() was
// calling call->hangup() from this same unregistered RingRTC callback
// thread - unlike the Signal-call-bridges-to-SIP direction (where
// startSipDial() always runs first for that call, on that same thread,
// and registers it), the SIP-triggers-a-Signal-call direction has no
// earlier pjsua2 call on that thread to register it first. Silently
// broke that account's own SIP registration refresh a few seconds after
// the next failed/timed-out call - not a crash, so it went unnoticed
// until the registration itself quietly expired with nothing to renew
// it (user's own diagnosis: registration died a few seconds after the
// last failed Signal call, and stayed fine indefinitely when no call was
// ever attempted).
void registerPjsipThreadIfNeeded() {
    thread_local bool registered = false;
    if (!registered && g_ep) {
        try {
            g_ep->libRegisterThread("ringrtc-callback");
        } catch (pj::Error& err) {
            std::cerr << "[daemon] libRegisterThread failed: " << err.info() << "\n";
        }
        registered = true;
    }
}

// Places an outbound SIP INVITE to bridgeTarget(acct.config) - called at
// the incoming Signal call's Ringing state, deliberately BEFORE that
// Signal call is ever accepted on this device. This is what lets the SIP
// leg ring/queue/IVR on the PBX side as an independent participant in the
// account's normal multi-device fan-out, racing fairly against a real
// linked device (phone, Desktop, ...) instead of the daemon eagerly
// accepting the instant it's willing to bridge at all - the earlier
// version of this code called signal2sip_call_accept() right after
// Ringing, unconditionally, which (being near-instant) always beat a
// human tapping Accept on their phone (see
// [[project_signal2sip_incoming_call_steals_accept_bug]] in memory for
// that first version of the problem - this is the same race, one layer
// deeper: even gated on canBridgeToSip(), accepting before the PBX side
// has actually answered still steals the call for a bridge attempt that
// might itself go unanswered). BridgeCall::onCallState() is what actually
// calls signal2sip_call_accept(), once and only once the SIP INVITE
// reaches PJSIP_INV_STATE_CONFIRMED - i.e. once a real person/queue/IVR
// on the PBX side has genuinely picked up.
void startSipDial(AccountState& acct) {
    auto it = g_sipAccounts.find(acct.config.name);
    if (it == g_sipAccounts.end() || !it->second->registered.load()) {
        std::cerr << "[daemon][" << acct.config.name << "] cannot bridge to SIP: not registered\n";
        return;
    }
    BridgeAccount& sipAccount = *it->second;

    registerPjsipThreadIfNeeded();

    acct.bridge = std::make_unique<voip::RingRtcSipBridge>(acct.handle);

    // Real, pre-existing bug found live 08-04: this always used "sip:"
    // regardless of transport, unlike acfg.idUri/regConfig.registrarUri
    // above (built with the correct sips:-for-tls scheme) - a plain
    // "sip:" request URI tells PJSIP this call's security_level is 0,
    // which PJSIP_ESESSIONINSECURE's own check (pjsua_media.c:
    // "security_level < acc->cfg.srtp_secure_signaling") then correctly
    // rejects for any account that left srtp_secure_signaling at its
    // real default of 1 (every sip_transport=tls account here, since
    // main.cpp only ever relaxes that default for non-tls accounts).
    std::string scheme = acct.config.sipTransport == "tls" ? "sips" : "sip";
    std::string destUri = scheme + ":" + bridgeTarget(acct.config) + "@" + acct.config.sipHost;
    std::cout << "[daemon][" << acct.config.name << "][sip] placing bridge call to " << destUri << "\n";
    auto* call = new BridgeCall(sipAccount, *acct.bridge, acct);
    acct.sipCall = call;
    pj::CallOpParam prm(true);
    prm.opt.audioCount = 1;
    prm.opt.videoCount = 0;

    // Caller-info passthrough to the PBX, mirroring tg2sip-webrtc's proven
    // X-TG-* header pattern (gateway.cpp's DialSip::operator()) so FreePBX
    // can show/route on the real Signal caller's identity instead of just
    // the bare "signal2sip-<account>" trunk name. UUID (the caller's ACI)
    // is always known from RingRTC's remotePeerId; phone/name need a real
    // synced contact record - only ever populated for a gendb-linked
    // account with an actual contact list (see StorageServiceSync.h's own
    // doc comment), so they're best-effort/optional.
    if (!acct.remotePeerId.empty()) {
        pj::SipHeader header;
        header.hName = "X-Signal-UUID";
        header.hValue = acct.remotePeerId;
        prm.txOption.headers.push_back(header);

        auto contact = acct.storage->loadSyncedContactByAci(acct.remotePeerId);
        if (contact) {
            if (!contact->e164.empty()) {
                header.hName = "X-Signal-Phone";
                header.hValue = contact->e164;
                prm.txOption.headers.push_back(header);
            }
            std::string name = contact->given_name;
            if (!contact->family_name.empty()) name += (name.empty() ? "" : " ") + contact->family_name;
            if (!name.empty()) {
                header.hName = "X-Signal-Name";
                header.hValue = name;
                prm.txOption.headers.push_back(header);
            }
        }
    }

    try {
        call->makeCall(destUri, prm);
    } catch (pj::Error& err) {
        std::cerr << "[daemon][" << acct.config.name << "] FAIL: makeCall: " << err.info() << "\n";
    }
}

void stopSipBridge(AccountState& acct) {
    registerPjsipThreadIfNeeded();
    if (acct.bridge) {
        acct.bridge->Stop();
    }
    if (acct.sipCall) {
        auto* call = static_cast<BridgeCall*>(acct.sipCall);
        call->weHungUp_ = true; // before hangup() - see onCallState's DISCONNECTED handling
        pj::CallOpParam hprm;
        try {
            call->hangup(hprm);
        } catch (...) {
        }
        for (int i = 0; i < 50 && !call->disconnected_.load(); i++) {
            std::this_thread::sleep_for(std::chrono::milliseconds(100));
        }
        {
            // See AccountState::callHandoffMutex's own doc comment -
            // only the delete+nullptr needs the lock, not the hangup()/
            // disconnect-poll above.
            std::lock_guard<std::mutex> lock(acct.callHandoffMutex);
            delete call;
            acct.sipCall = nullptr;
        }
    }
    acct.bridge.reset();
}

// Mirrors stopSipBridge() for the opposite direction (IncomingSipCall
// instead of BridgeCall) - see AccountState::incomingSipCall's own doc
// comment. acct.bridge is the same shared field either function may have
// populated; harmless no-op here if the OTHER direction is what's
// actually active (acct.bridge already null, guard below just skips).
void stopIncomingSipCall(AccountState& acct) {
    registerPjsipThreadIfNeeded();
    if (acct.bridge) {
        acct.bridge->Stop();
    }
    if (acct.incomingSipCall) {
        auto* call = static_cast<IncomingSipCall*>(acct.incomingSipCall);
        call->weHungUp_ = true; // before hangup() - see onCallState's DISCONNECTED handling
        pj::CallOpParam hprm;
        try {
            call->hangup(hprm);
        } catch (...) {
        }
        for (int i = 0; i < 50 && !call->disconnected_.load(); i++) {
            std::this_thread::sleep_for(std::chrono::milliseconds(100));
        }
        {
            // See AccountState::callHandoffMutex's own doc comment -
            // only the delete+nullptr needs the lock, not the hangup()/
            // disconnect-poll above.
            std::lock_guard<std::mutex> lock(acct.callHandoffMutex);
            delete call;
            acct.incomingSipCall = nullptr;
        }
    }
    acct.bridge.reset();
}

// --- Outgoing-call test probe (mirrors pjsip_ringrtc_echo_test.cpp's peerA) ---

void runProbe(AccountState& acct) {
    const int sampleRate = 48000;
    const int toneHz = 440;
    const int totalSamples = sampleRate * 10;
    std::vector<int16_t> tone(totalSamples);
    for (int i = 0; i < totalSamples; i++) {
        tone[i] = static_cast<int16_t>(8000.0 * std::sin(2.0 * M_PI * toneHz * i / sampleRate));
    }
    std::vector<int16_t> received;
    received.reserve(totalSamples * 2);
    const int chunk = 480;
    for (int offset = 0; offset < totalSamples; offset += chunk) {
        int n = std::min(chunk, totalSamples - offset);
        signal2sip_push_recorded_samples(acct.handle, tone.data() + offset, n);
        int16_t buf[chunk];
        size_t got = signal2sip_pull_playout_samples(acct.handle, buf, chunk);
        if (got > 0) received.insert(received.end(), buf, buf + got);
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }
    std::cout << "[daemon][" << acct.config.name << "][probe] pulled " << received.size() << " samples\n";
    double sumSquares = 0;
    for (int16_t s : received) sumSquares += static_cast<double>(s) * s;
    double rms = received.empty() ? 0.0 : std::sqrt(sumSquares / received.size());
    std::cout << "[daemon][" << acct.config.name << "][probe] RMS of received (echoed) audio: " << rms << "\n";
    bool audioFlowed = received.size() > static_cast<size_t>(sampleRate) && rms > 20.0;
    std::cout << "[daemon][" << acct.config.name << "] " << (audioFlowed ? "PASS" : "FAIL")
               << ": tone round-tripped through the real Signal call + remote's SIP bridge\n";

    signal2sip_call_hangup(acct.handle);
}

// --- RingRTC call state machine ---

void onCallState(void* context, const char* remotePeerId, uint64_t callId, int32_t state) {
    auto& acct = *static_cast<AccountState*>(context);
    acct.activeCallId = callId;
    {
        std::lock_guard<std::mutex> lock(acct.callHandoffMutex);
        acct.remotePeerId = remotePeerId;
    }
    std::cout << "[daemon][" << acct.config.name << "] call_state -> " << state << " (peer " << remotePeerId
               << ")\n";

    // Called synchronously from RingRTC (Rust) - same FFI-exception-safety
    // reasoning as the onSend* callbacks above.
    safeCallback("onCallState", [&] {
        if (state == SIGNAL2SIP_CALL_STATE_OUTGOING_AUDIO) {
            signal2sip_call_proceed(acct.handle, callId);
        } else if (state == SIGNAL2SIP_CALL_STATE_INCOMING_AUDIO) {
            // Only proceed (which answers the call, on THIS device, right
            // now) if there's an actual, currently-reachable SIP
            // destination to bridge it to (see canBridgeToSip's own doc
            // comment) - proceeding otherwise just steals the Accept from
            // this account's other real devices (a linked phone, Signal
            // Desktop, ...) before they even get a chance to ring, for a
            // bridge that either doesn't exist or was never going to work
            // anyway. Confirmed live 08-04: an account with neither bridge
            // field set auto-accepted every incoming call into a null
            // audio device, and the user's own real phone (a linked
            // device on the same account) got "AcceptedOnAnotherDevice" -
            // this device had already answered first. Leaving state
            // untouched here means this device simply never answers, same
            // as never having this account open at all - the call rings
            // through to the account's other devices normally, exactly
            // like any other idle Signal client that never calls
            // proceed()/accept().
            if (canBridgeToSip(acct.config)) {
                acct.isCallee = true;
                signal2sip_call_proceed(acct.handle, callId);
            }
        } else if (state == SIGNAL2SIP_CALL_STATE_RINGING && acct.isCallee.load()) {
            // Used to call signal2sip_call_accept() right here (see
            // signal2sip_call_accept()'s own doc comment for why it's only
            // legal after Ringing, never right after proceed()) - but
            // doing so unconditionally meant the daemon always won the
            // multi-device accept race the instant it was willing to
            // bridge at all, before the PBX side had even been dialed,
            // let alone answered (confirmed live 2026-08-05: calling
            // +123456789002 from another Signal account, the daemon
            // intercepted the call immediately and the real linked phone
            // never got a chance to ring). Re-checking canBridgeToSip()
            // here mirrors the same re-check this branch used to do at
            // CONNECTED, in case registration dropped between Proceed and
            // Ringing. Accepting now happens in BridgeCall::onCallState()
            // once the SIP leg placed by startSipDial() actually reaches
            // PJSIP_INV_STATE_CONFIRMED - i.e. once the PBX side has
            // genuinely answered - so a real linked device tapping Accept
            // first still wins normally.
            if (canBridgeToSip(acct.config)) {
                startSipDial(acct);
            }
        } else if (state == SIGNAL2SIP_CALL_STATE_CONNECTED) {
            // The isCallee branch that used to live here (calling
            // startSipBridge() once Signal was Accepted) is gone - the SIP
            // leg is now dialed earlier, at Ringing, and BridgeCall's own
            // onCallMediaState() wires+starts the bridge independently
            // once the SIP side has media, regardless of exactly when
            // Signal's own CONNECTED fires relative to that.
            if (!acct.isCallee.load() && acct.incomingSipCall) {
                // The mirror image of the above: a real SIP call is
                // sitting in Ringing (BridgeAccount::onIncomingCall()
                // placed it, never answered) waiting on exactly this
                // moment - the outgoing Signal call it triggered just
                // connected, so answer it now. IncomingSipCall's own
                // onCallMediaState() wires+starts the bridge once this
                // 200 OK's SDP answer negotiates media, same as the
                // BridgeCall side. registerPjsipThreadIfNeeded() matters
                // here too - this runs on RingRTC's own callback thread,
                // same as stopSipBridge()/stopIncomingSipCall() (see that
                // function's own doc comment for the live bug this fixes).
                registerPjsipThreadIfNeeded();
                auto* sipCall = static_cast<IncomingSipCall*>(acct.incomingSipCall);
                pj::CallOpParam ansPrm;
                ansPrm.statusCode = PJSIP_SC_OK;
                try {
                    sipCall->answer(ansPrm);
                } catch (pj::Error& err) {
                    std::cerr << "[daemon][" << acct.config.name << "][sip] answer(200) failed: " << err.info()
                               << "\n";
                }
            } else if (!acct.isCallee.load() && !acct.config.outgoingCallTarget.empty()) {
                std::thread([&acct] { runProbe(acct); }).detach();
            }
        } else if (state == SIGNAL2SIP_CALL_STATE_ENDED || state == SIGNAL2SIP_CALL_STATE_CONCLUDED) {
            stopSipBridge(acct);
            stopIncomingSipCall(acct);
            acct.isCallee = false;
        }
    });
}

Signal2sipCallbacks makeCallbacks(AccountState& acct) {
    Signal2sipCallbacks cb{};
    cb.context = &acct;
    cb.send_offer = onSendOffer;
    cb.send_answer = onSendAnswer;
    cb.send_ice = onSendIce;
    cb.send_hangup = onSendHangup;
    cb.call_state = onCallState;
    return cb;
}

// --- Incoming envelope handling ---

void onPush(AccountState& acct, const std::string& verb, const std::string& path, const Bytes& body) {
    if (verb != "PUT" || path != "/api/v1/message" || body.empty()) return;

    signalservice::Envelope envelope;
    if (!envelope.ParseFromArray(body.data(), static_cast<int>(body.size()))) {
        std::cerr << "[daemon][" << acct.config.name << "] failed to parse pushed Envelope\n";
        return;
    }

    Bytes plaintext;
    std::string senderServiceId;
    uint32_t senderDeviceId = 0;
    // Only meaningful for the DOUBLE_RATCHET/PREKEY_MESSAGE branch below -
    // captured before the decrypt attempt so they're still available in
    // the catch block to build a DecryptionErrorMessage reply.
    bool isIdentifiedCiphertext = false;
    Bytes originalCiphertext;
    uint8_t originalMessageType = 0;

    try {
        // Same lock CallMessageSender::sendCallMessage takes - this runs
        // on the websocket read thread, which can otherwise race an
        // outgoing send's session-store mutation on RingRTC's callback
        // thread (see ProtocolStores::mutex()).
        std::lock_guard<std::mutex> lock(acct.stores->mutex());
        if (envelope.type() == signalservice::Envelope_Type_UNIDENTIFIED_SENDER) {
            Bytes ciphertext(envelope.content().begin(), envelope.content().end());
            SealedSenderResult result =
                decryptSealedSender(*acct.stores, Address{acct.localServiceId, static_cast<uint32_t>(acct.account.device_id)},
                                    ciphertext, envelope.servertimestamp());
            plaintext = result.plaintext;
            senderServiceId = result.senderServiceId;
            senderDeviceId = result.senderDeviceId;
        } else if (envelope.type() == signalservice::Envelope_Type_DOUBLE_RATCHET ||
                   envelope.type() == signalservice::Envelope_Type_PREKEY_MESSAGE) {
            senderServiceId = resolveServiceId(envelope.sourceserviceidbinary());
            senderDeviceId = envelope.sourcedeviceid();
            isIdentifiedCiphertext = true;
            originalMessageType = envelope.type() == signalservice::Envelope_Type_PREKEY_MESSAGE
                                        ? SignalCiphertextMessageTypePreKey
                                        : SignalCiphertextMessageTypeWhisper;
            originalCiphertext.assign(envelope.content().begin(), envelope.content().end());
            plaintext = decryptCiphertext(*acct.stores,
                                          Address{acct.localServiceId, static_cast<uint32_t>(acct.account.device_id)},
                                          Address{senderServiceId, senderDeviceId}, originalMessageType,
                                          originalCiphertext);
        } else {
            return; // receipt/other envelope type - nothing to decrypt
        }
    } catch (const std::exception& e) {
        std::cerr << "[daemon][" << acct.config.name << "] failed to decrypt envelope: " << e.what() << "\n";
        // Real Signal Protocol recovery: tell the sender so its own
        // client can detect the desync and fall back to a fresh PreKey
        // handshake, instead of this failing silently forever every time
        // (see CallSignaling.h's sendDecryptionErrorReply() doc comment -
        // found live against a real phone's already-desynced session
        // with no other way to recover it). Only meaningful for
        // identified (non-sealed-sender) ciphertext, where we know who
        // sent it and have the raw bytes needed to build the reply; a
        // sealed-sender envelope whose outer unseal itself failed gives
        // us neither.
        if (isIdentifiedCiphertext && !senderServiceId.empty()) {
            // sendDecryptionErrorReply() manages its own (narrow, never
            // held across network I/O) locking internally - see its
            // definition - so no lock is taken here.
            acct.dispatchQueue.push([&acct, senderServiceId, senderDeviceId, originalCiphertext, originalMessageType,
                                     clientTimestamp = envelope.clienttimestamp()] {
                sendDecryptionErrorReply(*acct.socket, *acct.stores, *acct.sender, acct.localServiceId,
                                         static_cast<uint32_t>(acct.account.device_id), senderServiceId,
                                         senderDeviceId, originalCiphertext, originalMessageType, clientTimestamp);
            });
        }
        return;
    }

    std::cout << "[daemon][" << acct.config.name << "][diag] decrypted envelope from " << senderServiceId
               << " device " << senderDeviceId << " (" << plaintext.size() << " bytes plaintext)\n";

    signalservice::Content content;
    if (!content.ParseFromArray(plaintext.data(), static_cast<int>(plaintext.size()))) {
        std::cerr << "[daemon][" << acct.config.name << "] failed to parse decrypted Content\n";
        return;
    }
    if (content.has_datamessage()) {
        const auto& dataMessage = content.datamessage();
        std::cout << "[daemon][" << acct.config.name << "][diag] DataMessage body: " << dataMessage.body() << "\n";

        // DTMF-over-text: Signal's own apps have no in-call dialpad at
        // all (confirmed 2026-08-13 via source - zero "dtmf" matches
        // anywhere in Signal-Android; Signal-iOS explicitly disables it,
        // `callUpdate.supportsDTMF = false` plus a stubbed
        // CXPlayDTMFCallAction handler in CallKitCallUIAdaptee.swift) -
        // so a caller bridged through signal2sip has no way to press
        // touch-tones into a PBX IVR/menu. Same workaround already
        // proven live in this project's sibling Telegram bridge
        // (tg2sip-webrtc/tg2sip/gateway.cpp's IsDtmfString/DialDtmf,
        // hitting the identical "no in-call dialpad" problem there):
        // while a call with a given peer is active, a plain 1:1 text
        // message from that SAME peer matching the DTMF alphabet is
        // forwarded as a real SIP DTMF event (RFC 2833) into the
        // bridged call instead of being treated as a chat message.
        // `A-Da-d` (not just uppercase like tg2sip's original) because
        // PJSIP itself lowercases before matching - matching only
        // uppercase would silently reject a real lowercase digit for no
        // reason. Group messages excluded - this is a 1:1-call-scoped
        // feature, a group chat message that happens to look like
        // digits from the same person shouldn't fire it.
        static const std::regex kDtmfRegex("^[0-9A-Da-d*#]{1,32}$");
        if (!dataMessage.has_groupv2() && std::regex_match(dataMessage.body(), kDtmfRegex)) {
            // See AccountState::callHandoffMutex's own doc comment -
            // remotePeerId/sipCall/incomingSipCall are written from
            // RingRTC's own callback thread, this runs on a
            // libsignal-net-chat worker thread; held across the whole
            // check+send since dialDtmf() is a fast, local,
            // non-blocking PJSIP call (pjmedia_stream_dial_dtmf just
            // pushes into a small buffer under its own separate
            // mutex), not a network round-trip.
            std::lock_guard<std::mutex> lock(acct.callHandoffMutex);
            if (senderServiceId == acct.remotePeerId) {
                pj::Call* call = acct.sipCall ? acct.sipCall : acct.incomingSipCall;
                if (call) {
                    std::cout << "[daemon][" << acct.config.name << "] sending DTMF '" << dataMessage.body()
                               << "' into the bridged SIP call\n";
                    // Required before any pjsua2 call from a thread
                    // that's never touched PJSIP before - see this
                    // function's own doc comment for the two silent-
                    // breakage bugs this project already hit from
                    // skipping it.
                    registerPjsipThreadIfNeeded();
                    try {
                        call->dialDtmf(dataMessage.body());
                    } catch (pj::Error& err) {
                        std::cerr << "[daemon][" << acct.config.name << "] DTMF send failed: " << err.info()
                                   << "\n";
                    }
                }
            }
        }
    }
    // A real primary device sends this (SyncMessage.Keys) whenever an
    // already-linked secondary device's account_entropy_pool needs
    // updating - e.g. after a rotation, or in response to this account's
    // own sendKeysRequest() (see syncStorageContacts()/setupAccount()).
    // Found live 2026-08-05: before this handler existed, any such update
    // was silently dropped (this dispatch only ever looked at
    // DataMessage/CallMessage), so a linked account's locally-stored AEP
    // could go stale forever relative to whatever's actually encrypting
    // its real StorageService data - see project memory
    // project_signal2sip_storage_service_sync.md for the live account
    // this was found on.
    if (content.has_syncmessage() && content.syncmessage().has_keys() &&
        content.syncmessage().keys().has_accountentropypool()) {
        acct.account.account_entropy_pool = content.syncmessage().keys().accountentropypool();
        acct.storage->saveAccount(acct.account);
        std::cout << "[daemon][" << acct.config.name
                   << "] received updated account_entropy_pool via SyncMessage.Keys, saved\n";
        // Without this, a fresh key received here just sits unused until
        // the next periodic tick - up to storageSyncIntervalSec (12h
        // default) away - because setupAccount()'s own initial
        // syncStorageContacts() call (which always runs before this reply
        // can possibly arrive) already stamped lastStorageSyncMs, and the
        // periodic loop only re-fires once that interval elapses. Deferred
        // onto the dispatch queue rather than called inline - this handler
        // runs on the websocket read thread, and fetchStorageContacts()
        // does synchronous network I/O (matches the existing
        // sendDecryptionErrorReply() dispatch a few lines up).
        acct.dispatchQueue.push([&acct] { syncStorageContacts(acct); });
    }
    if (!content.has_callmessage()) return;

    std::cout << "[daemon][" << acct.config.name << "] CallMessage from " << senderServiceId << " device "
               << senderDeviceId << "\n";

    // Must not call handleCallMessage() directly on this thread: it's a
    // libsignal-net-chat worker thread (AuthSocket's ChatListener push
    // callback, see AuthSocket.cpp's own doc comment - no longer a single
    // fixed serviceThread since the 2026-08-12 libwebsockets -> FFI
    // migration, but still not a thread that's safe to block at length
    // on), and RingRTC can synchronously invoke a send_offer/send_answer/
    // send_ice callback in reaction to this incoming CallMessage. Those
    // callbacks block on AuthSocket::request() waiting for a response.
    // Before the migration this was a *guaranteed* self-deadlock (only
    // one thread ever delivered any response, and it would be the one
    // blocked); the new async/multi-worker-thread model doesn't have
    // that exact single-point failure, but nesting a blocking wait
    // inside a callback invoked from the runtime's own worker pool is
    // still the kind of thing that starves it under load, not something
    // to rely on being safe. Dispatching via the ordered queue (see
    // EnvelopeDispatchQueue) keeps this thread free to keep servicing
    // the socket, while still processing envelopes in arrival order and
    // giving shutdown something to join.
    signalservice::CallMessage callMessage = content.callmessage();
    uint32_t localDeviceId = static_cast<uint32_t>(acct.account.device_id);
    acct.dispatchQueue.push([&acct, senderServiceId, senderDeviceId, localDeviceId, callMessage] {
        handleCallMessage(acct.handle, *acct.stores, senderServiceId, senderDeviceId, localDeviceId, callMessage);
    });
}

std::atomic<bool> g_running{true};
void onSignal(int) { g_running = false; }

// SIGHUP: standard unix "reload config" convention (nginx/postfix etc.) -
// simplest possible trigger, no new control socket/protocol needed. Just
// sets a flag; the actual reload happens on the main thread's own loop
// (reloadConfig() below), never inside the signal handler itself.
std::atomic<bool> g_reloadRequested{false};
void onReloadSignal(int) { g_reloadRequested = true; }

std::string g_configPath; // set once in main(), read by reloadConfig()

// Same helper gendb/main.cpp has (kept independent rather than shared -
// both are tiny, and pulling in a shared util header for one line isn't
// worth it).
std::string dirName(const std::string& path) {
    auto pos = path.find_last_of('/');
    return pos == std::string::npos ? std::string(".") : path.substr(0, pos);
}

// Written once at startup, removed on clean shutdown (see main()'s
// shutdown path) - `gendb <name> config set/enable/disable` reads this to
// find and SIGHUP the running daemon for near-instant config pickup
// instead of waiting out GlobalConfig::configPollIntervalSec (see that
// field's own doc comment). Same path gendb derives independently
// (dirName(dbPath) + "/signal2sip.pid") - no config knob needed since
// both processes already agree on dbPath.
std::string pidFilePath(const GlobalConfig& global) {
    return dirName(global.dbPath) + "/signal2sip.pid";
}

void writePidFile(const GlobalConfig& global) {
    std::ofstream f(pidFilePath(global));
    if (!f) {
        std::cerr << "[daemon] warning: could not write pidfile at " << pidFilePath(global)
                   << " - `gendb config set/enable/disable` won't be able to SIGHUP this process for instant "
                      "pickup, it'll fall back to the periodic poll instead\n";
        return;
    }
    f << ::getpid() << "\n";
}
GlobalConfig g_global;    // set once in main() from config.global, read by setupAccount()

// Creates the shared Endpoint the first time any account needs it - either
// during main()'s startup loop, or later via a SIGHUP reload adding the
// first-ever SIP-enabled account to a daemon that started with none. Does
// NOT create any transport itself anymore - every account gets its own
// dedicated one (see createAccountUdpTransport()/
// createAccountTlsTransport(), both called from setupAccount()).
// `epStorage` is function-static (not a main()-local variable) specifically
// so it survives past the point where main()'s own startup code has
// finished running, in case this is called again later from reloadConfig().
void ensureSharedEndpoint() {
    if (g_ep) return; // already created

    static std::unique_ptr<pj::Endpoint> epStorage;
    epStorage = std::make_unique<pj::Endpoint>();
    try {
        epStorage->libCreate();
        pj::EpConfig epConfig;
        epConfig.medConfig.ecTailLen = 0;
        epConfig.medConfig.noVad = true;
        // 10ms ptime required to keep an uncompressed L16 RTP packet
        // below the MTU (tg2sip-webrtc/tg2sip/sip.cpp's own comment).
        epConfig.medConfig.audioFramePtime = 10;
        epConfig.medConfig.ptime = 10;
        epConfig.medConfig.clockRate = 48000;
        epStorage->libInit(epConfig);
        epStorage->audDevManager().setNullDev();

        // Force L16/48000/1 (raw PCM, mono) as the only codec PJSIP will
        // ever offer/accept, matching RingRtcSipBridge's fixed format
        // exactly - same technique as tg2sip-webrtc's ep.codecSetPriority()
        // loop. codecEnum() (returning CodecInfoVector, a vector of
        // pointers) is gone in this PJSIP version - only codecEnum2()
        // (CodecInfoVector2, a vector of values) remains; see
        // native/CMakeLists.txt's PJPROJECT_DIR comment for why this
        // project moved off PJSIP 2.9.
        for (const auto& codec : epStorage->codecEnum2()) {
            epStorage->codecSetPriority(codec.codecId, codec.codecId == "L16/48000/1" ? 255 : 0);
        }

        epStorage->libStart();
        g_ep = epStorage.get();
    } catch (pj::Error& err) {
        std::cerr << "[daemon] SIP Endpoint setup failed: " << err.info() << "\n";
        epStorage.reset();
        g_ep = nullptr;
    }
}

// Creates a UDP transport dedicated to ONE account. Local port 0 (OS
// picks any free ephemeral port) - Asterisk always dials back to
// whatever Contact this account's own registration advertised, so the
// exact port doesn't need to be predictable, same reasoning as
// createAccountTlsTransport()'s own port 0. Returns pj::PJSUA_INVALID_ID
// on failure (logged there, caller just won't get a working account).
// Requires g_ep to already exist (ensureSharedEndpoint() must run first).
pj::TransportId createAccountUdpTransport(const AccountConfig& accountConfig) {
    if (!g_ep) return PJSUA_INVALID_ID;

    try {
        pj::TransportConfig tcfg;
        tcfg.port = 0;
        pj::TransportId id = g_ep->transportCreate(PJSIP_TRANSPORT_UDP, tcfg);
        std::cout << "[daemon][" << accountConfig.name << "] UDP transport created\n";
        return id;
    } catch (pj::Error& err) {
        std::cerr << "[daemon][" << accountConfig.name << "] UDP transport setup failed: " << err.info() << "\n";
        return PJSUA_INVALID_ID;
    }
}

// Creates a TLS (SIPS) transport dedicated to ONE account - PJSIP's TLS
// trust settings (CaListFile/verifyServer) are configured once per
// transport factory and apply to every connection made through it, so two
// accounts pointing at two different Asterisk hosts with two different
// (self-signed) certificates genuinely need their own transport each -
// see AccountConfig::sipTlsCaFile's own doc comment. Local port 0 (OS
// picks any free port) is fine here - TLS/TCP is connection-oriented, so
// Asterisk calls back over the same persistent connection this process
// already opened for registration, unlike UDP where a specific advertised
// port matters. Returns pj::PJSUA_INVALID_ID on failure. Requires g_ep to
// already exist (ensureSharedEndpoint() must run first).
pj::TransportId createAccountTlsTransport(const AccountConfig& accountConfig) {
    if (!g_ep) return PJSUA_INVALID_ID;

    try {
        pj::TransportConfig tcfg;
        tcfg.port = 0;
        // PJSIP's own default TLS method is the ancient PJSIP_TLSV1_METHOD
        // (TLS 1.0) - found live that Asterisk's transport-tls rejects
        // that outright (TLSV1_ALERT_PROTOCOL_VERSION). Restrict to modern
        // versions explicitly instead of relying on the default.
        tcfg.tlsConfig.proto = PJ_SSL_SOCK_PROTO_TLS1_2 | PJ_SSL_SOCK_PROTO_TLS1_3;
        if (!accountConfig.sipTlsCaFile.empty()) {
            tcfg.tlsConfig.CaListFile = accountConfig.sipTlsCaFile;
            tcfg.tlsConfig.verifyServer = true;
        } else {
            // Config::load() already refuses sip_transport=tls with
            // neither sip_tls_ca_file nor sip_tls_insecure=yes set, so
            // reaching here with an empty CaListFile means the operator
            // explicitly opted into this.
            tcfg.tlsConfig.verifyServer = false;
        }
        pj::TransportId id = g_ep->transportCreate(PJSIP_TRANSPORT_TLS, tcfg);
        std::cout << "[daemon][" << accountConfig.name << "] TLS transport created"
                   << (accountConfig.sipTlsCaFile.empty() ? " (server cert verification DISABLED - sip_tls_insecure=yes)"
                                                          : " (pinned to " + accountConfig.sipTlsCaFile + ")")
                   << "\n";
        return id;
    } catch (pj::Error& err) {
        std::cerr << "[daemon][" << accountConfig.name << "] TLS transport setup failed: " << err.info() << "\n";
        return PJSUA_INVALID_ID;
    }
}

// A real SIP call arrived at this account's registered contact - place a
// real outgoing Signal call in response. Found live 2026-08-05: this
// direction (PBX calls IN to a signal2sip SIP trunk to originate a real
// Signal call out) had no handler at all - pjsua2's default
// Account::onIncomingCall() (i.e. not overriding it) leaves its
// temporary Call wrapper to be destroyed at the end of the callback,
// which itself hangs up with a bare 500 - every such INVITE was silently
// rejected before this existed.
//
// The destination is read from the raw Request-URI's user part (NOT
// this->acctState's own configured number) - confirmed live that
// Asterisk's outbound-route/trunk config for a given destination number
// can point its INVITE at a DIFFERENT account's registered contact than
// that number itself (this test: a trunk for "123456789002" sent its
// INVITE to 123456789004's TLS contact, Request-URI user still
// "123456789002") - so the account that answers is just "whichever
// identity Asterisk chose to send this INVITE from", and the number to
// call is purely whatever's in the Request-URI, regardless of whether
// that number also happens to be one of this daemon's own configured
// accounts (user's own framing: "как обычный сигнал звонок").
//
// RESOLVED 2026-08-06: a second, worse variant of the same class of
// problem - this time pjsua ITSELF (not Asterisk) picked the wrong
// account. A real INVITE whose Request-URI and the resulting Asterisk
// CDR both unambiguously showed it physically arrived on account
// 123456789003's own dedicated transport still fired this callback with
// `this->acctState` bound to 123456789002 - confirmed live (the outgoing
// Signal call that resulted used 123456789002's own contact list/
// identity, not 123456789003's). Root cause: pjsua's internal incoming-
// call account matching compares the Request-URI against each account's
// own registered AOR, and none of them match a bare phone number like
// "+123456789001" - it silently falls back to some other, observed-live-
// to-be-wrong heuristic instead of "whichever transport the packet
// physically arrived on". See g_portToAccount's own doc comment for the
// fix: cross-check (and override if necessary) against a registry this
// project controls directly, keyed by each transport's own real local
// port - not pjsua's account selection.
void BridgeAccount::onIncomingCall(pj::OnIncomingCallParam& iprm) {
    if (!acctState) {
        // Shouldn't happen - every BridgeAccount is constructed with a
        // matching AccountState in setupAccount() before it can ever
        // register (and therefore before it could receive any INVITE).
        pj::Call tmp(*this, iprm.callId);
        pj::CallOpParam prm;
        prm.statusCode = PJSIP_SC_SERVICE_UNAVAILABLE;
        try {
            tmp.hangup(prm);
        } catch (...) {
        }
        return;
    }

    auto* rdata = static_cast<pjsip_rx_data*>(iprm.rdata.pjRxData);

    // Don't just trust that pjsua2 invoked this callback on the "right"
    // Account object (this->acctState) - see g_portToAccount's own doc
    // comment for the real, live-confirmed misattribution this guards
    // against. The receiving transport's own local port is ground truth.
    AccountState* resolvedAcct = acctState;
    if (rdata && rdata->tp_info.transport) {
        int actualPort = pj_sockaddr_get_port(&rdata->tp_info.transport->local_addr);
        auto it = g_portToAccount.find(actualPort);
        if (it != g_portToAccount.end() && it->second != acctState) {
            std::cerr << "[daemon][" << acctState->config.name << "][sip] pjsua invoked onIncomingCall on the "
                       << "wrong account - INVITE actually arrived on port " << actualPort << " (account '"
                       << it->second->config.name << "'), not this one - using the correct account instead\n";
            resolvedAcct = it->second;
        }
    }
    AccountState& acct = *resolvedAcct;
    if (acct.incomingSipCall || acct.sipCall) {
        // Already bridging a call in one direction or the other -
        // this project's one-call-at-a-time-per-account scope (see
        // AccountState::bridge's own doc comment).
        pj::Call tmp(*this, iprm.callId);
        pj::CallOpParam prm;
        prm.statusCode = PJSIP_SC_BUSY_HERE;
        try {
            tmp.hangup(prm);
        } catch (...) {
        }
        return;
    }

    std::string destUser;
    if (rdata && rdata->msg_info.msg) {
        pjsip_uri* reqUri = rdata->msg_info.msg->line.req.uri;
        if (PJSIP_URI_SCHEME_IS_SIP(reqUri) || PJSIP_URI_SCHEME_IS_SIPS(reqUri)) {
            auto* sipUri = static_cast<pjsip_sip_uri*>(pjsip_uri_get_uri(reqUri));
            destUser.assign(sipUri->user.ptr, sipUri->user.slen);
        }
    }
    // Request-URI user parts are plain digits by SIP convention (no '+'),
    // but resolveOutgoingTarget()/ContactResolver.cpp only treats a target
    // as a phone number needing CDSI resolution when it starts with '+' -
    // anything else is assumed to already be a ServiceId. Found live
    // 2026-08-05: without this, a bare "123456789001" from Asterisk's
    // INVITE skipped CDSI entirely and got used as-is, so RingRTC tried
    // fetching prekeys from "GET /v2/keys/123456789001/*" - a phone
    // number, not a real ServiceId UUID - and always 404'd.
    //
    // Strip any leading '+'(s) first, then add exactly one back - found
    // live 2026-08-06: Asterisk itself can send an R-URI user part
    // already containing "++<e164>" (a trunk's own dialoutprefix='+'
    // stacking with a caller who already dialed a leading '+'), which
    // the old "only add if missing" check let straight through as an
    // invalid double-plus number - CDSI correctly rejected it as not a
    // real e164 every time. Normalizing to exactly one '+' regardless of
    // how many Asterisk's R-URI already had is robust to this regardless
    // of trunk dialoutprefix config on the Asterisk side.
    if (!destUser.empty()) {
        std::size_t firstNonPlus = destUser.find_first_not_of('+');
        destUser = "+" + destUser.substr(firstNonPlus == std::string::npos ? destUser.size() : firstNonPlus);
    }
    std::cout << "[daemon][" << acct.config.name << "][sip] incoming SIP call for '" << destUser << "'\n";
    if (destUser.empty()) {
        pj::Call tmp(*this, iprm.callId);
        pj::CallOpParam prm;
        prm.statusCode = PJSIP_SC_NOT_FOUND;
        try {
            tmp.hangup(prm);
        } catch (...) {
        }
        return;
    }

    acct.bridge = std::make_unique<voip::RingRtcSipBridge>(acct.handle);
    auto* call = new IncomingSipCall(*this, iprm.callId, *acct.bridge, acct);
    acct.incomingSipCall = call;

    // Ringing, not answered yet - held here until the outgoing Signal
    // call this triggers actually connects (see onCallState's own
    // CONNECTED handler for where the real answer(200) happens).
    pj::CallOpParam ringPrm;
    ringPrm.statusCode = PJSIP_SC_RINGING;
    try {
        call->answer(ringPrm);
    } catch (pj::Error& err) {
        std::cerr << "[daemon][" << acct.config.name << "][sip] answer(180) failed: " << err.info() << "\n";
    }

    // outgoing_call_target's own e164-resolution path (ContactResolver.h)
    // reused verbatim - same CDSI-backed cache, same TTL.
    std::string resolvedTarget;
    try {
        resolvedTarget = resolveOutgoingTarget(*acct.socket, *acct.storage, destUser, g_global.resolvedContactTtlSec);
    } catch (const std::exception& e) {
        std::cerr << "[daemon][" << acct.config.name << "][sip] could not resolve '" << destUser
                   << "': " << e.what() << "\n";
    }
    if (resolvedTarget.empty()) {
        stopIncomingSipCall(acct);
        return;
    }

    acct.isCallee = false;
    uint64_t callId = signal2sip_call_start_outgoing(acct.handle, resolvedTarget.c_str(),
                                                       static_cast<uint32_t>(acct.account.device_id));
    if (callId == 0) {
        std::cerr << "[daemon][" << acct.config.name << "][sip] signal2sip_call_start_outgoing failed\n";
        stopIncomingSipCall(acct);
    }
}

// Brings up one account: Signal (storage/protocol stores/websocket/RingRTC
// call manager) always, PJSIP registration only if this account has
// [sip.<name>]. Reusable by both main()'s startup loop and reloadConfig()
// - wrapped in its own try/catch so one account's bad config/network
// failure never affects any other account sharing this process. Returns
// false (and leaves no trace in g_accounts) on failure.
// Fires GlobalConfig::onAccountErrorCmd (see its own doc comment for the
// full rationale) for one account transitioning into or out of a known
// problem state. No-op if the hook isn't configured. Double-forks so the
// grandchild running the actual command is reparented to init/PID 1 and
// reaped independently - this daemon's own process only ever waits on
// the immediate (fast-exiting) first child, never on the hook itself, so
// a slow or hanging hook script can't stall SIP/Signal handling for
// every other account.
void runAccountErrorHook(const std::string& cmd, const std::string& accountName, const std::string& e164,
                          const std::string& errorType) {
    if (cmd.empty()) return;

    pid_t pid = fork();
    if (pid < 0) {
        std::cerr << "[daemon] on_account_error_cmd: fork failed: " << strerror(errno) << "\n";
        return;
    }
    if (pid > 0) {
        int status = 0;
        waitpid(pid, &status, 0);
        return;
    }

    pid_t grandchild = fork();
    if (grandchild == 0) {
        // account_name/e164/errorType arrive as $1/$2/$3 inside `cmd` -
        // real argv entries to /bin/sh, never string-concatenated into
        // the command line itself.
        execl("/bin/sh", "sh", "-c", cmd.c_str(), "signal2sip-hook", accountName.c_str(), e164.c_str(),
              errorType.c_str(), (char*)nullptr);
        _exit(127); // execl only returns on failure
    }
    _exit(0);
}

bool setupAccount(const AccountConfig& accountConfig) {
    try {
        // Moved here (from a one-time up-front check in main()) so an
        // account whose SIP config gets added later via `gendb config
        // set`/enable (picked up by reloadConfig()'s poll/SIGHUP path,
        // not just at startup) still brings the shared Endpoint up the
        // first time it's actually needed - ensureSharedEndpoint() is
        // idempotent (`if (g_ep) return;`), so this is a no-op on every
        // account after the first SIP-using one.
        if (accountConfig.hasSip()) ensureSharedEndpoint();

        AccountState& acct = *(g_accounts[accountConfig.name] = std::make_unique<AccountState>());
        acct.config = accountConfig;

        acct.storage = std::make_unique<Storage>(g_global.dbPath, g_global.dbKey, accountConfig.name);
        acct.account = acct.storage->loadAccount();
        acct.stores = std::make_unique<ProtocolStores>(*acct.storage, "aci");
        acct.localServiceId = acct.account.aci;
        std::cout << "[daemon][" << accountConfig.name << "] own ACI: " << acct.localServiceId << "\n";

        acct.handle = signal2sip_call_manager_create(makeCallbacks(acct));
        if (!acct.handle) {
            throw std::runtime_error("could not create RingRTC call manager");
        }

        std::string username = acct.account.device_id == 1
                                    ? acct.account.aci
                                    : (acct.account.aci + "." + std::to_string(acct.account.device_id));
        acct.socket = std::make_unique<AuthSocket>(
            username, acct.account.password,
            [&acct](const std::string& verb, const std::string& path, const Bytes& body) {
                onPush(acct, verb, path, body);
            },
            accountConfig.signalProxy, accountConfig.signalCensorshipCircumvention);
        acct.sender = std::make_unique<CallMessageSender>(*acct.socket, *acct.stores, acct.account.aci,
                                                           static_cast<uint32_t>(acct.account.device_id));

        // Must be running before connect() - onPush() can start pushing
        // work onto it as soon as the socket is live.
        acct.dispatchQueue.start();

        acct.socket->connect();
        std::cout << "[daemon][" << accountConfig.name << "] connected to chat.signal.org as "
                   << acct.account.e164 << "\n";

        // A fresh connect succeeding is the real "recovered" moment for a
        // previously-alerted deauthorized account (see the watchdog loop's
        // own comment on AuthSocket::isDeauthorized() - that state never
        // clears itself without a full setupAccount() cycle, i.e. a daemon
        // restart after `gendb link`/`unlink`+`link`). Any other startup
        // failure below throws and this whole account setup is skipped by
        // the caller's try/catch, leaving last_error as-is - only a
        // genuinely working connection clears it.
        if (!acct.account.last_error.empty()) {
            try {
                acct.storage->clearAccountLastError();
            } catch (const std::exception& e) {
                std::cerr << "[daemon][" << accountConfig.name << "] failed to clear last_error: " << e.what()
                           << "\n";
            }
            runAccountErrorHook(g_global.onAccountErrorCmd, accountConfig.name, acct.account.e164, "recovered");
        }

        refreshPrekeys(*acct.storage, *acct.socket, acct.account);
        refreshAccountAttributes(*acct.socket, acct.account);

        // Initial sync - see main()'s own storage-sync loop for the
        // periodic re-sync every g_global.storageSyncIntervalSec.
        syncStorageContacts(acct);

        // Ask the real primary device (if any) to resend this account's
        // current account_entropy_pool - see sendKeysRequest()'s own doc
        // comment and main.cpp's SyncMessage.Keys handling in the
        // envelope dispatch for where the (async, only-if/when-the-
        // primary-is-online) reply gets applied. One-shot at startup only
        // (not on every periodic storage-sync tick) - this is a "fix a
        // possibly-stale local key" nudge, not something to repeat
        // indefinitely. Wrapped in try/catch - found live 2026-08-05 that
        // an uncaught exception here (e.g. a real 429 from repeatedly
        // restarting the daemon during testing, hitting Signal-Server's
        // PRE_KEYS rate limit) aborted this WHOLE setupAccount() call,
        // taking SIP registration down with it - a best-effort key-sync
        // nudge should never be able to do that.
        if (acct.account.account_entropy_pool && !acct.account.account_entropy_pool->empty()) {
            try {
                acct.sender->sendKeysRequest();
            } catch (const std::exception& e) {
                std::cerr << "[daemon][" << accountConfig.name << "] sendKeysRequest failed (non-fatal): " << e.what()
                           << "\n";
            }
        }

        if (accountConfig.hasSip()) {
            ensureSharedEndpoint(); // no-ops if g_ep already exists
            // Every account gets its own dedicated transport, bound
            // explicitly via acfg.sipConfig.transportId below - see
            // AccountConfig::sipTransport's own doc comment for why
            // sharing one transport across accounts doesn't work for
            // incoming calls.
            pj::TransportId transportId = accountConfig.sipTransport == "tls"
                                               ? createAccountTlsTransport(accountConfig)
                                               : createAccountUdpTransport(accountConfig);
            if (g_ep && transportId != PJSUA_INVALID_ID) {
                // See g_portToAccount's own doc comment - this is the
                // authoritative record of which account this port belongs
                // to, independent of whatever pjsua's own (unreliable)
                // incoming-call account matching later decides.
                try {
                    std::string localAddr = g_ep->transportGetInfo(transportId).localAddress;
                    std::size_t colon = localAddr.rfind(':');
                    if (colon != std::string::npos) {
                        int port = std::stoi(localAddr.substr(colon + 1));
                        g_portToAccount[port] = &acct;
                    }
                } catch (pj::Error& err) {
                    std::cerr << "[daemon][" << accountConfig.name
                               << "] could not record transport port for incoming-call routing: " << err.info()
                               << "\n";
                } catch (const std::exception& e) {
                    std::cerr << "[daemon][" << accountConfig.name
                               << "] could not record transport port for incoming-call routing: " << e.what()
                               << "\n";
                }

                auto sipAccount = std::make_unique<BridgeAccount>();
                pj::AccountConfig acfg;
                acfg.sipConfig.transportId = transportId;
                // sips: (not sip:) is what actually routes this account's
                // registration/calls over its own TLS transport instead of
                // a UDP one - see AccountConfig::sipTransport's own doc
                // comment, including the "sip_host's port usually needs
                // updating too" gotcha.
                std::string scheme = accountConfig.sipTransport == "tls" ? "sips" : "sip";
                acfg.idUri = scheme + ":" + accountConfig.sipExtension + "@" + accountConfig.sipHost;
                acfg.regConfig.registrarUri = scheme + ":" + accountConfig.sipHost;
                pj::AuthCredInfo cred("digest", "*", accountConfig.sipExtension, 0, accountConfig.sipPassword);
                acfg.sipConfig.authCreds.push_back(cred);

                // See AccountConfig::sipSrtp's own doc comment (Config.h) -
                // "disabled" (default) leaves PJSIP's own default (plain
                // RTP) untouched.
                if (accountConfig.sipSrtp == "optional") {
                    acfg.mediaConfig.srtpUse = PJMEDIA_SRTP_OPTIONAL;
                } else if (accountConfig.sipSrtp == "mandatory") {
                    acfg.mediaConfig.srtpUse = PJMEDIA_SRTP_MANDATORY;
                }
                // srtpSecureSignaling's PJSIP default (1) REQUIRES a
                // secure/TLS transport for SRTP to negotiate at all - only
                // relax it to 0 for a plain UDP account (matches this
                // project's original SRTP verification, done over UDP);
                // a tls account leaves the default, which is now
                // genuinely satisfied instead of just working around it.
                if (accountConfig.sipSrtp != "disabled" && accountConfig.sipTransport != "tls") {
                    acfg.mediaConfig.srtpSecureSignaling = 0;
                }

                sipAccount->acctState = &acct;
                sipAccount->transportId = transportId;
                sipAccount->create(acfg);

                std::cout << "[daemon][" << accountConfig.name << "] waiting for SIP registration...\n";
                for (int i = 0; i < 100 && !sipAccount->registered.load(); i++) {
                    std::this_thread::sleep_for(std::chrono::milliseconds(100));
                }
                if (sipAccount->registered.load()) {
                    std::cout << "[daemon][" << accountConfig.name << "] SIP registered as "
                               << accountConfig.sipExtension << "@" << accountConfig.sipHost << "\n";
                } else {
                    std::cerr << "[daemon][" << accountConfig.name << "] SIP registration did not complete in time\n";
                }
                g_sipAccounts[accountConfig.name] = std::move(sipAccount);
            }
        }

        if (!accountConfig.outgoingCallTarget.empty()) {
            // outgoing_call_target may be a plain e164 now, not just an
            // already-known ACI/PNI - resolveOutgoingTarget leaves an
            // actual ServiceId untouched and only hits the network (real,
            // rate-limited CDSI) for an e164 that isn't already cached
            // from a previous resolution. See ContactResolver.h.
            std::string resolvedTarget;
            try {
                resolvedTarget = resolveOutgoingTarget(*acct.socket, *acct.storage, accountConfig.outgoingCallTarget,
                                                        g_global.resolvedContactTtlSec);
            } catch (const std::exception& e) {
                std::cerr << "[daemon][" << accountConfig.name << "] FAIL: could not resolve outgoing_call_target '"
                           << accountConfig.outgoingCallTarget << "': " << e.what() << "\n";
                resolvedTarget.clear();
            }
            if (!resolvedTarget.empty()) {
                std::cout << "[daemon][" << accountConfig.name << "] placing outgoing call to "
                           << accountConfig.outgoingCallTarget << " (resolved: " << resolvedTarget << ")\n";
                uint64_t callId = signal2sip_call_start_outgoing(acct.handle, resolvedTarget.c_str(),
                                                                  static_cast<uint32_t>(acct.account.device_id));
                if (callId == 0) {
                    std::cerr << "[daemon][" << accountConfig.name
                               << "] FAIL: signal2sip_call_start_outgoing failed\n";
                }
            }
        } else {
            std::cout << "[daemon][" << accountConfig.name << "] waiting for incoming calls\n";
        }
        return true;
    } catch (const std::exception& e) {
        bool deauthorized = false;
        if (auto lookup = g_accounts.find(accountConfig.name);
            lookup != g_accounts.end() && lookup->second->socket) {
            deauthorized = lookup->second->socket->isDeauthorized();
        }
        if (deauthorized) {
            std::cerr << "<3>[daemon][" << accountConfig.name
                       << "] account setup failed: Signal rejected this device's credentials (401/403/4401) - "
                          "the account was most likely unlinked or deleted on the real Signal side before this "
                          "daemon even started. Run `signal2sip-gendb " << accountConfig.name
                       << " link` to re-link it, then restart the daemon - skipping this account for now, "
                          "continuing with the rest\n";

            // The runtime watchdog loop (below, later in this file) only
            // ever persists last_error/fires the hook for a drop that
            // happens WHILE this process is running - an account that's
            // already deauthorized before setupAccount() even gets this
            // far (e.g. unlinked while the daemon was down, then
            // restarted) hit a completely different code path and was
            // silently skipped - confirmed live 2026-08-15: after a
            // restart, this branch fired repeatedly but last_error in the
            // DB never changed. Only persist+notify the FIRST time this
            // process sees it as new (last_error was empty going into this
            // attempt) - avoids re-notifying on every subsequent restart
            // of an already-known-broken account (e.g. a crash-restart
            // loop from some unrelated cause), mirroring the runtime
            // watchdog's own "alert once" behavior
            // (AccountState::deauthorizedAlerted) which has no equivalent
            // here since this is always a fresh process's first attempt.
            if (auto it = g_accounts.find(accountConfig.name);
                it != g_accounts.end() && it->second->account.last_error.empty()) {
                const std::string errorMsg =
                    "deauthorized: Signal rejected this device's credentials (401/403/4401)";
                const int64_t nowEpochSec = std::chrono::duration_cast<std::chrono::seconds>(
                                                 std::chrono::system_clock::now().time_since_epoch())
                                                 .count();
                try {
                    it->second->storage->setAccountLastError(errorMsg, nowEpochSec);
                } catch (const std::exception& persistErr) {
                    std::cerr << "[daemon][" << accountConfig.name
                               << "] failed to persist last_error: " << persistErr.what() << "\n";
                }
                runAccountErrorHook(g_global.onAccountErrorCmd, accountConfig.name, it->second->account.e164,
                                     "deauthorized");
            }
        } else {
            std::cerr << "[daemon][" << accountConfig.name << "] account setup failed: " << e.what()
                       << " - skipping this account, continuing with the rest\n";
        }
        // If the failure happened after dispatchQueue.start() (e.g.
        // socket->connect() or SIP registration throwing), its worker
        // thread is still running - erasing the map entry directly would
        // destroy a joinable std::thread and call std::terminate() instead
        // of unwinding cleanly. stopAndJoin() is always safe to call even
        // if start() was never reached (EnvelopeDispatchQueue::stopAndJoin()
        // no-ops on a non-joinable thread).
        if (auto it = g_accounts.find(accountConfig.name); it != g_accounts.end()) {
            it->second->dispatchQueue.stopAndJoin();
            // Same reasoning: if signal2sip_call_manager_create() already
            // succeeded before the failure, its handle would otherwise
            // leak (own threads, WebRTC PeerConnectionFactory, raw-PCM
            // ADM) since it never reaches the normal shutdown path below.
            if (it->second->handle) {
                signal2sip_call_manager_destroy(it->second->handle);
            }
            if (it->second->socket) {
                it->second->socket->close();
            }
        }
        g_accounts.erase(accountConfig.name);
        return false;
    }
}

// Tears down one account: stop any active SIP bridge, drain and join its
// dispatch queue (queued work dereferences acct.handle/stores/socket, so
// this must happen before any of those are destroyed), then tear down
// RingRTC and the websocket. Reusable by both final shutdown and
// reloadConfig(). No-ops if `name` isn't currently running.
void teardownAccount(const std::string& name) {
    auto it = g_accounts.find(name);
    if (it == g_accounts.end()) return;
    AccountState& acct = *it->second;
    stopSipBridge(acct);
    stopIncomingSipCall(acct);
    acct.dispatchQueue.stopAndJoin();
    signal2sip_call_manager_destroy(acct.handle);
    acct.socket->close();

    if (auto sipIt = g_sipAccounts.find(name); sipIt != g_sipAccounts.end() && g_ep) {
        BridgeAccount& sipAccount = *sipIt->second;

        // Graceful unregister (REGISTER Expires:0) before tearing anything
        // else down - found live 2026-08-07 (config-in-DB work made
        // teardown+setup routine, not just a rare restart): without this,
        // Asterisk's AOR still holds the OLD contact (this project's real
        // AORs all use max_contacts=1 + remove_existing=false - confirmed
        // via `pjsip show aor` on .81), so the NEW registration a fresh
        // setupAccount() immediately attempts gets rejected 403 Forbidden
        // until the stale contact naturally expires - observed live taking
        // the full ~5 minutes (default_expiration=3600 but PJSIP's own
        // client re-registers well before that, so the real wait is
        // whatever was left on the most recent re-register, not the full
        // hour). setRegistration() is asynchronous (completion arrives via
        // onRegState()), so wait briefly for it - best-effort: if it
        // doesn't finish in time, teardown proceeds anyway and the
        // registration watchdog on the next incarnation eventually
        // recovers exactly as it did before this fix, just slower.
        if (sipAccount.registered.load()) {
            try {
                sipAccount.setRegistration(false);
                for (int i = 0; i < 20 && sipAccount.registered.load(); i++) {
                    std::this_thread::sleep_for(std::chrono::milliseconds(100));
                }
            } catch (pj::Error& err) {
                std::cerr << "[daemon][" << name << "] graceful unregister failed (non-fatal): " << err.info()
                           << "\n";
            }
        }

        // Explicitly release this account's dedicated PJSIP transport slot -
        // see BridgeAccount::transportId's own doc comment for why this is
        // required, not just nice-to-have (a fixed-size table that's never
        // auto-reclaimed otherwise).
        if (sipAccount.transportId != PJSUA_INVALID_ID) {
            try {
                g_ep->transportClose(sipAccount.transportId);
            } catch (pj::Error& err) {
                std::cerr << "[daemon][" << name << "] transportClose failed (non-fatal): " << err.info() << "\n";
            }
        }
    }
    g_sipAccounts.erase(name);
    g_accounts.erase(it);
}

// Re-reads [global] from the config file plus every enabled account's
// SIP/deployment config from the database (DaemonConfig::load() - see its
// own doc comment) and diffs against g_accounts: accounts no longer
// present (deleted, or disabled via `gendb <name> disable`) get torn
// down, accounts not yet present (added, or just enabled) get set up. An
// account present in both gets left running untouched UNLESS its
// config_version (see schema.sql's own doc comment on that column)
// doesn't match what it was last set up with - `gendb <name> config set`
// bumps that column, so this is how an already-running account picks up
// a changed sip_password/sip_host/etc without a manual disable+enable
// round-trip. Called both from the SIGHUP handler below and from a
// periodic timer in main()'s loop (see GlobalConfig::configPollIntervalSec's
// own doc comment for why both exist).
void reloadConfig(const std::string& configPath) {
    DaemonConfig newConfig;
    try {
        newConfig = DaemonConfig::load(configPath);
    } catch (const std::exception& e) {
        std::cerr << "[daemon] reload: config error: " << e.what() << " - keeping the previous config running\n";
        return;
    }

    // Accounts already running were constructed against the *old* g_global
    // (captured by value at construction time inside their own Storage),
    // so updating this doesn't retroactively change them - only new
    // accounts brought up below see the new value.
    g_global = newConfig.global;

    std::map<std::string, AccountConfig> newByName;
    for (const auto& accountConfig : newConfig.accounts) newByName.emplace(accountConfig.name, accountConfig);

    for (auto it = g_accounts.begin(); it != g_accounts.end(); ) {
        if (!newByName.count(it->first)) {
            std::cout << "[daemon] reload: removing account " << it->first << "\n";
            std::string name = it->first;
            ++it; // teardownAccount() erases g_accounts[name] itself
            teardownAccount(name);
        } else {
            ++it;
        }
    }

    for (const auto& [name, accountConfig] : newByName) {
        auto it = g_accounts.find(name);
        if (it == g_accounts.end()) {
            std::cout << "[daemon] reload: adding account " << name << "\n";
            setupAccount(accountConfig);
        } else if (it->second->config.configVersion != accountConfig.configVersion) {
            std::cout << "[daemon] reload: config changed for account " << name << " (version "
                       << it->second->config.configVersion << " -> " << accountConfig.configVersion
                       << "), rebuilding\n";
            teardownAccount(name);
            setupAccount(accountConfig);
        }
    }
}

void printUsage() {
    std::cerr
        << "usage: signal2sip-daemon [config-path]\n"
          "\n"
          "Config file defaults to /etc/signal2sip/signal2sip.conf (else ./signal2sip.conf) when no path is\n"
          "given, and only ever needs a [global] section - see signal2sip-gendb --help to create one. Every\n"
          "account's SIP/deployment config + enabled flag lives in the database instead, editable live via\n"
          "`signal2sip-gendb <name> config set/enable/disable` - picked up within [global]\n"
          "config_poll_interval_sec (default 30s), or immediately via SIGHUP (which `gendb` sends automatically\n"
          "on a best-effort basis). See reloadConfig()'s own doc comment for exactly what a reload does.\n";
}

} // namespace

int main(int argc, char** argv) {
    for (int i = 1; i < argc; i++) {
        std::string arg = argv[i];
        if (arg == "--help" || arg == "-h") {
            printUsage();
            return 0;
        }
    }

    refuseIfRunningAsRoot("signal2sip-daemon");

    // A redirected (non-tty) stdout is fully buffered by default - a
    // long-running daemon's log output would otherwise sit invisible in
    // an in-process buffer for a long time (or vanish entirely on a
    // crash). Confirmed live: the test harnesses this project already
    // has hit the exact same issue (see pjsip_ringrtc_echo_test.cpp's
    // comment on the same fix).
    setvbuf(stdout, nullptr, _IONBF, 0);
    setvbuf(stderr, nullptr, _IONBF, 0);

    // Required once per process before any RegistrationClient use (see
    // that class's own doc comment) - StorageServiceSync's storage.signal.org
    // calls are the first daemon-side (not just gendb-side) user of it.
    curl_global_init(CURL_GLOBAL_DEFAULT);

    std::signal(SIGINT, onSignal);
    std::signal(SIGTERM, onSignal);
    // Reload config (add/remove accounts) without restarting - see
    // reloadConfig()'s own doc comment above for exactly what it does and
    // does not support.
    std::signal(SIGHUP, onReloadSignal);

    g_configPath = resolveConfigPath(argc, argv);
    checkOwnerAndModeOrDie(g_configPath, /*requireExactMode0600=*/true);
    DaemonConfig config;
    try {
        config = DaemonConfig::load(g_configPath);
    } catch (const std::exception& e) {
        std::cerr << "[daemon] config error: " << e.what() << "\n";
        return 1;
    }
    checkOwnerAndModeOrDie(config.global.dbPath, /*requireExactMode0600=*/false);
    std::cout << "[daemon] loaded [global] from " << g_configPath << ", " << config.accounts.size()
               << " enabled account(s) from the database\n";
    g_global = config.global;
    writePidFile(g_global);

    signal2sip_init_logging(); // process-wide, once, regardless of account count

    // --- Per-account setup (see setupAccount()'s own doc comment). Each
    // call brings up the shared PJSIP Endpoint itself the first time it
    // hits a SIP-using account (see ensureSharedEndpoint()'s own doc
    // comment) - no separate up-front check needed here.
    for (const AccountConfig& accountConfig : config.accounts) {
        setupAccount(accountConfig);
    }

    if (g_accounts.empty()) {
        std::cerr << "[daemon] no account came up successfully, exiting\n";
        return 1;
    }

    // Set right before the loop starts (not 0) so the first real poll
    // happens after a full configPollIntervalSec from here, not
    // immediately - the per-account setup loop just above already
    // applied the current config, there's nothing new to pick up yet.
    int64_t lastConfigPollMs = std::chrono::duration_cast<std::chrono::milliseconds>(
                                    std::chrono::steady_clock::now().time_since_epoch())
                                    .count();

    while (g_running.load()) {
        if (g_reloadRequested.exchange(false)) {
            std::cout << "[daemon] SIGHUP received, reloading [global] from " << g_configPath
                       << " and every account's config from the database\n";
            reloadConfig(g_configPath);
        }

        // Registration watchdog - see BridgeAccount::unregisteredSinceMs's
        // own doc comment for why this exists (PJSIP silently gives up
        // forever on failure codes like 403, outside its own small
        // auto-retry allowlist). setRegistration(true) just sends a fresh
        // REGISTER through the same account/transport - it's the same
        // call PJSIP's own auto-retry would have made, so this is a
        // no-op on the (common) case where the account is fine or PJSIP
        // is already handling the retry itself; it only matters for the
        // stuck case.
        int64_t nowMs = std::chrono::duration_cast<std::chrono::milliseconds>(
                            std::chrono::steady_clock::now().time_since_epoch())
                            .count();

        // Config poll - see GlobalConfig::configPollIntervalSec's own doc
        // comment for why this is a separate, much longer timer than the
        // watchdogs below rather than checking every ~200ms tick. Same
        // reloadConfig() the SIGHUP handler above calls - this is just an
        // additional trigger, not a different code path, so a `gendb
        // config set` still takes effect even if its best-effort SIGHUP
        // never reached this process (daemon not running yet when it
        // ran, stale/missing pidfile, etc).
        if (nowMs - lastConfigPollMs >= static_cast<int64_t>(g_global.configPollIntervalSec) * 1000) {
            lastConfigPollMs = nowMs;
            reloadConfig(g_configPath);
        }

        for (auto& [name, sipAccount] : g_sipAccounts) {
            // Don't fight the Signal websocket watchdog below: if that
            // account's credentials were rejected (401/403/4401 - see
            // AuthSocket::isDeauthorized()), the Signal side is
            // permanently dead and forcing SIP back up here would just
            // recreate exactly the "stale Registered nothing can actually
            // route to" problem the two watchdogs were built to prevent
            // in the first place - found live 2026-08-07: this watchdog
            // blindly re-registered a deauthorized account's SIP trunk
            // 60s after the other watchdog had correctly brought it down.
            if (auto acctIt = g_accounts.find(name);
                acctIt != g_accounts.end() && acctIt->second->socket && acctIt->second->socket->isDeauthorized()) {
                continue;
            }
            int64_t since = sipAccount->unregisteredSinceMs.load();
            if (since != 0 && nowMs - since >= static_cast<int64_t>(g_global.sipRegWatchdogSec) * 1000) {
                std::cerr << "[daemon][" << name << "] registration watchdog: still unregistered after "
                           << g_global.sipRegWatchdogSec << "s, forcing a fresh attempt\n";
                try {
                    sipAccount->setRegistration(true);
                } catch (pj::Error& err) {
                    std::cerr << "[daemon][" << name << "] watchdog re-registration attempt failed: " << err.info()
                               << "\n";
                }
                // Reset the clock regardless of outcome - if it's still
                // down next tick, we'll try again after another full
                // watchdog interval rather than spamming every 200ms.
                sipAccount->unregisteredSinceMs = nowMs;
            }
        }

        // Signal WebSocket watchdog - AuthSocket has no built-in reconnect
        // (see AuthSocket::reconnect()'s own doc comment); found live
        // 2026-08-06 that a dropped chat.signal.org connection left an
        // account's SIP registration looking perfectly healthy (PJSIP
        // itself never notices - the drop is on a completely separate
        // connection) while incoming Signal calls silently never reached
        // the daemon at all, for hours, with nothing in the log past the
        // initial disconnect. Bring SIP down the moment the socket drops -
        // an honest "Unregistered" beats a stale "Registered" nothing can
        // actually route to - and keep retrying the WebSocket every
        // kSocketReconnectIntervalMs until it's back, then bring SIP back
        // up too.
        for (auto& [name, acctPtr] : g_accounts) {
            AccountState& acct = *acctPtr;
            if (!acct.socket) continue;
            auto sipIt = g_sipAccounts.find(name);

            bool nowConnected = acct.socket->isConnected();
            if (acct.socketConnected && !nowConnected) {
                std::cerr << "[daemon][" << name << "] Signal websocket dropped\n";
                if (sipIt != g_sipAccounts.end()) {
                    try {
                        sipIt->second->setRegistration(false);
                    } catch (pj::Error& err) {
                        std::cerr << "[daemon][" << name
                                   << "] could not bring SIP registration down: " << err.info() << "\n";
                    }
                }
            }
            acct.socketConnected = nowConnected;

            // Signal itself told us this device's credentials are no
            // longer valid (401/403 on the upgrade, or a live session
            // closed with code 4401 - see AuthSocket::isDeauthorized()'s
            // own doc comment) - almost always a real unlink/deregistration
            // done elsewhere, or a delete-account. Retrying with the same
            // credentials can never succeed, so stop spinning the 5s
            // reconnect loop for this account specifically (unlike a
            // generic drop, which keeps retrying below) and say so loudly
            // exactly once, instead of the silent "dropped"/"reconnect
            // failed" spam this used to produce forever.
            if (!nowConnected && acct.socket->isDeauthorized()) {
                if (!acct.deauthorizedAlerted) {
                    acct.deauthorizedAlerted = true;
                    // "<3>" is systemd's syslog-level-prefix convention
                    // (LOG_ERR) - the unit's stderr already lands in
                    // journald by default (no StandardError= override in
                    // signal2sip-daemon.service, SyslogLevelPrefix=yes is
                    // systemd's own default), so this alone makes the line
                    // greppable via `journalctl -p err` or usable in a
                    // systemd OnFailure=/alerting setup with zero new
                    // dependencies.
                    std::cerr << "<3>[daemon][" << name
                               << "] Signal rejected this device's credentials (401/403/4401) - the account was "
                                  "most likely unlinked or deleted on the real Signal side, or (once Registration "
                                  "Lock support exists) a takeover attempt was rejected for lack of the right PIN. "
                                  "Giving up on automatic reconnection for this account; run `signal2sip-gendb "
                               << name
                               << " link` to re-link it (or `unlink` first if it needs a clean local slate), then "
                                  "restart the daemon.\n";

                    const std::string errorMsg =
                        "deauthorized: Signal rejected this device's credentials (401/403/4401)";
                    // nowMs (above) is steady_clock - fine for interval math
                    // in this same loop, but meaningless as a stored
                    // timestamp (its epoch is unspecified, e.g. time since
                    // boot on Linux - confirmed live 2026-08-15, a real
                    // deauth event persisted last_error_at=523610, not a
                    // real Unix time). last_error_at needs wall-clock time
                    // since it's read back by gendb/the TUI well after this
                    // process's own steady_clock reference point is gone.
                    const int64_t nowEpochSec = std::chrono::duration_cast<std::chrono::seconds>(
                                                     std::chrono::system_clock::now().time_since_epoch())
                                                     .count();
                    try {
                        acct.storage->setAccountLastError(errorMsg, nowEpochSec);
                    } catch (const std::exception& e) {
                        std::cerr << "[daemon][" << name << "] failed to persist last_error: " << e.what() << "\n";
                    }
                    runAccountErrorHook(g_global.onAccountErrorCmd, name, acct.account.e164, "deauthorized");
                }
                continue;
            }

            if (!nowConnected &&
                nowMs - acct.lastSocketReconnectAttemptMs >= kSocketReconnectIntervalMs) {
                acct.lastSocketReconnectAttemptMs = nowMs;
                std::cout << "[daemon][" << name << "] reconnecting Signal websocket...\n";
                try {
                    acct.socket->reconnect();
                    std::cout << "[daemon][" << name << "] Signal websocket reconnected\n";
                    acct.socketConnected = true;
                    acct.deauthorizedAlerted = false;
                    if (sipIt != g_sipAccounts.end()) {
                        try {
                            sipIt->second->setRegistration(true);
                        } catch (pj::Error& err) {
                            std::cerr << "[daemon][" << name
                                       << "] could not bring SIP registration back up: " << err.info() << "\n";
                        }
                    }
                } catch (const std::exception& e) {
                    std::cerr << "[daemon][" << name << "] Signal websocket reconnect failed: " << e.what() << "\n";
                }
            }
        }

        // Periodic StorageService re-sync - see syncStorageContacts()'s own
        // doc comment and GlobalConfig::storageSyncIntervalSec's. Runs
        // synchronously on this same loop/thread like everything else here
        // (matches this codebase's existing style - nothing in main()'s
        // loop is async) - a real network hiccup could block this loop
        // (and therefore the registration watchdog above, SIGHUP handling,
        // etc.) for up to ~90s worst case (3 sequential 30s-timeout HTTP
        // calls inside fetchStorageContacts()), but only once per account
        // per storageSyncIntervalSec (12h default), not every 200ms tick.
        for (auto& [name, acctPtr] : g_accounts) {
            AccountState& acct = *acctPtr;
            if (nowMs - acct.lastStorageSyncMs >= static_cast<int64_t>(g_global.storageSyncIntervalSec) * 1000) {
                syncStorageContacts(acct);
            }
        }

        std::this_thread::sleep_for(std::chrono::milliseconds(200));
    }

    // Shutdown, per account (see teardownAccount()'s own doc comment).
    // unique_ptr members (storage/stores/socket/sender) clean themselves
    // up once each AccountState itself is erased.
    while (!g_accounts.empty()) {
        teardownAccount(g_accounts.begin()->first);
    }
    // Best-effort - if this fails, gendb's own /proc/<pid>/comm check
    // (signalDaemonBestEffort()) still won't mistakenly signal a
    // recycled pid, it'll just harmlessly skip once until the daemon
    // restarts and overwrites the stale file.
    ::unlink(pidFilePath(g_global).c_str());
    return 0;
}
