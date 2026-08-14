#include "AuthSocket.h"

#include <signal_ffi.h>

#include <atomic>
#include <chrono>
#include <condition_variable>
#include <cstring>
#include <iostream>
#include <mutex>
#include <stdexcept>
#include <thread>

#include "FfiUtil.h"

// Built on libsignal's own C FFI chat-connection client
// (signal_authenticated_chat_connection_* in signal_ffi.h) - see
// AuthSocket.h's own doc comment for why. Every network call here
// (connect/send/disconnect) is async: it takes a SignalCPromise<T> (a
// {complete fn ptr, opaque context, cancellation_id} struct, same pattern
// signal/Cdsi.cpp already uses for CDSI lookups - see that file's own doc
// comment for the general contract) and the `complete` callback fires
// later, from an arbitrary libsignal-net/tokio worker thread, never the
// thread that made the call and never a fixed thread across calls. This
// file blocks the calling thread on a condition_variable for each one,
// same blocking-call shape AuthSocket's callers already expect.
//
// One real hazard specific to *this* file that Cdsi.cpp's simpler
// one-shot-call pattern doesn't have to deal with: a doConnect() can give
// up waiting (timeout) while the real connect attempt is still in flight
// on some tokio thread and may still complete - successfully! - after
// we've already told our caller it failed. The old lws-based
// implementation had the exact same hazard (see the "currentWsi/
// abandonedWsi" comment this file used to carry) and it was a real,
// previously-hit bug (a stale attempt reaching ESTABLISHED after
// doConnect() already gave up caused a second live session for the same
// device, which Signal's server then kicked with a 4409 "Connected
// elsewhere" - a self-sustaining flap loop). ConnectState below
// heap-allocates itself and self-destructs from whichever side (the
// timeout or the late completion) loses the race, instead of assuming
// the waiter is always still there when `complete` eventually fires.

namespace signal2sip {

namespace {

constexpr uint8_t kEnvironmentProd = 1;
constexpr uint8_t kBuildVariantProduction = 0;
constexpr const char* kUserAgent = "signal2sip";
constexpr auto kConnectTimeout = std::chrono::seconds(20);
constexpr uint32_t kRequestTimeoutMillis = 30000;

// Signal error codes this file cares about (signal_error_get_type()'s
// return value) - see rust/bridge/shared/types/src/ffi/error.rs in the
// libsignal checkout this project builds against. Not exhaustive, just
// the ones with a distinct meaning to AuthSocket's callers.
constexpr uint32_t kErrorDeviceDeregistered = 171;   // 403 on connect
constexpr uint32_t kErrorConnectionInvalidated = 172; // WS close 4401 equivalent
constexpr uint32_t kErrorConnectedElsewhere = 173;    // WS close 4409 equivalent

SignalMutPointerConnectionManager makeConnectionManager() {
    // signal_connection_manager_new rejects a null remote_config map
    // outright (confirmed live in Cdsi.cpp's own comment on this exact
    // call) - build an empty one and free our copy after, same sequence
    // Cdsi.cpp already uses successfully against this libsignal version.
    SignalMutPointerBridgedStringMap remoteConfig{};
    checkError(signal_bridged_string_map_new(&remoteConfig, /*initial_capacity=*/0));
    SignalMutPointerConnectionManager manager{};
    checkError(signal_connection_manager_new(&manager, kEnvironmentProd,
                                              reinterpret_cast<const int8_t*>(kUserAgent), remoteConfig,
                                              kBuildVariantProduction));
    checkError(signal_bridged_string_map_destroy(remoteConfig));
    return manager;
}

// Best-effort teardown of a chat connection handle nobody's waiting on
// anymore (either a late-arriving connect() result after doConnect()
// already abandoned it, or a plain close()/reconnect() teardown) -
// mirrors the old implementation's forced-close-of-an-abandoned-attempt
// behavior. Never throws - this runs from contexts (FFI callbacks, best-
// effort cleanup) where a C++ exception must not escape.
void disconnectAndDestroyBestEffort(SignalConstPointerTokioAsyncContext runtime,
                                     SignalMutPointerAuthenticatedChatConnection chat) {
    if (!chat.raw) return;
    struct State {
        std::mutex mutex;
        std::condition_variable cv;
        bool done = false;
        SignalFfiError* error = nullptr;
    } state;
    SignalCPromisebool promise{};
    promise.context = &state;
    promise.complete = [](SignalFfiError* error, SignalType_ConstPointer_bool /*result*/, const void* context) {
        auto* st = const_cast<State*>(static_cast<const State*>(context));
        std::lock_guard<std::mutex> lock(st->mutex);
        if (error) signal_error_free(error);
        st->done = true;
        st->cv.notify_one();
    };
    SignalFfiError* callErr =
        signal_authenticated_chat_connection_disconnect(&promise, runtime, SignalConstPointerAuthenticatedChatConnection{chat.raw});
    if (callErr) {
        signal_error_free(callErr);
    } else {
        std::unique_lock<std::mutex> lock(state.mutex);
        state.cv.wait(lock, [&] { return state.done; });
    }
    SignalFfiError* destroyErr = signal_authenticated_chat_connection_destroy(chat);
    if (destroyErr) signal_error_free(destroyErr);
}

} // namespace

struct AuthSocket::Impl {
    std::string username;
    std::string password;
    std::string signalProxy;
    bool censorshipCircumvention = false;
    std::function<void(const std::string&, const std::string&, const Bytes&)> onPush;

    SignalMutPointerTokioAsyncContext asyncContext{};
    SignalMutPointerConnectionManager connectionManager{};
    SignalMutPointerAuthenticatedChatConnection chat{}; // .raw == nullptr when disconnected

    std::mutex connectMutex;
    bool connected = false;

    std::atomic<bool> deauthorized{false};

    std::thread keepAliveThread;
    std::atomic<bool> stopping{false};

    SignalFfiChatListenerStruct listenerStruct{};

    Impl() {
        checkError(signal_tokio_async_context_new(&asyncContext));
        connectionManager = makeConnectionManager();
        applyProxyConfig();

        listenerStruct.ctx = this;
        listenerStruct.received_incoming_message = &Impl::onReceivedIncomingMessage;
        listenerStruct.received_queue_empty = [](void*) -> int32_t { return 0; };
        listenerStruct.received_alerts = [](void*, SignalBytestringArray alerts) -> int32_t {
            signal_free_bytestring_array(alerts);
            return 0;
        };
        listenerStruct.received_server_timestamp = [](void*, uint64_t) -> int32_t { return 0; };
        listenerStruct.connection_interrupted = &Impl::onConnectionInterrupted;
        listenerStruct.destroy = [](void*) {};
    }

    ~Impl() {
        stopping = true;
        if (keepAliveThread.joinable()) keepAliveThread.join();
        SignalConstPointerTokioAsyncContext runtime{asyncContext.raw};
        disconnectAndDestroyBestEffort(runtime, chat);
        chat = SignalMutPointerAuthenticatedChatConnection{};
        SignalFfiError* err = signal_connection_manager_destroy(connectionManager);
        if (err) signal_error_free(err);
        err = signal_tokio_async_context_destroy(asyncContext);
        if (err) signal_error_free(err);
    }

    // "" clears the proxy (matches real clients' plain on/off), else
    // "host" or "host:port" (default 443) is built as the org.signal.tls
    // scheme - the transparent-relay proxy real Signal clients' manual
    // "Proxy" setting uses (see AuthSocket.h's own doc comment). Applying
    // this doesn't affect an already-open connection (libsignal-net docs
    // this explicitly - only the *next* connect() attempt sees it), which
    // is fine since a config change always goes through reconnect().
    void applyProxyConfig() {
        SignalConstPointerConnectionManager manager{connectionManager.raw};
        if (signalProxy.empty()) {
            checkError(signal_connection_manager_clear_proxy(manager));
        } else {
            std::string host = signalProxy;
            int port = 443;
            size_t colon = host.rfind(':');
            if (colon != std::string::npos) {
                port = std::stoi(host.substr(colon + 1));
                host = host.substr(0, colon);
            }
            SignalMutPointerConnectionProxyConfig proxyConfig{};
            checkError(signal_connection_proxy_config_new(&proxyConfig, reinterpret_cast<const int8_t*>("org.signal.tls"),
                                                            reinterpret_cast<const int8_t*>(host.c_str()), port,
                                                            /*username=*/nullptr, /*password=*/nullptr));
            checkError(signal_connection_manager_set_proxy(manager, SignalConstPointerConnectionProxyConfig{proxyConfig.raw}));
            checkError(signal_connection_proxy_config_destroy(proxyConfig));
        }
        checkError(signal_connection_manager_set_censorship_circumvention_enabled(manager, censorshipCircumvention));
    }

    static int32_t onReceivedIncomingMessage(void* ctx, SignalOwnedBuffer envelope, uint64_t /*timestamp*/,
                                              SignalMutPointerServerMessageAck ack) {
        auto* self = static_cast<Impl*>(ctx);
        Bytes body = takeOwned(envelope);
        // Ack immediately, before invoking onPush - matches the old
        // implementation's (and the Node prototype's) auto-ack-every-push
        // contract exactly.
        SignalFfiError* ackErr = signal_server_message_ack_send(SignalConstPointerServerMessageAck{ack.raw});
        if (ackErr) {
            std::cerr << "[authsocket][" << self->username << "] failed to ack a pushed message (non-fatal)\n";
            signal_error_free(ackErr);
        }
        SignalFfiError* destroyErr = signal_server_message_ack_destroy(ack);
        if (destroyErr) signal_error_free(destroyErr);
        // "PUT /api/v1/message" matches exactly what every real pushed
        // message looked like under the old raw-frame implementation -
        // this callback firing at all already means libsignal-net decoded
        // that same event, it just doesn't hand us the verb/path anymore
        // (see AuthSocket.h's own doc comment) - synthesize them so
        // main.cpp's onPush handler needs no changes.
        if (self->onPush) self->onPush("PUT", "/api/v1/message", body);
        return 0;
    }

    static int32_t onConnectionInterrupted(void* ctx, SignalFfiError* error) {
        auto* self = static_cast<Impl*>(ctx);
        {
            std::lock_guard<std::mutex> lock(self->connectMutex);
            self->connected = false;
        }
        if (error) {
            uint32_t code = signal_error_get_type(error);
            // kErrorConnectedElsewhere (4409-equivalent) is transient by
            // design (another session took over) - no flag change, same
            // as the old WS-close-4409 handling. kErrorConnectionInvalidated
            // (4401-equivalent) means the server itself revoked this
            // device's credentials.
            if (code == kErrorConnectionInvalidated) self->deauthorized.store(true);
            signal_error_free(error);
        }
        return 0;
    }

    // Shared by connect() (first-time setup) and reconnect() (after a
    // drop) - both just need a fresh chat connection against the
    // already-created ConnectionManager. Blocks until it completes or
    // throws on failure/timeout.
    void doConnect() {
        {
            std::lock_guard<std::mutex> lock(connectMutex);
            connected = false;
        }

        // Tear down whatever's left of a previous connection first - on
        // first connect() this is a no-op (chat.raw is null); on
        // reconnect() the old handle is already dead (connection_interrupted
        // already fired to get us here) but still needs destroying.
        SignalConstPointerTokioAsyncContext runtime{asyncContext.raw};
        disconnectAndDestroyBestEffort(runtime, chat);
        chat = SignalMutPointerAuthenticatedChatConnection{};

        struct ConnectState {
            std::mutex mutex;
            std::condition_variable cv;
            bool done = false;
            bool abandoned = false;
            SignalFfiError* error = nullptr;
            SignalMutPointerAuthenticatedChatConnection result{};
            SignalConstPointerTokioAsyncContext runtime{};
        };
        auto* state = new ConnectState();
        state->runtime = runtime;

        SignalCPromiseMutPointerAuthenticatedChatConnection promise{};
        promise.context = state;
        promise.complete = [](SignalFfiError* error, SignalType_ConstPointer_SignalMutPointerAuthenticatedChatConnection result,
                               const void* context) {
            auto* st = const_cast<ConnectState*>(static_cast<const ConnectState*>(context));
            bool selfCleanup = false;
            SignalMutPointerAuthenticatedChatConnection lateResult{};
            {
                std::lock_guard<std::mutex> lock(st->mutex);
                if (st->abandoned) {
                    selfCleanup = true;
                    if (!error && result) lateResult = *result;
                } else {
                    st->error = error;
                    if (!error && result) st->result = *result;
                    st->done = true;
                }
            }
            if (selfCleanup) {
                // Nobody's waiting anymore (doConnect() already timed
                // out) - this is exactly the "late-arriving stale
                // attempt" hazard the old lws implementation's
                // abandonedWsi guarded against. Don't leave a second live
                // session dangling.
                if (error) signal_error_free(error);
                if (lateResult.raw) {
                    // Best-effort only - this runs from a tokio worker
                    // thread with nothing else to report failure to.
                    // Safe to make a new blocking async call from here:
                    // this callback runs on a tokio blocking-pool thread
                    // (a real OS thread, not an async task), not inside a
                    // polled future, so synchronously waiting on another
                    // promise here doesn't stall the runtime.
                    disconnectAndDestroyBestEffort(st->runtime, lateResult);
                }
                delete st;
            } else {
                st->cv.notify_all();
            }
        };

        SignalBorrowedBytestringArray noLanguages{};
        SignalFfiError* callErr = signal_authenticated_chat_connection_connect(
            &promise, runtime, SignalConstPointerConnectionManager{connectionManager.raw},
            reinterpret_cast<const int8_t*>(username.c_str()), reinterpret_cast<const int8_t*>(password.c_str()),
            /*receive_stories=*/false, noLanguages);
        if (callErr) {
            delete state;
            checkError(callErr);
        }

        bool ok;
        {
            std::unique_lock<std::mutex> lock(state->mutex);
            ok = state->cv.wait_for(lock, kConnectTimeout, [&] { return state->done; });
            if (!ok) state->abandoned = true;
        }
        if (!ok) {
            // `state` is now owned by whichever side finishes last (see
            // the completion lambda's selfCleanup branch) - do not touch
            // or delete it here.
            throw std::runtime_error("timed out connecting to chat.signal.org");
        }

        SignalFfiError* connectErrPtr = state->error;
        SignalMutPointerAuthenticatedChatConnection connectResult = state->result;
        delete state;

        if (connectErrPtr) {
            uint32_t code = signal_error_get_type(connectErrPtr);
            if (code == kErrorDeviceDeregistered) deauthorized.store(true);
            checkError(connectErrPtr); // throws, frees connectErrPtr
        }

        chat = connectResult;
        checkError(signal_authenticated_chat_connection_init_listener(
            SignalConstPointerAuthenticatedChatConnection{chat.raw}, SignalConstPointerFfiChatListenerStruct{&listenerStruct}));

        deauthorized.store(false);
        {
            std::lock_guard<std::mutex> lock(connectMutex);
            connected = true;
        }
    }

    Response doRequest(const std::string& verb, const std::string& path, const Bytes* body) {
        SignalMutPointerHttpRequest httpRequest{};
        if (body) {
            checkError(signal_http_request_new_with_body(&httpRequest, reinterpret_cast<const int8_t*>(verb.c_str()),
                                                          reinterpret_cast<const int8_t*>(path.c_str()), borrow(*body)));
            checkError(signal_http_request_add_header(SignalConstPointerHttpRequest{httpRequest.raw},
                                                       reinterpret_cast<const int8_t*>("content-type"),
                                                       reinterpret_cast<const int8_t*>("application/json")));
        } else {
            checkError(signal_http_request_new_without_body(&httpRequest, reinterpret_cast<const int8_t*>(verb.c_str()),
                                                             reinterpret_cast<const int8_t*>(path.c_str())));
        }

        struct SendState {
            std::mutex mutex;
            std::condition_variable cv;
            bool done = false;
            SignalFfiError* error = nullptr;
            SignalFfiChatResponse response{};
            bool hasResponse = false;
        } state;

        SignalCPromiseFfiChatResponse promise{};
        promise.context = &state;
        promise.complete = [](SignalFfiError* error, SignalType_ConstPointer_SignalFfiChatResponse result,
                               const void* context) {
            auto* st = const_cast<SendState*>(static_cast<const SendState*>(context));
            std::lock_guard<std::mutex> lock(st->mutex);
            st->error = error;
            if (!error && result) {
                st->response = *result;
                st->hasResponse = true;
            }
            st->done = true;
            st->cv.notify_one();
        };

        // A chat connection that's gone (never connected, or dropped
        // since) can't send at all - report it the same way a dropped-
        // mid-request response is reported below (status 0), not as a
        // thrown exception, matching the old implementation's contract
        // that gendb's delete-account command depends on (see its own
        // comment there for why status==0 is treated as "ambiguous", not
        // a hard failure).
        if (!chat.raw) {
            checkError(signal_http_request_destroy(httpRequest));
            return Response{0, {}};
        }

        SignalFfiError* callErr = signal_authenticated_chat_connection_send(
            &promise, SignalConstPointerTokioAsyncContext{asyncContext.raw}, SignalConstPointerAuthenticatedChatConnection{chat.raw},
            SignalConstPointerHttpRequest{httpRequest.raw}, kRequestTimeoutMillis);
        if (callErr) {
            checkError(signal_http_request_destroy(httpRequest));
            checkError(callErr);
        }

        // httpRequest must stay alive until the async send actually
        // consumes it (some tokio worker thread builds the real outgoing
        // message from it after this call returns, not before) - destroy
        // it only after the promise completes, same ordering Cdsi.cpp
        // already uses for its own request object. Destroying it right
        // after firing the call (as an earlier version of this function
        // did) is a real use-after-free - caught it live via a SIGSEGV
        // deep inside libsignal-net's own OutgoingRequest::make_message.
        std::unique_lock<std::mutex> lock(state.mutex);
        state.cv.wait(lock, [&] { return state.done; });
        lock.unlock();
        checkError(signal_http_request_destroy(httpRequest));

        if (state.error) {
            uint32_t code = signal_error_get_type(state.error);
            // The connection dropped while this request was in flight -
            // same ambiguous-outcome case the old implementation reported
            // as status 0 rather than an exception (LWS_CALLBACK_CLIENT_CLOSED
            // resolving every pending request that way). Only this
            // specific case gets the sentinel; every other error (bad
            // request, genuine timeout, ...) still throws normally.
            if (code == kErrorConnectionInvalidated || code == kErrorConnectedElsewhere ||
                code == kErrorWebSocketGeneric) {
                signal_error_free(state.error);
                return Response{0, {}};
            }
            checkError(state.error);
        }

        Response response;
        if (state.hasResponse) {
            response.status = state.response.status;
            response.body = takeOwned(state.response.body);
            signal_free_list_of_strings(state.response.headers);
        }
        return response;
    }

    static constexpr uint32_t kErrorWebSocketGeneric = 146;

    void sendKeepAlive() {
        {
            std::lock_guard<std::mutex> lock(connectMutex);
            if (!connected) return;
        }
        try {
            doRequest("GET", "/v1/keepalive", nullptr);
        } catch (const std::exception&) {
            // Best-effort - the reconnect watchdog (main.cpp) is
            // responsible for noticing a real drop via isConnected(),
            // this is just a liveness ping.
        }
    }
};

AuthSocket::AuthSocket(std::string username, std::string password,
                       std::function<void(const std::string&, const std::string&, const Bytes&)> onPush,
                       std::string signalProxy, bool censorshipCircumvention)
    : impl_(new Impl()) {
    impl_->username = std::move(username);
    impl_->password = std::move(password);
    impl_->onPush = std::move(onPush);
    impl_->signalProxy = std::move(signalProxy);
    impl_->censorshipCircumvention = censorshipCircumvention;
    // Constructor already built connectionManager/asyncContext with a
    // default (no-proxy) config - re-apply now that the real per-account
    // settings are known, before the first connect().
    impl_->applyProxyConfig();
}

AuthSocket::~AuthSocket() {
    close();
    delete impl_;
}

void AuthSocket::connect() {
    impl_->doConnect();
    impl_->keepAliveThread = std::thread([this] {
        while (!impl_->stopping.load()) {
            std::this_thread::sleep_for(std::chrono::seconds(15));
            if (!impl_->stopping.load()) impl_->sendKeepAlive();
        }
    });
}

bool AuthSocket::isConnected() const {
    std::lock_guard<std::mutex> lock(impl_->connectMutex);
    return impl_->connected;
}

void AuthSocket::reconnect() { impl_->doConnect(); }

bool AuthSocket::isDeauthorized() const { return impl_->deauthorized.load(); }

AuthSocket::Response AuthSocket::request(const std::string& verb, const std::string& path, const Bytes* body) {
    return impl_->doRequest(verb, path, body);
}

void AuthSocket::close() {
    if (impl_->stopping.exchange(true)) return;
    if (impl_->keepAliveThread.joinable()) impl_->keepAliveThread.join();
    SignalConstPointerTokioAsyncContext runtime{impl_->asyncContext.raw};
    disconnectAndDestroyBestEffort(runtime, impl_->chat);
    impl_->chat = SignalMutPointerAuthenticatedChatConnection{};
    {
        std::lock_guard<std::mutex> lock(impl_->connectMutex);
        impl_->connected = false;
    }
}

} // namespace signal2sip
