#pragma once

// Authenticated request/response client over Signal's persistent WebSocket
// (wss://chat.signal.org/v1/websocket/), C++ port of layer1/authSocket.js.
// Some Signal-Server endpoints (e.g. PUT /v2/keys) only exist as an
// HTTP-over-websocket call - there is no plain REST equivalent - so this is
// a required transport, not a convenience wrapper.
//
// Implemented on top of libsignal's own C FFI chat-connection client
// (libsignal-net-chat, signal_authenticated_chat_connection_* in
// signal_ffi.h) as of 2026-08-12 - previously a hand-rolled libwebsockets
// client. Switched after a real production threading bug in the old
// implementation (see AuthSocket.cpp's own history) led to discovering
// this FFI surface is Signal-iOS's own sole, production chat transport and
// already has proxy/censorship-circumvention support built in, which the
// hand-rolled version would have had to reimplement from scratch (see
// project memory: signal2sip-authsocket-ffi-migration). The constructor's
// caCertPath parameter (kept at first for API stability, but always
// ignored since the FFI's own Environment::Prod pinning replaced it) was
// dropped 2026-08-14 once nothing else in the class needed it.

#include <cstdint>
#include <functional>
#include <string>

#include "../storage/Storage.h"

namespace signal2sip {

class AuthSocket {
public:
    struct Response {
        uint32_t status = 0;
        Bytes body;
    };

    // onPush is invoked (from a libsignal-net worker thread - see
    // AuthSocket.cpp's own note on this) for every server-pushed message
    // (this class acks each one automatically before invoking the
    // callback, same as the old implementation and the Node prototype it
    // was originally ported from).
    //
    // signalProxy: "" (default) = no proxy, else "host" or "host:port"
    // (default port 443) - a transparent TCP/TLS relay to chat.signal.org,
    // matching real Signal clients' manual "Proxy" setting (the
    // `org.signal.tls` scheme - see project memory:
    // signal2sip-censorship-circumvention for the full protocol writeup).
    // censorshipCircumvention: matches real clients' separate "Censorship
    // circumvention" toggle (automatic SNI domain fronting via Signal's
    // own Fastly/Google Cloud Run infrastructure) - independent of
    // signalProxy, both can be set at once though that's not a real
    // client's usual configuration.
    AuthSocket(std::string username, std::string password,
               std::function<void(const std::string& verb, const std::string& path, const Bytes& body)> onPush,
               std::string signalProxy = "", bool censorshipCircumvention = false);
    ~AuthSocket();

    AuthSocket(const AuthSocket&) = delete;
    AuthSocket& operator=(const AuthSocket&) = delete;

    // Connects and blocks until the WebSocket upgrade completes (or throws
    // on failure/timeout).
    void connect();

    // True once the connection has completed and hasn't been closed
    // since - cleared from the ChatListener's connection_interrupted
    // callback. Poll this instead of assuming a connect()ed socket stays
    // connected forever; chat.signal.org (or the network path to it) can
    // and does drop the connection with no warning.
    bool isConnected() const;

    // Re-establishes the connection after isConnected() has gone false.
    // Reuses the existing ConnectionManager/async runtime, just redoes the
    // chat connection itself - safe to call repeatedly from a watchdog
    // loop. Blocks until the handshake completes (or throws on
    // failure/timeout), same as connect().
    void reconnect();

    // True once the most recent connection attempt (or an already-
    // established session) ended because Signal's server rejected or
    // revoked this device's credentials, rather than an ordinary
    // transient network failure: either the WebSocket upgrade itself
    // returned HTTP 401/403, or an established session was closed with
    // close code 4401 ("Reauthentication required" - Signal's real
    // signal for this device having been unlinked/deregistered/had its
    // credentials rotated elsewhere, see WebSocketDisconnectionRequestListener
    // in Signal-Server). Retrying reconnect()/connect() with the same
    // credentials after this is true is futile until the account is
    // re-linked - a caller's watchdog loop should stop retrying and
    // surface this instead of looping forever. Cleared back to false by
    // a subsequent successful connection.
    bool isDeauthorized() const;

    // Client-initiated request (e.g. GET /v2/keys/..., PUT /v1/messages/...).
    // Blocks the calling thread until a response arrives or times out.
    Response request(const std::string& verb, const std::string& path, const Bytes* body = nullptr);

    void close();

private:
    struct Impl;
    Impl* impl_;
};

} // namespace signal2sip
