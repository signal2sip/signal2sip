// Live connectivity check for Milestone B's transport layer: connects to
// the real chat.signal.org websocket with real account credentials and
// issues one harmless authenticated request (GET /v1/keepalive), to prove
// the TLS handshake (pinned by libsignal-net-chat's own Environment::Prod,
// since the FFI migration - see AuthSocket.h), Basic Auth, and
// WebSocketMessage protobuf framing all work end-to-end before any
// libsignal-dependent code is layered on top. Credentials are passed as
// argv, not compiled in.

#include "../signal/AuthSocket.h"

#include <iostream>

int main(int argc, char** argv) {
    if (argc != 3) {
        std::cerr << "usage: authsocket_test <username> <password>\n";
        return 2;
    }
    std::string username = argv[1];
    std::string password = argv[2];

    signal2sip::AuthSocket socket(username, password,
                                   [](const std::string& verb, const std::string& path, const signal2sip::Bytes&) {
                                       std::cout << "PUSH: " << verb << " " << path << "\n";
                                   });

    std::cout << "connecting...\n";
    socket.connect();
    std::cout << "PASS: connected\n";

    auto response = socket.request("GET", "/v1/keepalive");
    std::cout << "GET /v1/keepalive -> status " << response.status << "\n";
    std::cout << (response.status == 200 ? "PASS" : "FAIL") << ": keepalive request round-trips\n";

    socket.close();
    return response.status == 200 ? 0 : 1;
}
