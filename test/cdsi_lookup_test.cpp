// Live verification for native/signal/Cdsi.h - resolves one or more e164
// phone numbers to their real ACI/PNI via Signal's production Contact
// Discovery Service. Throwaway/manual verification only, same role as
// refresh_prekeys_test.cpp for its own milestone - not a permanent CLI tool
// (gendb stays limited to account lifecycle: register/link/verify).
//
// usage: cdsi_lookup_test <account.json> <e164> [e164...]

#include <fstream>
#include <iostream>
#include <sstream>

#include <nlohmann/json.hpp>

#include "../daemon/Config.h"
#include "../signal/AuthSocket.h"
#include "../signal/Cdsi.h"

using namespace signal2sip;
using json = nlohmann::json;

namespace {

std::string readFile(const std::string& path) {
    std::ifstream f(path);
    if (!f) throw std::runtime_error("cannot open " + path);
    std::stringstream ss;
    ss << f.rdbuf();
    return ss.str();
}

}  // namespace

int main(int argc, char** argv) try {
    if (argc < 3) {
        std::cerr << "usage: cdsi_lookup_test <account.json> <e164> [e164...]\n";
        return 2;
    }
    json account = json::parse(readFile(argv[1]));

    std::string aci = account.at("aci").get<std::string>();
    int deviceId = account.at("deviceId").get<int>();
    std::string password = account.at("password").get<std::string>();
    // Matches main.cpp's AuthSocket username.
    std::string username = deviceId == 1 ? aci : (aci + "." + std::to_string(deviceId));

    std::vector<std::string> e164s(argv + 2, argv + argc);

    // CDSI itself is NOT reached over this socket (see Cdsi.h's doc
    // comment - it's a separate libsignal `net`/attested-enclave
    // transport) - this is only to fetch the short-lived directory-
    // service token GET /v2/directory/auth requires, via the account's
    // normal persistent credentials.
    AuthSocket socket(username, password,
                       [](const std::string&, const std::string&, const Bytes&) {});
    socket.connect();
    std::cout << "PASS: connected to chat.signal.org\n";

    AuthSocket::Response authResponse = socket.request("GET", "/v2/directory/auth");
    if (authResponse.status != 200) {
        throw std::runtime_error("GET /v2/directory/auth -> status " + std::to_string(authResponse.status));
    }
    json authToken = json::parse(std::string(authResponse.body.begin(), authResponse.body.end()));
    std::string cdsiUsername = authToken.at("username").get<std::string>();
    std::string cdsiPassword = authToken.at("password").get<std::string>();
    socket.close();
    std::cout << "PASS: got directory-service token (username=" << cdsiUsername << ")\n";

    std::cout << "Looking up " << e164s.size() << " e164(s) via CDSI...\n";
    std::vector<CdsiLookupResult> results = cdsiLookup(cdsiUsername, cdsiPassword, e164s);

    std::cout << "PASS: got " << results.size() << " result(s)\n";
    for (const auto& r : results) {
        std::cout << "  " << r.e164 << " -> aci=" << (r.aci.empty() ? "(not found)" : r.aci)
                   << " pni=" << (r.pni.empty() ? "(none)" : r.pni) << "\n";
    }
    return 0;
} catch (const std::exception& e) {
    std::cerr << "FAIL: " << e.what() << "\n";
    return 1;
}
