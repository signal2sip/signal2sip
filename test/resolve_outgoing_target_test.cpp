// Live verification for ContactResolver.h's cache+CDSI resolution path,
// stopping short of actually placing a call (unlike signal2sip-daemon
// itself, this never touches signal2sip_call_start_outgoing) - run twice
// against the same target to see the second run hit the cache instead of
// making a real CDSI network call.
//
// usage: resolve_outgoing_target_test <db_path> <db_key> <account_name> <target> [ttl_sec]

#include <chrono>
#include <iostream>

#include "../daemon/Config.h"
#include "../daemon/ContactResolver.h"

using namespace signal2sip;

int main(int argc, char** argv) try {
    if (argc < 5 || argc > 6) {
        std::cerr << "usage: resolve_outgoing_target_test <db_path> <db_key> <account_name> <target> [ttl_sec]\n";
        return 2;
    }
    uint32_t ttlSec = argc == 6 ? static_cast<uint32_t>(std::stoul(argv[5])) : 86400;
    Storage storage(argv[1], argv[2], argv[3]);
    AccountRecord account = storage.loadAccount();

    std::string username =
        account.device_id == 1 ? account.aci : (account.aci + "." + std::to_string(account.device_id));
    AuthSocket socket(username, account.password,
                       [](const std::string&, const std::string&, const Bytes&) {});
    auto t0 = std::chrono::steady_clock::now();
    socket.connect();
    auto t1 = std::chrono::steady_clock::now();

    std::string resolved = resolveOutgoingTarget(socket, storage, argv[4], ttlSec);
    auto t2 = std::chrono::steady_clock::now();
    std::cout << "PASS: " << argv[4] << " -> " << resolved << "\n";

    socket.close();
    auto t3 = std::chrono::steady_clock::now();
    auto ms = [](auto a, auto b) { return std::chrono::duration_cast<std::chrono::milliseconds>(b - a).count(); };
    std::cerr << "timing: connect=" << ms(t0, t1) << "ms resolve=" << ms(t1, t2) << "ms close=" << ms(t2, t3)
               << "ms\n";
    return 0;
} catch (const std::exception& e) {
    std::cerr << "FAIL: " << e.what() << "\n";
    return 1;
}
