// Regression test for two real bugs fixed in fetchStorageContacts() - see
// StorageServiceSync.cpp's own history comment for the full story:
// (1) a BoringSSL/OpenSSL symbol collision (tools/isolate_webrtc_boringssl_symbols.py)
// that made manifest decrypt intermittently fail, and (2) a missing SSRE2
// record-IKM item-key derivation path that made every single contact item
// fail to decrypt (100% of the time, not intermittently). Calls
// fetchStorageContacts() N times in a row against a real, already-linked
// account and reports a pass/fail line + contact count per iteration -
// every iteration should now PASS with the account's full real contact
// count every time (72/72 for account 123456789002, confirmed 2026-08-06).
//
// usage: storage_sync_loop_test <signal2sip.conf path> <account name> [iterations]

#include <iostream>

#include "../daemon/Config.h"
#include "../daemon/StorageServiceSync.h"
#include "../signal/AuthSocket.h"
#include "../storage/Storage.h"

using namespace signal2sip;

int main(int argc, char** argv) {
    if (argc < 3) {
        std::cerr << "usage: storage_sync_loop_test <signal2sip.conf path> <account name> [iterations]\n";
        return 2;
    }
    std::string confPath = argv[1];
    std::string accountName = argv[2];
    int iterations = argc >= 4 ? std::stoi(argv[3]) : 20;

    DaemonConfig config = DaemonConfig::load(confPath);
    const AccountConfig* accountConfig = nullptr;
    for (const auto& a : config.accounts) {
        if (a.name == accountName) accountConfig = &a;
    }
    if (!accountConfig) {
        std::cerr << "no [account." << accountName << "] section in " << confPath << "\n";
        return 2;
    }

    Storage storage(config.global.dbPath, config.global.dbKey, accountName);
    AccountRecord account = storage.loadAccount();
    if (!account.account_entropy_pool || account.account_entropy_pool->empty()) {
        std::cerr << "account " << accountName << " has no account_entropy_pool stored\n";
        return 2;
    }

    std::string username =
        account.device_id == 1 ? account.aci : (account.aci + "." + std::to_string(account.device_id));
    AuthSocket socket(username, account.password,
                       [](const std::string&, const std::string&, const Bytes&) {});
    socket.connect();
    std::cout << "connected as " << account.e164 << " (" << account.aci << "), running " << iterations
              << " iterations\n";

    int passes = 0, fails = 0;
    for (int i = 1; i <= iterations; i++) {
        try {
            std::vector<StorageContact> contacts = fetchStorageContacts(socket, *account.account_entropy_pool);
            std::cout << "iteration " << i << ": PASS (" << contacts.size() << " contacts)\n";
            passes++;
        } catch (const std::exception& e) {
            std::cout << "iteration " << i << ": FAIL - " << e.what() << "\n";
            fails++;
        }
    }
    socket.close();

    std::cout << "\n" << passes << " passed, " << fails << " failed out of " << iterations << "\n";
    return fails == 0 ? 0 : 1;
}
