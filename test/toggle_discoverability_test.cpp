// Throwaway helper: forces a real PUT /v1/accounts/attributes/ with a
// specific discoverableByPhoneNumber value, using an account's already-
// stored real credentials/registration ids (never generates fresh ones -
// this is a live attribute update on an existing account, not a new
// registration, and getting registrationId/capabilities wrong here could
// disrupt the account's own working device state).
//
// Built to debug a real 2026-08-05 finding: an account registered via
// signal2sip-gendb with discoverableByPhoneNumber=true already set at
// registration time still didn't show up in CDS contact-discovery
// lookups days later, even though a real (linked) Signal-Android account
// started showing up immediately after toggling the same setting in the
// app. Since this gendb-only account has no real app UI to toggle the
// setting from, this forces the same kind of attribute *change* (not
// just resend of the same value) server-side, to give Signal's CDS
// directory-sync pipeline (DynamoDB Streams -> Lambda -> Kinesis -> CDS
// enclave) another chance to pick it up.
//
// usage: toggle_discoverability_test <db_path> <db_key> <account_name> <true|false>

#include <iostream>

#include <nlohmann/json.hpp>

#include "../signal/AuthSocket.h"
#include "../storage/Storage.h"

using namespace signal2sip;
using json = nlohmann::json;

int main(int argc, char** argv) {
    if (argc != 5) {
        std::cerr << "usage: toggle_discoverability_test <db_path> <db_key> <account_name> <true|false>\n";
        return 2;
    }
    Storage storage(argv[1], argv[2], argv[3]);
    AccountRecord account = storage.loadAccount();
    bool discoverable = std::string(argv[4]) == "true";

    std::string username =
        account.device_id == 1 ? account.aci : (account.aci + "." + std::to_string(account.device_id));

    AuthSocket socket(username, account.password,
                       [](const std::string& verb, const std::string& path, const Bytes&) {
                           std::cout << "PUSH: " << verb << " " << path << "\n";
                       });
    std::cout << "connecting as " << username << "...\n";
    socket.connect();
    std::cout << "PASS: connected\n";

    // Same shape as signal2sip-gendb's own registration/link request
    // bodies (main.cpp) - reusing this account's REAL stored
    // registrationId/pniRegistrationId rather than generating fresh
    // ones, since PUT /v1/accounts/attributes/ is a live update to an
    // account already in active use by the daemon.
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
        {"discoverableByPhoneNumber", discoverable},
    };
    std::string bodyStr = body.dump();
    Bytes bodyBytes(bodyStr.begin(), bodyStr.end());

    auto response = socket.request("PUT", "/v1/accounts/attributes/", &bodyBytes);
    std::cout << "PUT /v1/accounts/attributes/ (discoverableByPhoneNumber=" << (discoverable ? "true" : "false")
               << ") -> status " << response.status << "\n";
    std::cout << (response.status / 100 == 2 ? "PASS" : "FAIL") << "\n";

    socket.close();
    return response.status / 100 == 2 ? 0 : 1;
}
