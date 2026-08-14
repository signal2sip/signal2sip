// Live Milestone C verification (first slice): C++ port of
// layer1/refreshPreKeys.js - generates a fresh signed EC prekey + last-
// resort Kyber prekey for both aci/pni identities of an existing real
// account, uploads them via PUT /v2/keys (only exists over the
// authenticated websocket), and confirms the real server accepts them.
// Safe/idempotent against a real account - refreshing prekeys is normal
// operation any real Signal client does periodically.
//
// usage: refresh_prekeys_test <account.json>

#include <chrono>
#include <fstream>
#include <iostream>
#include <sstream>

#include <nlohmann/json.hpp>

#include "../daemon/Config.h"
#include "../signal/AuthSocket.h"
#include "../signal/PreKeys.h"
#include "../storage/Storage.h"
#include "../util/Base64.h"

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

Bytes b64(const json& j, const char* key) {
    return base64Decode(j.at(key).get<std::string>());
}

} // namespace

int main(int argc, char** argv) {
    if (argc != 2) {
        std::cerr << "usage: refresh_prekeys_test <account.json>\n";
        return 2;
    }
    json account = json::parse(readFile(argv[1]));

    std::string e164 = account.at("e164").get<std::string>();
    std::string aci = account.at("aci").get<std::string>();
    int deviceId = account.at("deviceId").get<int>();
    std::string password = account.at("password").get<std::string>();
    Bytes aciPrivateKey = b64(account.at("aciIdentityKeyPair"), "privateKey");
    Bytes pniPrivateKey = b64(account.at("pniIdentityKeyPair"), "privateKey");

    // Fresh key ids each run (see refreshPreKeys.js's nextKeyId comment: a
    // stale cached bundle must fail loudly, not silently, if a peer had
    // cached the previous key material under the same id).
    int64_t keyId = static_cast<int64_t>(
        std::chrono::duration_cast<std::chrono::seconds>(std::chrono::system_clock::now().time_since_epoch())
            .count() %
        0xfffffe);

    GeneratedSignedPreKey aciSigned = generateSignedPreKey(aciPrivateKey, keyId);
    GeneratedSignedPreKey pniSigned = generateSignedPreKey(pniPrivateKey, keyId);
    GeneratedKyberPreKey aciKyber = generateKyberPreKey(aciPrivateKey, keyId);
    GeneratedKyberPreKey pniKyber = generateKyberPreKey(pniPrivateKey, keyId);
    std::cout << "PASS: generated fresh signed+kyber prekeys (keyId=" << keyId << ") for aci and pni\n";

    std::string username = deviceId == 1 ? aci : (aci + "." + std::to_string(deviceId));
    AuthSocket socket(username, password,
                      [](const std::string&, const std::string&, const Bytes&) {});
    socket.connect();
    std::cout << "PASS: connected to chat.signal.org as " << e164 << "\n";

    auto upload = [&](const char* identity, const GeneratedSignedPreKey& signedPreKey,
                       const GeneratedKyberPreKey& kyberPreKey) {
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
        std::cout << "PUT /v2/keys?identity=" << identity << " -> status " << response.status << "\n";
        return response.status;
    };

    int aciStatus = upload("aci", aciSigned, aciKyber);
    int pniStatus = upload("pni", pniSigned, pniKyber);
    socket.close();

    bool ok = aciStatus == 204 && pniStatus == 204;
    std::cout << (ok ? "PASS" : "FAIL") << ": both identities' prekeys uploaded\n";
    return ok ? 0 : 1;
}
