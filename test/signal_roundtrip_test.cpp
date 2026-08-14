// Live Milestone B verification: migrates the existing +380000000001
// account (already registered by the Node prototype this session, its
// JSON files are the proven-correct reference) into a fresh SQLCipher
// Storage, then uses the pure-C++ signal2sip_signal + signal2sip_authsocket
// stack to fetch a real prekey bundle for +380000000002's ACI, establish a
// session, encrypt a real Content message, and send it via the real
// PUT /v1/messages endpoint - the same operation this session's
// layer1/sendMessage.js already proved correct, now fully re-implemented
// in C++ with no Node.js involved.
//
// usage: signal_roundtrip_test <sender-account.json> <sender-sessions.json> <destination-service-id> "<text>"

#include <chrono>
#include <fstream>
#include <iostream>
#include <map>
#include <sstream>

#include <nlohmann/json.hpp>

#include "../daemon/Config.h"
#include "../signal/AuthSocket.h"
#include "../signal/Crypto.h"
#include "../signal/ProtocolStores.h"
#include "../storage/Storage.h"
#include "../util/Base64.h"
#include "SignalService.pb.h"

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

// Populates a fresh Storage from the Node prototype's account.json +
// sessions.json shape (layer1/accountStore.js / protocolStores.js) - a
// one-time migration path, not part of the eventual gendb tool (which will
// generate keys directly in C++ instead of importing them).
void migrateAccount(Storage& storage, const std::string& accountJsonPath, const std::string& sessionsJsonPath) {
    json account = json::parse(readFile(accountJsonPath));

    AccountRecord record;
    record.e164 = account.at("e164").get<std::string>();
    record.aci = account.at("aci").get<std::string>();
    record.pni = account.at("pni").get<std::string>();
    record.device_id = account.at("deviceId").get<int>();
    record.password = account.at("password").get<std::string>();
    record.registration_id = account.at("registrationId").get<int64_t>();
    record.pni_registration_id = account.at("pniRegistrationId").get<int64_t>();
    storage.saveAccount(record);

    storage.saveIdentityKeypair(
        "aci", IdentityKeypairRecord{b64(account.at("aciIdentityKeyPair"), "privateKey"),
                                     b64(account.at("aciIdentityKeyPair"), "publicKey")});

    const auto& signedPreKey = account.at("aciSignedPreKey");
    storage.saveSignedPrekey(
        "aci", SignedPrekeyRecord{signedPreKey.at("keyId").get<int64_t>(), b64(signedPreKey, "record")});

    const auto& kyberPreKey = account.at("aciPqLastResortPreKey");
    storage.saveKyberPrekey(
        "aci", KyberPrekeyRecord{kyberPreKey.at("keyId").get<int64_t>(), b64(kyberPreKey, "record")});

    if (!sessionsJsonPath.empty()) {
        std::ifstream f(sessionsJsonPath);
        if (f) {
            json sessions = json::parse(readFile(sessionsJsonPath));
            for (auto& [address, recordB64] : sessions.at("sessions").items()) {
                storage.saveSession(address, base64Decode(recordB64.get<std::string>()));
            }
            for (auto& [address, keyB64] : sessions.at("identities").items()) {
                storage.saveRemoteIdentity(address, base64Decode(keyB64.get<std::string>()));
            }
        }
    }
}

} // namespace

int main(int argc, char** argv) {
    if (argc != 5) {
        std::cerr << "usage: signal_roundtrip_test <account.json> <sessions.json> <destination-service-id> "
                     "\"<text>\"\n";
        return 2;
    }
    std::string accountJsonPath = argv[1];
    std::string sessionsJsonPath = argv[2];
    std::string destinationServiceId = argv[3];
    std::string text = argv[4];

    std::string dbPath = "/tmp/signal2sip_roundtrip_test.db";
    std::remove(dbPath.c_str());
    Storage storage(dbPath, "roundtrip-test-key", "test");
    migrateAccount(storage, accountJsonPath, sessionsJsonPath);
    std::cout << "PASS: migrated account into SQLCipher storage\n";

    AccountRecord account = storage.loadAccount();
    Address localAddress{account.aci, static_cast<uint32_t>(account.device_id)};
    std::string username = account.device_id == 1 ? account.aci : (account.aci + "." + std::to_string(account.device_id));

    ProtocolStores stores(storage, "aci");

    AuthSocket socket(username, account.password,
                      [](const std::string&, const std::string&, const Bytes&) {});
    socket.connect();
    std::cout << "PASS: connected to chat.signal.org as " << account.e164 << "\n";

    // Resolve device ids: use whatever sessions we already migrated, else
    // fetch a fresh prekey bundle and establish sessions - same fallback
    // preKeyBundle.js/sendMessage.js use.
    auto deviceIds = storage.knownDeviceIdsFor(destinationServiceId);
    std::map<int, uint32_t> registrationIds;
    if (deviceIds.empty()) {
        std::cout << "no existing session with " << destinationServiceId << " - fetching prekey bundle\n";
        auto response = socket.request("GET", "/v2/keys/" + destinationServiceId + "/*");
        if (response.status != 200) {
            std::cerr << "FAIL: GET /v2/keys -> " << response.status << "\n";
            return 1;
        }
        json body = json::parse(std::string(response.body.begin(), response.body.end()));
        Bytes identityKey = base64Decode(body.at("identityKey").get<std::string>());

        for (const auto& device : body.at("devices")) {
            RemotePreKeyBundle bundle;
            bundle.serviceId = destinationServiceId;
            bundle.deviceId = device.at("deviceId").get<uint32_t>();
            bundle.registrationId = device.at("registrationId").get<uint32_t>();
            if (device.contains("preKey") && !device.at("preKey").is_null()) {
                bundle.preKeyId = device.at("preKey").at("keyId").get<uint32_t>();
                bundle.preKeyPublic = b64(device.at("preKey"), "publicKey");
            }
            const auto& signedPreKey = device.at("signedPreKey");
            bundle.signedPreKeyId = signedPreKey.at("keyId").get<uint32_t>();
            bundle.signedPreKeyPublic = b64(signedPreKey, "publicKey");
            bundle.signedPreKeySignature = b64(signedPreKey, "signature");
            bundle.identityKey = identityKey;
            const auto& pqPreKey = device.at("pqPreKey");
            bundle.kyberPreKeyId = pqPreKey.at("keyId").get<uint32_t>();
            bundle.kyberPreKeyPublic = b64(pqPreKey, "publicKey");
            bundle.kyberPreKeySignature = b64(pqPreKey, "signature");

            establishSession(stores, localAddress, bundle);
            deviceIds.push_back(bundle.deviceId);
            registrationIds[bundle.deviceId] = bundle.registrationId;
        }
        std::cout << "PASS: established sessions with " << deviceIds.size() << " device(s)\n";
    } else {
        std::cout << "PASS: reusing " << deviceIds.size() << " migrated session(s)\n";
    }

    auto sendOne = [&](const std::string& label, const std::string& body, bool urgent = true,
                        int64_t timestampOffsetMs = 0) {
        int64_t nowMs =
            std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::system_clock::now().time_since_epoch())
                .count();
        signalservice::Content content;
        content.mutable_datamessage()->set_body(body);
        content.mutable_datamessage()->set_timestamp(nowMs);
        std::string contentBytes;
        content.SerializeToString(&contentBytes);
        Bytes contentPlaintext(contentBytes.begin(), contentBytes.end());

        json messages = json::array();
        int firstType = -1;
        for (int deviceId : deviceIds) {
            EncryptedMessage encrypted = encryptForDevice(
                stores, localAddress, Address{destinationServiceId, static_cast<uint32_t>(deviceId)}, contentPlaintext);
            int envelopeType = encrypted.type == SignalCiphertextMessageTypePreKey ? 3 : 1;
            if (firstType == -1) firstType = envelopeType;
            messages.push_back(
                {{"type", envelopeType},
                 {"destinationDeviceId", deviceId},
                 {"destinationRegistrationId", registrationIds.count(deviceId) ? registrationIds[deviceId] : 0},
                 {"content", base64Encode(encrypted.ciphertext)}});
        }
        std::cout << "PASS: [" << label << "] encrypted message for " << messages.size()
                   << " device(s), envelope type=" << firstType << "\n";

        json requestBody = {{"destination", destinationServiceId},
                             {"timestamp", nowMs + timestampOffsetMs},
                             {"messages", messages},
                             {"online", true},
                             {"urgent", urgent}};
        std::string bodyStr = requestBody.dump();
        Bytes bodyBytes(bodyStr.begin(), bodyStr.end());
        auto sendResponse = socket.request("PUT", "/v1/messages/" + destinationServiceId + "?story=false", &bodyBytes);
        std::cout << "[" << label << "] PUT /v1/messages -> status " << sendResponse.status << "\n";
        std::cout << "[" << label << "] body: " << std::string(sendResponse.body.begin(), sendResponse.body.end())
                   << "\n";
        return sendResponse.status / 100 == 2;
    };

    bool ok1 = sendOne("first (PreKey, fresh session)", text);
    bool ok2 = sendOne("second (Whisper, established session)", text + " [second]", /*urgent=*/false);
    bool ok3 = sendOne("third (online:true, timestamp +30s future)", text + " [future-ts]", /*urgent=*/true,
                        /*timestampOffsetMs=*/30000);
    std::cout << (ok1 && ok2 && ok3 ? "PASS" : "FAIL") << ": message send round-trips\n";

    socket.close();
    return ok1 && ok2 && ok3 ? 0 : 1;
}
