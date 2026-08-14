#pragma once

// Flow B's provisioning WebSocket (device-linking), C++ port of
// layer1/link-new-device.js's connection/QR/decrypt half (the finishing
// PUT /v1/devices/link call is done separately by the caller via
// RegistrationClient, using this class's result - mirrors main.cpp's own
// split between AuthSocket and the JSON body building it does itself).
//
// Unlike AuthSocket (this project's other WebSocket client), the
// provisioning socket needs no account auth and only ever receives two
// pushed requests from the server: PUT /v1/address (an opaque address to
// embed in a QR code) and PUT /v1/message (the encrypted ProvisionMessage,
// once a primary device scans that QR and approves linking).

#include <optional>
#include <string>

#include "../storage/Storage.h"

namespace signal2sip {

struct ProvisionMessageResult {
    std::string e164;
    std::string aci;
    std::string pni;
    Bytes aciIdentityKeyPublic;
    Bytes aciIdentityKeyPrivate;
    Bytes pniIdentityKeyPublic;
    Bytes pniIdentityKeyPrivate;
    std::string provisioningCode;
    std::optional<Bytes> profileKey;
    std::optional<std::string> accountEntropyPool;
    std::optional<Bytes> mediaRootBackupKey;
};

class ProvisioningClient {
public:
    explicit ProvisioningClient(std::string serverHost = "chat.signal.org");
    ~ProvisioningClient();

    ProvisioningClient(const ProvisioningClient&) = delete;
    ProvisioningClient& operator=(const ProvisioningClient&) = delete;

    // Connects, prints the sgnl://linkdevice URL plus an ASCII QR render of
    // it once the server hands us an address (10s timeout - matches
    // link-new-device.js's ADDRESS_TIMEOUT_MS), then blocks until a
    // primary device scans it and approves linking, sending back a real,
    // decrypted ProvisionMessage (90s total lifespan from connect -
    // LIFESPAN_MS). Throws std::runtime_error on any timeout/failure
    // (including a provisioning-cipher decrypt/MAC failure).
    ProvisionMessageResult waitForProvisionMessage();

private:
    struct Impl;
    Impl* impl_;
};

} // namespace signal2sip
