#include "ProvisioningClient.h"

#include <signal_ffi.h>
#include <qrencode.h>

#include <chrono>
#include <condition_variable>
#include <cstring>
#include <fstream>
#include <iostream>
#include <mutex>
#include <sstream>
#include <stdexcept>

#include "ProvisioningCipher.h"
#include "Provisioning.pb.h"
#include "../signal/FfiUtil.h"
#include "../util/Base64.h"

// Built on libsignal's own C FFI provisioning-chat client
// (signal_provisioning_chat_connection_* in signal_ffi.h) as of
// 2026-08-12, replacing a hand-rolled libwebsockets client - same
// migration as AuthSocket.cpp (see that file's own doc comment for the
// full rationale and the general SignalCPromise/async-callback contract,
// identical here). Two real simplifications this connection type gets
// for free over AuthSocket's: no auth handshake (this is genuinely an
// unauthenticated connection, matching the real protocol - the server is
// just a rendezvous, it never sees the provisioning keys/crypto), and no
// generic send() capability at all - the FFI only exposes connect/
// disconnect/init_listener for this connection type, matching that the
// real protocol never has the linking device send anything over this
// socket, only receive (an address, then later an encrypted envelope).
// That also means no keepalive is needed here on our side - nothing to
// periodically send, and WebSocket-level ping/pong is handled inside the
// FFI's own transport, same as it was for the old lws code (which never
// implemented a provisioning-level ping either, just relied on lws's).

namespace signal2sip {

namespace {

std::string base64NoPadding(const Bytes& data) {
    std::string s = base64Encode(data);
    while (!s.empty() && s.back() == '=') s.pop_back();
    return s;
}

std::string urlEncode(const std::string& in) {
    static const char* hex = "0123456789ABCDEF";
    std::string out;
    for (unsigned char c : in) {
        if (isalnum(c) || c == '-' || c == '_' || c == '.' || c == '~') {
            out.push_back(static_cast<char>(c));
        } else {
            out.push_back('%');
            out.push_back(hex[c >> 4]);
            out.push_back(hex[c & 0xF]);
        }
    }
    return out;
}

// Half-block ("small") terminal QR render - two module rows per printed
// text row, same visual density qrcode-terminal's {small:true} produced in
// the Node version. Camera scanning of this is font/terminal-dependent
// (the half-block trick assumes the terminal's character cells are close
// enough to 1:2 width:height that each glyph renders as two roughly-square
// modules - not guaranteed for every font/terminal, and line-wrapping in a
// narrow window silently corrupts the whole pattern) - renderQr() below
// also always writes a real PNG as a dependency-free fallback that sidesteps
// all of that.
//
// Two real scan-failure causes fixed 2026-08-08 after a live report of a
// phone camera refusing to lock onto this: (1) the quiet zone here was only
// 2 modules - the QR spec (ISO/IEC 18004) calls for 4, and most scanners'
// finder-pattern search genuinely relies on that full margin being blank;
// (2) this printed with no explicit colors at all, so it inherited
// whatever the surrounding terminal's colors were - on a dark-themed
// terminal (the common case) that renders as light block glyphs on a dark
// background, the exact inverse of the dark-modules-on-light convention
// scanners are tuned for. Explicit SGR codes force true black-on-white
// here regardless of the terminal's own theme; signal2sip-tui's Screen 5
// does the equivalent at the FTXUI layer for the same reason (raw ANSI
// codes piped through a subprocess don't reach FTXUI's own text styling).
void printQrAscii(const QRcode* qr) {
    int width = qr->width;
    auto dark = [&](int x, int y) -> bool {
        if (x < 0 || y < 0 || x >= width || y >= width) return false;
        return (qr->data[y * width + x] & 1) != 0;
    };
    std::cout << "\x1b[30;107m"; // black-on-bright-white, overriding the terminal's own theme
    // 6-module quiet zone border on every side - past ISO/IEC 18004's
    // 4-module recommended minimum, deliberately generous since each
    // "module" here is only a character cell (coarse compared to a real
    // printed/screen QR), and this was still hard to lock onto with just
    // the spec minimum in a live test.
    for (int y = -6; y < width + 6; y += 2) {
        std::string line;
        for (int x = -6; x < width + 6; x++) {
            bool top = dark(x, y);
            bool bottom = dark(x, y + 1);
            if (top && bottom) {
                line += "█";
            } else if (top) {
                line += "▀";
            } else if (bottom) {
                line += "▄";
            } else {
                line += " ";
            }
        }
        std::cout << line << "\n";
    }
    std::cout << "\x1b[0m"; // reset - don't leak black-on-white into whatever prints next
}

uint32_t crc32Of(const uint8_t* data, size_t len) {
    static uint32_t table[256];
    static bool tableReady = false;
    if (!tableReady) {
        for (uint32_t n = 0; n < 256; n++) {
            uint32_t c = n;
            for (int k = 0; k < 8; k++) c = (c & 1) ? (0xEDB88320u ^ (c >> 1)) : (c >> 1);
            table[n] = c;
        }
        tableReady = true;
    }
    uint32_t crc = 0xFFFFFFFFu;
    for (size_t i = 0; i < len; i++) crc = table[(crc ^ data[i]) & 0xFF] ^ (crc >> 8);
    return crc ^ 0xFFFFFFFFu;
}

void putBE32(std::vector<uint8_t>& out, uint32_t v) {
    out.push_back(static_cast<uint8_t>(v >> 24));
    out.push_back(static_cast<uint8_t>(v >> 16));
    out.push_back(static_cast<uint8_t>(v >> 8));
    out.push_back(static_cast<uint8_t>(v));
}

void writePngChunk(std::vector<uint8_t>& out, const char* type, const std::vector<uint8_t>& data) {
    putBE32(out, static_cast<uint32_t>(data.size()));
    std::vector<uint8_t> typeAndData(type, type + 4);
    typeAndData.insert(typeAndData.end(), data.begin(), data.end());
    out.insert(out.end(), typeAndData.begin(), typeAndData.end());
    putBE32(out, crc32Of(typeAndData.data(), typeAndData.size()));
}

// Wraps `data` as a minimal, valid zlib stream using deflate's "stored"
// (uncompressed) block type - a legal subset of the deflate spec that
// needs no real compression, so PNG's IDAT payload (which must be
// zlib-compressed) can be produced without a zlib/libpng dependency. Fine
// for a small 1-bit QR bitmap.
std::vector<uint8_t> zlibStoreUncompressed(const std::vector<uint8_t>& data) {
    std::vector<uint8_t> out{0x78, 0x01}; // zlib header: deflate, no/low compression
    size_t offset = 0;
    do {
        size_t chunkLen = std::min<size_t>(65535, data.size() - offset);
        bool isLast = (offset + chunkLen) >= data.size();
        out.push_back(isLast ? 1 : 0); // BFINAL | BTYPE=00 (stored), already byte-aligned
        auto len = static_cast<uint16_t>(chunkLen);
        auto nlen = static_cast<uint16_t>(~len);
        out.push_back(static_cast<uint8_t>(len));
        out.push_back(static_cast<uint8_t>(len >> 8));
        out.push_back(static_cast<uint8_t>(nlen));
        out.push_back(static_cast<uint8_t>(nlen >> 8));
        out.insert(out.end(), data.begin() + static_cast<long>(offset), data.begin() + static_cast<long>(offset + chunkLen));
        offset += chunkLen;
    } while (offset < data.size());

    uint32_t a = 1, b = 0;
    for (uint8_t byte : data) {
        a = (a + byte) % 65521;
        b = (b + a) % 65521;
    }
    putBE32(out, (b << 16) | a);
    return out;
}

// 1-bit grayscale PNG, `scale` pixels per QR module plus a 4-module quiet
// zone - a real image sidesteps every terminal-rendering quirk that can
// make printQrAscii()'s output fail to scan (font metrics, line-wrapping,
// color inversion): open it in any image viewer (VS Code can preview a
// PNG directly) and scan it off the screen instead.
void writeQrPng(const QRcode* qr, int scale, const std::string& path) {
    constexpr int kQuietModules = 4;
    int modules = qr->width;
    int size = (modules + kQuietModules * 2) * scale;
    int rowBytes = (size + 7) / 8;

    std::vector<uint8_t> raw;
    raw.reserve(static_cast<size_t>(size) * (1 + rowBytes));
    for (int y = 0; y < size; y++) {
        raw.push_back(0); // filter type: None
        std::vector<uint8_t> row(static_cast<size_t>(rowBytes), 0xFF); // all white (bit=1) by default
        int qy = y / scale - kQuietModules;
        for (int x = 0; x < size; x++) {
            int qx = x / scale - kQuietModules;
            bool dark = qx >= 0 && qx < modules && qy >= 0 && qy < modules &&
                       (qr->data[qy * modules + qx] & 1) != 0;
            if (dark) row[static_cast<size_t>(x / 8)] &= static_cast<uint8_t>(~(0x80 >> (x % 8)));
        }
        raw.insert(raw.end(), row.begin(), row.end());
    }

    std::vector<uint8_t> png{0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A};
    std::vector<uint8_t> ihdr;
    putBE32(ihdr, static_cast<uint32_t>(size));
    putBE32(ihdr, static_cast<uint32_t>(size));
    ihdr.push_back(1); // bit depth
    ihdr.push_back(0); // color type: grayscale
    ihdr.push_back(0); // compression method
    ihdr.push_back(0); // filter method
    ihdr.push_back(0); // interlace method
    writePngChunk(png, "IHDR", ihdr);
    writePngChunk(png, "IDAT", zlibStoreUncompressed(raw));
    writePngChunk(png, "IEND", {});

    std::ofstream f(path, std::ios::binary);
    if (!f) throw std::runtime_error("cannot write " + path);
    f.write(reinterpret_cast<const char*>(png.data()), static_cast<std::streamsize>(png.size()));
}

constexpr const char* kQrPngPath = "/tmp/signal2sip-link-qr.png";

void renderQr(const std::string& text) {
    QRcode* qr = QRcode_encodeString(text.c_str(), 0, QR_ECLEVEL_L, QR_MODE_8, 1);
    if (!qr) {
        std::cout << "[link] (failed to render QR - use the URL above)\n";
        return;
    }
    printQrAscii(qr);
    try {
        writeQrPng(qr, 8, kQrPngPath);
        std::cout << "[link] if the terminal QR above doesn't scan, a PNG was also written to " << kQrPngPath
                  << " on this machine. If this is a headless/remote box, fetch it to view locally, e.g.:\n";
        std::cout << "  scp <user>@<this-host>:" << kQrPngPath << " .\n";
        std::cout << "then open the downloaded file and scan that instead.\n";
    } catch (const std::exception& e) {
        std::cout << "[link] (could not also write " << kQrPngPath << ": " << e.what() << ")\n";
    }
    QRcode_free(qr);
}

} // namespace

namespace {
constexpr uint8_t kEnvironmentProd = 1;
constexpr uint8_t kBuildVariantProduction = 0;
constexpr const char* kUserAgent = "signal2sip";

SignalMutPointerConnectionManager makeConnectionManager() {
    // signal_connection_manager_new rejects a null remote_config map -
    // see AuthSocket.cpp's identical helper for the full explanation.
    SignalMutPointerBridgedStringMap remoteConfig{};
    checkError(signal_bridged_string_map_new(&remoteConfig, /*initial_capacity=*/0));
    SignalMutPointerConnectionManager manager{};
    checkError(signal_connection_manager_new(&manager, kEnvironmentProd,
                                              reinterpret_cast<const int8_t*>(kUserAgent), remoteConfig,
                                              kBuildVariantProduction));
    checkError(signal_bridged_string_map_destroy(remoteConfig));
    return manager;
}
} // namespace

struct ProvisioningClient::Impl {
    std::string serverHost;   // unused - kEnvironmentProd is hardcoded in makeConnectionManager()
    KeyPair ourKeyPair;

    SignalMutPointerTokioAsyncContext asyncContext{};
    SignalMutPointerConnectionManager connectionManager{};
    SignalMutPointerProvisioningChatConnection chat{};

    std::mutex resultMutex;
    std::condition_variable resultCv;
    bool gotAddress = false;
    std::optional<ProvisionMessageResult> result;
    std::optional<std::string> failure;

    SignalFfiProvisioningListenerStruct listenerStruct{};

    Impl() {
        checkError(signal_tokio_async_context_new(&asyncContext));
        connectionManager = makeConnectionManager();
        ourKeyPair = generateKeyPair();

        listenerStruct.ctx = this;
        listenerStruct.received_address = &Impl::onReceivedAddress;
        listenerStruct.received_envelope = &Impl::onReceivedEnvelope;
        listenerStruct.connection_interrupted = &Impl::onConnectionInterrupted;
        listenerStruct.destroy = [](void*) {};
    }

    ~Impl() {
        if (chat.raw) {
            struct State {
                std::mutex mutex;
                std::condition_variable cv;
                bool done = false;
            } state;
            SignalCPromisebool promise{};
            promise.context = &state;
            promise.complete = [](SignalFfiError* error, SignalType_ConstPointer_bool, const void* context) {
                auto* st = const_cast<State*>(static_cast<const State*>(context));
                if (error) signal_error_free(error);
                {
                    std::lock_guard<std::mutex> lock(st->mutex);
                    st->done = true;
                }
                st->cv.notify_one();
            };
            SignalFfiError* callErr = signal_provisioning_chat_connection_disconnect(
                &promise, SignalConstPointerTokioAsyncContext{asyncContext.raw}, SignalConstPointerProvisioningChatConnection{chat.raw});
            if (callErr) {
                signal_error_free(callErr);
            } else {
                std::unique_lock<std::mutex> lock(state.mutex);
                state.cv.wait(lock, [&] { return state.done; });
            }
            SignalFfiError* destroyErr = signal_provisioning_chat_connection_destroy(chat);
            if (destroyErr) signal_error_free(destroyErr);
        }
        SignalFfiError* err = signal_connection_manager_destroy(connectionManager);
        if (err) signal_error_free(err);
        err = signal_tokio_async_context_destroy(asyncContext);
        if (err) signal_error_free(err);
    }

    void printLinkUrl(const std::string& address) {
        std::string url =
            "sgnl://linkdevice?uuid=" + urlEncode(address) + "&pub_key=" + urlEncode(base64NoPadding(ourKeyPair.publicKey));
        std::cout << "[link] scan this with the Signal app on your phone (Settings > Linked devices > Link a "
                     "device):\n";
        std::cout << url << "\n";
        renderQr(url);
    }

    // The FFI already unwraps the old WebSocketRequestMessage(verb=PUT,
    // path=/v1/address) framing and the ProvisioningAddress protobuf for
    // us - this callback just gets the plain address string directly, no
    // manual parsing needed anymore (unlike the old lws implementation's
    // handleIncomingMessage()).
    static int32_t onReceivedAddress(void* ctx, SignalCStringPtr address, SignalMutPointerServerMessageAck ack) {
        auto* self = static_cast<Impl*>(ctx);
        std::string addressStr(reinterpret_cast<const char*>(address));
        signal_free_string(address);

        SignalFfiError* ackErr = signal_server_message_ack_send(SignalConstPointerServerMessageAck{ack.raw});
        if (ackErr) signal_error_free(ackErr);
        SignalFfiError* destroyErr = signal_server_message_ack_destroy(ack);
        if (destroyErr) signal_error_free(destroyErr);

        {
            std::lock_guard<std::mutex> lock(self->resultMutex);
            self->gotAddress = true;
        }
        self->resultCv.notify_all();
        self->printLinkUrl(addressStr);
        return 0;
    }

    // Unlike the address, the envelope's crypto is genuinely ours to
    // handle (ECDH against our own ephemeral keypair, see
    // ProvisioningCipher.h) - the FFI has no reason to know our key, so
    // it just hands back the raw ProvisionEnvelope protobuf bytes exactly
    // like the old implementation received, and everything from here
    // down is unchanged from before.
    static int32_t onReceivedEnvelope(void* ctx, SignalOwnedBuffer envelope, SignalMutPointerServerMessageAck ack) {
        auto* self = static_cast<Impl*>(ctx);
        Bytes envelopeBytes = takeOwned(envelope);

        SignalFfiError* ackErr = signal_server_message_ack_send(SignalConstPointerServerMessageAck{ack.raw});
        if (ackErr) signal_error_free(ackErr);
        SignalFfiError* destroyErr = signal_server_message_ack_destroy(ack);
        if (destroyErr) signal_error_free(destroyErr);

        try {
            signalservice::ProvisionEnvelope pe;
            if (!pe.ParseFromArray(envelopeBytes.data(), static_cast<int>(envelopeBytes.size()))) {
                throw std::runtime_error("bad ProvisionEnvelope");
            }
            Bytes publicKey(pe.publickey().begin(), pe.publickey().end());
            Bytes body(pe.body().begin(), pe.body().end());
            Bytes plaintext = decryptProvisionEnvelope(self->ourKeyPair.privateKey, publicKey, body);

            signalservice::ProvisionMessage pm;
            if (!pm.ParseFromArray(plaintext.data(), static_cast<int>(plaintext.size()))) {
                throw std::runtime_error("bad ProvisionMessage");
            }

            ProvisionMessageResult r;
            r.e164 = pm.number();
            r.aci = pm.aci();
            r.pni = pm.pni();
            r.aciIdentityKeyPublic.assign(pm.aciidentitykeypublic().begin(), pm.aciidentitykeypublic().end());
            r.aciIdentityKeyPrivate.assign(pm.aciidentitykeyprivate().begin(), pm.aciidentitykeyprivate().end());
            r.pniIdentityKeyPublic.assign(pm.pniidentitykeypublic().begin(), pm.pniidentitykeypublic().end());
            r.pniIdentityKeyPrivate.assign(pm.pniidentitykeyprivate().begin(), pm.pniidentitykeyprivate().end());
            r.provisioningCode = pm.provisioningcode();
            if (pm.has_profilekey()) r.profileKey = Bytes(pm.profilekey().begin(), pm.profilekey().end());
            if (pm.has_accountentropypool()) r.accountEntropyPool = pm.accountentropypool();
            if (pm.has_mediarootbackupkey()) {
                r.mediaRootBackupKey = Bytes(pm.mediarootbackupkey().begin(), pm.mediarootbackupkey().end());
            }

            std::lock_guard<std::mutex> lock(self->resultMutex);
            self->result = std::move(r);
        } catch (const std::exception& e) {
            std::lock_guard<std::mutex> lock(self->resultMutex);
            self->failure = e.what();
        }
        self->resultCv.notify_all();
        return 0;
    }

    static int32_t onConnectionInterrupted(void* ctx, SignalFfiError* error) {
        auto* self = static_cast<Impl*>(ctx);
        if (error) signal_error_free(error);
        std::lock_guard<std::mutex> lock(self->resultMutex);
        if (!self->result && !self->failure) self->failure = "socket closed before linking completed";
        self->resultCv.notify_all();
        return 0;
    }
};

ProvisioningClient::ProvisioningClient(std::string serverHost) : impl_(new Impl()) {
    impl_->serverHost = std::move(serverHost);
}

ProvisioningClient::~ProvisioningClient() { delete impl_; }

ProvisionMessageResult ProvisioningClient::waitForProvisionMessage() {
    struct ConnectState {
        std::mutex mutex;
        std::condition_variable cv;
        bool done = false;
        bool abandoned = false;
        SignalFfiError* error = nullptr;
        SignalMutPointerProvisioningChatConnection result{};
    };
    auto* state = new ConnectState();

    SignalCPromiseMutPointerProvisioningChatConnection promise{};
    promise.context = state;
    promise.complete = [](SignalFfiError* error, SignalType_ConstPointer_SignalMutPointerProvisioningChatConnection result,
                           const void* context) {
        auto* st = const_cast<ConnectState*>(static_cast<const ConnectState*>(context));
        bool selfCleanup = false;
        {
            std::lock_guard<std::mutex> lock(st->mutex);
            if (st->abandoned) {
                selfCleanup = true;
            } else {
                st->error = error;
                if (!error && result) st->result = *result;
                st->done = true;
            }
        }
        if (selfCleanup) {
            if (error) signal_error_free(error);
            // Nobody's waiting anymore (waitForProvisionMessage() already
            // gave up) - just let the connection get dropped rather than
            // trying to tear it down from here; this is a one-shot CLI
            // tool, not a long-lived service that needs to avoid a
            // second live session the way AuthSocket's reconnect() does.
            delete st;
        } else {
            st->cv.notify_all();
        }
    };

    SignalFfiError* callErr = signal_provisioning_chat_connection_connect(
        &promise, SignalConstPointerTokioAsyncContext{impl_->asyncContext.raw}, SignalConstPointerConnectionManager{impl_->connectionManager.raw});
    if (callErr) {
        delete state;
        checkError(callErr);
    }

    bool ok;
    {
        std::unique_lock<std::mutex> lock(state->mutex);
        ok = state->cv.wait_for(lock, std::chrono::seconds(15), [&] { return state->done; });
        if (!ok) state->abandoned = true;
    }
    if (!ok) throw std::runtime_error("timed out connecting to provisioning websocket");

    SignalFfiError* connectErrPtr = state->error;
    SignalMutPointerProvisioningChatConnection connectResult = state->result;
    delete state;
    checkError(connectErrPtr);

    impl_->chat = connectResult;
    checkError(signal_provisioning_chat_connection_init_listener(
        SignalConstPointerProvisioningChatConnection{impl_->chat.raw},
        SignalConstPointerFfiProvisioningListenerStruct{&impl_->listenerStruct}));

    // LIFESPAN_MS/ADDRESS_TIMEOUT_MS from link-new-device.js, both measured
    // from the moment the socket is actually open (same as its ws.on('open')
    // handler).
    auto opened = std::chrono::steady_clock::now();
    auto addressDeadline = opened + std::chrono::seconds(10);
    auto lifespanDeadline = opened + std::chrono::seconds(90);

    std::unique_lock<std::mutex> lock(impl_->resultMutex);
    bool gotAddressInTime = impl_->resultCv.wait_until(
        lock, addressDeadline, [this] { return impl_->gotAddress || impl_->result || impl_->failure; });
    if (!gotAddressInTime) throw std::runtime_error("no address received within 10s");
    if (impl_->failure) throw std::runtime_error(*impl_->failure);

    bool done = impl_->resultCv.wait_until(lock, lifespanDeadline,
                                           [this] { return impl_->result.has_value() || impl_->failure.has_value(); });
    if (!done) throw std::runtime_error("lifespan expired with no completed link (90s)");
    if (impl_->failure) throw std::runtime_error(*impl_->failure);
    return *impl_->result;
}

} // namespace signal2sip
