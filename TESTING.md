# Tests

These aren't a conventional unit-test suite (no test runner, no
assertions-stop-the-build) - most are standalone verification binaries
built by the normal `cmake --build build`, each proving one specific
milestone/bugfix end-to-end. Run whichever one you need directly from
`build/`.

**Several of these are "live"**: they hit the real `chat.signal.org`
production servers or a real SIP trunk using real account credentials,
not a sandbox. Only run those against test accounts/trunks you're willing
to actually mutate (register prekeys, change discoverability, send real
messages, place real calls) - see each test's own row below.

## Local, offline unit tests

No arguments, no network, no real account needed - safe to run anytime.

| Binary | What it proves |
|---|---|
| `storage_test` | SQLCipher link + schema work end-to-end, and the resulting `.db` file is genuinely encrypted (not plain SQLite readable without the key). |
| `padding_test` | Message padding/unpadding round-trips correctly at the length-class boundaries. |
| `decryption_error_message_test` | `buildDecryptionErrorMessage()` (session-recovery) round-trips and its ratchet key matches the real sender ratchet key, for both a fresh PreKey message and an already-acknowledged Whisper message. |
| `ringrtc_two_party_test` | Two independent OS processes, each with one RingRTC `CallManager`, reach `Connected` over a synthetic (non-network) signaling relay and a tone pushed into one side's raw-PCM mic comes out the other side's playout. Two *processes* specifically because RingRTC's audio-transport registration is a single process-wide global - see the file's own comment. |
| `two_call_managers_audio_isolation_test` | Two independent call pairs (4 `CallManager`s, 4 raw-PCM audio device modules) run concurrently in **one** process without their audio crossing over - the fix that makes the real multi-account daemon's single-process design possible. |

## Live tests against real Signal servers

Each needs real credentials for an existing account (a JSON dump or the
shared SQLCipher DB) - use test accounts, not production ones.

| Binary | Usage | What it does |
|---|---|---|
| `authsocket_test` | `authsocket_test <username> <password>` | Connects to the real `chat.signal.org` websocket and issues one harmless authenticated `GET /v1/keepalive` - proves TLS (pinned by libsignal-net-chat's own `Environment::Prod`), Basic Auth, and WebSocketMessage framing all work. |
| `signal_roundtrip_test` | `signal_roundtrip_test <sender-account.json> <sender-sessions.json> <destination-service-id> "<text>"` | Fetches a real prekey bundle, establishes a session, encrypts a real Content message, and sends it via `PUT /v1/messages` - a real message is delivered to the destination. |
| `refresh_prekeys_test` | `refresh_prekeys_test <account.json>` | Generates a fresh signed EC prekey + last-resort Kyber prekey and uploads via `PUT /v2/keys`. Safe/idempotent - real clients do this periodically anyway. |
| `cdsi_lookup_test` | `cdsi_lookup_test <account.json> <e164> [e164...]` | Resolves one or more phone numbers to their real ACI/PNI via production Contact Discovery Service. |
| `resolve_outgoing_target_test` | `resolve_outgoing_target_test <db_path> <db_key> <account_name> <target> [ttl_sec]` | Exercises `ContactResolver`'s cache+CDSI resolution path (same one the daemon uses for outgoing calls) without placing a call. Run twice against the same target to see the second run hit cache instead of a real CDSI call. |
| `storage_sync_loop_test` | `storage_sync_loop_test <signal2sip.conf path> <account name> [iterations]` | Calls `fetchStorageContacts()` N times (default 20) against a real, already-linked account and reports pass/fail + contact count per iteration - regression check for two past Storage Service decrypt bugs. |
| `toggle_discoverability_test` | `toggle_discoverability_test <db_path> <db_key> <account_name> <true\|false>` | Forces a real `PUT /v1/accounts/attributes/` change to `discoverableByPhoneNumber` on an existing account, to kick Signal's CDS directory-sync pipeline. Debug tool, not routine - mutates real account state. |

## Live tests against a real SIP trunk

Need a reachable SIP server/extension (e.g. a FreePBX test box) - these
place or receive real calls.

| Binary | Usage | What it does |
|---|---|---|
| `sip_bridge_codec_test` | `sip_bridge_codec_test <sip_host> <sip_extension> <sip_password> <dest>` | Reproduces `signal2sip-daemon`'s exact shared-UDP-transport SIP setup (`ensureSharedEndpoint()`/`setupAccount()`) and places one outbound call, with no Signal/RingRTC involved - for iterating on SIP-side codec/transport bugs without needing a real Signal call each time. |
| `pjsip_ringrtc_echo_test` | `pjsip_ringrtc_echo_test <sip_host> <extension> <password>` | Two processes: one plain RingRTC peer pushing a 440Hz tone and measuring its own playout RMS, the other bridged via `RingRtcSipBridge` to a real SIP call dialing `*43` (echo test) on the given host. If the tone comes back, audio genuinely crossed the RingRTC<->SIP bridge and back. |

## Helper (not a test)

| Binary | Usage | What it does |
|---|---|---|
| `dump_account_json_test` | `dump_account_json_test <db_path> <db_key> <account_name>` | Dumps an existing account's `aci`/`password`/`e164`/`deviceId` as JSON, in the exact shape `refresh_prekeys_test`/`cdsi_lookup_test`/`signal_roundtrip_test` expect on their command line - so those can be pointed at a real account already in the shared DB without hand-copying credentials. |

## Building

All of the above build as part of the normal top-level build:

```
cmake -B build && cmake --build build -j
```

Binaries land directly in `build/` (e.g. `build/storage_test`). To build
just one: `cmake --build build --target storage_test`.
