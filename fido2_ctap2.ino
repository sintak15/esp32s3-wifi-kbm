// FIDO2 / CTAP2 (WebAuthn) over USB HID for ESP32-S3 (TinyUSB).
//
// This file is compiled as part of the same Arduino sketch translation unit.
// It relies on helpers and globals defined in `esp32s3-wifi-kbm.ino` (LED, BOOT button, NVS cred store).
//
// Supported:
// - authenticatorGetInfo (0x04)
// - authenticatorMakeCredential (0x01) with ES256 (-7), user presence (BOOT)
// - authenticatorGetAssertion (0x02) with allowList, user presence (BOOT)
// - authenticatorReset (0x07), user presence (BOOT)
//
// Not supported:
// - Full CTAP2.1 PIN/UV feature set (this build supports a minimal ClientPIN entry flow)
// - Resident/discoverable credentials (rk)
// - CTAP1/U2F (CTAPHID_MSG)
// - Extensions and enterprise attestation

#ifndef FIDO_DEBUG
#define FIDO_DEBUG 0
#endif

#ifndef FIDO_FORCE_MAKECRED_EARLY_ERROR
#define FIDO_FORCE_MAKECRED_EARLY_ERROR 0
#endif

#ifndef FIDO_FORCE_MAKECRED_PARSE_ONLY_ERROR
#define FIDO_FORCE_MAKECRED_PARSE_ONLY_ERROR 0
#endif

#ifndef FIDO_FORCE_DIRECT_MAKECRED_ERROR
#define FIDO_FORCE_DIRECT_MAKECRED_ERROR 0
#endif

// Debug stage checkpoints for makeCredential:
// 0 = normal flow
// 1 = return error after successful parse
// 2 = return error after key generation
// 3 = return error after credential store write
// 4 = return error after attestation/signing
#ifndef FIDO_MAKECRED_TEST_STAGE
#define FIDO_MAKECRED_TEST_STAGE 0
#endif

// Temporary troubleshooting switch:
// - 1: use a fixed P-256 test keypair (private = 1, public = generator point)
// - 0: generate a random keypair with mbedTLS
#ifndef FIDO_USE_STATIC_TEST_KEYPAIR
#define FIDO_USE_STATIC_TEST_KEYPAIR 0
#endif

// Writing credentials/sign counters to NVS can stall long enough to destabilize
// CTAP HID on some ESP32-S3 setups. Keep FIDO state in RAM for reliability.
#ifndef FIDO_DISABLE_PERSISTENCE
#define FIDO_DISABLE_PERSISTENCE 1
#endif

#ifndef FIDO_STABILITY_SKIP_CRED_DESCRIPTOR_PARSE
#define FIDO_STABILITY_SKIP_CRED_DESCRIPTOR_PARSE 1
#endif

#ifndef FIDO_STABILITY_MINIMAL_MAKECRED_PARSE
#define FIDO_STABILITY_MINIMAL_MAKECRED_PARSE 1
#endif

#ifndef USB_ENABLE_KBM_HID
#define USB_ENABLE_KBM_HID 0
#endif

// Development toggle:
// - 1: require PIN for gated operations
// - 0: disable PIN gate for easier testing
#ifndef FIDO_REQUIRE_PIN
#define FIDO_REQUIRE_PIN 0 // Disabled as per user request
#endif

static constexpr size_t   FIDO_HID_PACKET_SIZE = 64;
// In composite keyboard/mouse mode, keep FIDO on its own report ID.
// In FIDO-only mode, use report ID 0 (no report ID).
#if USB_ENABLE_KBM_HID
static constexpr uint8_t  FIDO_HID_REPORT_ID = HID_REPORT_ID_GAMEPAD;
#else
static constexpr uint8_t  FIDO_HID_REPORT_ID = HID_REPORT_ID_NONE;
#endif
static constexpr uint32_t CTAPHID_BROADCAST_CID = 0xFFFFFFFFUL;

static constexpr uint8_t CTAPHID_CMD_PING = 0x01;
static constexpr uint8_t CTAPHID_CMD_MSG = 0x03;
static constexpr uint8_t CTAPHID_CMD_INIT = 0x06;
static constexpr uint8_t CTAPHID_CMD_WINK = 0x08;
static constexpr uint8_t CTAPHID_CMD_CBOR = 0x10;
static constexpr uint8_t CTAPHID_CMD_CANCEL = 0x11;
static constexpr uint8_t CTAPHID_CMD_KEEPALIVE = 0x3B;
static constexpr uint8_t CTAPHID_CMD_ERROR = 0x3F;

static constexpr uint8_t CTAPHID_KEEPALIVE_STATUS_PROCESSING = 0x01;
static constexpr uint8_t CTAPHID_KEEPALIVE_STATUS_UP_NEEDED = 0x02;

static constexpr uint8_t CTAPHID_ERR_INVALID_CMD = 0x01;
static constexpr uint8_t CTAPHID_ERR_INVALID_LEN = 0x03;
static constexpr uint8_t CTAPHID_ERR_INVALID_SEQ = 0x04;
static constexpr uint8_t CTAPHID_ERR_CHANNEL_BUSY = 0x06;
static constexpr uint8_t CTAPHID_ERR_INVALID_CHANNEL = 0x0B;

static constexpr uint8_t CTAPHID_CAP_WINK = 0x01;
static constexpr uint8_t CTAPHID_CAP_CBOR = 0x04;
static constexpr uint8_t CTAPHID_CAP_NMSG = 0x08;

static constexpr uint8_t CTAP2_OK = 0x00;
static constexpr uint8_t CTAP2_ERR_INVALID_COMMAND = 0x01;
static constexpr uint8_t CTAP2_ERR_INVALID_PARAMETER = 0x02;
static constexpr uint8_t CTAP2_ERR_INVALID_LENGTH = 0x03;
static constexpr uint8_t CTAP2_ERR_TIMEOUT = 0x05;
static constexpr uint8_t CTAP2_ERR_CHANNEL_BUSY = 0x06;
static constexpr uint8_t CTAP2_ERR_CBOR_PARSING = 0x10;
static constexpr uint8_t CTAP2_ERR_CBOR_UNEXPECTED_TYPE = 0x11;
static constexpr uint8_t CTAP2_ERR_INVALID_CBOR = 0x12;
static constexpr uint8_t CTAP2_ERR_MISSING_PARAMETER = 0x14;
static constexpr uint8_t CTAP2_ERR_LIMIT_EXCEEDED = 0x15;
static constexpr uint8_t CTAP2_ERR_CREDENTIAL_EXCLUDED = 0x19;
static constexpr uint8_t CTAP2_ERR_PROCESSING = 0x21;
static constexpr uint8_t CTAP2_ERR_INVALID_CREDENTIAL = 0x22;
static constexpr uint8_t CTAP2_ERR_UNSUPPORTED_ALGORITHM = 0x26;
static constexpr uint8_t CTAP2_ERR_KEY_STORE_FULL = 0x28;
static constexpr uint8_t CTAP2_ERR_UNSUPPORTED_OPTION = 0x2B;
static constexpr uint8_t CTAP2_ERR_KEEPALIVE_CANCEL = 0x2D;
static constexpr uint8_t CTAP2_ERR_NO_CREDENTIALS = 0x2E;
static constexpr uint8_t CTAP2_ERR_USER_ACTION_TIMEOUT = 0x2F;
static constexpr uint8_t CTAP2_ERR_NOT_ALLOWED = 0x30;
static constexpr uint8_t CTAP2_ERR_PIN_INVALID = 0x31;
static constexpr uint8_t CTAP2_ERR_PIN_BLOCKED = 0x32;
static constexpr uint8_t CTAP2_ERR_PIN_AUTH_INVALID = 0x33;
static constexpr uint8_t CTAP2_ERR_PIN_NOT_SET = 0x35;
static constexpr uint8_t CTAP2_ERR_PIN_REQUIRED = 0x36;
static constexpr uint8_t CTAP2_ERR_REQUEST_TOO_LARGE = 0x39;
static constexpr uint8_t CTAP1_ERR_OTHER = 0x7F;

static constexpr uint8_t CTAP_CMD_MAKE_CREDENTIAL = 0x01;
static constexpr uint8_t CTAP_CMD_GET_ASSERTION = 0x02;
static constexpr uint8_t CTAP_CMD_GET_INFO = 0x04;
static constexpr uint8_t CTAP_CMD_CLIENT_PIN = 0x06;
static constexpr uint8_t CTAP_CMD_RESET = 0x07;
static constexpr uint8_t CTAP_CMD_GET_NEXT_ASSERTION = 0x08;
static constexpr uint8_t CTAP_CMD_BIO_ENROLLMENT = 0x09;
static constexpr uint8_t CTAP_CMD_CREDENTIAL_MANAGEMENT = 0x0A;
static constexpr uint8_t CTAP_CMD_SELECTION = 0x0B;
static constexpr uint8_t CTAP_CMD_LARGE_BLOBS = 0x0C;
static constexpr uint8_t CTAP_CMD_CONFIG = 0x0D;

static constexpr uint8_t CTAP_CLIENT_PIN_GET_RETRIES = 0x01;
static constexpr uint8_t CTAP_CLIENT_PIN_GET_KEY_AGREEMENT = 0x02;
static constexpr uint8_t CTAP_CLIENT_PIN_SET_PIN = 0x03;
static constexpr uint8_t CTAP_CLIENT_PIN_CHANGE_PIN = 0x04;
static constexpr uint8_t CTAP_CLIENT_PIN_GET_PIN_TOKEN = 0x05;
static constexpr uint8_t CTAP_CLIENT_PIN_GET_UV_RETRIES = 0x07;
static constexpr uint8_t CTAP_CLIENT_PIN_GET_PIN_UV_AUTH_TOKEN_USING_PIN_WITH_PERMISSIONS = 0x09;
static constexpr uint8_t CTAP_PIN_UV_AUTH_PROTOCOL_1 = 0x01;
static constexpr size_t CTAP_PIN_HASH_ENC_LEN = 16;
static constexpr size_t CTAP_PIN_UV_AUTH_PARAM_LEN = 16;
static constexpr size_t CTAP_PIN_TOKEN_LEN = 32;

static constexpr size_t FIDO_MAX_PAYLOAD = 1024;
static constexpr uint32_t CTAP_UP_TIMEOUT_MS = 30 * 1000;
static constexpr uint32_t CTAP_KEEPALIVE_EVERY_MS = 100;

// Development toggle:
// - 1: require BOOT button for user presence (stronger local-presence semantics)
// - 0: auto-approve UP after a short delay (easier interoperability testing)
#ifndef FIDO_REQUIRE_BOOT_BUTTON_FOR_UP
#define FIDO_REQUIRE_BOOT_BUTTON_FOR_UP 0 // Disabled as per user request
#endif

#if FIDO_REQUIRE_BOOT_BUTTON_FOR_UP
static constexpr uint32_t CTAP_UP_MIN_HOLD_MS = 250;
#else
static constexpr uint32_t CTAP_UP_AUTO_APPROVE_MS = 250;
#endif

static constexpr uint8_t CTAP_CRED_SECRET_VER = 1;
static constexpr uint8_t CTAP_CRED_FLAG_RK = 0x01;

static const uint8_t CTAP_AAGUID[16] = {0x7a, 0x85, 0x2a, 0x5d, 0x77, 0x6a, 0x4a, 0x12,
                                        0x86, 0x1d, 0x0b, 0x4f, 0x2b, 0x67, 0x0c, 0x8e};

static uint32_t fidoAssignedCid = 0;
static uint32_t fidoSignCount = 0;
static bool fidoAwaitingUserPresence = false;

// Shared security policy hooks implemented in esp32s3-wifi-kbm.ino.
bool security_pin_configured();
bool security_pin_unlocked_now();
bool security_fido_pin_hash16_get(uint8_t outHash16[16]);

struct FidoDiagState {
  uint32_t lastCid = 0;
  uint8_t lastHidCmd = 0;
  uint8_t lastCtapCmd = 0;
  uint8_t lastCtapStatus = 0;
  uint8_t lastHidError = 0;
  uint8_t lastReportIdSeen = 0;
  uint8_t lastReportIdDropped = 0;
  uint16_t lastReportLenSeen = 0;
  uint16_t lastReportLenDropped = 0;
  uint32_t totalCtapRequests = 0;
  uint32_t totalCtapOk = 0;
  uint32_t totalCtapErr = 0;
  uint32_t totalPinGateBlocks = 0;
  uint32_t totalUpSatisfied = 0;
  uint32_t totalHidOutCallbacks = 0;
  uint32_t totalHidSetFeatureCallbacks = 0;
  uint32_t totalHidGetFeatureCallbacks = 0;
  uint32_t totalUnexpectedReportId = 0;
  uint32_t totalDroppedBadLen = 0;
  uint32_t totalNormalizedPackets = 0;
  uint32_t lastRxMs = 0;
  uint32_t lastTxMs = 0;
};

static FidoDiagState fidoDiag;

struct FidoClientPinState {
  uint8_t keyAgreementPriv[32] = {0};
  uint8_t keyAgreementX[32] = {0};
  uint8_t keyAgreementY[32] = {0};
  bool keyAgreementReady = false;
  uint8_t pinUvAuthToken[CTAP_PIN_TOKEN_LEN] = {0};
  uint8_t pinRetries = 8;
};

static FidoClientPinState fidoClientPin;

static bool fido_client_pin_available();
static bool fido_client_pin_hash_ready();

static const char* ctaphid_cmd_name(const uint8_t cmd) {
  switch (cmd) {
    case CTAPHID_CMD_PING: return "PING";
    case CTAPHID_CMD_MSG: return "MSG";
    case CTAPHID_CMD_INIT: return "INIT";
    case CTAPHID_CMD_WINK: return "WINK";
    case CTAPHID_CMD_CBOR: return "CBOR";
    case CTAPHID_CMD_CANCEL: return "CANCEL";
    case CTAPHID_CMD_KEEPALIVE: return "KEEPALIVE";
    case CTAPHID_CMD_ERROR: return "ERROR";
    default: return "UNKNOWN";
  }
}

static const char* ctaphid_err_name(const uint8_t err) {
  switch (err) {
    case CTAPHID_ERR_INVALID_CMD: return "INVALID_CMD";
    case CTAPHID_ERR_INVALID_LEN: return "INVALID_LEN";
    case CTAPHID_ERR_INVALID_SEQ: return "INVALID_SEQ";
    case CTAPHID_ERR_CHANNEL_BUSY: return "CHANNEL_BUSY";
    case CTAPHID_ERR_INVALID_CHANNEL: return "INVALID_CHANNEL";
    default: return "ERR_UNKNOWN";
  }
}

static const char* ctap_cmd_name(const uint8_t cmd) {
  switch (cmd) {
    case CTAP_CMD_MAKE_CREDENTIAL: return "authenticatorMakeCredential";
    case CTAP_CMD_GET_ASSERTION: return "authenticatorGetAssertion";
    case CTAP_CMD_GET_INFO: return "authenticatorGetInfo";
    case CTAP_CMD_CLIENT_PIN: return "authenticatorClientPIN";
    case CTAP_CMD_RESET: return "authenticatorReset";
    case CTAP_CMD_GET_NEXT_ASSERTION: return "authenticatorGetNextAssertion";
    case CTAP_CMD_BIO_ENROLLMENT: return "authenticatorBioEnrollment";
    case CTAP_CMD_CREDENTIAL_MANAGEMENT: return "authenticatorCredentialManagement";
    case CTAP_CMD_SELECTION: return "authenticatorSelection";
    case CTAP_CMD_LARGE_BLOBS: return "authenticatorLargeBlobs";
    case CTAP_CMD_CONFIG: return "authenticatorConfig";
    default: return "ctapUnknown";
  }
}

static const char* ctap2_status_name(const uint8_t st) {
  switch (st) {
    case CTAP2_OK: return "CTAP2_OK";
    case CTAP2_ERR_INVALID_COMMAND: return "CTAP2_ERR_INVALID_COMMAND";
    case CTAP2_ERR_INVALID_PARAMETER: return "CTAP2_ERR_INVALID_PARAMETER";
    case CTAP2_ERR_INVALID_LENGTH: return "CTAP2_ERR_INVALID_LENGTH";
    case CTAP2_ERR_TIMEOUT: return "CTAP2_ERR_TIMEOUT";
    case CTAP2_ERR_CHANNEL_BUSY: return "CTAP2_ERR_CHANNEL_BUSY";
    case CTAP2_ERR_CBOR_PARSING: return "CTAP2_ERR_CBOR_PARSING";
    case CTAP2_ERR_CBOR_UNEXPECTED_TYPE: return "CTAP2_ERR_CBOR_UNEXPECTED_TYPE";
    case CTAP2_ERR_INVALID_CBOR: return "CTAP2_ERR_INVALID_CBOR";
    case CTAP2_ERR_MISSING_PARAMETER: return "CTAP2_ERR_MISSING_PARAMETER";
    case CTAP2_ERR_LIMIT_EXCEEDED: return "CTAP2_ERR_LIMIT_EXCEEDED";
    case CTAP2_ERR_CREDENTIAL_EXCLUDED: return "CTAP2_ERR_CREDENTIAL_EXCLUDED";
    case CTAP2_ERR_PROCESSING: return "CTAP2_ERR_PROCESSING";
    case CTAP2_ERR_INVALID_CREDENTIAL: return "CTAP2_ERR_INVALID_CREDENTIAL";
    case CTAP2_ERR_UNSUPPORTED_ALGORITHM: return "CTAP2_ERR_UNSUPPORTED_ALGORITHM";
    case CTAP2_ERR_KEY_STORE_FULL: return "CTAP2_ERR_KEY_STORE_FULL";
    case CTAP2_ERR_UNSUPPORTED_OPTION: return "CTAP2_ERR_UNSUPPORTED_OPTION";
    case CTAP2_ERR_KEEPALIVE_CANCEL: return "CTAP2_ERR_KEEPALIVE_CANCEL";
    case CTAP2_ERR_NO_CREDENTIALS: return "CTAP2_ERR_NO_CREDENTIALS";
    case CTAP2_ERR_USER_ACTION_TIMEOUT: return "CTAP2_ERR_USER_ACTION_TIMEOUT";
    case CTAP2_ERR_NOT_ALLOWED: return "CTAP2_ERR_NOT_ALLOWED";
    case CTAP2_ERR_PIN_INVALID: return "CTAP2_ERR_PIN_INVALID";
    case CTAP2_ERR_PIN_BLOCKED: return "CTAP2_ERR_PIN_BLOCKED";
    case CTAP2_ERR_PIN_AUTH_INVALID: return "CTAP2_ERR_PIN_AUTH_INVALID";
    case CTAP2_ERR_PIN_NOT_SET: return "CTAP2_ERR_PIN_NOT_SET";
    case CTAP2_ERR_PIN_REQUIRED: return "CTAP2_ERR_PIN_REQUIRED";
    case CTAP2_ERR_REQUEST_TOO_LARGE: return "CTAP2_ERR_REQUEST_TOO_LARGE";
    default: return "CTAP2_ERR_OTHER";
  }
}

#if FIDO_DEBUG
#define FIDO_LOG(fmt, ...) Serial.printf("[FIDO] " fmt "\n", ##__VA_ARGS__)
#else
#define FIDO_LOG(...) \
  do {                \
  } while (0)
#endif

static inline uint32_t read_be_u32(const uint8_t* p) {
  return (static_cast<uint32_t>(p[0]) << 24) | (static_cast<uint32_t>(p[1]) << 16) | (static_cast<uint32_t>(p[2]) << 8) |
         static_cast<uint32_t>(p[3]);
}

static inline void write_be_u16(uint8_t* p, const uint16_t v) {
  p[0] = static_cast<uint8_t>((v >> 8) & 0xFFU);
  p[1] = static_cast<uint8_t>(v & 0xFFU);
}

static inline void write_be_u32(uint8_t* p, const uint32_t v) {
  p[0] = static_cast<uint8_t>((v >> 24) & 0xFFU);
  p[1] = static_cast<uint8_t>((v >> 16) & 0xFFU);
  p[2] = static_cast<uint8_t>((v >> 8) & 0xFFU);
  p[3] = static_cast<uint8_t>(v & 0xFFU);
}

static bool sha256_ret(const uint8_t* data, const size_t len, uint8_t out[32]) {
  if (data == nullptr || out == nullptr) return false;
  return mbedtls_sha256(data, len, out, 0) == 0;
}

static int mbedtls_rng(void* ctx, unsigned char* out, const size_t len) {
  (void)ctx;
  if (out == nullptr || len == 0) return 0;
  esp_fill_random(out, len);
  return 0;
}

struct EcKeyPair {
  uint8_t priv[32];
  uint8_t x[32];
  uint8_t y[32];
};

static bool ec_generate(EcKeyPair* out) {
  if (!out) return false;
#if FIDO_USE_STATIC_TEST_KEYPAIR
  static const uint8_t kPriv[32] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                                    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                                    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01};
  static const uint8_t kX[32] = {0x6b, 0x17, 0xd1, 0xf2, 0xe1, 0x2c, 0x42, 0x47, 0xf8, 0xbc, 0xe6,
                                 0xe5, 0x63, 0xa4, 0x40, 0xf2, 0x77, 0x03, 0x7d, 0x81, 0x2d, 0xeb,
                                 0x33, 0xa0, 0xf4, 0xa1, 0x39, 0x45, 0xd8, 0x98, 0xc2, 0x96};
  static const uint8_t kY[32] = {0x4f, 0xe3, 0x42, 0xe2, 0xfe, 0x1a, 0x7f, 0x9b, 0x8e, 0xe7, 0xeb,
                                 0x4a, 0x7c, 0x0f, 0x9e, 0x16, 0x2c, 0xbc, 0xe3, 0x35, 0x76, 0xb3,
                                 0x15, 0xec, 0xec, 0xbb, 0x64, 0x06, 0x83, 0x7b, 0xf5, 0x1f};
  memcpy(out->priv, kPriv, sizeof(out->priv));
  memcpy(out->x, kX, sizeof(out->x));
  memcpy(out->y, kY, sizeof(out->y));
  return true;
#else
  mbedtls_ecp_keypair key;
  mbedtls_ecp_keypair_init(&key);
  const int rc = mbedtls_ecp_gen_key(MBEDTLS_ECP_DP_SECP256R1, &key, mbedtls_rng, nullptr);
  if (rc != 0) {
    mbedtls_ecp_keypair_free(&key);
    return false;
  }
  size_t privLen = 0;
  const int rc1 = mbedtls_ecp_write_key_ext(&key, &privLen, out->priv, sizeof(out->priv));

  uint8_t pub[65] = {0};
  size_t pubLen = 0;
  const int rc2 = mbedtls_ecp_write_public_key(&key, MBEDTLS_ECP_PF_UNCOMPRESSED, &pubLen, pub, sizeof(pub));
  int rc3 = -1;
  if (rc2 == 0 && pubLen == sizeof(pub) && pub[0] == 0x04) {
    memcpy(out->x, pub + 1, sizeof(out->x));
    memcpy(out->y, pub + 1 + sizeof(out->x), sizeof(out->y));
    rc3 = 0;
  }
  mbedtls_ecp_keypair_free(&key);
  return (rc1 == 0) && (privLen == sizeof(out->priv)) && (rc2 == 0) && (rc3 == 0);
#endif
}

static bool ec_sign_der(const uint8_t priv[32], const uint8_t hash[32], uint8_t* sigOut, const size_t sigOutMax, size_t* sigLenOut) {
  if (!priv || !hash || !sigOut || !sigLenOut) return false;
  *sigLenOut = 0;

  mbedtls_ecp_keypair key;
  mbedtls_ecp_keypair_init(&key);
  if (mbedtls_ecp_read_key(MBEDTLS_ECP_DP_SECP256R1, &key, priv, 32) != 0) {
    mbedtls_ecp_keypair_free(&key);
    return false;
  }
  if (mbedtls_ecp_keypair_calc_public(&key, mbedtls_rng, nullptr) != 0) {
    mbedtls_ecp_keypair_free(&key);
    return false;
  }

  mbedtls_ecdsa_context ecdsa;
  mbedtls_ecdsa_init(&ecdsa);
  if (mbedtls_ecdsa_from_keypair(&ecdsa, &key) != 0) {
    mbedtls_ecdsa_free(&ecdsa);
    mbedtls_ecp_keypair_free(&key);
    return false;
  }

  size_t sigLen = 0;
  const int rc = mbedtls_ecdsa_write_signature(&ecdsa, MBEDTLS_MD_SHA256, hash, 32, sigOut, sigOutMax, &sigLen, mbedtls_rng,
                                               nullptr);
  mbedtls_ecdsa_free(&ecdsa);
  mbedtls_ecp_keypair_free(&key);
  if (rc != 0) return false;
  if (sigLen > sigOutMax) return false;
  *sigLenOut = sigLen;
  return true;
}

static bool fido_ct_equal(const uint8_t* a, const uint8_t* b, const size_t len) {
  if (!a || !b) return false;
  uint8_t diff = 0;
  for (size_t i = 0; i < len; ++i) diff |= static_cast<uint8_t>(a[i] ^ b[i]);
  return diff == 0;
}

static bool fido_hmac_sha256(const uint8_t* key, const size_t keyLen, const uint8_t* msg, const size_t msgLen, uint8_t out[32]) {
  if (!key || !msg || !out) return false;
  const mbedtls_md_info_t* info = mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);
  if (!info) return false;

  mbedtls_md_context_t ctx;
  mbedtls_md_init(&ctx);
  int rc = mbedtls_md_setup(&ctx, info, 1);
  if (rc == 0) rc = mbedtls_md_hmac_starts(&ctx, key, keyLen);
  if (rc == 0) rc = mbedtls_md_hmac_update(&ctx, msg, msgLen);
  if (rc == 0) rc = mbedtls_md_hmac_finish(&ctx, out);
  mbedtls_md_free(&ctx);
  return rc == 0;
}

static bool fido_aes256_cbc_crypt(const uint8_t key[32], const bool encrypt, const uint8_t* in, const size_t len, uint8_t* out) {
  if (!key || !in || !out) return false;
  if (len == 0 || (len % 16U) != 0U) return false;

  mbedtls_aes_context aes;
  mbedtls_aes_init(&aes);
  uint8_t iv[16] = {0};
  int rc = encrypt ? mbedtls_aes_setkey_enc(&aes, key, 256) : mbedtls_aes_setkey_dec(&aes, key, 256);
  if (rc == 0) {
    rc = mbedtls_aes_crypt_cbc(&aes, encrypt ? MBEDTLS_AES_ENCRYPT : MBEDTLS_AES_DECRYPT, len, iv, in, out);
  }
  mbedtls_aes_free(&aes);
  return rc == 0;
}

static bool fido_client_pin_prepare_key_agreement() {
  EcKeyPair kp;
  if (!ec_generate(&kp)) return false;
  memcpy(fidoClientPin.keyAgreementPriv, kp.priv, sizeof(fidoClientPin.keyAgreementPriv));
  memcpy(fidoClientPin.keyAgreementX, kp.x, sizeof(fidoClientPin.keyAgreementX));
  memcpy(fidoClientPin.keyAgreementY, kp.y, sizeof(fidoClientPin.keyAgreementY));
  fidoClientPin.keyAgreementReady = true;
  return true;
}

static bool fido_client_pin_compute_shared_secret(const uint8_t peerX[32], const uint8_t peerY[32], uint8_t outSharedSecret[32]) {
  if (!peerX || !peerY || !outSharedSecret) return false;
  if (!fidoClientPin.keyAgreementReady && !fido_client_pin_prepare_key_agreement()) return false;

  uint8_t peerPub[65] = {0};
  peerPub[0] = 0x04;
  memcpy(peerPub + 1, peerX, 32);
  memcpy(peerPub + 33, peerY, 32);

  mbedtls_ecp_group grp;
  mbedtls_ecp_group_init(&grp);
  mbedtls_mpi d;
  mbedtls_mpi_init(&d);
  mbedtls_ecp_point qPeer;
  mbedtls_ecp_point_init(&qPeer);
  mbedtls_mpi z;
  mbedtls_mpi_init(&z);

  int rc = mbedtls_ecp_group_load(&grp, MBEDTLS_ECP_DP_SECP256R1);
  if (rc == 0) rc = mbedtls_mpi_read_binary(&d, fidoClientPin.keyAgreementPriv, sizeof(fidoClientPin.keyAgreementPriv));
  if (rc == 0) rc = mbedtls_ecp_point_read_binary(&grp, &qPeer, peerPub, sizeof(peerPub));
  if (rc == 0) rc = mbedtls_ecdh_compute_shared(&grp, &z, &qPeer, &d, mbedtls_rng, nullptr);

  uint8_t zBytes[32] = {0};
  if (rc == 0) rc = mbedtls_mpi_write_binary(&z, zBytes, sizeof(zBytes));
  bool ok = false;
  if (rc == 0) ok = sha256_ret(zBytes, sizeof(zBytes), outSharedSecret);

  secure_zero(zBytes, sizeof(zBytes));
  mbedtls_mpi_free(&z);
  mbedtls_ecp_point_free(&qPeer);
  mbedtls_mpi_free(&d);
  mbedtls_ecp_group_free(&grp);
  return ok;
}

static uint8_t fido_parse_cose_p256_pubkey(CborValue* value, uint8_t outX[32], uint8_t outY[32]) {
  if (!value || !outX || !outY) return CTAP2_ERR_INVALID_PARAMETER;
  if (!cbor_value_is_map(value)) return CTAP2_ERR_CBOR_UNEXPECTED_TYPE;

  CborValue it;
  if (cbor_value_enter_container(value, &it) != CborNoError) return CTAP2_ERR_INVALID_CBOR;
  bool haveX = false;
  bool haveY = false;
  while (!cbor_value_at_end(&it)) {
    int key = 0;
    if (!cbor_value_is_integer(&it) || cbor_value_get_int(&it, &key) != CborNoError) return CTAP2_ERR_INVALID_CBOR;
    if (cbor_value_advance(&it) != CborNoError) return CTAP2_ERR_INVALID_CBOR;
    if (key == -2 || key == -3) {
      if (!cbor_value_is_byte_string(&it)) return CTAP2_ERR_CBOR_UNEXPECTED_TYPE;
      size_t n = 0;
      if (cbor_value_calculate_string_length(&it, &n) != CborNoError) return CTAP2_ERR_INVALID_CBOR;
      if (n != 32) return CTAP2_ERR_INVALID_LENGTH;
      size_t copy = 32;
      uint8_t* dst = (key == -2) ? outX : outY;
      if (cbor_value_copy_byte_string(&it, dst, &copy, nullptr) != CborNoError) return CTAP2_ERR_INVALID_CBOR;
      if (copy != 32) return CTAP2_ERR_INVALID_LENGTH;
      if (key == -2) haveX = true;
      else haveY = true;
    }
    if (cbor_value_advance(&it) != CborNoError) return CTAP2_ERR_INVALID_CBOR;
  }
  if (cbor_value_leave_container(value, &it) != CborNoError) return CTAP2_ERR_INVALID_CBOR;
  if (!haveX || !haveY) return CTAP2_ERR_MISSING_PARAMETER;
  return CTAP2_OK;
}

static bool fido_verify_pin_uv_auth_param(const uint8_t clientDataHash[32], const uint8_t pinUvAuthParam[16]) {
  if (!clientDataHash || !pinUvAuthParam) return false;
  uint8_t mac[32] = {0};
  bool ok = false;

  // Legacy CTAP2.0 path (getPINToken): token is treated as 16-byte key material.
  if (fido_hmac_sha256(fidoClientPin.pinUvAuthToken, 16, clientDataHash, 32, mac) && fido_ct_equal(mac, pinUvAuthParam, 16)) {
    ok = true;
  }

  // CTAP2.1-style path (token-with-permissions): token may be 32-byte key material.
  if (!ok && fido_hmac_sha256(fidoClientPin.pinUvAuthToken, sizeof(fidoClientPin.pinUvAuthToken), clientDataHash, 32, mac) &&
      fido_ct_equal(mac, pinUvAuthParam, 16)) {
    ok = true;
  }

  secure_zero(mac, sizeof(mac));
  return ok;
}

static uint8_t ctap2_client_pin(const uint8_t* req, const size_t reqLen, uint8_t* out, const size_t outMax, size_t* outLen) {
  if (!req || !out || !outLen) return CTAP1_ERR_OTHER;
  *outLen = 0;
  if (reqLen == 0) return CTAP2_ERR_INVALID_LENGTH;

  CborParser parser;
  CborValue root;
  if (cbor_parser_init(req, reqLen, 0, &parser, &root) != CborNoError) return CTAP2_ERR_INVALID_CBOR;
  if (!cbor_value_is_map(&root)) return CTAP2_ERR_CBOR_UNEXPECTED_TYPE;

  int pinUvAuthProtocol = 0;
  int subCommand = 0;
  bool haveSubCommand = false;
  uint8_t peerX[32] = {0};
  uint8_t peerY[32] = {0};
  bool haveKeyAgreement = false;
  uint8_t pinHashEnc[CTAP_PIN_HASH_ENC_LEN] = {0};
  bool havePinHashEnc = false;
  uint64_t permissions = 0;
  bool havePermissions = false;

  CborValue it;
  if (cbor_value_enter_container(&root, &it) != CborNoError) return CTAP2_ERR_INVALID_CBOR;
  while (!cbor_value_at_end(&it)) {
    bool valueConsumedByLeave = false;
    int k = 0;
    if (!cbor_value_is_integer(&it) || cbor_value_get_int(&it, &k) != CborNoError) return CTAP2_ERR_INVALID_CBOR;
    if (cbor_value_advance(&it) != CborNoError) return CTAP2_ERR_INVALID_CBOR;

    if (k == 0x01) {
      if (!cbor_value_is_integer(&it) || cbor_value_get_int(&it, &pinUvAuthProtocol) != CborNoError) return CTAP2_ERR_INVALID_CBOR;
    } else if (k == 0x02) {
      if (!cbor_value_is_integer(&it) || cbor_value_get_int(&it, &subCommand) != CborNoError) return CTAP2_ERR_INVALID_CBOR;
      haveSubCommand = true;
    } else if (k == 0x03) {
      const uint8_t st = fido_parse_cose_p256_pubkey(&it, peerX, peerY);
      if (st != CTAP2_OK) return st;
      haveKeyAgreement = true;
      valueConsumedByLeave = true;
    } else if (k == 0x06) {
      if (!cbor_value_is_byte_string(&it)) return CTAP2_ERR_CBOR_UNEXPECTED_TYPE;
      size_t n = 0;
      if (cbor_value_calculate_string_length(&it, &n) != CborNoError) return CTAP2_ERR_INVALID_CBOR;
      if (n != CTAP_PIN_HASH_ENC_LEN) return CTAP2_ERR_INVALID_LENGTH;
      size_t copy = sizeof(pinHashEnc);
      if (cbor_value_copy_byte_string(&it, pinHashEnc, &copy, nullptr) != CborNoError) return CTAP2_ERR_INVALID_CBOR;
      if (copy != sizeof(pinHashEnc)) return CTAP2_ERR_INVALID_LENGTH;
      havePinHashEnc = true;
    } else if (k == 0x09) {
      if (!cbor_value_is_integer(&it)) return CTAP2_ERR_CBOR_UNEXPECTED_TYPE;
      if (cbor_value_get_uint64(&it, &permissions) != CborNoError) return CTAP2_ERR_INVALID_CBOR;
      havePermissions = true;
    } else if (k == 0x0A) {
      // rpId (optional for makeCredential/assertion permissions); accepted and ignored in this minimal flow.
      if (!cbor_value_is_text_string(&it)) return CTAP2_ERR_CBOR_UNEXPECTED_TYPE;
    }

    if (!valueConsumedByLeave) {
      if (cbor_value_advance(&it) != CborNoError) return CTAP2_ERR_INVALID_CBOR;
    }
  }
  if (cbor_value_leave_container(&root, &it) != CborNoError) return CTAP2_ERR_INVALID_CBOR;
  if (!haveSubCommand) return CTAP2_ERR_MISSING_PARAMETER;

  if (subCommand == CTAP_CLIENT_PIN_GET_RETRIES) {
    CborEncoder enc;
    cbor_encoder_init(&enc, out, outMax, 0);
    CborEncoder map;
    if (cbor_encoder_create_map(&enc, &map, 1) != CborNoError) return CTAP2_ERR_CBOR_PARSING;
    if (cbor_encode_int(&map, 0x03) != CborNoError) return CTAP2_ERR_CBOR_PARSING;
    if (cbor_encode_uint(&map, fidoClientPin.pinRetries) != CborNoError) return CTAP2_ERR_CBOR_PARSING;
    if (cbor_encoder_close_container(&enc, &map) != CborNoError) return CTAP2_ERR_CBOR_PARSING;
    *outLen = cbor_encoder_get_buffer_size(&enc, out);
    return CTAP2_OK;
  }

  if (subCommand == CTAP_CLIENT_PIN_GET_UV_RETRIES) {
    CborEncoder enc;
    cbor_encoder_init(&enc, out, outMax, 0);
    CborEncoder map;
    if (cbor_encoder_create_map(&enc, &map, 1) != CborNoError) return CTAP2_ERR_CBOR_PARSING;
    if (cbor_encode_int(&map, 0x05) != CborNoError) return CTAP2_ERR_CBOR_PARSING;
    if (cbor_encode_uint(&map, 0) != CborNoError) return CTAP2_ERR_CBOR_PARSING;
    if (cbor_encoder_close_container(&enc, &map) != CborNoError) return CTAP2_ERR_CBOR_PARSING;
    *outLen = cbor_encoder_get_buffer_size(&enc, out);
    return CTAP2_OK;
  }

  if (subCommand == CTAP_CLIENT_PIN_GET_KEY_AGREEMENT) {
    if (!fido_client_pin_prepare_key_agreement()) return CTAP2_ERR_PROCESSING;
    CborEncoder enc;
    cbor_encoder_init(&enc, out, outMax, 0);
    CborEncoder map;
    if (cbor_encoder_create_map(&enc, &map, 1) != CborNoError) return CTAP2_ERR_CBOR_PARSING;
    if (cbor_encode_int(&map, 0x01) != CborNoError) return CTAP2_ERR_CBOR_PARSING;
    CborEncoder ka;
    if (cbor_encoder_create_map(&map, &ka, 5) != CborNoError) return CTAP2_ERR_CBOR_PARSING;
    if (cbor_encode_int(&ka, 1) != CborNoError) return CTAP2_ERR_CBOR_PARSING;
    if (cbor_encode_int(&ka, 2) != CborNoError) return CTAP2_ERR_CBOR_PARSING;
    if (cbor_encode_int(&ka, 3) != CborNoError) return CTAP2_ERR_CBOR_PARSING;
    if (cbor_encode_int(&ka, -25) != CborNoError) return CTAP2_ERR_CBOR_PARSING;
    if (cbor_encode_int(&ka, -1) != CborNoError) return CTAP2_ERR_CBOR_PARSING;
    if (cbor_encode_int(&ka, 1) != CborNoError) return CTAP2_ERR_CBOR_PARSING;
    if (cbor_encode_int(&ka, -2) != CborNoError) return CTAP2_ERR_CBOR_PARSING;
    if (cbor_encode_byte_string(&ka, fidoClientPin.keyAgreementX, sizeof(fidoClientPin.keyAgreementX)) != CborNoError)
      return CTAP2_ERR_CBOR_PARSING;
    if (cbor_encode_int(&ka, -3) != CborNoError) return CTAP2_ERR_CBOR_PARSING;
    if (cbor_encode_byte_string(&ka, fidoClientPin.keyAgreementY, sizeof(fidoClientPin.keyAgreementY)) != CborNoError)
      return CTAP2_ERR_CBOR_PARSING;
    if (cbor_encoder_close_container(&map, &ka) != CborNoError) return CTAP2_ERR_CBOR_PARSING;
    if (cbor_encoder_close_container(&enc, &map) != CborNoError) return CTAP2_ERR_CBOR_PARSING;
    *outLen = cbor_encoder_get_buffer_size(&enc, out);
    return CTAP2_OK;
  }

  if (subCommand == CTAP_CLIENT_PIN_GET_PIN_TOKEN || subCommand == CTAP_CLIENT_PIN_GET_PIN_UV_AUTH_TOKEN_USING_PIN_WITH_PERMISSIONS) {
    if (!security_pin_configured()) return CTAP2_ERR_PIN_NOT_SET;
    if (pinUvAuthProtocol != CTAP_PIN_UV_AUTH_PROTOCOL_1) return CTAP2_ERR_INVALID_PARAMETER;
    if (!haveKeyAgreement || !havePinHashEnc) return CTAP2_ERR_MISSING_PARAMETER;
    if (subCommand == CTAP_CLIENT_PIN_GET_PIN_UV_AUTH_TOKEN_USING_PIN_WITH_PERMISSIONS && !havePermissions)
      return CTAP2_ERR_MISSING_PARAMETER;
    if (fidoClientPin.pinRetries == 0) return CTAP2_ERR_PIN_BLOCKED;
    if (!fido_client_pin_hash_ready()) return CTAP2_ERR_PIN_NOT_SET;

    uint8_t expectedHash16[16] = {0};
    if (!security_fido_pin_hash16_get(expectedHash16)) return CTAP2_ERR_PIN_NOT_SET;

    uint8_t sharedSecret[32] = {0};
    if (!fido_client_pin_compute_shared_secret(peerX, peerY, sharedSecret)) {
      secure_zero(expectedHash16, sizeof(expectedHash16));
      return CTAP2_ERR_PROCESSING;
    }

    uint8_t pinHashPlain[16] = {0};
    const bool decOk = fido_aes256_cbc_crypt(sharedSecret, false, pinHashEnc, sizeof(pinHashEnc), pinHashPlain);
    if (!decOk || !fido_ct_equal(pinHashPlain, expectedHash16, sizeof(pinHashPlain))) {
      if (fidoClientPin.pinRetries > 0) fidoClientPin.pinRetries--;
      const uint8_t st = (fidoClientPin.pinRetries == 0) ? CTAP2_ERR_PIN_BLOCKED : CTAP2_ERR_PIN_INVALID;
      secure_zero(sharedSecret, sizeof(sharedSecret));
      secure_zero(pinHashPlain, sizeof(pinHashPlain));
      secure_zero(expectedHash16, sizeof(expectedHash16));
      return st;
    }

    fidoClientPin.pinRetries = 8;
    const size_t tokenOutLen =
      (subCommand == CTAP_CLIENT_PIN_GET_PIN_TOKEN) ? static_cast<size_t>(16) : static_cast<size_t>(CTAP_PIN_TOKEN_LEN);
    uint8_t pinTokenEnc[CTAP_PIN_TOKEN_LEN] = {0};
    if (!fido_aes256_cbc_crypt(sharedSecret, true, fidoClientPin.pinUvAuthToken, tokenOutLen, pinTokenEnc)) {
      secure_zero(sharedSecret, sizeof(sharedSecret));
      secure_zero(pinHashPlain, sizeof(pinHashPlain));
      secure_zero(expectedHash16, sizeof(expectedHash16));
      secure_zero(pinTokenEnc, sizeof(pinTokenEnc));
      return CTAP2_ERR_PROCESSING;
    }

    CborEncoder enc;
    cbor_encoder_init(&enc, out, outMax, 0);
    CborEncoder map;
    if (cbor_encoder_create_map(&enc, &map, 1) != CborNoError) return CTAP2_ERR_CBOR_PARSING;
    if (cbor_encode_int(&map, 0x02) != CborNoError) return CTAP2_ERR_CBOR_PARSING;
    if (cbor_encode_byte_string(&map, pinTokenEnc, tokenOutLen) != CborNoError) return CTAP2_ERR_CBOR_PARSING;
    if (cbor_encoder_close_container(&enc, &map) != CborNoError) return CTAP2_ERR_CBOR_PARSING;
    *outLen = cbor_encoder_get_buffer_size(&enc, out);

    secure_zero(sharedSecret, sizeof(sharedSecret));
    secure_zero(pinHashPlain, sizeof(pinHashPlain));
    secure_zero(expectedHash16, sizeof(expectedHash16));
    secure_zero(pinTokenEnc, sizeof(pinTokenEnc));
    return CTAP2_OK;
  }

  if (subCommand == CTAP_CLIENT_PIN_SET_PIN || subCommand == CTAP_CLIENT_PIN_CHANGE_PIN) {
    // PIN provisioning is done through /hsm web UI; ClientPIN currently supports entry flow only.
    return CTAP2_ERR_NOT_ALLOWED;
  }

  // Some hosts probe additional ClientPIN subcommands; respond softly.
  return CTAP2_ERR_NOT_ALLOWED;
}

static bool fido_client_pin_available() {
  return security_pin_configured();
}

static bool fido_client_pin_hash_ready() {
  uint8_t h[16] = {0};
  const bool ok = security_fido_pin_hash16_get(h);
  secure_zero(h, sizeof(h));
  return ok;
}

static bool build_cred_secret(const bool rk, const uint8_t* user, const size_t userLen, const uint8_t priv[32], uint8_t* out,
                              size_t* outLen) {
  if (!priv || !out || !outLen) return false;
  if (userLen > 64) return false;
  const size_t need = 3 + userLen + 32;
  if (need > CRED_MAX_SECRET_LEN) return false;
  out[0] = CTAP_CRED_SECRET_VER;
  out[1] = rk ? CTAP_CRED_FLAG_RK : 0;
  out[2] = static_cast<uint8_t>(userLen);
  if (userLen > 0 && user) memcpy(out + 3, user, userLen);
  memcpy(out + 3 + userLen, priv, 32);
  *outLen = need;
  return true;
}

static bool parse_cred_secret(const uint8_t* secret, const size_t secretLen, bool* rkOut, uint8_t* userOut, size_t* userLenOut,
                              uint8_t privOut[32]) {
  if (!secret || secretLen < (3 + 32) || !rkOut || !userLenOut || !privOut) return false;
  if (secret[0] != CTAP_CRED_SECRET_VER) return false;
  const bool rk = (secret[1] & CTAP_CRED_FLAG_RK) != 0;
  const size_t userLen = secret[2];
  const size_t need = 3 + userLen + 32;
  if (need != secretLen) return false;
  if (userLen > 64) return false;
  if (userLen > 0 && userOut) memcpy(userOut, secret + 3, userLen);
  memcpy(privOut, secret + 3 + userLen, 32);
  *rkOut = rk;
  *userLenOut = userLen;
  return true;
}

static uint32_t load_sign_count() {
#if FIDO_DISABLE_PERSISTENCE
  return 0;
#else
  prefs.begin("kbm", true);
  const uint32_t v = prefs.getUInt("sc", 0);
  prefs.end();
  return v;
#endif
}

static void save_sign_count(const uint32_t v) {
#if FIDO_DISABLE_PERSISTENCE
  (void)v;
#else
  prefs.begin("kbm", false);
  prefs.putUInt("sc", v);
  prefs.end();
#endif
}

static constexpr size_t RUNTIME_CRED_SLOTS = 8;
struct RuntimeCredRecord {
  bool used = false;
  char rpId[CRED_MAX_RPID_LEN + 1] = {0};
  uint8_t id[CRED_MAX_ID_LEN] = {0};
  uint16_t idLen = 0;
  uint8_t secret[CRED_MAX_SECRET_LEN] = {0};
  uint16_t secretLen = 0;
  uint32_t stamp = 0;
};

static RuntimeCredRecord runtimeCreds[RUNTIME_CRED_SLOTS];
static uint32_t runtimeCredStamp = 1;

static int runtime_cred_find(const uint8_t* id, const size_t idLen) {
  if (!id || idLen == 0 || idLen > CRED_MAX_ID_LEN) return -1;
  for (size_t i = 0; i < RUNTIME_CRED_SLOTS; ++i) {
    const RuntimeCredRecord& rec = runtimeCreds[i];
    if (!rec.used) continue;
    if (rec.idLen != idLen) continue;
    if (memcmp(rec.id, id, idLen) == 0) return static_cast<int>(i);
  }
  return -1;
}

static void runtime_cred_clear() {
  for (size_t i = 0; i < RUNTIME_CRED_SLOTS; ++i) {
    RuntimeCredRecord& rec = runtimeCreds[i];
    if (rec.used && rec.secretLen > 0) secure_zero(rec.secret, rec.secretLen);
    rec.used = false;
    rec.rpId[0] = '\0';
    rec.idLen = 0;
    rec.secretLen = 0;
    rec.stamp = 0;
  }
  runtimeCredStamp = 1;
}

static bool runtime_cred_exists(const uint8_t* id, const size_t idLen) {
  return runtime_cred_find(id, idLen) >= 0;
}

static bool runtime_cred_add(const char* rpId, const uint8_t* id, const size_t idLen, const uint8_t* secret, const size_t secretLen) {
  if (!rpId || rpId[0] == '\0' || !id || idLen == 0 || idLen > CRED_MAX_ID_LEN || !secret || secretLen == 0 ||
      secretLen > CRED_MAX_SECRET_LEN) {
    return false;
  }

  int idx = runtime_cred_find(id, idLen);
  if (idx < 0) {
    for (size_t i = 0; i < RUNTIME_CRED_SLOTS; ++i) {
      if (!runtimeCreds[i].used) {
        idx = static_cast<int>(i);
        break;
      }
    }
  }
  if (idx < 0) {
    uint32_t oldest = UINT32_MAX;
    size_t oldestIdx = 0;
    for (size_t i = 0; i < RUNTIME_CRED_SLOTS; ++i) {
      if (runtimeCreds[i].stamp < oldest) {
        oldest = runtimeCreds[i].stamp;
        oldestIdx = i;
      }
    }
    idx = static_cast<int>(oldestIdx);
  }

  RuntimeCredRecord& rec = runtimeCreds[idx];
  if (rec.used && rec.secretLen > 0) secure_zero(rec.secret, rec.secretLen);
  rec.used = true;

  const size_t rpLen = strnlen(rpId, CRED_MAX_RPID_LEN);
  memcpy(rec.rpId, rpId, rpLen);
  rec.rpId[rpLen] = '\0';

  rec.idLen = static_cast<uint16_t>(idLen);
  memcpy(rec.id, id, idLen);

  rec.secretLen = static_cast<uint16_t>(secretLen);
  memcpy(rec.secret, secret, secretLen);

  rec.stamp = runtimeCredStamp++;
  if (runtimeCredStamp == 0) runtimeCredStamp = 1;
  return true;
}

static bool runtime_cred_lookup(const uint8_t* id, const size_t idLen, char* rpOut, const size_t rpOutMax, uint8_t* secretOut,
                                size_t* secretLenOut) {
  if (secretLenOut) *secretLenOut = 0;
  if (rpOut && rpOutMax) rpOut[0] = '\0';

  const int idx = runtime_cred_find(id, idLen);
  if (idx < 0) return false;
  const RuntimeCredRecord& rec = runtimeCreds[idx];

  if (rpOut && rpOutMax) {
    const size_t rpLen = strnlen(rec.rpId, CRED_MAX_RPID_LEN);
    const size_t copyLen = (rpLen < (rpOutMax - 1)) ? rpLen : (rpOutMax - 1);
    memcpy(rpOut, rec.rpId, copyLen);
    rpOut[copyLen] = '\0';
  }
  if (secretOut && secretLenOut) {
    memcpy(secretOut, rec.secret, rec.secretLen);
    *secretLenOut = rec.secretLen;
  }
  return true;
}

static bool runtime_cred_lookup_by_rpid(const char* rpId, uint8_t* idOut, const size_t idOutMax, size_t* idLenOut, uint8_t* secretOut,
                                        const size_t secretOutMax, size_t* secretLenOut) {
  if (idLenOut) *idLenOut = 0;
  if (secretLenOut) *secretLenOut = 0;
  if (!rpId || rpId[0] == '\0' || !idOut || !idLenOut || !secretOut || !secretLenOut) return false;
  if (idOutMax < CRED_MAX_ID_LEN || secretOutMax < CRED_MAX_SECRET_LEN) return false;

  int bestIdx = -1;
  uint32_t bestStamp = 0;
  for (size_t i = 0; i < RUNTIME_CRED_SLOTS; ++i) {
    const RuntimeCredRecord& rec = runtimeCreds[i];
    if (!rec.used) continue;
    if (strcmp(rec.rpId, rpId) != 0) continue;
    if (bestIdx < 0 || rec.stamp >= bestStamp) {
      bestIdx = static_cast<int>(i);
      bestStamp = rec.stamp;
    }
  }
  if (bestIdx < 0) return false;

  const RuntimeCredRecord& rec = runtimeCreds[bestIdx];
  memcpy(idOut, rec.id, rec.idLen);
  *idLenOut = rec.idLen;
  memcpy(secretOut, rec.secret, rec.secretLen);
  *secretLenOut = rec.secretLen;
  return true;
}

static bool cred_store_id_exists(const uint8_t* id, const size_t idLen) {
  static constexpr size_t kStoreHdrLen = 12;
  static constexpr size_t kRecHdrLen = 12;
  if (!id || idLen == 0 || idLen > CRED_MAX_ID_LEN) return false;
  if (runtime_cred_exists(id, idLen)) return true;

#if FIDO_DISABLE_PERSISTENCE
  return false;
#endif

  uint8_t* buf = nullptr;
  size_t len = 0;
  uint16_t count = 0;
  if (!cred_store_load(&buf, &len, &count)) return false;

  bool found = false;
  if (buf && len >= kStoreHdrLen) {
    size_t off = kStoreHdrLen;
    for (uint16_t i = 0; i < count; ++i) {
      const uint16_t rpLen = read_le_u16(buf + off + 0);
      const uint16_t labelLen = read_le_u16(buf + off + 2);
      const uint16_t curIdLen = read_le_u16(buf + off + 4);
      const uint16_t secretLen = read_le_u16(buf + off + 6);
      const size_t recTotal = kRecHdrLen + static_cast<size_t>(rpLen) + static_cast<size_t>(labelLen) + static_cast<size_t>(curIdLen) +
                              static_cast<size_t>(secretLen);
      const uint8_t* rp = buf + off + kRecHdrLen;
      const uint8_t* label = rp + rpLen;
      const uint8_t* curId = label + labelLen;
      if (curIdLen == idLen && memcmp(curId, id, idLen) == 0) {
        found = true;
        break;
      }
      off += recTotal;
    }
  }

  if (buf) {
    secure_zero(buf, len);
    free(buf);
  }
  return found;
}

static bool cred_store_add_credential(const char* rpId, const uint8_t* id, const size_t idLen, const uint8_t* secret, const size_t secretLen) {
  static constexpr size_t kStoreHdrLen = 12;
  static constexpr size_t kRecHdrLen = 12;
  if (!rpId || rpId[0] == '\0' || !id || idLen == 0 || idLen > CRED_MAX_ID_LEN || !secret || secretLen == 0 ||
      secretLen > CRED_MAX_SECRET_LEN) {
    return false;
  }
  const size_t rpLen = strnlen(rpId, CRED_MAX_RPID_LEN + 1);
  if (rpLen == 0 || rpLen > CRED_MAX_RPID_LEN) return false;
  if (runtime_cred_exists(id, idLen)) return false;
  if (!runtime_cred_add(rpId, id, idLen, secret, secretLen)) return false;

#if FIDO_DISABLE_PERSISTENCE
  return true;
#endif

  uint8_t* buf = nullptr;
  size_t len = 0;
  uint16_t count = 0;
  if (!cred_store_load(&buf, &len, &count)) return false;

  // Check for duplicate IDs within the loaded blob.
  if (buf && len >= kStoreHdrLen) {
    size_t off = kStoreHdrLen;
    for (uint16_t i = 0; i < count; ++i) {
      const uint16_t rpLen2 = read_le_u16(buf + off + 0);
      const uint16_t labelLen2 = read_le_u16(buf + off + 2);
      const uint16_t curIdLen = read_le_u16(buf + off + 4);
      const uint16_t secretLen2 = read_le_u16(buf + off + 6);
      const size_t recTotal = kRecHdrLen + static_cast<size_t>(rpLen2) + static_cast<size_t>(labelLen2) + static_cast<size_t>(curIdLen) +
                              static_cast<size_t>(secretLen2);
      const uint8_t* rp = buf + off + kRecHdrLen;
      const uint8_t* label = rp + rpLen2;
      const uint8_t* curId = label + labelLen2;
      if (curIdLen == idLen && memcmp(curId, id, idLen) == 0) {
        secure_zero(buf, len);
        free(buf);
        return false;
      }
      off += recTotal;
    }
  }

  const size_t recTotal = kRecHdrLen + rpLen + 0 + idLen + secretLen;
  const size_t baseLen = (buf && len >= kStoreHdrLen) ? len : kStoreHdrLen;
  const size_t newLen = baseLen + recTotal;
  if (newLen > CRED_STORE_MAX_BYTES) {
    if (buf) {
      secure_zero(buf, len);
      free(buf);
    }
    return false;
  }

  const uint16_t newCount = count + 1;
  uint8_t* out = static_cast<uint8_t*>(malloc(newLen));
  if (!out) {
    if (buf) {
      secure_zero(buf, len);
      free(buf);
    }
    return false;
  }

  write_cred_store_header(out, newCount);
  size_t w = kStoreHdrLen;
  if (buf && len >= kStoreHdrLen) {
    memcpy(out + w, buf + kStoreHdrLen, len - kStoreHdrLen);
    w += (len - kStoreHdrLen);
  }

  const uint32_t createdAt = static_cast<uint32_t>(millis());
  write_le_u16(out + w + 0, static_cast<uint16_t>(rpLen));
  write_le_u16(out + w + 2, 0);
  write_le_u16(out + w + 4, static_cast<uint16_t>(idLen));
  write_le_u16(out + w + 6, static_cast<uint16_t>(secretLen));
  write_le_u32(out + w + 8, createdAt);
  w += kRecHdrLen;
  memcpy(out + w, rpId, rpLen);
  w += rpLen;
  memcpy(out + w, id, idLen);
  w += idLen;
  memcpy(out + w, secret, secretLen);
  w += secretLen;

  const bool ok = (w == newLen) && cred_store_save(out, newLen);
  secure_zero(out, newLen);
  free(out);
  if (buf) {
    secure_zero(buf, len);
    free(buf);
  }
  return ok;
}

static bool cred_store_lookup(const uint8_t* id, const size_t idLen, char* rpOut, const size_t rpOutMax, uint8_t* secretOut,
                              size_t* secretLenOut) {
  static constexpr size_t kStoreHdrLen = 12;
  static constexpr size_t kRecHdrLen = 12;
  if (secretLenOut) *secretLenOut = 0;
  if (rpOut && rpOutMax) rpOut[0] = '\0';
  if (!id || idLen == 0 || idLen > CRED_MAX_ID_LEN) return false;

  if (runtime_cred_lookup(id, idLen, rpOut, rpOutMax, secretOut, secretLenOut)) return true;
#if FIDO_DISABLE_PERSISTENCE
  return false;
#endif

  uint8_t* buf = nullptr;
  size_t len = 0;
  uint16_t count = 0;
  if (!cred_store_load(&buf, &len, &count)) return false;
  if (!buf || len < kStoreHdrLen) return false;

  bool found = false;
  size_t off = kStoreHdrLen;
  for (uint16_t i = 0; i < count; ++i) {
    const uint16_t rpLen = read_le_u16(buf + off + 0);
    const uint16_t labelLen = read_le_u16(buf + off + 2);
    const uint16_t curIdLen = read_le_u16(buf + off + 4);
    const uint16_t secretLen = read_le_u16(buf + off + 6);
    const size_t recTotal = kRecHdrLen + static_cast<size_t>(rpLen) + static_cast<size_t>(labelLen) + static_cast<size_t>(curIdLen) +
                            static_cast<size_t>(secretLen);
    const uint8_t* rp = buf + off + kRecHdrLen;
    const uint8_t* label = rp + rpLen;
    const uint8_t* curId = label + labelLen;
    const uint8_t* curSecret = curId + curIdLen;
    if (curIdLen == idLen && memcmp(curId, id, idLen) == 0) {
      if (rpOut && rpOutMax) {
        const size_t copyLen = (rpLen < (rpOutMax - 1)) ? rpLen : (rpOutMax - 1);
        memcpy(rpOut, rp, copyLen);
        rpOut[copyLen] = '\0';
      }
      if (secretOut && secretLenOut && secretLen <= CRED_MAX_SECRET_LEN) {
        memcpy(secretOut, curSecret, secretLen);
        *secretLenOut = secretLen;
      }
      found = true;
      break;
    }
    off += recTotal;
  }

  secure_zero(buf, len);
  free(buf);
  return found;
}

static bool ctap2_build_cose_p256_es256(const uint8_t x[32], const uint8_t y[32], uint8_t* out, const size_t outMax, size_t* outLen) {
  if (!x || !y || !out || !outLen) return false;
  *outLen = 0;
  CborEncoder enc;
  cbor_encoder_init(&enc, out, outMax, 0);
  CborEncoder m;
  if (cbor_encoder_create_map(&enc, &m, 5) != CborNoError) return false;
  if (cbor_encode_int(&m, 1) != CborNoError) return false;
  if (cbor_encode_int(&m, 2) != CborNoError) return false; // kty: EC2
  if (cbor_encode_int(&m, 3) != CborNoError) return false;
  if (cbor_encode_int(&m, -7) != CborNoError) return false; // alg: ES256
  if (cbor_encode_int(&m, -1) != CborNoError) return false;
  if (cbor_encode_int(&m, 1) != CborNoError) return false; // crv: P-256
  if (cbor_encode_int(&m, -2) != CborNoError) return false;
  if (cbor_encode_byte_string(&m, x, 32) != CborNoError) return false;
  if (cbor_encode_int(&m, -3) != CborNoError) return false;
  if (cbor_encode_byte_string(&m, y, 32) != CborNoError) return false;
  if (cbor_encoder_close_container(&enc, &m) != CborNoError) return false;
  *outLen = cbor_encoder_get_buffer_size(&enc, out);
  return (*outLen > 0) && (*outLen <= outMax);
}

static uint8_t ctap2_parse_pubkey_cred_descriptor(CborValue* descMap, uint8_t* idOut, const size_t idOutMax, size_t* idLenOut,
                                                   bool* typePublicKeyOut) {
  if (!descMap || !idOut || !idLenOut || !typePublicKeyOut) return CTAP1_ERR_OTHER;
  if (!cbor_value_is_map(descMap)) return CTAP2_ERR_CBOR_UNEXPECTED_TYPE;

  *idLenOut = 0;
  *typePublicKeyOut = false;

  CborValue dIt;
  if (cbor_value_enter_container(descMap, &dIt) != CborNoError) return CTAP2_ERR_INVALID_CBOR;

  uint16_t descLoopGuard = 0;
  while (!cbor_value_at_end(&dIt)) {
    if (++descLoopGuard > 16) return CTAP2_ERR_INVALID_CBOR;
    bool keyIsType = false;
    bool keyIsId = false;

    if (cbor_value_is_integer(&dIt)) {
      int dk = 0;
      if (cbor_value_get_int(&dIt, &dk) != CborNoError) return CTAP2_ERR_INVALID_CBOR;
      keyIsType = (dk == 0x01);
      keyIsId = (dk == 0x02);
      if (cbor_value_advance(&dIt) != CborNoError) return CTAP2_ERR_INVALID_CBOR;
    } else if (cbor_value_is_text_string(&dIt)) {
      if (cbor_value_text_string_equals(&dIt, "type", &keyIsType) != CborNoError) return CTAP2_ERR_INVALID_CBOR;
      if (cbor_value_text_string_equals(&dIt, "id", &keyIsId) != CborNoError) return CTAP2_ERR_INVALID_CBOR;
      if (cbor_value_advance(&dIt) != CborNoError) return CTAP2_ERR_INVALID_CBOR; // key -> value
    } else {
      return CTAP2_ERR_INVALID_CBOR;
    }

    if (keyIsType) {
      if (!cbor_value_is_text_string(&dIt)) return CTAP2_ERR_CBOR_UNEXPECTED_TYPE;
      bool isPublicKey = false;
      if (cbor_value_text_string_equals(&dIt, "public-key", &isPublicKey) != CborNoError) return CTAP2_ERR_INVALID_CBOR;
      if (isPublicKey) *typePublicKeyOut = true;
    } else if (keyIsId) {
      if (!cbor_value_is_byte_string(&dIt)) return CTAP2_ERR_CBOR_UNEXPECTED_TYPE;
      size_t n = 0;
      if (cbor_value_calculate_string_length(&dIt, &n) != CborNoError) return CTAP2_ERR_INVALID_CBOR;
      if (n == 0 || n > idOutMax) return CTAP2_ERR_LIMIT_EXCEEDED;
      size_t copyLen = idOutMax;
      if (cbor_value_copy_byte_string(&dIt, idOut, &copyLen, nullptr) != CborNoError) return CTAP2_ERR_INVALID_CBOR;
      *idLenOut = copyLen;
    }

    if (cbor_value_advance(&dIt) != CborNoError) return CTAP2_ERR_INVALID_CBOR; // value -> next key/end
  }

  if (cbor_value_leave_container(descMap, &dIt) != CborNoError) return CTAP2_ERR_INVALID_CBOR;
  return CTAP2_OK;
}

static uint8_t ctap2_get_info(uint8_t* out, const size_t outMax, size_t* outLen) {
  if (!out || !outLen) return CTAP1_ERR_OTHER;
  *outLen = 0;
  const bool clientPin = fido_client_pin_available();
  const size_t mapPairs = clientPin ? 5 : 4;
  CborEncoder enc;
  cbor_encoder_init(&enc, out, outMax, 0);

  // Keep getInfo compact enough to fit a single CTAPHID frame.
  // Map keys:
  // - 0x01 versions
  // - 0x03 aaguid
  // - 0x04 options
  // - 0x05 maxMsgSize
  // - 0x06 pinUvAuthProtocols (when clientPin is configured)
  CborEncoder map;
  if (cbor_encoder_create_map(&enc, &map, mapPairs) != CborNoError) return CTAP2_ERR_CBOR_PARSING;

  // versions
  if (cbor_encode_int(&map, 0x01) != CborNoError) return CTAP2_ERR_CBOR_PARSING;
  CborEncoder versions;
  if (cbor_encoder_create_array(&map, &versions, 1) != CborNoError) return CTAP2_ERR_CBOR_PARSING;
  if (cbor_encode_text_stringz(&versions, "FIDO_2_0") != CborNoError) return CTAP2_ERR_CBOR_PARSING;
  if (cbor_encoder_close_container(&map, &versions) != CborNoError) return CTAP2_ERR_CBOR_PARSING;

  // aaguid
  if (cbor_encode_int(&map, 0x03) != CborNoError) return CTAP2_ERR_CBOR_PARSING;
  if (cbor_encode_byte_string(&map, CTAP_AAGUID, sizeof(CTAP_AAGUID)) != CborNoError) return CTAP2_ERR_CBOR_PARSING;

  // options
  if (cbor_encode_int(&map, 0x04) != CborNoError) return CTAP2_ERR_CBOR_PARSING;
  CborEncoder opt;
  if (cbor_encoder_create_map(&map, &opt, 3) != CborNoError) return CTAP2_ERR_CBOR_PARSING;
  if (cbor_encode_text_stringz(&opt, "up") != CborNoError) return CTAP2_ERR_CBOR_PARSING;
  if (cbor_encode_boolean(&opt, true) != CborNoError) return CTAP2_ERR_CBOR_PARSING;
  if (cbor_encode_text_stringz(&opt, "rk") != CborNoError) return CTAP2_ERR_CBOR_PARSING;
  if (cbor_encode_boolean(&opt, true) != CborNoError) return CTAP2_ERR_CBOR_PARSING;
  if (cbor_encode_text_stringz(&opt, "clientPin") != CborNoError) return CTAP2_ERR_CBOR_PARSING;
  if (cbor_encode_boolean(&opt, clientPin) != CborNoError) return CTAP2_ERR_CBOR_PARSING;
  if (cbor_encoder_close_container(&map, &opt) != CborNoError) return CTAP2_ERR_CBOR_PARSING;

  // maxMsgSize
  if (cbor_encode_int(&map, 0x05) != CborNoError) return CTAP2_ERR_CBOR_PARSING;
  if (cbor_encode_uint(&map, FIDO_MAX_PAYLOAD) != CborNoError) return CTAP2_ERR_CBOR_PARSING;

  if (clientPin) {
    // pinUvAuthProtocols = [1]
    if (cbor_encode_int(&map, 0x06) != CborNoError) return CTAP2_ERR_CBOR_PARSING;
    CborEncoder prots;
    if (cbor_encoder_create_array(&map, &prots, 1) != CborNoError) return CTAP2_ERR_CBOR_PARSING;
    if (cbor_encode_uint(&prots, CTAP_PIN_UV_AUTH_PROTOCOL_1) != CborNoError) return CTAP2_ERR_CBOR_PARSING;
    if (cbor_encoder_close_container(&map, &prots) != CborNoError) return CTAP2_ERR_CBOR_PARSING;
  }

  if (cbor_encoder_close_container(&enc, &map) != CborNoError) return CTAP2_ERR_CBOR_PARSING;
  *outLen = cbor_encoder_get_buffer_size(&enc, out);
  return CTAP2_OK;
}

static uint8_t ctap2_make_credential(const uint8_t* req, const size_t reqLen, uint8_t* out, const size_t outMax, size_t* outLen) {
  if (!req || !out || !outLen) return CTAP1_ERR_OTHER;
  *outLen = 0;
  if (reqLen == 0) return CTAP2_ERR_INVALID_LENGTH;
  FIDO_LOG("makeCredential: begin reqLen=%u", static_cast<unsigned>(reqLen));
#if FIDO_FORCE_MAKECRED_EARLY_ERROR
  FIDO_LOG("makeCredential: forced early error");
  return CTAP2_ERR_INVALID_CBOR;
#endif
  if (reqLen >= 8) {
    FIDO_LOG("makeCredential: head=%02X%02X%02X%02X tail=%02X%02X%02X%02X", req[0], req[1], req[2], req[3], req[reqLen - 4],
             req[reqLen - 3], req[reqLen - 2], req[reqLen - 1]);
  }
  uint8_t reqHash[32];
  if (sha256_ret(req, reqLen, reqHash)) {
    FIDO_LOG("makeCredential: hash=%02X%02X%02X%02X...%02X%02X%02X%02X", reqHash[0], reqHash[1], reqHash[2], reqHash[3],
             reqHash[28], reqHash[29], reqHash[30], reqHash[31]);
  }

  // Parse request map
  CborParser parser;
  CborValue root;
  if (cbor_parser_init(req, reqLen, 0, &parser, &root) != CborNoError) return CTAP2_ERR_INVALID_CBOR;
  FIDO_LOG("makeCredential: cbor_parser_init ok");
  if (!cbor_value_is_map(&root)) return CTAP2_ERR_CBOR_UNEXPECTED_TYPE;
  FIDO_LOG("makeCredential: root is map");

  uint8_t clientDataHash[32] = {0};
  bool haveClientHash = false;
  char rpId[CRED_MAX_RPID_LEN + 1];
  rpId[0] = '\0';
  bool haveRpId = false;
  uint8_t userId[64];
  size_t userIdLen = 0;
  bool haveUser = false;
  bool haveAlg = false;
  bool optionRk = false;
  bool optionUv = false;
  bool excludeHit = false;
#if FIDO_REQUIRE_PIN
  const bool pinGate = security_pin_configured() && !security_pin_unlocked_now();
#else
  const bool pinGate = false;
#endif
  bool pinAuthSatisfied = false;
  uint8_t pinUvAuthParam[CTAP_PIN_UV_AUTH_PARAM_LEN] = {0};
  bool havePinUvAuthParam = false;
  int pinUvAuthProtocol = 0;
  bool havePinUvAuthProtocol = false;

  CborValue it;
  if (cbor_value_enter_container(&root, &it) != CborNoError) return CTAP2_ERR_INVALID_CBOR;
  FIDO_LOG("makeCredential: entered root map");
  uint16_t topLoopGuard = 0;
  bool minimalParsedEnough = false;
  while (!cbor_value_at_end(&it)) {
    if (++topLoopGuard > 64) return CTAP2_ERR_INVALID_CBOR;
    bool valueConsumedByLeave = false;
    int k = 0;
    if (!cbor_value_is_integer(&it) || cbor_value_get_int(&it, &k) != CborNoError) return CTAP2_ERR_INVALID_CBOR;
    if (cbor_value_advance(&it) != CborNoError) return CTAP2_ERR_INVALID_CBOR;
    FIDO_LOG("makeCredential: key=%d", k);

#if FIDO_STABILITY_MINIMAL_MAKECRED_PARSE
    if (!pinGate && haveClientHash && haveRpId && (k != 0x01) && (k != 0x02)) {
      // Stop after the required fields to avoid unstable deep-map traversal paths.
      FIDO_LOG("makeCredential: minimal parse early exit at key=%d", k);
      minimalParsedEnough = true;
      break;
    }
#endif

    if (k == 0x01) {
      if (!cbor_value_is_byte_string(&it)) return CTAP2_ERR_CBOR_UNEXPECTED_TYPE;
      size_t n = 0;
      if (cbor_value_calculate_string_length(&it, &n) != CborNoError) return CTAP2_ERR_INVALID_CBOR;
      if (n != 32) return CTAP2_ERR_INVALID_LENGTH;
      size_t copy = sizeof(clientDataHash);
      if (cbor_value_copy_byte_string(&it, clientDataHash, &copy, nullptr) != CborNoError) return CTAP2_ERR_INVALID_CBOR;
      haveClientHash = true;
      FIDO_LOG("makeCredential: key 0x01 ok");
    } else if (k == 0x02) {
      if (!cbor_value_is_map(&it)) return CTAP2_ERR_CBOR_UNEXPECTED_TYPE;
      CborValue rpIt;
      if (cbor_value_enter_container(&it, &rpIt) != CborNoError) return CTAP2_ERR_INVALID_CBOR;
      uint16_t rpLoopGuard = 0;
      while (!cbor_value_at_end(&rpIt)) {
        if (++rpLoopGuard > 16) return CTAP2_ERR_INVALID_CBOR;
        if (!cbor_value_is_text_string(&rpIt)) return CTAP2_ERR_INVALID_CBOR;
        bool keyIsId = false;
        if (cbor_value_text_string_equals(&rpIt, "id", &keyIsId) != CborNoError) return CTAP2_ERR_INVALID_CBOR;
        if (cbor_value_advance(&rpIt) != CborNoError) return CTAP2_ERR_INVALID_CBOR; // key -> value
        if (keyIsId) {
          if (!cbor_value_is_text_string(&rpIt)) return CTAP2_ERR_CBOR_UNEXPECTED_TYPE;
          size_t idLen = 0;
          if (cbor_value_calculate_string_length(&rpIt, &idLen) != CborNoError) return CTAP2_ERR_INVALID_CBOR;
          if (idLen == 0 || idLen > CRED_MAX_RPID_LEN) return CTAP2_ERR_LIMIT_EXCEEDED;
          size_t copyLen = sizeof(rpId);
          if (cbor_value_copy_text_string(&rpIt, rpId, &copyLen, nullptr) != CborNoError) return CTAP2_ERR_INVALID_CBOR;
          rpId[sizeof(rpId) - 1] = '\0';
          haveRpId = true;
        }
        if (cbor_value_advance(&rpIt) != CborNoError) return CTAP2_ERR_INVALID_CBOR; // value -> next key/end
      }
      if (cbor_value_leave_container(&it, &rpIt) != CborNoError) return CTAP2_ERR_INVALID_CBOR;
      valueConsumedByLeave = true;
      FIDO_LOG("makeCredential: key 0x02 ok");
    } else if (k == 0x03) {
      if (!cbor_value_is_map(&it)) return CTAP2_ERR_CBOR_UNEXPECTED_TYPE;
#if FIDO_STABILITY_MINIMAL_MAKECRED_PARSE
      // Stability mode: do not parse user map deeply.
      FIDO_LOG("makeCredential: key 0x03 skip deep user parse");
#else
      CborValue uIt;
      if (cbor_value_enter_container(&it, &uIt) != CborNoError) return CTAP2_ERR_INVALID_CBOR;
      uint16_t userLoopGuard = 0;
      while (!cbor_value_at_end(&uIt)) {
        if (++userLoopGuard > 24) return CTAP2_ERR_INVALID_CBOR;
        if (!cbor_value_is_text_string(&uIt)) return CTAP2_ERR_INVALID_CBOR;
        bool keyIsId = false;
        if (cbor_value_text_string_equals(&uIt, "id", &keyIsId) != CborNoError) return CTAP2_ERR_INVALID_CBOR;
        if (cbor_value_advance(&uIt) != CborNoError) return CTAP2_ERR_INVALID_CBOR; // key -> value
        if (keyIsId) {
          if (!cbor_value_is_byte_string(&uIt)) return CTAP2_ERR_CBOR_UNEXPECTED_TYPE;
          size_t n = 0;
          if (cbor_value_calculate_string_length(&uIt, &n) != CborNoError) return CTAP2_ERR_INVALID_CBOR;
          if (n == 0 || n > sizeof(userId)) return CTAP2_ERR_LIMIT_EXCEEDED;
          userIdLen = sizeof(userId);
          if (cbor_value_copy_byte_string(&uIt, userId, &userIdLen, nullptr) != CborNoError) return CTAP2_ERR_INVALID_CBOR;
          haveUser = true;
        }
        if (cbor_value_advance(&uIt) != CborNoError) return CTAP2_ERR_INVALID_CBOR; // value -> next key/end
      }
      if (cbor_value_leave_container(&it, &uIt) != CborNoError) return CTAP2_ERR_INVALID_CBOR;
      valueConsumedByLeave = true;
      FIDO_LOG("makeCredential: key 0x03 ok");
#endif
    } else if (k == 0x04) {
      if (!cbor_value_is_array(&it)) return CTAP2_ERR_CBOR_UNEXPECTED_TYPE;
#if FIDO_STABILITY_MINIMAL_MAKECRED_PARSE
      // Stability mode: accept supported algorithm set from platform request
      // without parsing each descriptor.
      haveAlg = true;
      FIDO_LOG("makeCredential: key 0x04 skip deep alg parse");
#else
      CborValue aIt;
      if (cbor_value_enter_container(&it, &aIt) != CborNoError) return CTAP2_ERR_INVALID_CBOR;
      uint16_t paramsOuterLoopGuard = 0;
      while (!cbor_value_at_end(&aIt)) {
        if (++paramsOuterLoopGuard > 16) return CTAP2_ERR_INVALID_CBOR;
        if (!cbor_value_is_map(&aIt)) return CTAP2_ERR_CBOR_UNEXPECTED_TYPE;
        bool typeOk = false;
        bool algOk = false;
        int alg = 0;
        CborValue pIt;
        if (cbor_value_enter_container(&aIt, &pIt) != CborNoError) return CTAP2_ERR_INVALID_CBOR;
        uint16_t paramsInnerLoopGuard = 0;
        while (!cbor_value_at_end(&pIt)) {
          if (++paramsInnerLoopGuard > 12) return CTAP2_ERR_INVALID_CBOR;
          if (!cbor_value_is_text_string(&pIt)) return CTAP2_ERR_INVALID_CBOR;
          bool keyIsType = false;
          bool keyIsAlg = false;
          if (cbor_value_text_string_equals(&pIt, "type", &keyIsType) != CborNoError) return CTAP2_ERR_INVALID_CBOR;
          if (cbor_value_text_string_equals(&pIt, "alg", &keyIsAlg) != CborNoError) return CTAP2_ERR_INVALID_CBOR;
          if (cbor_value_advance(&pIt) != CborNoError) return CTAP2_ERR_INVALID_CBOR; // key -> value
          if (keyIsType) {
            if (!cbor_value_is_text_string(&pIt)) return CTAP2_ERR_CBOR_UNEXPECTED_TYPE;
            bool isPublicKey = false;
            if (cbor_value_text_string_equals(&pIt, "public-key", &isPublicKey) != CborNoError) return CTAP2_ERR_INVALID_CBOR;
            if (isPublicKey) typeOk = true;
          } else if (keyIsAlg) {
            if (!cbor_value_is_integer(&pIt) || cbor_value_get_int(&pIt, &alg) != CborNoError) return CTAP2_ERR_INVALID_CBOR;
            if (alg == -7) algOk = true;
          }
          if (cbor_value_advance(&pIt) != CborNoError) return CTAP2_ERR_INVALID_CBOR; // value -> next key/end
        }
        if (cbor_value_leave_container(&aIt, &pIt) != CborNoError) return CTAP2_ERR_INVALID_CBOR;
        if (typeOk && algOk) haveAlg = true;
        if (cbor_value_advance(&aIt) != CborNoError) return CTAP2_ERR_INVALID_CBOR;
      }
      if (cbor_value_leave_container(&it, &aIt) != CborNoError) return CTAP2_ERR_INVALID_CBOR;
      valueConsumedByLeave = true;
      FIDO_LOG("makeCredential: key 0x04 ok alg=%u", static_cast<unsigned>(haveAlg));
#endif
    } else if (k == 0x05) {
      // excludeList
      if (!cbor_value_is_array(&it)) return CTAP2_ERR_CBOR_UNEXPECTED_TYPE;
#if FIDO_STABILITY_SKIP_CRED_DESCRIPTOR_PARSE
      // Stability mode: skip parsing credential descriptors to avoid parser crash paths.
      FIDO_LOG("makeCredential: key 0x05 skip descriptor parsing");
#else
      CborValue exIt;
      if (cbor_value_enter_container(&it, &exIt) != CborNoError) return CTAP2_ERR_INVALID_CBOR;
      uint16_t excludeLoopGuard = 0;
      while (!cbor_value_at_end(&exIt)) {
        if (++excludeLoopGuard > 16) return CTAP2_ERR_INVALID_CBOR;
        uint8_t cid[CRED_MAX_ID_LEN];
        size_t cidLen = 0;
        bool typePublicKey = false;
        const uint8_t st = ctap2_parse_pubkey_cred_descriptor(&exIt, cid, sizeof(cid), &cidLen, &typePublicKey);
        if (st != CTAP2_OK) return st;
        if (typePublicKey && cidLen > 0 && cred_store_id_exists(cid, cidLen)) excludeHit = true;
        if (cbor_value_advance(&exIt) != CborNoError) return CTAP2_ERR_INVALID_CBOR;
      }
      if (cbor_value_leave_container(&it, &exIt) != CborNoError) return CTAP2_ERR_INVALID_CBOR;
      valueConsumedByLeave = true;
      FIDO_LOG("makeCredential: key 0x05 ok excludeHit=%u", static_cast<unsigned>(excludeHit));
#endif
    } else if (k == 0x07) {
      // options
      if (!cbor_value_is_map(&it)) return CTAP2_ERR_CBOR_UNEXPECTED_TYPE;
#if FIDO_STABILITY_MINIMAL_MAKECRED_PARSE
      FIDO_LOG("makeCredential: key 0x07 skip options parse");
#else
      CborValue oIt;
      if (cbor_value_enter_container(&it, &oIt) != CborNoError) return CTAP2_ERR_INVALID_CBOR;
      uint16_t optionsLoopGuard = 0;
      while (!cbor_value_at_end(&oIt)) {
        if (++optionsLoopGuard > 12) return CTAP2_ERR_INVALID_CBOR;
        if (!cbor_value_is_text_string(&oIt)) return CTAP2_ERR_INVALID_CBOR;
        bool keyIsRk = false;
        bool keyIsUv = false;
        if (cbor_value_text_string_equals(&oIt, "rk", &keyIsRk) != CborNoError) return CTAP2_ERR_INVALID_CBOR;
        if (cbor_value_text_string_equals(&oIt, "uv", &keyIsUv) != CborNoError) return CTAP2_ERR_INVALID_CBOR;
        if (cbor_value_advance(&oIt) != CborNoError) return CTAP2_ERR_INVALID_CBOR; // key -> value
        if (!cbor_value_is_boolean(&oIt)) return CTAP2_ERR_CBOR_UNEXPECTED_TYPE;
        bool v = false;
        if (cbor_value_get_boolean(&oIt, &v) != CborNoError) return CTAP2_ERR_INVALID_CBOR;
        if (keyIsRk) optionRk = v;
        else if (keyIsUv) optionUv = v;
        if (cbor_value_advance(&oIt) != CborNoError) return CTAP2_ERR_INVALID_CBOR;
      }
      if (cbor_value_leave_container(&it, &oIt) != CborNoError) return CTAP2_ERR_INVALID_CBOR;
      valueConsumedByLeave = true;
      FIDO_LOG("makeCredential: key 0x07 ok rk=%u uv=%u", static_cast<unsigned>(optionRk), static_cast<unsigned>(optionUv));
#endif
    } else if (k == 0x08) {
      if (!cbor_value_is_byte_string(&it)) return CTAP2_ERR_CBOR_UNEXPECTED_TYPE;
      size_t n = 0;
      if (cbor_value_calculate_string_length(&it, &n) != CborNoError) return CTAP2_ERR_INVALID_CBOR;
      if (n != CTAP_PIN_UV_AUTH_PARAM_LEN) return CTAP2_ERR_INVALID_LENGTH;
      size_t copy = sizeof(pinUvAuthParam);
      if (cbor_value_copy_byte_string(&it, pinUvAuthParam, &copy, nullptr) != CborNoError) return CTAP2_ERR_INVALID_CBOR;
      if (copy != sizeof(pinUvAuthParam)) return CTAP2_ERR_INVALID_LENGTH;
      havePinUvAuthParam = true;
    } else if (k == 0x09) {
      if (!cbor_value_is_integer(&it) || cbor_value_get_int(&it, &pinUvAuthProtocol) != CborNoError) return CTAP2_ERR_INVALID_CBOR;
      havePinUvAuthProtocol = true;
    }

    if (!valueConsumedByLeave) {
      if (cbor_value_advance(&it) != CborNoError) return CTAP2_ERR_INVALID_CBOR;
    }
  }
#if FIDO_STABILITY_MINIMAL_MAKECRED_PARSE
  if (!minimalParsedEnough) cbor_value_leave_container(&root, &it);
#else
  cbor_value_leave_container(&root, &it);
#endif
  FIDO_LOG("makeCredential: finished parse loop");

#if FIDO_STABILITY_MINIMAL_MAKECRED_PARSE
  haveUser = true;
  haveAlg = true;
#endif

  if (excludeHit) return CTAP2_ERR_CREDENTIAL_EXCLUDED;
  if (!haveClientHash || !haveRpId || !haveUser) return CTAP2_ERR_MISSING_PARAMETER;
  if (!haveAlg) return CTAP2_ERR_UNSUPPORTED_ALGORITHM;
  if (optionUv) return CTAP2_ERR_UNSUPPORTED_OPTION;
  if (pinGate) {
    if (!fido_client_pin_available()) return CTAP2_ERR_PIN_NOT_SET;
    if (!fido_client_pin_hash_ready()) return CTAP2_ERR_PIN_NOT_SET;
    if (!havePinUvAuthParam || !havePinUvAuthProtocol) return CTAP2_ERR_PIN_REQUIRED;
    if (pinUvAuthProtocol != CTAP_PIN_UV_AUTH_PROTOCOL_1) return CTAP2_ERR_PIN_AUTH_INVALID;
    if (!fido_verify_pin_uv_auth_param(clientDataHash, pinUvAuthParam)) return CTAP2_ERR_PIN_AUTH_INVALID;
    pinAuthSatisfied = true;
  }
  FIDO_LOG("makeCredential: parsed rpId=%s userIdLen=%u optionRk=%u", rpId, static_cast<unsigned>(userIdLen),
           static_cast<unsigned>(optionRk));

#if FIDO_MAKECRED_TEST_STAGE == 1
  FIDO_LOG("makeCredential: test-stage 1 (after parse)");
  return CTAP2_ERR_INVALID_CBOR;
#endif

#if FIDO_FORCE_MAKECRED_PARSE_ONLY_ERROR
  FIDO_LOG("makeCredential: forced parse-only error");
  return CTAP2_ERR_INVALID_CBOR;
#endif

  // Create keypair and credentialId
  EcKeyPair kp;
  FIDO_LOG("makeCredential: ec_generate start");
  if (!ec_generate(&kp)) return CTAP2_ERR_PROCESSING;
  FIDO_LOG("makeCredential: ec_generate done");

#if FIDO_MAKECRED_TEST_STAGE == 2
  FIDO_LOG("makeCredential: test-stage 2 (after keygen)");
  return CTAP2_ERR_INVALID_CBOR;
#endif

  uint8_t credId[16];
  for (uint8_t tries = 0; tries < 10; ++tries) {
    esp_fill_random(credId, sizeof(credId));
    if (!cred_store_id_exists(credId, sizeof(credId))) break;
  }
  if (cred_store_id_exists(credId, sizeof(credId))) return CTAP2_ERR_KEY_STORE_FULL;
  FIDO_LOG("makeCredential: credId allocated");

  uint8_t secret[CRED_MAX_SECRET_LEN];
  size_t secretLen = 0;
  FIDO_LOG("makeCredential: build_cred_secret start");
  if (!build_cred_secret(optionRk, userId, userIdLen, kp.priv, secret, &secretLen)) return CTAP2_ERR_PROCESSING;
  FIDO_LOG("makeCredential: build_cred_secret done len=%u", static_cast<unsigned>(secretLen));

  FIDO_LOG("makeCredential: cred_store_add start");
  if (!cred_store_add_credential(rpId, credId, sizeof(credId), secret, secretLen)) return CTAP2_ERR_KEY_STORE_FULL;
  FIDO_LOG("makeCredential: cred_store_add done");

#if FIDO_MAKECRED_TEST_STAGE == 3
  FIDO_LOG("makeCredential: test-stage 3 (after store)");
  return CTAP2_ERR_INVALID_CBOR;
#endif

  // Build COSE public key
  uint8_t cose[96];
  size_t coseLen = 0;
  FIDO_LOG("makeCredential: build cose start");
  if (!ctap2_build_cose_p256_es256(kp.x, kp.y, cose, sizeof(cose), &coseLen)) return CTAP2_ERR_PROCESSING;
  FIDO_LOG("makeCredential: build cose done len=%u", static_cast<unsigned>(coseLen));

  // Build authenticatorData
  uint8_t rpIdHash[32];
  FIDO_LOG("makeCredential: rpId hash start");
  if (!sha256_ret(reinterpret_cast<const uint8_t*>(rpId), strlen(rpId), rpIdHash)) return CTAP2_ERR_PROCESSING;
  FIDO_LOG("makeCredential: rpId hash done");

  uint8_t authData[256];
  size_t authLen = 0;
  memcpy(authData + authLen, rpIdHash, 32);
  authLen += 32;
  const uint8_t flags = 0x01 /*UP*/ | (pinAuthSatisfied ? 0x04 : 0x00) /*UV*/ | 0x40 /*AT*/;
  authData[authLen++] = flags;
  write_be_u32(authData + authLen, fidoSignCount);
  authLen += 4;
  memcpy(authData + authLen, CTAP_AAGUID, sizeof(CTAP_AAGUID));
  authLen += sizeof(CTAP_AAGUID);
  write_be_u16(authData + authLen, sizeof(credId));
  authLen += 2;
  memcpy(authData + authLen, credId, sizeof(credId));
  authLen += sizeof(credId);
  memcpy(authData + authLen, cose, coseLen);
  authLen += coseLen;

  // Attestation
  const bool attestNone = (attestationProfile == AttestationProfile::None);
  const char* fmt = attestNone ? "none" : "packed";

  uint8_t sigDer[80];
  size_t sigLen = 0;
  if (!attestNone) {
    uint8_t msg[256 + 32];
    const size_t msgLen = authLen + 32;
    memcpy(msg, authData, authLen);
    memcpy(msg + authLen, clientDataHash, 32);
    uint8_t msgHash[32];
    if (!sha256_ret(msg, msgLen, msgHash)) return CTAP2_ERR_PROCESSING;
    if (!ec_sign_der(kp.priv, msgHash, sigDer, sizeof(sigDer), &sigLen)) return CTAP2_ERR_PROCESSING;
  }
  FIDO_LOG("makeCredential: attestation done fmt=%s sigLen=%u", fmt, static_cast<unsigned>(sigLen));

#if FIDO_MAKECRED_TEST_STAGE == 4
  FIDO_LOG("makeCredential: test-stage 4 (after attestation)");
  return CTAP2_ERR_INVALID_CBOR;
#endif

  // Build response map (definite length)
  CborEncoder enc;
  cbor_encoder_init(&enc, out, outMax, 0);
  CborEncoder map;
  if (cbor_encoder_create_map(&enc, &map, 3) != CborNoError) return CTAP2_ERR_CBOR_PARSING;
  if (cbor_encode_int(&map, 0x01) != CborNoError) return CTAP2_ERR_CBOR_PARSING;
  if (cbor_encode_text_stringz(&map, fmt) != CborNoError) return CTAP2_ERR_CBOR_PARSING;
  if (cbor_encode_int(&map, 0x02) != CborNoError) return CTAP2_ERR_CBOR_PARSING;
  if (cbor_encode_byte_string(&map, authData, authLen) != CborNoError) return CTAP2_ERR_CBOR_PARSING;
  if (cbor_encode_int(&map, 0x03) != CborNoError) return CTAP2_ERR_CBOR_PARSING;
  CborEncoder att;
  const size_t attPairs = attestNone ? 0 : 2;
  if (cbor_encoder_create_map(&map, &att, attPairs) != CborNoError) return CTAP2_ERR_CBOR_PARSING;
  if (!attestNone) {
    if (cbor_encode_text_stringz(&att, "alg") != CborNoError) return CTAP2_ERR_CBOR_PARSING;
    if (cbor_encode_int(&att, -7) != CborNoError) return CTAP2_ERR_CBOR_PARSING;
    if (cbor_encode_text_stringz(&att, "sig") != CborNoError) return CTAP2_ERR_CBOR_PARSING;
    if (cbor_encode_byte_string(&att, sigDer, sigLen) != CborNoError) return CTAP2_ERR_CBOR_PARSING;
  }
  if (cbor_encoder_close_container(&map, &att) != CborNoError) return CTAP2_ERR_CBOR_PARSING;
  if (cbor_encoder_close_container(&enc, &map) != CborNoError) return CTAP2_ERR_CBOR_PARSING;
  *outLen = cbor_encoder_get_buffer_size(&enc, out);
  FIDO_LOG("makeCredential: response cborLen=%u", static_cast<unsigned>(*outLen));
  FIDO_LOG("makeCredential OK rpId=%s credIdLen=%u authDataLen=%u fmt=%s", rpId, static_cast<unsigned>(sizeof(credId)),
           static_cast<unsigned>(authLen), fmt);
  return CTAP2_OK;
}

static uint8_t ctap2_get_assertion(const uint8_t* req, const size_t reqLen, uint8_t* out, const size_t outMax, size_t* outLen) {
  if (!req || !out || !outLen) return CTAP1_ERR_OTHER;
  *outLen = 0;
  if (reqLen == 0) return CTAP2_ERR_INVALID_LENGTH;
  FIDO_LOG("getAssertion: begin reqLen=%u", static_cast<unsigned>(reqLen));

  CborParser parser;
  CborValue root;
  if (cbor_parser_init(req, reqLen, 0, &parser, &root) != CborNoError) return CTAP2_ERR_INVALID_CBOR;
  if (!cbor_value_is_map(&root)) return CTAP2_ERR_CBOR_UNEXPECTED_TYPE;
  FIDO_LOG("getAssertion: root is map");

  char rpId[CRED_MAX_RPID_LEN + 1];
  rpId[0] = '\0';
  bool haveRpId = false;
  uint8_t clientDataHash[32] = {0};
  bool haveClientHash = false;
  bool optionUv = false;
#if FIDO_REQUIRE_PIN
  const bool pinGate = security_pin_configured() && !security_pin_unlocked_now();
#else
  const bool pinGate = false;
#endif
  bool pinAuthSatisfied = false;
  uint8_t pinUvAuthParam[CTAP_PIN_UV_AUTH_PARAM_LEN] = {0};
  bool havePinUvAuthParam = false;
  int pinUvAuthProtocol = 0;
  bool havePinUvAuthProtocol = false;

  // allowList required in this minimal implementation (non-discoverable credentials)
  static constexpr size_t kMaxAllowCreds = 8;
  uint8_t allowCredIds[kMaxAllowCreds][CRED_MAX_ID_LEN];
  size_t allowCredLens[kMaxAllowCreds] = {0};
  size_t allowCredCount = 0;

  uint8_t selectedCredId[CRED_MAX_ID_LEN];
  size_t selectedCredIdLen = 0;
  uint8_t selectedSecret[CRED_MAX_SECRET_LEN];
  size_t selectedSecretLen = 0;
  bool haveCred = false;

  CborValue it;
  if (cbor_value_enter_container(&root, &it) != CborNoError) return CTAP2_ERR_INVALID_CBOR;
  uint16_t topLoopGuard = 0;
  bool minimalParsedEnough = false;
  while (!cbor_value_at_end(&it)) {
    if (++topLoopGuard > 64) return CTAP2_ERR_INVALID_CBOR;
    bool valueConsumedByLeave = false;
    int k = 0;
    if (!cbor_value_is_integer(&it) || cbor_value_get_int(&it, &k) != CborNoError) return CTAP2_ERR_INVALID_CBOR;
    if (cbor_value_advance(&it) != CborNoError) return CTAP2_ERR_INVALID_CBOR;
    FIDO_LOG("getAssertion: key=%d", k);

#if FIDO_STABILITY_MINIMAL_MAKECRED_PARSE
    if (!pinGate && haveRpId && haveClientHash && (k != 0x01) && (k != 0x02)) {
      FIDO_LOG("getAssertion: minimal parse early exit at key=%d", k);
      minimalParsedEnough = true;
      break;
    }
#endif

    if (k == 0x01) {
      if (!cbor_value_is_text_string(&it)) return CTAP2_ERR_CBOR_UNEXPECTED_TYPE;
      size_t idLen = 0;
      if (cbor_value_calculate_string_length(&it, &idLen) != CborNoError) return CTAP2_ERR_INVALID_CBOR;
      if (idLen == 0 || idLen > CRED_MAX_RPID_LEN) return CTAP2_ERR_LIMIT_EXCEEDED;
      size_t copyLen = sizeof(rpId);
      if (cbor_value_copy_text_string(&it, rpId, &copyLen, nullptr) != CborNoError) return CTAP2_ERR_INVALID_CBOR;
      rpId[sizeof(rpId) - 1] = '\0';
      haveRpId = true;
      FIDO_LOG("getAssertion: key 0x01 rpId=%s", rpId);
    } else if (k == 0x02) {
      if (!cbor_value_is_byte_string(&it)) return CTAP2_ERR_CBOR_UNEXPECTED_TYPE;
      size_t n = 0;
      if (cbor_value_calculate_string_length(&it, &n) != CborNoError) return CTAP2_ERR_INVALID_CBOR;
      if (n != 32) return CTAP2_ERR_INVALID_LENGTH;
      size_t copy = sizeof(clientDataHash);
      if (cbor_value_copy_byte_string(&it, clientDataHash, &copy, nullptr) != CborNoError) return CTAP2_ERR_INVALID_CBOR;
      haveClientHash = true;
      FIDO_LOG("getAssertion: key 0x02 clientDataHash ok");
    } else if (k == 0x03) {
      if (!cbor_value_is_array(&it)) return CTAP2_ERR_CBOR_UNEXPECTED_TYPE;
#if FIDO_STABILITY_SKIP_CRED_DESCRIPTOR_PARSE
      // Stability mode: skip allowList descriptor parsing; silent probing will
      // return NO_CREDENTIALS without touching descriptor internals.
      FIDO_LOG("getAssertion: key 0x03 skip descriptor parsing");
#else
      CborValue aIt;
      if (cbor_value_enter_container(&it, &aIt) != CborNoError) return CTAP2_ERR_INVALID_CBOR;
      uint16_t allowListLoopGuard = 0;
      while (!cbor_value_at_end(&aIt)) {
        if (++allowListLoopGuard > 16) return CTAP2_ERR_INVALID_CBOR;
        uint8_t cid[CRED_MAX_ID_LEN];
        size_t cidLen = 0;
        bool typePublicKey = false;
        const uint8_t st = ctap2_parse_pubkey_cred_descriptor(&aIt, cid, sizeof(cid), &cidLen, &typePublicKey);
        if (st != CTAP2_OK) return st;
        if (typePublicKey && cidLen > 0) {
          if (allowCredCount >= kMaxAllowCreds) return CTAP2_ERR_LIMIT_EXCEEDED;
          memcpy(allowCredIds[allowCredCount], cid, cidLen);
          allowCredLens[allowCredCount] = cidLen;
          allowCredCount++;
        }
        if (cbor_value_advance(&aIt) != CborNoError) return CTAP2_ERR_INVALID_CBOR;
      }
      if (cbor_value_leave_container(&it, &aIt) != CborNoError) return CTAP2_ERR_INVALID_CBOR;
      valueConsumedByLeave = true;
      FIDO_LOG("getAssertion: key 0x03 allowCredCount=%u", static_cast<unsigned>(allowCredCount));
#endif
    } else if (k == 0x05) {
      // options
      if (!cbor_value_is_map(&it)) return CTAP2_ERR_CBOR_UNEXPECTED_TYPE;
      CborValue oIt;
      if (cbor_value_enter_container(&it, &oIt) != CborNoError) return CTAP2_ERR_INVALID_CBOR;
      uint16_t optionsLoopGuard = 0;
      while (!cbor_value_at_end(&oIt)) {
        if (++optionsLoopGuard > 12) return CTAP2_ERR_INVALID_CBOR;
        if (!cbor_value_is_text_string(&oIt)) return CTAP2_ERR_INVALID_CBOR;
        bool keyIsUv = false;
        if (cbor_value_text_string_equals(&oIt, "uv", &keyIsUv) != CborNoError) return CTAP2_ERR_INVALID_CBOR;
        if (cbor_value_advance(&oIt) != CborNoError) return CTAP2_ERR_INVALID_CBOR; // key -> value
        if (!cbor_value_is_boolean(&oIt)) return CTAP2_ERR_CBOR_UNEXPECTED_TYPE;
        bool v = false;
        if (cbor_value_get_boolean(&oIt, &v) != CborNoError) return CTAP2_ERR_INVALID_CBOR;
        if (keyIsUv) optionUv = v;
        if (cbor_value_advance(&oIt) != CborNoError) return CTAP2_ERR_INVALID_CBOR;
      }
      if (cbor_value_leave_container(&it, &oIt) != CborNoError) return CTAP2_ERR_INVALID_CBOR;
      valueConsumedByLeave = true;
      FIDO_LOG("getAssertion: key 0x05 options uv=%u", static_cast<unsigned>(optionUv));
    } else if (k == 0x06) {
      if (!cbor_value_is_byte_string(&it)) return CTAP2_ERR_CBOR_UNEXPECTED_TYPE;
      size_t n = 0;
      if (cbor_value_calculate_string_length(&it, &n) != CborNoError) return CTAP2_ERR_INVALID_CBOR;
      if (n != CTAP_PIN_UV_AUTH_PARAM_LEN) return CTAP2_ERR_INVALID_LENGTH;
      size_t copy = sizeof(pinUvAuthParam);
      if (cbor_value_copy_byte_string(&it, pinUvAuthParam, &copy, nullptr) != CborNoError) return CTAP2_ERR_INVALID_CBOR;
      if (copy != sizeof(pinUvAuthParam)) return CTAP2_ERR_INVALID_LENGTH;
      havePinUvAuthParam = true;
    } else if (k == 0x07) {
      if (!cbor_value_is_integer(&it) || cbor_value_get_int(&it, &pinUvAuthProtocol) != CborNoError) return CTAP2_ERR_INVALID_CBOR;
      havePinUvAuthProtocol = true;
    }

    if (!valueConsumedByLeave) {
      if (cbor_value_advance(&it) != CborNoError) return CTAP2_ERR_INVALID_CBOR;
    }
  }
#if FIDO_STABILITY_MINIMAL_MAKECRED_PARSE
  if (!minimalParsedEnough) cbor_value_leave_container(&root, &it);
#else
  cbor_value_leave_container(&root, &it);
#endif
  FIDO_LOG("getAssertion: parse done haveRpId=%u haveClientHash=%u allowCredCount=%u", static_cast<unsigned>(haveRpId),
           static_cast<unsigned>(haveClientHash), static_cast<unsigned>(allowCredCount));

  if (!haveRpId || !haveClientHash) return CTAP2_ERR_MISSING_PARAMETER;
  if (optionUv) return CTAP2_ERR_UNSUPPORTED_OPTION;
  if (pinGate) {
    if (!fido_client_pin_available()) return CTAP2_ERR_PIN_NOT_SET;
    if (!fido_client_pin_hash_ready()) return CTAP2_ERR_PIN_NOT_SET;
    if (!havePinUvAuthParam || !havePinUvAuthProtocol) return CTAP2_ERR_PIN_REQUIRED;
    if (pinUvAuthProtocol != CTAP_PIN_UV_AUTH_PROTOCOL_1) return CTAP2_ERR_PIN_AUTH_INVALID;
    if (!fido_verify_pin_uv_auth_param(clientDataHash, pinUvAuthParam)) return CTAP2_ERR_PIN_AUTH_INVALID;
    pinAuthSatisfied = true;
  }
  for (size_t i = 0; i < allowCredCount && !haveCred; ++i) {
    char storedRp[CRED_MAX_RPID_LEN + 1];
    uint8_t secret[CRED_MAX_SECRET_LEN];
    size_t secretLen = 0;
    if (cred_store_lookup(allowCredIds[i], allowCredLens[i], storedRp, sizeof(storedRp), secret, &secretLen)) {
      if (strcmp(storedRp, rpId) == 0) {
        memcpy(selectedCredId, allowCredIds[i], allowCredLens[i]);
        selectedCredIdLen = allowCredLens[i];
        memcpy(selectedSecret, secret, secretLen);
        selectedSecretLen = secretLen;
        haveCred = true;
      }
    }
    secure_zero(secret, secretLen);
  }
  if (!haveCred && allowCredCount == 0) {
    if (runtime_cred_lookup_by_rpid(rpId, selectedCredId, sizeof(selectedCredId), &selectedCredIdLen, selectedSecret,
                                    sizeof(selectedSecret), &selectedSecretLen)) {
      haveCred = true;
      FIDO_LOG("getAssertion: runtime rp fallback selected idLen=%u", static_cast<unsigned>(selectedCredIdLen));
    }
  }
  FIDO_LOG("getAssertion: credential matched=%u", static_cast<unsigned>(haveCred));
  if (!haveCred) return CTAP2_ERR_NO_CREDENTIALS;

  bool rk = false;
  uint8_t userHandle[64];
  size_t userHandleLen = 0;
  uint8_t priv[32];
  if (!parse_cred_secret(selectedSecret, selectedSecretLen, &rk, userHandle, &userHandleLen, priv)) {
    secure_zero(selectedSecret, selectedSecretLen);
    return CTAP2_ERR_INVALID_CREDENTIAL;
  }
  secure_zero(selectedSecret, selectedSecretLen);

  // Build authenticatorData
  uint8_t rpIdHash[32];
  if (!sha256_ret(reinterpret_cast<const uint8_t*>(rpId), strlen(rpId), rpIdHash)) return CTAP2_ERR_PROCESSING;

  // Update signCount
  fidoSignCount++;
  save_sign_count(fidoSignCount);

  uint8_t authData[37];
  memcpy(authData + 0, rpIdHash, 32);
  authData[32] = static_cast<uint8_t>(0x01U | (pinAuthSatisfied ? 0x04U : 0x00U)); // UP + optional UV
  write_be_u32(authData + 33, fidoSignCount);

  // Signature over authData || clientDataHash
  uint8_t msg[37 + 32];
  memcpy(msg, authData, 37);
  memcpy(msg + 37, clientDataHash, 32);
  uint8_t msgHash[32];
  if (!sha256_ret(msg, sizeof(msg), msgHash)) return CTAP2_ERR_PROCESSING;
  uint8_t sigDer[80];
  size_t sigLen = 0;
  if (!ec_sign_der(priv, msgHash, sigDer, sizeof(sigDer), &sigLen)) return CTAP2_ERR_PROCESSING;

  // Build response map (definite length): credential, authData, signature
  CborEncoder enc;
  cbor_encoder_init(&enc, out, outMax, 0);
  CborEncoder map;
  if (cbor_encoder_create_map(&enc, &map, 3) != CborNoError) return CTAP2_ERR_CBOR_PARSING;
  if (cbor_encode_int(&map, 0x01) != CborNoError) return CTAP2_ERR_CBOR_PARSING;
  CborEncoder cred;
  if (cbor_encoder_create_map(&map, &cred, 2) != CborNoError) return CTAP2_ERR_CBOR_PARSING;
  if (cbor_encode_text_stringz(&cred, "type") != CborNoError) return CTAP2_ERR_CBOR_PARSING;
  if (cbor_encode_text_stringz(&cred, "public-key") != CborNoError) return CTAP2_ERR_CBOR_PARSING;
  if (cbor_encode_text_stringz(&cred, "id") != CborNoError) return CTAP2_ERR_CBOR_PARSING;
  if (cbor_encode_byte_string(&cred, selectedCredId, selectedCredIdLen) != CborNoError) return CTAP2_ERR_CBOR_PARSING;
  if (cbor_encoder_close_container(&map, &cred) != CborNoError) return CTAP2_ERR_CBOR_PARSING;
  if (cbor_encode_int(&map, 0x02) != CborNoError) return CTAP2_ERR_CBOR_PARSING;
  if (cbor_encode_byte_string(&map, authData, sizeof(authData)) != CborNoError) return CTAP2_ERR_CBOR_PARSING;
  if (cbor_encode_int(&map, 0x03) != CborNoError) return CTAP2_ERR_CBOR_PARSING;
  if (cbor_encode_byte_string(&map, sigDer, sigLen) != CborNoError) return CTAP2_ERR_CBOR_PARSING;
  if (cbor_encoder_close_container(&enc, &map) != CborNoError) return CTAP2_ERR_CBOR_PARSING;
  *outLen = cbor_encoder_get_buffer_size(&enc, out);
  FIDO_LOG("getAssertion OK rpId=%s credIdLen=%u signCount=%lu", rpId, static_cast<unsigned>(selectedCredIdLen),
           static_cast<unsigned long>(fidoSignCount));
  return CTAP2_OK;
}

static uint8_t ctap2_reset() {
  runtime_cred_clear();
#if !FIDO_DISABLE_PERSISTENCE
  cred_store_clear();
#endif
  fidoSignCount = 0;
  save_sign_count(0);
  return CTAP2_OK;
}

// FIDO descriptor with explicit FEATURE report support.
// Some Windows CTAP paths probe/report via HID feature transactions.
static const uint8_t fido_report_descriptor[] = {
  HID_USAGE_PAGE_N(HID_USAGE_PAGE_FIDO, 2),
  HID_USAGE(HID_USAGE_FIDO_U2FHID),
  HID_COLLECTION(HID_COLLECTION_APPLICATION),
#if USB_ENABLE_KBM_HID
    HID_REPORT_ID(FIDO_HID_REPORT_ID)
#endif
    HID_USAGE(HID_USAGE_FIDO_DATA_IN),
    HID_LOGICAL_MIN(0),
    HID_LOGICAL_MAX_N(0xFF, 2),
    HID_REPORT_SIZE(8),
    HID_REPORT_COUNT(FIDO_HID_PACKET_SIZE),
    HID_INPUT(HID_DATA | HID_VARIABLE | HID_ABSOLUTE),
    HID_USAGE(HID_USAGE_FIDO_DATA_OUT),
    HID_LOGICAL_MIN(0),
    HID_LOGICAL_MAX_N(0xFF, 2),
    HID_REPORT_SIZE(8),
    HID_REPORT_COUNT(FIDO_HID_PACKET_SIZE),
    HID_OUTPUT(HID_DATA | HID_VARIABLE | HID_ABSOLUTE),
    HID_USAGE(HID_USAGE_FIDO_DATA_OUT),
    HID_LOGICAL_MIN(0),
    HID_LOGICAL_MAX_N(0xFF, 2),
    HID_REPORT_SIZE(8),
    HID_REPORT_COUNT(FIDO_HID_PACKET_SIZE),
    HID_FEATURE(HID_DATA | HID_VARIABLE | HID_ABSOLUTE),
  HID_COLLECTION_END
};

struct FidoRxState {
  bool active = false;
  uint32_t cid = 0;
  uint8_t cmd = 0;
  uint16_t total = 0;
  uint16_t received = 0;
  uint8_t nextSeq = 0;
  uint32_t lastMs = 0;
};

static FidoRxState fidoRx;

struct FidoRequest {
  volatile bool ready = false;
  uint32_t cid = 0;
  uint8_t cmd = 0;
  uint16_t len = 0;
  uint8_t data[FIDO_MAX_PAYLOAD];
};

static FidoRequest fidoReq;

struct PendingCtap {
  bool active = false;
  uint32_t cid = 0;
  uint8_t cmd = 0; // CTAP command byte
  uint16_t len = 0;
  uint8_t data[FIDO_MAX_PAYLOAD];
  uint32_t startedMs = 0;
  uint32_t lastKeepaliveMs = 0;
  bool sawButtonRelease = false;
  uint32_t buttonDownSinceMs = 0;
};

static PendingCtap pendingCtap;

struct ActiveCtap {
  volatile bool active = false;
  volatile uint32_t cid = 0;
};

static ActiveCtap activeCtap;
static portMUX_TYPE fidoFeatureQueueMux = portMUX_INITIALIZER_UNLOCKED;

static void fido_hid_on_packet(const uint8_t* buffer, uint16_t lenBytes);

class USBHIDFidoDevice final : public USBHIDDevice {
private:
  USBHID hid;
  static constexpr uint8_t FEATURE_QUEUE_DEPTH = 24;
  uint8_t featureQueue[FEATURE_QUEUE_DEPTH][FIDO_HID_PACKET_SIZE];
  uint8_t featureHead = 0;
  uint8_t featureTail = 0;
  uint8_t featureCount = 0;

  void queueFeaturePacket(const uint8_t* data, size_t lenBytes) {
    if (!data || lenBytes != FIDO_HID_PACKET_SIZE) return;
    portENTER_CRITICAL(&fidoFeatureQueueMux);
    memcpy(featureQueue[featureTail], data, FIDO_HID_PACKET_SIZE);
    featureTail = static_cast<uint8_t>((featureTail + 1U) % FEATURE_QUEUE_DEPTH);
    if (featureCount < FEATURE_QUEUE_DEPTH) {
      featureCount++;
    } else {
      // Drop oldest packet when full.
      featureHead = static_cast<uint8_t>((featureHead + 1U) % FEATURE_QUEUE_DEPTH);
    }
    portEXIT_CRITICAL(&fidoFeatureQueueMux);
  }

  bool popFeaturePacket(uint8_t* out) {
    if (!out) return false;
    portENTER_CRITICAL(&fidoFeatureQueueMux);
    if (featureCount == 0) {
      portEXIT_CRITICAL(&fidoFeatureQueueMux);
      return false;
    }
    memcpy(out, featureQueue[featureHead], FIDO_HID_PACKET_SIZE);
    featureHead = static_cast<uint8_t>((featureHead + 1U) % FEATURE_QUEUE_DEPTH);
    featureCount--;
    portEXIT_CRITICAL(&fidoFeatureQueueMux);
    return true;
  }

  void clearFeatureQueue() {
    portENTER_CRITICAL(&fidoFeatureQueueMux);
    featureHead = 0;
    featureTail = 0;
    featureCount = 0;
    portEXIT_CRITICAL(&fidoFeatureQueueMux);
  }

  void dispatchNormalizedPacket(const uint8_t* pkt64) {
    if (!pkt64) return;
    fidoDiag.totalNormalizedPackets++;
    fido_hid_on_packet(pkt64, FIDO_HID_PACKET_SIZE);
  }

  void handleIncomingReport(uint8_t report_id, const uint8_t* buffer, uint16_t lenBytes) {
    if (!buffer) return;
    fidoDiag.lastReportIdSeen = report_id;
    fidoDiag.lastReportLenSeen = lenBytes;
    const bool noReportIdMode = (FIDO_HID_REPORT_ID == HID_REPORT_ID_NONE);
    if (!noReportIdMode && report_id != 0 && report_id != FIDO_HID_REPORT_ID) {
      // Keep parsing anyway: some host paths surface an unexpected report ID even
      // though payload bytes are valid CTAPHID packets.
      fidoDiag.totalUnexpectedReportId++;
      fidoDiag.lastReportIdDropped = report_id;
    }

    if (lenBytes == FIDO_HID_PACKET_SIZE) {
      dispatchNormalizedPacket(buffer);
      return;
    }

    // Most host paths deliver 65-byte reports with a leading report-ID byte.
    // Always normalize by stripping that first byte to avoid misaligned CTAPHID.
    if (lenBytes == (FIDO_HID_PACKET_SIZE + 1)) {
      (void)noReportIdMode;
      dispatchNormalizedPacket(buffer + 1);
      return;
    }

    fidoDiag.totalDroppedBadLen++;
    fidoDiag.lastReportLenDropped = lenBytes;
  }

public:
  USBHIDFidoDevice() : hid(HID_ITF_PROTOCOL_NONE) {
    static bool initialized = false;
    if (!initialized) {
      initialized = true;
      hid.addDevice(this, sizeof(fido_report_descriptor));
    }
  }

  void begin() {
    hid.begin();
    clearFeatureQueue();
  }

  void clearQueue() { clearFeatureQueue(); }

  void task() {}

  bool sendPacket(const uint8_t* data, const size_t lenBytes) {
    queueFeaturePacket(data, lenBytes);
    return hid.SendReport(FIDO_HID_REPORT_ID, data, lenBytes, 100);
  }

  uint16_t _onGetDescriptor(uint8_t* dst) override {
    memcpy(dst, fido_report_descriptor, sizeof(fido_report_descriptor));
    return sizeof(fido_report_descriptor);
  }

  uint16_t _onGetFeature(uint8_t report_id, uint8_t* buffer, uint16_t lenBytes) override {
    if (!buffer) return 0;
    fidoDiag.totalHidGetFeatureCallbacks++;
    fidoDiag.lastReportIdSeen = report_id;
    fidoDiag.lastReportLenSeen = lenBytes;
    const bool noReportIdMode = (FIDO_HID_REPORT_ID == HID_REPORT_ID_NONE);
    if (!noReportIdMode && report_id != 0 && report_id != FIDO_HID_REPORT_ID) {
      // Accept anyway for compatibility; we still emit a valid FIDO frame.
      fidoDiag.totalUnexpectedReportId++;
      fidoDiag.lastReportIdDropped = report_id;
    }

    uint8_t pkt[FIDO_HID_PACKET_SIZE];
    if (!popFeaturePacket(pkt)) {
      // If host polls before a command is fully processed, answer with keepalive
      // instead of an empty/stale frame.
      uint32_t kaCid = 0;
      uint8_t kaStatus = CTAPHID_KEEPALIVE_STATUS_PROCESSING;
      bool haveKeepalive = false;
      if (pendingCtap.active) {
        haveKeepalive = true;
        kaCid = pendingCtap.cid;
#if FIDO_REQUIRE_BOOT_BUTTON_FOR_UP
        kaStatus = CTAPHID_KEEPALIVE_STATUS_UP_NEEDED;
#endif
      } else if (activeCtap.active) {
        haveKeepalive = true;
        kaCid = activeCtap.cid;
      } else if (fidoReq.ready) {
        haveKeepalive = true;
        kaCid = fidoReq.cid;
      } else if (fidoRx.active) {
        haveKeepalive = true;
        kaCid = fidoRx.cid;
      }

      if (haveKeepalive && kaCid != 0) {
        memset(pkt, 0, sizeof(pkt));
        write_be_u32(pkt + 0, kaCid);
        pkt[4] = static_cast<uint8_t>(0x80U | (CTAPHID_CMD_KEEPALIVE & 0x7FU));
        write_be_u16(pkt + 5, 1);
        pkt[7] = kaStatus;
      } else {
        memset(pkt, 0, sizeof(pkt));
      }
    }

    if (noReportIdMode) {
      // Some host APIs still allocate an extra leading byte for report-id 0.
      if (lenBytes >= (FIDO_HID_PACKET_SIZE + 1U)) {
        buffer[0] = 0;
        memcpy(buffer + 1, pkt, FIDO_HID_PACKET_SIZE);
        return static_cast<uint16_t>(FIDO_HID_PACKET_SIZE + 1U);
      }
      if (lenBytes >= FIDO_HID_PACKET_SIZE) {
        memcpy(buffer, pkt, FIDO_HID_PACKET_SIZE);
        return FIDO_HID_PACKET_SIZE;
      }
      memset(buffer, 0, lenBytes);
      return lenBytes;
    }

    if (lenBytes >= (FIDO_HID_PACKET_SIZE + 1U)) {
      const uint8_t outReportId = (report_id != 0) ? report_id : FIDO_HID_REPORT_ID;
      buffer[0] = outReportId;
      memcpy(buffer + 1, pkt, FIDO_HID_PACKET_SIZE);
      return static_cast<uint16_t>(FIDO_HID_PACKET_SIZE + 1U);
    }
    if (lenBytes >= FIDO_HID_PACKET_SIZE) {
      memcpy(buffer, pkt, FIDO_HID_PACKET_SIZE);
      return FIDO_HID_PACKET_SIZE;
    }
    memset(buffer, 0, lenBytes);
    return lenBytes;
  }

  void _onOutput(uint8_t report_id, const uint8_t* buffer, uint16_t lenBytes) override {
    fidoDiag.totalHidOutCallbacks++;
    handleIncomingReport(report_id, buffer, lenBytes);
  }

  void _onSetFeature(uint8_t report_id, const uint8_t* buffer, uint16_t lenBytes) override {
    // ESP32 Arduino's TinyUSB shim can route report-id traffic via SetFeature.
    // Handle it the same way so CTAPHID packets are not dropped on Windows.
    fidoDiag.totalHidSetFeatureCallbacks++;
    handleIncomingReport(report_id, buffer, lenBytes);
  }
};

static USBHIDFidoDevice fidoHid;

static void fido_send_response(const uint32_t cid, const uint8_t cmd, const uint8_t* payload, const size_t payloadLen) {
  if (cmd != CTAPHID_CMD_KEEPALIVE) {
    FIDO_LOG("TX %s cid=%08lX len=%u", ctaphid_cmd_name(cmd), static_cast<unsigned long>(cid), static_cast<unsigned>(payloadLen));
  }
  uint8_t pkt[FIDO_HID_PACKET_SIZE];
  memset(pkt, 0, sizeof(pkt));
  write_be_u32(pkt + 0, cid);
  pkt[4] = static_cast<uint8_t>(0x80U | (cmd & 0x7FU));
  write_be_u16(pkt + 5, static_cast<uint16_t>(payloadLen));

  const size_t first = (payloadLen > 57) ? 57 : payloadLen;
  if (first && payload) memcpy(pkt + 7, payload, first);
  fidoHid.sendPacket(pkt, sizeof(pkt));

  size_t off = first;
  uint8_t seq = 0;
  while (off < payloadLen) {
    memset(pkt, 0, sizeof(pkt));
    write_be_u32(pkt + 0, cid);
    pkt[4] = seq++;
    const size_t chunk = ((payloadLen - off) > 59) ? 59 : (payloadLen - off);
    memcpy(pkt + 5, payload + off, chunk);
    off += chunk;
    fidoHid.sendPacket(pkt, sizeof(pkt));
  }
}

static void fido_send_error(const uint32_t cid, const uint8_t err) {
  fidoDiag.lastCid = cid;
  fidoDiag.lastHidError = err;
  fidoDiag.lastTxMs = millis();
  FIDO_LOG("TX ERROR cid=%08lX err=%s(0x%02X)", static_cast<unsigned long>(cid), ctaphid_err_name(err), err);
  fido_send_response(cid, CTAPHID_CMD_ERROR, &err, 1);
}

static void fido_send_keepalive(const uint32_t cid, const uint8_t status) {
  fido_send_response(cid, CTAPHID_CMD_KEEPALIVE, &status, 1);
}

static void fido_send_ctap2_status(const uint32_t cid, const uint8_t status, const uint8_t* cbor, const size_t cborLen) {
  fidoDiag.lastCid = cid;
  fidoDiag.lastCtapStatus = status;
  fidoDiag.lastTxMs = millis();
  if (status == CTAP2_OK) {
    fidoDiag.totalCtapOk++;
  } else {
    fidoDiag.totalCtapErr++;
  }
  FIDO_LOG("TX CTAP2 cid=%08lX status=%s(0x%02X) cborLen=%u", static_cast<unsigned long>(cid), ctap2_status_name(status), status,
           static_cast<unsigned>(cborLen));
  uint8_t buf[1 + 512];
  buf[0] = status;
  size_t n = 1;
  if (status == CTAP2_OK && cbor && cborLen > 0) {
    if (cborLen > 512) {
      buf[0] = CTAP2_ERR_REQUEST_TOO_LARGE;
    } else {
      memcpy(buf + 1, cbor, cborLen);
      n = 1 + cborLen;
    }
  }
  fido_send_response(cid, CTAPHID_CMD_CBOR, buf, n);
}

static void fido_hid_on_packet(const uint8_t* buffer, const uint16_t lenBytes) {
  if (!buffer || lenBytes != FIDO_HID_PACKET_SIZE) return;
  const uint32_t cid = read_be_u32(buffer + 0);
  const uint8_t b4 = buffer[4];
  const uint32_t now = millis();
  fidoDiag.lastCid = cid;
  fidoDiag.lastRxMs = now;

  // If a complete request is waiting, report busy.
  if (fidoReq.ready) {
    fido_send_error(cid, CTAPHID_ERR_CHANNEL_BUSY);
    return;
  }

  if (b4 & 0x80) {
    // Initial packet
    const uint8_t cmd = static_cast<uint8_t>(b4 & 0x7F);
    fidoDiag.lastHidCmd = cmd;
    const uint16_t total = static_cast<uint16_t>((static_cast<uint16_t>(buffer[5]) << 8) | buffer[6]);
    FIDO_LOG("RX init cid=%08lX cmd=%s(0x%02X) total=%u", static_cast<unsigned long>(cid), ctaphid_cmd_name(cmd), cmd,
             static_cast<unsigned>(total));
    if (total > FIDO_MAX_PAYLOAD) {
      fido_send_error(cid, CTAPHID_ERR_INVALID_LEN);
      return;
    }

    fidoRx.active = true;
    fidoRx.cid = cid;
    fidoRx.cmd = cmd;
    fidoRx.total = total;
    fidoRx.received = 0;
    fidoRx.nextSeq = 0;
    fidoRx.lastMs = now;

    const size_t first = (total > 57) ? 57 : total;
    if (first) memcpy(fidoReq.data, buffer + 7, first);
    fidoRx.received = static_cast<uint16_t>(first);

    if (fidoRx.received >= fidoRx.total) {
      fidoReq.cid = cid;
      fidoReq.cmd = cmd;
      fidoReq.len = total;
      fidoReq.ready = true;
      fidoRx.active = false;
    }
    return;
  }

  // Continuation packet
  if (!fidoRx.active || fidoRx.cid != cid) {
    fido_send_error(cid, CTAPHID_ERR_INVALID_SEQ);
    return;
  }
  if (b4 != fidoRx.nextSeq) {
    // Some host paths can replay the immediately previous continuation frame.
    // Ignore harmless duplicates instead of aborting the full transaction.
    if (fidoRx.nextSeq > 0 && b4 == static_cast<uint8_t>(fidoRx.nextSeq - 1U)) {
      fidoRx.lastMs = now;
      return;
    }
    fido_send_error(cid, CTAPHID_ERR_INVALID_SEQ);
    fidoRx.active = false;
    return;
  }
  fidoRx.nextSeq++;
  fidoRx.lastMs = now;

  const uint16_t remaining = static_cast<uint16_t>(fidoRx.total - fidoRx.received);
  const size_t chunk = (remaining > 59) ? 59 : remaining;
  if (chunk) memcpy(fidoReq.data + fidoRx.received, buffer + 5, chunk);
  fidoRx.received = static_cast<uint16_t>(fidoRx.received + chunk);

  if (fidoRx.received >= fidoRx.total) {
    fidoReq.cid = cid;
    fidoReq.cmd = fidoRx.cmd;
    fidoReq.len = fidoRx.total;
    fidoReq.ready = true;
    fidoRx.active = false;
  }
}

static void fido_handle_init(const uint32_t cid, const uint8_t* data, const size_t len) {
  if (len != 8 || !data) {
    fido_send_error(cid, CTAPHID_ERR_INVALID_LEN);
    return;
  }

  uint8_t resp[17];
  memcpy(resp + 0, data, 8);

  // CTAPHID_INIT on an allocated CID is a synchronization request and must echo that CID.
  // CTAPHID_INIT on broadcast allocates a fresh CID.
  uint32_t newCid = cid;
  if (cid == CTAPHID_BROADCAST_CID) {
    do {
      newCid = esp_random();
    } while (newCid == 0 || newCid == CTAPHID_BROADCAST_CID);
  }

  // Synchronize state for the active channel.
  fidoRx.active = false;
  fidoReq.ready = false;
  pendingCtap.active = false;
  fidoAwaitingUserPresence = false;
  fidoHid.clearQueue();
  fidoAssignedCid = newCid;

  write_be_u32(resp + 8, newCid);
  resp[12] = 2;    // CTAPHID protocol version
  resp[13] = 1;    // major
  resp[14] = 0;    // minor
  resp[15] = 0;    // build
  // Match behavior used by known-good TinyUSB implementations (WINK + CBOR).
  resp[16] = static_cast<uint8_t>(CTAPHID_CAP_WINK | CTAPHID_CAP_CBOR);
  fido_send_response(cid, CTAPHID_CMD_INIT, resp, sizeof(resp));
}

static void fido_start_pending(const uint32_t cid, const uint8_t ctapCmd, const uint8_t* data, const size_t len) {
  if (pendingCtap.active) {
    fido_send_ctap2_status(cid, CTAP2_ERR_CHANNEL_BUSY, nullptr, 0);
    return;
  }
  if (len > FIDO_MAX_PAYLOAD) {
    fido_send_ctap2_status(cid, CTAP2_ERR_REQUEST_TOO_LARGE, nullptr, 0);
    return;
  }
  pendingCtap.active = true;
  pendingCtap.cid = cid;
  pendingCtap.cmd = ctapCmd;
  pendingCtap.len = static_cast<uint16_t>(len);
  if (len && data) memcpy(pendingCtap.data, data, len);
  pendingCtap.startedMs = millis();
  pendingCtap.lastKeepaliveMs = pendingCtap.startedMs;
  pendingCtap.sawButtonRelease = !boot_button_down();
  pendingCtap.buttonDownSinceMs = boot_button_down() ? pendingCtap.startedMs : 0;
  fidoAwaitingUserPresence = true;
  fido_send_keepalive(cid, CTAPHID_KEEPALIVE_STATUS_UP_NEEDED);
  FIDO_LOG("Pending start cid=%08lX cmd=%s(0x%02X) len=%u", static_cast<unsigned long>(cid), ctap_cmd_name(ctapCmd), ctapCmd,
           static_cast<unsigned>(len));
}

static void fido_cancel_pending(const uint32_t cid) {
  if (pendingCtap.active && pendingCtap.cid == cid) {
    pendingCtap.active = false;
    fidoAwaitingUserPresence = false;
    FIDO_LOG("Pending cancel cid=%08lX", static_cast<unsigned long>(cid));
    fido_send_ctap2_status(cid, CTAP2_ERR_KEEPALIVE_CANCEL, nullptr, 0);
  }
}

static void fido_handle_cbor(const uint32_t cid, const uint8_t* data, const size_t len) {
  if (!data || len < 1) {
    fido_send_error(cid, CTAPHID_ERR_INVALID_LEN);
    return;
  }
  if (fidoAssignedCid != 0 && cid != fidoAssignedCid) {
    fido_send_error(cid, CTAPHID_ERR_INVALID_CHANNEL);
    return;
  }

  const uint8_t ctapCmd = data[0];
  const uint8_t* payload = data + 1;
  const size_t payloadLen = len - 1;
  fidoDiag.lastCid = cid;
  fidoDiag.lastCtapCmd = ctapCmd;
  fidoDiag.totalCtapRequests++;
  fidoDiag.lastRxMs = millis();
  FIDO_LOG("RX CTAP2 cid=%08lX cmd=%s(0x%02X) payloadLen=%u", static_cast<unsigned long>(cid), ctap_cmd_name(ctapCmd), ctapCmd,
           static_cast<unsigned>(payloadLen));

  if (ctapCmd == CTAP_CMD_GET_INFO) {
    uint8_t body[256];
    size_t bodyLen = 0;
    const uint8_t st = ctap2_get_info(body, sizeof(body), &bodyLen);
    fido_send_ctap2_status(cid, st, body, bodyLen);
    return;
  }

  if (ctapCmd == CTAP_CMD_CLIENT_PIN) {
    uint8_t body[256];
    size_t bodyLen = 0;
    const uint8_t st = ctap2_client_pin(payload, payloadLen, body, sizeof(body), &bodyLen);
    fido_send_ctap2_status(cid, st, body, bodyLen);
    return;
  }

  if (ctapCmd == CTAP_CMD_SELECTION) {
    // Selection is a no-op for this device but should succeed.
    fido_send_ctap2_status(cid, CTAP2_OK, nullptr, 0);
    return;
  }

  if (ctapCmd == CTAP_CMD_BIO_ENROLLMENT || ctapCmd == CTAP_CMD_CREDENTIAL_MANAGEMENT || ctapCmd == CTAP_CMD_LARGE_BLOBS ||
      ctapCmd == CTAP_CMD_CONFIG) {
    // Explicitly report not-allowed instead of invalid-command to improve host compatibility.
    fido_send_ctap2_status(cid, CTAP2_ERR_NOT_ALLOWED, nullptr, 0);
    return;
  }

  if (ctapCmd == CTAP_CMD_GET_NEXT_ASSERTION) {
    fido_send_ctap2_status(cid, CTAP2_ERR_NOT_ALLOWED, nullptr, 0);
    return;
  }

  if (ctapCmd == CTAP_CMD_RESET) {
#if FIDO_REQUIRE_PIN
    // Reset has no pinUvAuthParam field in this implementation; require local unlock window if PIN is configured.
    if (security_pin_configured() && !security_pin_unlocked_now()) {
      fidoDiag.totalPinGateBlocks++;
      FIDO_LOG("Security PIN gate blocked cmd=%s", ctap_cmd_name(ctapCmd));
      fido_send_ctap2_status(cid, CTAP2_ERR_PIN_REQUIRED, nullptr, 0);
      return;
    }
#endif
  }

  if (ctapCmd == CTAP_CMD_MAKE_CREDENTIAL) {
#if FIDO_FORCE_DIRECT_MAKECRED_ERROR
    // Isolation mode: prove large request reassembly + immediate CBOR response path.
    fido_send_ctap2_status(cid, CTAP2_ERR_INVALID_CBOR, nullptr, 0);
    return;
#endif
  }

  if (ctapCmd == CTAP_CMD_MAKE_CREDENTIAL || ctapCmd == CTAP_CMD_GET_ASSERTION || ctapCmd == CTAP_CMD_RESET) {
    fido_start_pending(cid, ctapCmd, payload, payloadLen);
    return;
  }

  // For unsupported CTAP commands, prefer NOT_ALLOWED over INVALID_COMMAND for host compatibility.
  fido_send_ctap2_status(cid, CTAP2_ERR_NOT_ALLOWED, nullptr, 0);
}

static void fido_process_request() {
  if (!fidoReq.ready) return;
  const uint32_t cid = fidoReq.cid;
  const uint8_t cmd = fidoReq.cmd;
  const uint16_t len = fidoReq.len;
  const uint8_t* data = fidoReq.data;
  FIDO_LOG("Process cid=%08lX cmd=%s(0x%02X) len=%u", static_cast<unsigned long>(cid), ctaphid_cmd_name(cmd), cmd,
           static_cast<unsigned>(len));

  if (cmd == CTAPHID_CMD_INIT) {
    fido_handle_init(cid, data, len);
  } else if (cmd == CTAPHID_CMD_PING) {
    fido_send_response(cid, CTAPHID_CMD_PING, data, len);
  } else if (cmd == CTAPHID_CMD_WINK) {
    // Provide a short visual hint if an LED is present.
    if (led_available()) set_led_rgb(32, 32, 0);
    fido_send_response(cid, CTAPHID_CMD_WINK, nullptr, 0);
  } else if (cmd == CTAPHID_CMD_CANCEL) {
    // CTAPHID_CANCEL never gets a direct HID response.
    fido_cancel_pending(cid);
  } else if (cmd == CTAPHID_CMD_CBOR) {
    fido_handle_cbor(cid, data, len);
  } else if (cmd == CTAPHID_CMD_MSG) {
    fido_send_error(cid, CTAPHID_ERR_INVALID_CMD);
  } else {
    fido_send_error(cid, CTAPHID_ERR_INVALID_CMD);
  }

  fidoReq.ready = false;
}

static void fido_tick_pending() {
  if (!pendingCtap.active) return;

  const uint32_t now = millis();
  const uint32_t cid = pendingCtap.cid;
  bool upSatisfied = false;
 
  if (static_cast<int32_t>(now - pendingCtap.startedMs) > static_cast<int32_t>(CTAP_UP_TIMEOUT_MS)) {
    pendingCtap.active = false;
    fidoAwaitingUserPresence = false;
    FIDO_LOG("Pending timeout cid=%08lX", static_cast<unsigned long>(cid));
    fido_send_ctap2_status(cid, CTAP2_ERR_USER_ACTION_TIMEOUT, nullptr, 0);
    return;
  }
#if FIDO_REQUIRE_BOOT_BUTTON_FOR_UP
  if (static_cast<int32_t>(now - pendingCtap.lastKeepaliveMs) >= static_cast<int32_t>(CTAP_KEEPALIVE_EVERY_MS)) {
    pendingCtap.lastKeepaliveMs = now;
    fido_send_keepalive(cid, CTAPHID_KEEPALIVE_STATUS_UP_NEEDED);
  }
 
  const bool down = boot_button_down();
  if (!pendingCtap.sawButtonRelease) {
    // Require at least one release edge after request start so a stuck-low line
    // cannot satisfy user presence immediately.
    if (!down) {
      pendingCtap.sawButtonRelease = true;
      pendingCtap.buttonDownSinceMs = 0;
    }
    return;
  }
 
  if (down) {
    if (pendingCtap.buttonDownSinceMs == 0) pendingCtap.buttonDownSinceMs = now;
    upSatisfied = static_cast<int32_t>(now - pendingCtap.buttonDownSinceMs) >= static_cast<int32_t>(CTAP_UP_MIN_HOLD_MS);
  } else {
    pendingCtap.buttonDownSinceMs = 0;
  }
#else  // !FIDO_REQUIRE_BOOT_BUTTON_FOR_UP
  if (static_cast<int32_t>(now - pendingCtap.lastKeepaliveMs) >= static_cast<int32_t>(CTAP_KEEPALIVE_EVERY_MS)) {
    pendingCtap.lastKeepaliveMs = now;
    fido_send_keepalive(cid, CTAPHID_KEEPALIVE_STATUS_PROCESSING);
  }
  upSatisfied = static_cast<int32_t>(now - pendingCtap.startedMs) >= static_cast<int32_t>(CTAP_UP_AUTO_APPROVE_MS);
#endif
 
  if (!upSatisfied) return;
  fidoDiag.totalUpSatisfied++;
  FIDO_LOG("User presence satisfied cid=%08lX", static_cast<unsigned long>(cid));

  uint8_t body[512];
  size_t bodyLen = 0;
  uint8_t st = CTAP1_ERR_OTHER;
  activeCtap.cid = cid;
  activeCtap.active = true;

  if (pendingCtap.cmd == CTAP_CMD_MAKE_CREDENTIAL) {
    st = ctap2_make_credential(pendingCtap.data, pendingCtap.len, body, sizeof(body), &bodyLen);
  } else if (pendingCtap.cmd == CTAP_CMD_GET_ASSERTION) {
    st = ctap2_get_assertion(pendingCtap.data, pendingCtap.len, body, sizeof(body), &bodyLen);
  } else if (pendingCtap.cmd == CTAP_CMD_RESET) {
    st = ctap2_reset();
  } else {
    st = CTAP2_ERR_INVALID_COMMAND;
  }
  activeCtap.active = false;

  pendingCtap.active = false;
  fidoAwaitingUserPresence = false;
  fido_send_ctap2_status(cid, st, body, bodyLen);
}

void fido_begin() {
  fidoHid.begin();
  fidoAssignedCid = 0;
  fidoRx.active = false;
  fidoReq.ready = false;
  pendingCtap.active = false;
  activeCtap.active = false;
  activeCtap.cid = 0;
  fidoAwaitingUserPresence = false;
  fidoHid.clearQueue();
  fido_diag_clear();
  runtime_cred_clear();
  esp_fill_random(fidoClientPin.pinUvAuthToken, sizeof(fidoClientPin.pinUvAuthToken));
  fidoClientPin.pinRetries = 8;
  fidoClientPin.keyAgreementReady = false;
  secure_zero(fidoClientPin.keyAgreementPriv, sizeof(fidoClientPin.keyAgreementPriv));
  secure_zero(fidoClientPin.keyAgreementX, sizeof(fidoClientPin.keyAgreementX));
  secure_zero(fidoClientPin.keyAgreementY, sizeof(fidoClientPin.keyAgreementY));
  fidoSignCount = load_sign_count();
  FIDO_LOG("FIDO init signCount=%lu debug=%u", static_cast<unsigned long>(fidoSignCount), static_cast<unsigned>(FIDO_DEBUG));
}

bool fido_waiting_for_user_presence() {
  return pendingCtap.active;
}

void fido_diag_clear() {
  memset(&fidoDiag, 0, sizeof(fidoDiag));
}

void fido_diag_build_json(String& outJson) {
  const uint32_t now = millis();
  const uint32_t rxAgo = (fidoDiag.lastRxMs == 0) ? 0 : static_cast<uint32_t>(now - fidoDiag.lastRxMs);
  const uint32_t txAgo = (fidoDiag.lastTxMs == 0) ? 0 : static_cast<uint32_t>(now - fidoDiag.lastTxMs);

  outJson = "";
  outJson.reserve(1200);
  outJson += "{";
  outJson += "\"last_cid\":";
  outJson += String(fidoDiag.lastCid);
  outJson += ",\"last_hid_cmd\":";
  outJson += String(fidoDiag.lastHidCmd);
  outJson += ",\"last_hid_cmd_name\":\"";
  outJson += ctaphid_cmd_name(fidoDiag.lastHidCmd);
  outJson += "\"";
  outJson += ",\"last_ctap_cmd\":";
  outJson += String(fidoDiag.lastCtapCmd);
  outJson += ",\"last_ctap_cmd_name\":\"";
  outJson += ctap_cmd_name(fidoDiag.lastCtapCmd);
  outJson += "\"";
  outJson += ",\"last_ctap_status\":";
  outJson += String(fidoDiag.lastCtapStatus);
  outJson += ",\"last_ctap_status_name\":\"";
  outJson += ctap2_status_name(fidoDiag.lastCtapStatus);
  outJson += "\"";
  outJson += ",\"last_hid_error\":";
  outJson += String(fidoDiag.lastHidError);
  outJson += ",\"last_hid_error_name\":\"";
  outJson += ctaphid_err_name(fidoDiag.lastHidError);
  outJson += "\"";
  outJson += ",\"last_report_id_seen\":";
  outJson += String(fidoDiag.lastReportIdSeen);
  outJson += ",\"last_report_len_seen\":";
  outJson += String(fidoDiag.lastReportLenSeen);
  outJson += ",\"last_report_id_dropped\":";
  outJson += String(fidoDiag.lastReportIdDropped);
  outJson += ",\"last_report_len_dropped\":";
  outJson += String(fidoDiag.lastReportLenDropped);
  outJson += ",\"pending_waiting_up\":";
  outJson += (pendingCtap.active ? "true" : "false");
  outJson += ",\"rx_ms_ago\":";
  outJson += String(rxAgo);
  outJson += ",\"tx_ms_ago\":";
  outJson += String(txAgo);
  outJson += ",\"ctap_requests_total\":";
  outJson += String(fidoDiag.totalCtapRequests);
  outJson += ",\"ctap_ok_total\":";
  outJson += String(fidoDiag.totalCtapOk);
  outJson += ",\"ctap_err_total\":";
  outJson += String(fidoDiag.totalCtapErr);
  outJson += ",\"pin_gate_blocks_total\":";
  outJson += String(fidoDiag.totalPinGateBlocks);
  outJson += ",\"up_satisfied_total\":";
  outJson += String(fidoDiag.totalUpSatisfied);
  outJson += ",\"hid_out_callbacks_total\":";
  outJson += String(fidoDiag.totalHidOutCallbacks);
  outJson += ",\"hid_set_feature_callbacks_total\":";
  outJson += String(fidoDiag.totalHidSetFeatureCallbacks);
  outJson += ",\"hid_get_feature_callbacks_total\":";
  outJson += String(fidoDiag.totalHidGetFeatureCallbacks);
  outJson += ",\"unexpected_report_id_total\":";
  outJson += String(fidoDiag.totalUnexpectedReportId);
  outJson += ",\"dropped_bad_len_total\":";
  outJson += String(fidoDiag.totalDroppedBadLen);
  outJson += ",\"normalized_packets_total\":";
  outJson += String(fidoDiag.totalNormalizedPackets);
  outJson += "}";
}

void fido_task() {
  fidoHid.task();
  // Drop partial messages that time out.
  if (fidoRx.active && (static_cast<int32_t>(millis() - fidoRx.lastMs) > 1000)) {
    fidoRx.active = false;
  }

  fido_process_request();
  fido_tick_pending();
}
