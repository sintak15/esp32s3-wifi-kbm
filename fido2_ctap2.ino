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
// - ClientPIN / user verification (PIN/biometric)
// - Resident/discoverable credentials (rk)
// - CTAP1/U2F (CTAPHID_MSG)
// - Extensions and enterprise attestation

#ifndef FIDO_DEBUG
#define FIDO_DEBUG 0
#endif

static constexpr size_t   FIDO_HID_PACKET_SIZE = 64;
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
static constexpr uint8_t CTAP2_ERR_PIN_REQUIRED = 0x36;
static constexpr uint8_t CTAP2_ERR_REQUEST_TOO_LARGE = 0x39;
static constexpr uint8_t CTAP1_ERR_OTHER = 0x7F;

static constexpr uint8_t CTAP_CMD_MAKE_CREDENTIAL = 0x01;
static constexpr uint8_t CTAP_CMD_GET_ASSERTION = 0x02;
static constexpr uint8_t CTAP_CMD_GET_INFO = 0x04;
static constexpr uint8_t CTAP_CMD_CLIENT_PIN = 0x06;
static constexpr uint8_t CTAP_CMD_RESET = 0x07;
static constexpr uint8_t CTAP_CMD_GET_NEXT_ASSERTION = 0x08;

static constexpr size_t FIDO_MAX_PAYLOAD = 1024;
static constexpr uint32_t CTAP_UP_TIMEOUT_MS = 30 * 1000;
static constexpr uint32_t CTAP_KEEPALIVE_EVERY_MS = 100;

static constexpr uint8_t CTAP_CRED_SECRET_VER = 1;
static constexpr uint8_t CTAP_CRED_FLAG_RK = 0x01;

static const uint8_t CTAP_AAGUID[16] = {0x7a, 0x85, 0x2a, 0x5d, 0x77, 0x6a, 0x4a, 0x12,
                                        0x86, 0x1d, 0x0b, 0x4f, 0x2b, 0x67, 0x0c, 0x8e};

static uint32_t fidoAssignedCid = 0;
static uint32_t fidoSignCount = 0;
static bool fidoAwaitingUserPresence = false;

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
  prefs.begin("kbm", true);
  const uint32_t v = prefs.getUInt("sc", 0);
  prefs.end();
  return v;
}

static void save_sign_count(const uint32_t v) {
  prefs.begin("kbm", false);
  prefs.putUInt("sc", v);
  prefs.end();
}

static bool cred_store_id_exists(const uint8_t* id, const size_t idLen) {
  static constexpr size_t kStoreHdrLen = 12;
  static constexpr size_t kRecHdrLen = 12;
  if (!id || idLen == 0 || idLen > CRED_MAX_ID_LEN) return false;

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

  while (!cbor_value_at_end(&dIt)) {
    bool keyIsType = false;
    bool keyIsId = false;

    if (cbor_value_is_integer(&dIt)) {
      int dk = 0;
      if (cbor_value_get_int(&dIt, &dk) != CborNoError) return CTAP2_ERR_INVALID_CBOR;
      keyIsType = (dk == 0x01);
      keyIsId = (dk == 0x02);
      if (cbor_value_advance(&dIt) != CborNoError) return CTAP2_ERR_INVALID_CBOR;
    } else if (cbor_value_is_text_string(&dIt)) {
      char key[24];
      size_t keyLen = sizeof(key);
      if (cbor_value_copy_text_string(&dIt, key, &keyLen, &dIt) != CborNoError) return CTAP2_ERR_INVALID_CBOR;
      keyIsType = (strcmp(key, "type") == 0);
      keyIsId = (strcmp(key, "id") == 0);
    } else {
      return CTAP2_ERR_INVALID_CBOR;
    }

    if (keyIsType) {
      if (!cbor_value_is_text_string(&dIt)) return CTAP2_ERR_CBOR_UNEXPECTED_TYPE;
      char tv[16];
      size_t tvLen = sizeof(tv);
      if (cbor_value_copy_text_string(&dIt, tv, &tvLen, nullptr) != CborNoError) return CTAP2_ERR_INVALID_CBOR;
      if (strcmp(tv, "public-key") == 0) *typePublicKeyOut = true;
    } else if (keyIsId) {
      if (!cbor_value_is_byte_string(&dIt)) return CTAP2_ERR_CBOR_UNEXPECTED_TYPE;
      size_t n = 0;
      if (cbor_value_calculate_string_length(&dIt, &n) != CborNoError) return CTAP2_ERR_INVALID_CBOR;
      if (n == 0 || n > idOutMax) return CTAP2_ERR_LIMIT_EXCEEDED;
      size_t copyLen = idOutMax;
      if (cbor_value_copy_byte_string(&dIt, idOut, &copyLen, nullptr) != CborNoError) return CTAP2_ERR_INVALID_CBOR;
      *idLenOut = copyLen;
    }

    if (cbor_value_advance(&dIt) != CborNoError) return CTAP2_ERR_INVALID_CBOR;
  }

  cbor_value_leave_container(descMap, &dIt);
  return CTAP2_OK;
}

static uint8_t ctap2_get_info(uint8_t* out, const size_t outMax, size_t* outLen) {
  if (!out || !outLen) return CTAP1_ERR_OTHER;
  *outLen = 0;
  CborEncoder enc;
  cbor_encoder_init(&enc, out, outMax, 0);

  // Map keys per CTAP2 spec:
  // 0x01 versions, 0x03 aaguid, 0x04 options, 0x05 maxMsgSize, 0x08 maxCredIdLength, 0x09 transports
  CborEncoder map;
  if (cbor_encoder_create_map(&enc, &map, 6) != CborNoError) return CTAP2_ERR_CBOR_PARSING;

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
  if (cbor_encoder_create_map(&map, &opt, 5) != CborNoError) return CTAP2_ERR_CBOR_PARSING;
  if (cbor_encode_text_stringz(&opt, "up") != CborNoError) return CTAP2_ERR_CBOR_PARSING;
  if (cbor_encode_boolean(&opt, true) != CborNoError) return CTAP2_ERR_CBOR_PARSING;
  if (cbor_encode_text_stringz(&opt, "uv") != CborNoError) return CTAP2_ERR_CBOR_PARSING;
  if (cbor_encode_boolean(&opt, false) != CborNoError) return CTAP2_ERR_CBOR_PARSING;
  if (cbor_encode_text_stringz(&opt, "rk") != CborNoError) return CTAP2_ERR_CBOR_PARSING;
  if (cbor_encode_boolean(&opt, false) != CborNoError) return CTAP2_ERR_CBOR_PARSING;
  if (cbor_encode_text_stringz(&opt, "plat") != CborNoError) return CTAP2_ERR_CBOR_PARSING;
  if (cbor_encode_boolean(&opt, false) != CborNoError) return CTAP2_ERR_CBOR_PARSING;
  if (cbor_encode_text_stringz(&opt, "clientPin") != CborNoError) return CTAP2_ERR_CBOR_PARSING;
  if (cbor_encode_boolean(&opt, false) != CborNoError) return CTAP2_ERR_CBOR_PARSING;
  if (cbor_encoder_close_container(&map, &opt) != CborNoError) return CTAP2_ERR_CBOR_PARSING;

  // maxMsgSize
  if (cbor_encode_int(&map, 0x05) != CborNoError) return CTAP2_ERR_CBOR_PARSING;
  if (cbor_encode_uint(&map, FIDO_MAX_PAYLOAD) != CborNoError) return CTAP2_ERR_CBOR_PARSING;

  // maxCredIdLength
  if (cbor_encode_int(&map, 0x08) != CborNoError) return CTAP2_ERR_CBOR_PARSING;
  if (cbor_encode_uint(&map, CRED_MAX_ID_LEN) != CborNoError) return CTAP2_ERR_CBOR_PARSING;

  // transports
  if (cbor_encode_int(&map, 0x09) != CborNoError) return CTAP2_ERR_CBOR_PARSING;
  CborEncoder transports;
  if (cbor_encoder_create_array(&map, &transports, 1) != CborNoError) return CTAP2_ERR_CBOR_PARSING;
  if (cbor_encode_text_stringz(&transports, "usb") != CborNoError) return CTAP2_ERR_CBOR_PARSING;
  if (cbor_encoder_close_container(&map, &transports) != CborNoError) return CTAP2_ERR_CBOR_PARSING;

  if (cbor_encoder_close_container(&enc, &map) != CborNoError) return CTAP2_ERR_CBOR_PARSING;
  *outLen = cbor_encoder_get_buffer_size(&enc, out);
  return CTAP2_OK;
}

static uint8_t ctap2_make_credential(const uint8_t* req, const size_t reqLen, uint8_t* out, const size_t outMax, size_t* outLen) {
  if (!req || !out || !outLen) return CTAP1_ERR_OTHER;
  *outLen = 0;
  if (reqLen == 0) return CTAP2_ERR_INVALID_LENGTH;

  // Parse request map
  CborParser parser;
  CborValue root;
  if (cbor_parser_init(req, reqLen, 0, &parser, &root) != CborNoError) return CTAP2_ERR_INVALID_CBOR;
  if (!cbor_value_is_map(&root)) return CTAP2_ERR_CBOR_UNEXPECTED_TYPE;

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

  CborValue it;
  if (cbor_value_enter_container(&root, &it) != CborNoError) return CTAP2_ERR_INVALID_CBOR;
  while (!cbor_value_at_end(&it)) {
    int k = 0;
    if (!cbor_value_is_integer(&it) || cbor_value_get_int(&it, &k) != CborNoError) return CTAP2_ERR_INVALID_CBOR;
    if (cbor_value_advance(&it) != CborNoError) return CTAP2_ERR_INVALID_CBOR;

    if (k == 0x01) {
      if (!cbor_value_is_byte_string(&it)) return CTAP2_ERR_CBOR_UNEXPECTED_TYPE;
      size_t n = 0;
      if (cbor_value_calculate_string_length(&it, &n) != CborNoError) return CTAP2_ERR_INVALID_CBOR;
      if (n != 32) return CTAP2_ERR_INVALID_LENGTH;
      size_t copy = sizeof(clientDataHash);
      if (cbor_value_copy_byte_string(&it, clientDataHash, &copy, nullptr) != CborNoError) return CTAP2_ERR_INVALID_CBOR;
      haveClientHash = true;
    } else if (k == 0x02) {
      if (!cbor_value_is_map(&it)) return CTAP2_ERR_CBOR_UNEXPECTED_TYPE;
      CborValue rpIt;
      if (cbor_value_enter_container(&it, &rpIt) != CborNoError) return CTAP2_ERR_INVALID_CBOR;
      while (!cbor_value_at_end(&rpIt)) {
        if (!cbor_value_is_text_string(&rpIt)) return CTAP2_ERR_INVALID_CBOR;
        char key[32];
        size_t keyLen = sizeof(key);
        if (cbor_value_copy_text_string(&rpIt, key, &keyLen, &rpIt) != CborNoError) return CTAP2_ERR_INVALID_CBOR;
        if (strcmp(key, "id") == 0) {
          if (!cbor_value_is_text_string(&rpIt)) return CTAP2_ERR_CBOR_UNEXPECTED_TYPE;
          size_t idLen = 0;
          if (cbor_value_calculate_string_length(&rpIt, &idLen) != CborNoError) return CTAP2_ERR_INVALID_CBOR;
          if (idLen == 0 || idLen > CRED_MAX_RPID_LEN) return CTAP2_ERR_LIMIT_EXCEEDED;
          size_t copyLen = sizeof(rpId);
          if (cbor_value_copy_text_string(&rpIt, rpId, &copyLen, nullptr) != CborNoError) return CTAP2_ERR_INVALID_CBOR;
          rpId[sizeof(rpId) - 1] = '\0';
          haveRpId = true;
        }
        if (cbor_value_advance(&rpIt) != CborNoError) return CTAP2_ERR_INVALID_CBOR;
      }
      cbor_value_leave_container(&it, &rpIt);
    } else if (k == 0x03) {
      if (!cbor_value_is_map(&it)) return CTAP2_ERR_CBOR_UNEXPECTED_TYPE;
      CborValue uIt;
      if (cbor_value_enter_container(&it, &uIt) != CborNoError) return CTAP2_ERR_INVALID_CBOR;
      while (!cbor_value_at_end(&uIt)) {
        if (!cbor_value_is_text_string(&uIt)) return CTAP2_ERR_INVALID_CBOR;
        char key[32];
        size_t keyLen = sizeof(key);
        if (cbor_value_copy_text_string(&uIt, key, &keyLen, &uIt) != CborNoError) return CTAP2_ERR_INVALID_CBOR;
        if (strcmp(key, "id") == 0) {
          if (!cbor_value_is_byte_string(&uIt)) return CTAP2_ERR_CBOR_UNEXPECTED_TYPE;
          size_t n = 0;
          if (cbor_value_calculate_string_length(&uIt, &n) != CborNoError) return CTAP2_ERR_INVALID_CBOR;
          if (n == 0 || n > sizeof(userId)) return CTAP2_ERR_LIMIT_EXCEEDED;
          userIdLen = sizeof(userId);
          if (cbor_value_copy_byte_string(&uIt, userId, &userIdLen, nullptr) != CborNoError) return CTAP2_ERR_INVALID_CBOR;
          haveUser = true;
        }
        if (cbor_value_advance(&uIt) != CborNoError) return CTAP2_ERR_INVALID_CBOR;
      }
      cbor_value_leave_container(&it, &uIt);
    } else if (k == 0x04) {
      if (!cbor_value_is_array(&it)) return CTAP2_ERR_CBOR_UNEXPECTED_TYPE;
      CborValue aIt;
      if (cbor_value_enter_container(&it, &aIt) != CborNoError) return CTAP2_ERR_INVALID_CBOR;
      while (!cbor_value_at_end(&aIt)) {
        if (!cbor_value_is_map(&aIt)) return CTAP2_ERR_CBOR_UNEXPECTED_TYPE;
        bool typeOk = false;
        bool algOk = false;
        int alg = 0;
        CborValue pIt;
        if (cbor_value_enter_container(&aIt, &pIt) != CborNoError) return CTAP2_ERR_INVALID_CBOR;
        while (!cbor_value_at_end(&pIt)) {
          if (!cbor_value_is_text_string(&pIt)) return CTAP2_ERR_INVALID_CBOR;
          char key[32];
          size_t keyLen = sizeof(key);
          if (cbor_value_copy_text_string(&pIt, key, &keyLen, &pIt) != CborNoError) return CTAP2_ERR_INVALID_CBOR;
          if (strcmp(key, "type") == 0) {
            if (!cbor_value_is_text_string(&pIt)) return CTAP2_ERR_CBOR_UNEXPECTED_TYPE;
            char tv[16];
            size_t tvLen = sizeof(tv);
            if (cbor_value_copy_text_string(&pIt, tv, &tvLen, nullptr) != CborNoError) return CTAP2_ERR_INVALID_CBOR;
            if (strcmp(tv, "public-key") == 0) typeOk = true;
          } else if (strcmp(key, "alg") == 0) {
            if (!cbor_value_is_integer(&pIt) || cbor_value_get_int(&pIt, &alg) != CborNoError) return CTAP2_ERR_INVALID_CBOR;
            if (alg == -7) algOk = true;
          }
          if (cbor_value_advance(&pIt) != CborNoError) return CTAP2_ERR_INVALID_CBOR;
        }
        cbor_value_leave_container(&aIt, &pIt);
        if (typeOk && algOk) {
          haveAlg = true;
          break;
        }
        if (cbor_value_advance(&aIt) != CborNoError) return CTAP2_ERR_INVALID_CBOR;
      }
      cbor_value_leave_container(&it, &aIt);
    } else if (k == 0x05) {
      // excludeList
      if (!cbor_value_is_array(&it)) return CTAP2_ERR_CBOR_UNEXPECTED_TYPE;
      CborValue exIt;
      if (cbor_value_enter_container(&it, &exIt) != CborNoError) return CTAP2_ERR_INVALID_CBOR;
      while (!cbor_value_at_end(&exIt)) {
        uint8_t cid[CRED_MAX_ID_LEN];
        size_t cidLen = 0;
        bool typePublicKey = false;
        const uint8_t st = ctap2_parse_pubkey_cred_descriptor(&exIt, cid, sizeof(cid), &cidLen, &typePublicKey);
        if (st != CTAP2_OK) return st;
        if (typePublicKey && cidLen > 0 && cred_store_id_exists(cid, cidLen)) excludeHit = true;
        if (excludeHit) break;
        if (cbor_value_advance(&exIt) != CborNoError) return CTAP2_ERR_INVALID_CBOR;
      }
      cbor_value_leave_container(&it, &exIt);
    } else if (k == 0x07) {
      // options
      if (!cbor_value_is_map(&it)) return CTAP2_ERR_CBOR_UNEXPECTED_TYPE;
      CborValue oIt;
      if (cbor_value_enter_container(&it, &oIt) != CborNoError) return CTAP2_ERR_INVALID_CBOR;
      while (!cbor_value_at_end(&oIt)) {
        if (!cbor_value_is_text_string(&oIt)) return CTAP2_ERR_INVALID_CBOR;
        char key[32];
        size_t keyLen = sizeof(key);
        if (cbor_value_copy_text_string(&oIt, key, &keyLen, &oIt) != CborNoError) return CTAP2_ERR_INVALID_CBOR;
        if (!cbor_value_is_boolean(&oIt)) return CTAP2_ERR_CBOR_UNEXPECTED_TYPE;
        bool v = false;
        if (cbor_value_get_boolean(&oIt, &v) != CborNoError) return CTAP2_ERR_INVALID_CBOR;
        if (strcmp(key, "rk") == 0) optionRk = v;
        else if (strcmp(key, "uv") == 0) optionUv = v;
        if (cbor_value_advance(&oIt) != CborNoError) return CTAP2_ERR_INVALID_CBOR;
      }
      cbor_value_leave_container(&it, &oIt);
    } else if (k == 0x08 || k == 0x09) {
      // pinUvAuthParam / pinUvAuthProtocol present -> not supported
      return CTAP2_ERR_PIN_REQUIRED;
    }

    if (cbor_value_advance(&it) != CborNoError) return CTAP2_ERR_INVALID_CBOR;
  }
  cbor_value_leave_container(&root, &it);

  if (excludeHit) return CTAP2_ERR_CREDENTIAL_EXCLUDED;
  if (!haveClientHash || !haveRpId || !haveUser) return CTAP2_ERR_MISSING_PARAMETER;
  if (!haveAlg) return CTAP2_ERR_UNSUPPORTED_ALGORITHM;
  if (optionUv || optionRk) return CTAP2_ERR_UNSUPPORTED_OPTION;

  // Create keypair and credentialId
  EcKeyPair kp;
  if (!ec_generate(&kp)) return CTAP2_ERR_PROCESSING;

  uint8_t credId[16];
  for (uint8_t tries = 0; tries < 10; ++tries) {
    esp_fill_random(credId, sizeof(credId));
    if (!cred_store_id_exists(credId, sizeof(credId))) break;
  }
  if (cred_store_id_exists(credId, sizeof(credId))) return CTAP2_ERR_KEY_STORE_FULL;

  uint8_t secret[CRED_MAX_SECRET_LEN];
  size_t secretLen = 0;
  if (!build_cred_secret(false, userId, userIdLen, kp.priv, secret, &secretLen)) return CTAP2_ERR_PROCESSING;

  if (!cred_store_add_credential(rpId, credId, sizeof(credId), secret, secretLen)) return CTAP2_ERR_KEY_STORE_FULL;

  // Build COSE public key
  uint8_t cose[96];
  size_t coseLen = 0;
  if (!ctap2_build_cose_p256_es256(kp.x, kp.y, cose, sizeof(cose), &coseLen)) return CTAP2_ERR_PROCESSING;

  // Build authenticatorData
  uint8_t rpIdHash[32];
  if (!sha256_ret(reinterpret_cast<const uint8_t*>(rpId), strlen(rpId), rpIdHash)) return CTAP2_ERR_PROCESSING;

  uint8_t authData[256];
  size_t authLen = 0;
  memcpy(authData + authLen, rpIdHash, 32);
  authLen += 32;
  const uint8_t flags = 0x01 /*UP*/ | 0x40 /*AT*/;
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
  FIDO_LOG("makeCredential OK rpId=%s credIdLen=%u authDataLen=%u fmt=%s", rpId, static_cast<unsigned>(sizeof(credId)),
           static_cast<unsigned>(authLen), fmt);
  return CTAP2_OK;
}

static uint8_t ctap2_get_assertion(const uint8_t* req, const size_t reqLen, uint8_t* out, const size_t outMax, size_t* outLen) {
  if (!req || !out || !outLen) return CTAP1_ERR_OTHER;
  *outLen = 0;
  if (reqLen == 0) return CTAP2_ERR_INVALID_LENGTH;

  CborParser parser;
  CborValue root;
  if (cbor_parser_init(req, reqLen, 0, &parser, &root) != CborNoError) return CTAP2_ERR_INVALID_CBOR;
  if (!cbor_value_is_map(&root)) return CTAP2_ERR_CBOR_UNEXPECTED_TYPE;

  char rpId[CRED_MAX_RPID_LEN + 1];
  rpId[0] = '\0';
  bool haveRpId = false;
  uint8_t clientDataHash[32] = {0};
  bool haveClientHash = false;
  bool optionUv = false;

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
  while (!cbor_value_at_end(&it)) {
    int k = 0;
    if (!cbor_value_is_integer(&it) || cbor_value_get_int(&it, &k) != CborNoError) return CTAP2_ERR_INVALID_CBOR;
    if (cbor_value_advance(&it) != CborNoError) return CTAP2_ERR_INVALID_CBOR;

    if (k == 0x01) {
      if (!cbor_value_is_text_string(&it)) return CTAP2_ERR_CBOR_UNEXPECTED_TYPE;
      size_t idLen = 0;
      if (cbor_value_calculate_string_length(&it, &idLen) != CborNoError) return CTAP2_ERR_INVALID_CBOR;
      if (idLen == 0 || idLen > CRED_MAX_RPID_LEN) return CTAP2_ERR_LIMIT_EXCEEDED;
      size_t copyLen = sizeof(rpId);
      if (cbor_value_copy_text_string(&it, rpId, &copyLen, nullptr) != CborNoError) return CTAP2_ERR_INVALID_CBOR;
      rpId[sizeof(rpId) - 1] = '\0';
      haveRpId = true;
    } else if (k == 0x02) {
      if (!cbor_value_is_byte_string(&it)) return CTAP2_ERR_CBOR_UNEXPECTED_TYPE;
      size_t n = 0;
      if (cbor_value_calculate_string_length(&it, &n) != CborNoError) return CTAP2_ERR_INVALID_CBOR;
      if (n != 32) return CTAP2_ERR_INVALID_LENGTH;
      size_t copy = sizeof(clientDataHash);
      if (cbor_value_copy_byte_string(&it, clientDataHash, &copy, nullptr) != CborNoError) return CTAP2_ERR_INVALID_CBOR;
      haveClientHash = true;
    } else if (k == 0x03) {
      if (!cbor_value_is_array(&it)) return CTAP2_ERR_CBOR_UNEXPECTED_TYPE;
      CborValue aIt;
      if (cbor_value_enter_container(&it, &aIt) != CborNoError) return CTAP2_ERR_INVALID_CBOR;
      while (!cbor_value_at_end(&aIt)) {
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
      cbor_value_leave_container(&it, &aIt);
    } else if (k == 0x05) {
      // options
      if (!cbor_value_is_map(&it)) return CTAP2_ERR_CBOR_UNEXPECTED_TYPE;
      CborValue oIt;
      if (cbor_value_enter_container(&it, &oIt) != CborNoError) return CTAP2_ERR_INVALID_CBOR;
      while (!cbor_value_at_end(&oIt)) {
        if (!cbor_value_is_text_string(&oIt)) return CTAP2_ERR_INVALID_CBOR;
        char key[32];
        size_t keyLen = sizeof(key);
        if (cbor_value_copy_text_string(&oIt, key, &keyLen, &oIt) != CborNoError) return CTAP2_ERR_INVALID_CBOR;
        if (!cbor_value_is_boolean(&oIt)) return CTAP2_ERR_CBOR_UNEXPECTED_TYPE;
        bool v = false;
        if (cbor_value_get_boolean(&oIt, &v) != CborNoError) return CTAP2_ERR_INVALID_CBOR;
        if (strcmp(key, "uv") == 0) optionUv = v;
        if (cbor_value_advance(&oIt) != CborNoError) return CTAP2_ERR_INVALID_CBOR;
      }
      cbor_value_leave_container(&it, &oIt);
    } else if (k == 0x06 || k == 0x07) {
      // pinUvAuthParam / pinUvAuthProtocol present -> not supported
      return CTAP2_ERR_PIN_REQUIRED;
    }

    if (cbor_value_advance(&it) != CborNoError) return CTAP2_ERR_INVALID_CBOR;
  }
  cbor_value_leave_container(&root, &it);

  if (!haveRpId || !haveClientHash) return CTAP2_ERR_MISSING_PARAMETER;
  if (optionUv) return CTAP2_ERR_UNSUPPORTED_OPTION;
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
  authData[32] = 0x01; // UP
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
  cred_store_clear();
  fidoSignCount = 0;
  save_sign_count(0);
  return CTAP2_OK;
}

static const uint8_t fido_report_descriptor[] = {TUD_HID_REPORT_DESC_FIDO_U2F(FIDO_HID_PACKET_SIZE)};

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
};

static PendingCtap pendingCtap;

static void fido_hid_on_packet(const uint8_t* buffer, uint16_t lenBytes);

class USBHIDFidoDevice final : public USBHIDDevice {
private:
  USBHID hid;

public:
  USBHIDFidoDevice() : hid(HID_ITF_PROTOCOL_NONE) {
    static bool initialized = false;
    if (!initialized) {
      initialized = true;
      hid.addDevice(this, sizeof(fido_report_descriptor));
    }
  }

  void begin() { hid.begin(); }

  bool sendPacket(const uint8_t* data, const size_t lenBytes) { return hid.SendReport(0, data, lenBytes, 100); }

  uint16_t _onGetDescriptor(uint8_t* dst) override {
    memcpy(dst, fido_report_descriptor, sizeof(fido_report_descriptor));
    return sizeof(fido_report_descriptor);
  }

  void _onOutput(uint8_t report_id, const uint8_t* buffer, uint16_t lenBytes) override {
    (void)report_id;
    fido_hid_on_packet(buffer, lenBytes);
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
  FIDO_LOG("TX ERROR cid=%08lX err=%s(0x%02X)", static_cast<unsigned long>(cid), ctaphid_err_name(err), err);
  fido_send_response(cid, CTAPHID_CMD_ERROR, &err, 1);
}

static void fido_send_keepalive(const uint32_t cid, const uint8_t status) {
  fido_send_response(cid, CTAPHID_CMD_KEEPALIVE, &status, 1);
}

static void fido_send_ctap2_status(const uint32_t cid, const uint8_t status, const uint8_t* cbor, const size_t cborLen) {
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

  // If a complete request is waiting, report busy.
  if (fidoReq.ready) {
    fido_send_error(cid, CTAPHID_ERR_CHANNEL_BUSY);
    return;
  }

  if (b4 & 0x80) {
    // Initial packet
    const uint8_t cmd = static_cast<uint8_t>(b4 & 0x7F);
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
  fidoAssignedCid = newCid;

  write_be_u32(resp + 8, newCid);
  resp[12] = 2;    // CTAPHID protocol version
  resp[13] = 1;    // major
  resp[14] = 0;    // minor
  resp[15] = 0;    // build
  resp[16] = static_cast<uint8_t>(CTAPHID_CAP_WINK | CTAPHID_CAP_CBOR | CTAPHID_CAP_NMSG);
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
  pendingCtap.lastKeepaliveMs = 0;
  fidoAwaitingUserPresence = true;
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
    fido_send_ctap2_status(cid, CTAP2_ERR_PIN_REQUIRED, nullptr, 0);
    return;
  }

  if (ctapCmd == CTAP_CMD_GET_NEXT_ASSERTION) {
    fido_send_ctap2_status(cid, CTAP2_ERR_NOT_ALLOWED, nullptr, 0);
    return;
  }

  if (ctapCmd == CTAP_CMD_MAKE_CREDENTIAL || ctapCmd == CTAP_CMD_GET_ASSERTION || ctapCmd == CTAP_CMD_RESET) {
    fido_start_pending(cid, ctapCmd, payload, payloadLen);
    fido_send_keepalive(cid, CTAPHID_KEEPALIVE_STATUS_UP_NEEDED);
    return;
  }

  fido_send_ctap2_status(cid, CTAP2_ERR_INVALID_COMMAND, nullptr, 0);
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

  if (static_cast<int32_t>(now - pendingCtap.startedMs) > static_cast<int32_t>(CTAP_UP_TIMEOUT_MS)) {
    pendingCtap.active = false;
    fidoAwaitingUserPresence = false;
    FIDO_LOG("Pending timeout cid=%08lX", static_cast<unsigned long>(cid));
    fido_send_ctap2_status(cid, CTAP2_ERR_USER_ACTION_TIMEOUT, nullptr, 0);
    return;
  }

  if (pendingCtap.lastKeepaliveMs == 0 ||
      (static_cast<int32_t>(now - pendingCtap.lastKeepaliveMs) >= static_cast<int32_t>(CTAP_KEEPALIVE_EVERY_MS))) {
    pendingCtap.lastKeepaliveMs = now;
    fido_send_keepalive(cid, CTAPHID_KEEPALIVE_STATUS_UP_NEEDED);
  }

  if (!boot_button_down()) return;
  FIDO_LOG("User presence satisfied cid=%08lX", static_cast<unsigned long>(cid));

  uint8_t body[512];
  size_t bodyLen = 0;
  uint8_t st = CTAP1_ERR_OTHER;

  if (pendingCtap.cmd == CTAP_CMD_MAKE_CREDENTIAL) {
    st = ctap2_make_credential(pendingCtap.data, pendingCtap.len, body, sizeof(body), &bodyLen);
  } else if (pendingCtap.cmd == CTAP_CMD_GET_ASSERTION) {
    st = ctap2_get_assertion(pendingCtap.data, pendingCtap.len, body, sizeof(body), &bodyLen);
  } else if (pendingCtap.cmd == CTAP_CMD_RESET) {
    st = ctap2_reset();
  } else {
    st = CTAP2_ERR_INVALID_COMMAND;
  }

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
  fidoAwaitingUserPresence = false;
  fidoSignCount = load_sign_count();
  FIDO_LOG("FIDO init signCount=%lu debug=%u", static_cast<unsigned long>(fidoSignCount), static_cast<unsigned>(FIDO_DEBUG));
}

bool fido_waiting_for_user_presence() {
  return pendingCtap.active;
}

void fido_task() {
  // Drop partial messages that time out.
  if (fidoRx.active && (static_cast<int32_t>(millis() - fidoRx.lastMs) > 1000)) {
    fidoRx.active = false;
  }

  fido_process_request();
  fido_tick_pending();
}
