#include <Arduino.h>
#line 1 "C:\\Users\\Justin\\Documents\\Arduino\\esp32s3-wifi-kbm\\esp32s3-wifi-kbm.ino"
#include <WiFi.h>
#include <DNSServer.h>
#include <WebServer.h>
#include <Preferences.h>
#include <esp_system.h>
#include <esp_timer.h>
#include <ctype.h>
#include "esp_flash_encrypt.h"
#include "esp32-hal-rgb-led.h"
#include "mbedtls/md.h"
#include "mbedtls/pkcs5.h"
#include "mbedtls/aes.h"
#include "mbedtls/gcm.h"
#include "mbedtls/sha256.h"
#include "mbedtls/ecp.h"
#include "mbedtls/ecdh.h"
#include "mbedtls/ecdsa.h"
#include "USB.h"
#include "USBHID.h"
#include "USBHIDKeyboard.h"
#include "USBHIDMouse.h"
#include <cbor.h>

// FIDO2 CBOR parsing + crypto can be stack-heavy on ESP32-S3.
#line 25 "C:\\Users\\Justin\\Documents\\Arduino\\esp32s3-wifi-kbm\\esp32s3-wifi-kbm.ino"
size_t getArduinoLoopTaskStackSize();
#line 194 "C:\\Users\\Justin\\Documents\\Arduino\\esp32s3-wifi-kbm\\esp32s3-wifi-kbm.ino"
static bool usb_kbm_hid_enabled();
#line 198 "C:\\Users\\Justin\\Documents\\Arduino\\esp32s3-wifi-kbm\\esp32s3-wifi-kbm.ino"
static void usb_input_begin();
#line 205 "C:\\Users\\Justin\\Documents\\Arduino\\esp32s3-wifi-kbm\\esp32s3-wifi-kbm.ino"
static bool usb_type_text(const String& text);
#line 215 "C:\\Users\\Justin\\Documents\\Arduino\\esp32s3-wifi-kbm\\esp32s3-wifi-kbm.ino"
static bool usb_mouse_move(const int x, const int y);
#line 226 "C:\\Users\\Justin\\Documents\\Arduino\\esp32s3-wifi-kbm\\esp32s3-wifi-kbm.ino"
static bool usb_mouse_click(const String& btn);
#line 245 "C:\\Users\\Justin\\Documents\\Arduino\\esp32s3-wifi-kbm\\esp32s3-wifi-kbm.ino"
static void serial_diag_print_help();
#line 252 "C:\\Users\\Justin\\Documents\\Arduino\\esp32s3-wifi-kbm\\esp32s3-wifi-kbm.ino"
static void serial_diag_print_status();
#line 259 "C:\\Users\\Justin\\Documents\\Arduino\\esp32s3-wifi-kbm\\esp32s3-wifi-kbm.ino"
static void serial_diag_handle_line(const String& raw);
#line 285 "C:\\Users\\Justin\\Documents\\Arduino\\esp32s3-wifi-kbm\\esp32s3-wifi-kbm.ino"
static void serial_diag_task();
#line 25 "C:\\Users\\Justin\\Documents\\Arduino\\esp32s3-wifi-kbm\\esp32s3-wifi-kbm.ino"
SET_LOOP_TASK_STACK_SIZE(16 * 1024);  // 16KB loop task stack

// Stability mode for WebAuthn troubleshooting:
// - 1: disable Wi-Fi portal runtime so USB/FIDO gets all CPU+power budget
// - 0: run normal Wi-Fi portal + FIDO
#ifndef FIDO_STABILITY_MODE
#define FIDO_STABILITY_MODE 0
#endif

// USB mode switch:
// - 0 = FIDO-only HID (recommended for current Windows CTAP troubleshooting)
// - 1 = Composite HID keyboard + mouse + FIDO
#ifndef USB_ENABLE_KBM_HID
#define USB_ENABLE_KBM_HID 1
#endif

// Wi-Fi credentials for the ESP32-S3 access point
// Recommendation: change these before use.
static constexpr const char* AP_SSID = "ESP32-SuperMini";
static constexpr const char* AP_PASS = "password123";

// Token pairing (separate from the AP password):
// - Triple-tap BOOT to enable pairing for a short window.
// - In the portal, press "Pair" (or enter a previously saved token) to sign in.
// Note: secrets stored in NVS are protected at rest only if flash encryption is enabled.
static constexpr uint32_t PAIRING_WINDOW_MS = 60 * 1000;
static constexpr uint8_t  PAIRING_TAP_COUNT = 3;
static constexpr uint32_t TAP_MAX_MS = 350;
static constexpr uint32_t TAP_GAP_MS = 500;

// TOTP (6-digit / 30s by default). The shared secret is stored in NVS.
static constexpr uint8_t  TOTP_DEFAULT_DIGITS = 6;
static constexpr uint32_t TOTP_DEFAULT_PERIOD_S = 30;
static constexpr size_t   TOTP_KEY_MAX_BYTES = 64;

// HSM (P-256 / ES256) controls exposed over the authenticated web UI.
static constexpr size_t   HSM_PRIVKEY_BYTES = 32;
static constexpr size_t   HSM_PUBKEY_BYTES = 64; // X(32) || Y(32)
static constexpr size_t   HSM_SIGNATURE_DER_MAX = 80;
static constexpr size_t   HSM_SIGN_INPUT_MAX = 512;
static constexpr uint32_t HSM_SIGN_COOLDOWN_MS = 250;
static constexpr uint32_t HSM_PIN_UNLOCK_WINDOW_MS = 5 * 60 * 1000;
static constexpr uint32_t HSM_PIN_PBKDF2_ITERS = 30000;
static constexpr size_t   HSM_PIN_SALT_BYTES = 16;
static constexpr size_t   HSM_PIN_HASH_BYTES = 32;
static constexpr size_t   FIDO_PIN_HASH16_BYTES = 16;
static constexpr size_t   HSM_PIN_MIN_LEN = 4;
static constexpr size_t   HSM_PIN_MAX_LEN = 64;
static constexpr uint32_t HSM_PRESENCE_WINDOW_MS = 15 * 1000;
static constexpr uint32_t HSM_PRESENCE_HOLD_MIN_MS = 500;
static constexpr uint32_t HSM_PRESENCE_HOLD_MAX_MS = 1200;

// Admin unlock (physical presence) gating for sensitive actions (delete/export/restore).
// Hold BOOT for a few seconds to unlock briefly.
static constexpr uint32_t ADMIN_UNLOCK_WINDOW_MS = 60 * 1000;
static constexpr uint32_t ADMIN_UNLOCK_HOLD_MIN_MS = 1500;
static constexpr uint32_t ADMIN_UNLOCK_HOLD_MAX_MS = 4500;

// Credential inventory store used by the Keys page.
// Stored in NVS as a compact binary blob to allow listing/labeling/deletion and encrypted backup/restore.
static constexpr uint32_t CRED_STORE_MAGIC = 0x314D424BU; // "KBM1" (little-endian)
static constexpr uint16_t CRED_STORE_VERSION = 1;
static constexpr size_t   CRED_STORE_MAX_BYTES = 4096;
static constexpr size_t   CRED_MAX_RPID_LEN = 64;
static constexpr size_t   CRED_MAX_LABEL_LEN = 64;
static constexpr size_t   CRED_MAX_ID_LEN = 64;
static constexpr size_t   CRED_MAX_SECRET_LEN = 128;

static constexpr uint8_t  DNS_PORT = 53;
static constexpr uint16_t HTTP_PORT = 80;

// BOOT button is typically GPIO0 on ESP32-S3 dev boards (including many SuperMini variants).
static constexpr uint8_t  BOOT_BUTTON_PIN = 0;

// Optional: set to 1 if your LED is wired active-low.
#ifndef MODE_LED_ACTIVE_LOW
#define MODE_LED_ACTIVE_LOW 0
#endif

#if defined(RGB_BUILTIN)
static constexpr int MODE_LED_PIN = RGB_BUILTIN;
static constexpr bool MODE_LED_IS_RGB = true;
#elif defined(LED_BUILTIN)
static constexpr int MODE_LED_PIN = LED_BUILTIN;
static constexpr bool MODE_LED_IS_RGB = false;
#else
static constexpr int MODE_LED_PIN = -1;
static constexpr bool MODE_LED_IS_RGB = false;
#endif

DNSServer dnsServer;
WebServer server(HTTP_PORT);

// Force TinyUSB HID interface protocol to "none" so the composite HID descriptor
// can be recognized for FIDO usage in desktop WebAuthn flows.
// Without this, keyboard-first initialization may advertise boot-keyboard protocol
// and some hosts won't surface it as a security key transport.
USBHID _hidInterfaceMode(HID_ITF_PROTOCOL_NONE);

#if USB_ENABLE_KBM_HID
USBHIDKeyboard Keyboard;
USBHIDMouse Mouse;
#endif

enum class AttestationProfile : uint8_t {
  Diy = 0,
  None = 1,
};

static Preferences prefs;
static uint32_t buttonDownSince = 0;
static bool buttonDown = false;

static char pairTokenHex[33] = {0};
static uint32_t pairingActiveUntil = 0;
static bool pairingRotateArmed = false;

static uint32_t adminUnlockedUntil = 0;
static AttestationProfile attestationProfile = AttestationProfile::Diy;

static uint8_t tapCount = 0;
static uint32_t lastTapAt = 0;
static bool pendingSingleTap = false;
static uint32_t pendingSingleTapDue = 0;

static uint8_t totpKey[TOTP_KEY_MAX_BYTES];
static size_t totpKeyLen = 0;
static uint8_t totpDigits = TOTP_DEFAULT_DIGITS;
static uint32_t totpPeriodS = TOTP_DEFAULT_PERIOD_S;
static bool totpAppendEnter = false;

static bool timeSynced = false;
static int64_t timeOffsetUs = 0;
static bool apManagementMode = false; // true = management-only AP (no /move /click /type)

struct RestoreUploadState {
  uint8_t* buf = nullptr;
  size_t len = 0;
  size_t cap = 0;
  bool error = false;
};

static RestoreUploadState restoreUpload;

struct HsmState {
  bool loaded = false;
  uint8_t priv[HSM_PRIVKEY_BYTES] = {0};
  uint8_t pub[HSM_PUBKEY_BYTES] = {0}; // X || Y
  uint32_t createdAt = 0;              // unix seconds if known, else 0
  uint32_t signCount = 0;              // runtime counter (not persisted)
  uint32_t lastSignMs = 0;
};

static HsmState hsmState;
static bool hsmPinConfigured = false;
static uint8_t hsmPinSalt[HSM_PIN_SALT_BYTES] = {0};
static uint8_t hsmPinHash[HSM_PIN_HASH_BYTES] = {0};
static uint8_t fidoPinHash16[FIDO_PIN_HASH16_BYTES] = {0}; // left16(SHA-256(PIN)) for CTAP ClientPIN
static bool fidoPinHash16Valid = false;
static uint32_t hsmPinUnlockedUntil = 0;
static uint32_t hsmPresenceUntil = 0;

// FIDO2/CTAP2 over USB HID (implemented in `fido2_ctap2.ino`).
void fido_begin();
void fido_task();
bool fido_waiting_for_user_presence();
void fido_diag_clear();
void fido_diag_build_json(String& outJson);

static bool usb_kbm_hid_enabled() {
  return USB_ENABLE_KBM_HID != 0;
}

static void usb_input_begin() {
#if USB_ENABLE_KBM_HID
  Keyboard.begin();
  Mouse.begin();
#endif
}

static bool usb_type_text(const String& text) {
#if USB_ENABLE_KBM_HID
  Keyboard.print(text);
  return true;
#else
  (void)text;
  return false;
#endif
}

static bool usb_mouse_move(const int x, const int y) {
#if USB_ENABLE_KBM_HID
  Mouse.move(static_cast<int8_t>(x), static_cast<int8_t>(y));
  return true;
#else
  (void)x;
  (void)y;
  return false;
#endif
}

static bool usb_mouse_click(const String& btn) {
#if USB_ENABLE_KBM_HID
  if (btn == "left") {
    Mouse.click(MOUSE_LEFT);
    return true;
  }
  if (btn == "right") {
    Mouse.click(MOUSE_RIGHT);
    return true;
  }
  return false;
#else
  (void)btn;
  return false;
#endif
}

static String serialDiagLine;

static void serial_diag_print_help() {
  Serial.println("FIDO serial diag commands:");
  Serial.println("  diag        -> print FIDO diag JSON");
  Serial.println("  diag reset  -> clear FIDO diag counters");
  Serial.println("  help        -> show this help");
}

static void serial_diag_print_status() {
  String json;
  fido_diag_build_json(json);
  Serial.print("FIDO_DIAG ");
  Serial.println(json);
}

static void serial_diag_handle_line(const String& raw) {
  String cmd = raw;
  cmd.trim();
  if (cmd.length() == 0) return;

  if (cmd.equalsIgnoreCase("diag") || cmd.equalsIgnoreCase("diag status") || cmd.equalsIgnoreCase("status")) {
    serial_diag_print_status();
    return;
  }

  if (cmd.equalsIgnoreCase("diag reset") || cmd.equalsIgnoreCase("reset")) {
    fido_diag_clear();
    Serial.println("FIDO_DIAG reset");
    return;
  }

  if (cmd.equalsIgnoreCase("help") || cmd.equalsIgnoreCase("?")) {
    serial_diag_print_help();
    return;
  }

  Serial.print("FIDO_DIAG unknown command: ");
  Serial.println(cmd);
  serial_diag_print_help();
}

static void serial_diag_task() {
  while (Serial.available() > 0) {
    const int c = Serial.read();
    if (c < 0) break;
    if (c == '\n' || c == '\r') {
      if (serialDiagLine.length() > 0) {
        serial_diag_handle_line(serialDiagLine);
        serialDiagLine = "";
      }
      continue;
    }
    if (c >= 32 && c <= 126) {
      if (serialDiagLine.length() < 160) {
        serialDiagLine += static_cast<char>(c);
      }
    }
  }
}

// --- HTML & JAVASCRIPT FOR THE WEB UI ---
static const char index_html[] PROGMEM = R"rawliteral(
<!DOCTYPE html>
<html>
<head>
  <meta name="viewport" content="width=device-width, initial-scale=1.0, maximum-scale=1.0, user-scalable=no">
  <title>ESP32 Remote</title>
  <style>
    * {
      touch-action: none !important;
      overscroll-behavior: none !important;
      -webkit-touch-callout: none;
      -webkit-user-select: none;
      user-select: none;
    }

    html, body {
      position: fixed; top: 0; left: 0; right: 0; bottom: 0;
      width: 100%; height: 100%; overflow: hidden;
      font-family: Arial, sans-serif; text-align: center; margin: 0; padding: 0;
      background: #121212; color: white;
    }

    input {
      touch-action: auto !important;
      -webkit-user-select: auto;
      user-select: auto;
      padding: 12px; font-size: 16px; width: calc(100% - 100px); border-radius: 8px; border: none;
    }

    .container { padding: 15px; height: calc(100% - 30px); display: flex; flex-direction: column; }
    h2 { margin-top: 5px; flex: none; }

    #trackpad {
      flex-grow: 1; width: 100%; background: #2a2a2a; border-radius: 15px;
      margin-top: 15px; margin-bottom: 5px; border: 2px solid #444;
      touch-action: none;
    }

    .btn-row { display: flex; justify-content: space-between; margin-top: 5px; flex: none; }
    button { flex: 1; padding: 15px; font-size: 16px; margin: 5px; border-radius: 8px; border: none; background: #007bff; color: white; cursor: pointer; }
    button:active { background: #0056b3; }
    .input-row { display: flex; justify-content: center; align-items: center; gap: 10px; flex: none; }
  </style>
</head>
<body>
  <div class="container">
    <div style="display:flex; justify-content:space-between; align-items:center; gap:10px;">
      <h2 style="margin: 5px 0;">ESP32 Input Control</h2>
      <div style="display:flex; gap:12px; align-items:center;">
        <a href="/ap" style="color:#9ecbff; text-decoration:none; font-size:14px;">AP</a>
        <a href="/diag" style="color:#9ecbff; text-decoration:none; font-size:14px;">Diag</a>
        <a href="/keys" style="color:#9ecbff; text-decoration:none; font-size:14px;">Keys</a>
        <a href="/hsm" style="color:#9ecbff; text-decoration:none; font-size:14px;">HSM</a>
        <a href="/totp" style="color:#9ecbff; text-decoration:none; font-size:14px;">TOTP</a>
        <a href="/logout" style="color:#9ecbff; text-decoration:none; font-size:14px;">Sign out</a>
      </div>
    </div>
    <div class="input-row">
      <input type="text" id="textInput" placeholder="Type here...">
      <button style="width: 80px; flex: none;" onclick="sendText()">Send</button>
    </div>
    <div id="trackpad"></div>
    <div class="btn-row">
      <button onclick="sendClick('left')">Left Click</button>
      <button onclick="sendClick('right')">Right Click</button>
    </div>
  </div>

  <script>
    window.addEventListener('touchmove', function(e) {
      if (e.target.tagName !== 'INPUT') e.preventDefault();
    }, { passive: false, capture: true });

    let lastX = 0, lastY = 0, isDown = false;
    let accX = 0, accY = 0, isSending = false;
    let tapTime = 0, tapMoved = false, multiTouch = false;
    let activePointers = 0;

    const pad = document.getElementById('trackpad');

    function authFetch(url) {
      return fetch(url, { cache: 'no-store' }).then((r) => {
        if (r.status === 401) {
          window.location = '/';
          throw new Error('auth');
        }
        return r;
      });
    }

    // Keep time in sync for features that require it (ex: TOTP).
    authFetch('/time?ms=' + Date.now()).catch(() => {});

    function sendText() {
      let text = document.getElementById('textInput').value;
      if(text.length > 0) {
        authFetch('/type?t=' + encodeURIComponent(text)).catch(() => {});
        document.getElementById('textInput').value = '';
      }
    }

    function sendClick(btn) {
      authFetch('/click?b=' + btn).catch(() => {});
    }

    function handlePointerDown(e) {
      e.preventDefault();
      pad.setPointerCapture(e.pointerId);
      activePointers++;

      if (activePointers === 2) {
        multiTouch = true;
        sendClick('right');
        return;
      }

      if (activePointers === 1) {
        isDown = true;
        tapMoved = false;
        multiTouch = false;
        tapTime = Date.now();
        lastX = e.clientX;
        lastY = e.clientY;
      }
    }

    function handlePointerMove(e) {
      e.preventDefault();
      if (!isDown || multiTouch || !e.isPrimary) return;

      let dx = e.clientX - lastX;
      let dy = e.clientY - lastY;

      if (Math.abs(dx) > 2 || Math.abs(dy) > 2) {
        tapMoved = true;
      }

      accX += dx;
      accY += dy;
      lastX = e.clientX;
      lastY = e.clientY;

      sendMoveQueue();
    }

    function handlePointerUp(e) {
      e.preventDefault();
      activePointers--;
      if (activePointers < 0) activePointers = 0;

      if (activePointers === 0) {
        isDown = false;
        if (!multiTouch && !tapMoved && (Date.now() - tapTime < 250)) {
          sendClick('left');
        }
      }
    }

    function sendMoveQueue() {
      if(isSending || (Math.abs(accX) < 1 && Math.abs(accY) < 1)) return;

      isSending = true;
      let tx = Math.round(accX);
      let ty = Math.round(accY);

      if (tx > 120) tx = 120; else if (tx < -120) tx = -120;
      if (ty > 120) ty = 120; else if (ty < -120) ty = -120;

      accX -= tx;
      accY -= ty;

      authFetch('/move?x=' + tx + '&y=' + ty)
        .then(() => {
          isSending = false;
          sendMoveQueue();
        })
        .catch(() => { isSending = false; });
    }

    pad.addEventListener('pointerdown', handlePointerDown, { passive: false });
    pad.addEventListener('pointermove', handlePointerMove, { passive: false });
    pad.addEventListener('pointerup', handlePointerUp, { passive: false });
    pad.addEventListener('pointercancel', handlePointerUp, { passive: false });
  </script>
</body>
</html>
)rawliteral";

static const char login_html[] PROGMEM = R"rawliteral(
<!DOCTYPE html>
<html>
<head>
  <meta name="viewport" content="width=device-width, initial-scale=1.0, maximum-scale=1.0, user-scalable=no">
  <title>ESP32 Portal</title>
  <style>
    html, body {
      width: 100%; height: 100%; margin: 0; padding: 0;
      font-family: Arial, sans-serif;
      background: #121212; color: white;
      display: flex; align-items: center; justify-content: center;
    }
    .card {
      width: min(420px, calc(100% - 32px));
      background: #1c1c1c;
      border: 1px solid #2a2a2a;
      border-radius: 12px;
      padding: 18px;
      box-sizing: border-box;
      text-align: left;
    }
    h2 { margin: 0 0 10px 0; }
    p { margin: 8px 0; color: #cfcfcf; }
    input {
      width: 100%;
      padding: 12px;
      font-size: 16px;
      border-radius: 8px;
      border: none;
      margin-top: 10px;
      box-sizing: border-box;
    }
    button {
      width: 100%;
      padding: 12px;
      font-size: 16px;
      border-radius: 8px;
      border: none;
      margin-top: 10px;
      background: #007bff;
      color: white;
      cursor: pointer;
    }
    button:active { background: #0056b3; }
    .err { display:none; margin-top: 10px; color: #ff6b6b; }
    .ok { display:none; margin-top: 10px; color: #89ff9b; }
    .hint { font-size: 12px; margin-top: 10px; color: #9a9a9a; }
  </style>
</head>
<body>
  <div class="card">
    <h2>Sign in</h2>
    <p>Pair this phone (triple-tap BOOT, then press Pair) or enter a pairing token.</p>
    <form method="POST" action="/login">
      <input type="text" name="t" placeholder="Pairing token" autocapitalize="off" autocomplete="off" spellcheck="false">
      <button type="submit">Sign in</button>
      <div class="err" id="err">Token was not accepted.</div>
      <div class="ok" id="ok">Paired. Loading controls…</div>
    </form>
    <button type="button" onclick="pairNow()">Pair</button>
    <div class="hint">Pairing is only available for a short time after triple-tapping BOOT.</div>
  </div>
  <script>
    const e = new URLSearchParams(location.search).get('e');
    if (e) document.getElementById('err').style.display = 'block';
    async function pairNow() {
      try {
        const r = await fetch('/pair', { cache: 'no-store' });
        if (r.ok) {
          document.getElementById('ok').style.display = 'block';
          window.location = '/';
          return;
        }
        document.getElementById('err').textContent = 'Pairing is not available. Triple-tap BOOT and try again.';
        document.getElementById('err').style.display = 'block';
      } catch (e) {
        document.getElementById('err').textContent = 'Pairing request did not complete.';
        document.getElementById('err').style.display = 'block';
      }
    }
  </script>
</body>
</html>
)rawliteral";

static const char totp_html[] PROGMEM = R"rawliteral(
<!DOCTYPE html>
<html>
<head>
  <meta name="viewport" content="width=device-width, initial-scale=1.0, maximum-scale=1.0, user-scalable=no">
  <title>ESP32 TOTP</title>
  <style>
    html, body {
      width: 100%; height: 100%; margin: 0; padding: 0;
      font-family: Arial, sans-serif;
      background: #121212; color: white;
      display: flex; align-items: center; justify-content: center;
    }
    .card {
      width: min(520px, calc(100% - 32px));
      background: #1c1c1c;
      border: 1px solid #2a2a2a;
      border-radius: 12px;
      padding: 18px;
      box-sizing: border-box;
      text-align: left;
    }
    .top { display:flex; justify-content:space-between; align-items:center; margin-bottom: 10px; }
    a { color:#9ecbff; text-decoration:none; font-size:14px; }
    h2 { margin: 0 0 10px 0; }
    p { margin: 8px 0; color: #cfcfcf; }
    label { display:block; margin-top: 10px; font-size: 13px; color:#cfcfcf; }
    input[type="text"], input[type="password"], input[type="number"] {
      width: 100%;
      padding: 12px;
      font-size: 16px;
      border-radius: 8px;
      border: none;
      margin-top: 6px;
      box-sizing: border-box;
    }
    .row { display:flex; gap: 10px; }
    button {
      width: 100%;
      padding: 12px;
      font-size: 16px;
      border-radius: 8px;
      border: none;
      margin-top: 12px;
      background: #007bff;
      color: white;
      cursor: pointer;
    }
    button:active { background: #0056b3; }
    .danger { background: #b00020; }
    .danger:active { background: #7a0016; }
    .status {
      margin-top: 10px;
      padding: 10px;
      border: 1px solid #2a2a2a;
      border-radius: 10px;
      background: #171717;
      font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, "Liberation Mono", "Courier New", monospace;
      font-size: 13px;
      line-height: 1.4;
      white-space: pre-wrap;
    }
    .hint { font-size: 12px; margin-top: 10px; color: #9a9a9a; }
  </style>
</head>
<body>
  <div class="card">
    <div class="top">
      <a href="/">← Back</a>
      <div style="display:flex; gap:12px; align-items:center;">
        <a href="/ap">AP</a>
        <a href="/diag">Diag</a>
        <a href="/keys">Keys</a>
        <a href="/hsm">HSM</a>
        <a href="/logout">Sign out</a>
      </div>
    </div>
    <h2>TOTP</h2>
    <p>Single-tap BOOT to type the current code (after time sync).</p>

    <div class="status" id="status">Loading…</div>

    <form method="POST" action="/totp">
      <label>Shared secret (Base32)</label>
      <input type="password" name="s" placeholder="Example: JBSWY3DPEHPK3PXP" autocapitalize="off" autocomplete="off" spellcheck="false">

      <div class="row">
        <div style="flex:1;">
          <label>Digits</label>
          <input type="number" name="d" value="6" min="6" max="10">
        </div>
        <div style="flex:1;">
          <label>Period (seconds)</label>
          <input type="number" name="p" value="30" min="10" max="120">
        </div>
      </div>

      <label style="margin-top:12px;">
        <input type="checkbox" name="e" style="transform: scale(1.2); margin-right: 8px;">
        Append Enter
      </label>

      <button type="submit">Save</button>
    </form>

    <form method="POST" action="/totp/clear">
      <button class="danger" type="submit">Clear secret</button>
    </form>

    <div class="hint">Tip: opening the control page syncs time automatically.</div>
  </div>

  <script>
    async function refresh() {
      const r = await fetch('/totp/status', { cache: 'no-store' });
      if (r.status === 401) { window.location = '/'; return; }
      if (!r.ok) return;
      const j = await r.json();
      const lines = [];
      lines.push('configured: ' + (j.configured ? 'yes' : 'no'));
      lines.push('time_synced: ' + (j.time_synced ? 'yes' : 'no'));
      lines.push('code: ' + (j.code || ''));
      lines.push('seconds_remaining: ' + (j.seconds_remaining ?? ''));
      lines.push('flash_encryption: ' + (j.flash_encryption ? 'enabled' : 'disabled'));
      document.getElementById('status').textContent = lines.join('\\n');
    }
    refresh();
    setInterval(refresh, 1000);
  </script>
</body>
</html>
)rawliteral";

static const char keys_html[] PROGMEM = R"rawliteral(
<!DOCTYPE html>
<html>
<head>
  <meta name="viewport" content="width=device-width, initial-scale=1.0, maximum-scale=1.0, user-scalable=no">
  <title>ESP32 Keys</title>
  <style>
    html, body {
      width: 100%; height: 100%; margin: 0; padding: 0;
      font-family: Arial, sans-serif;
      background: #121212; color: white;
      display: flex; align-items: center; justify-content: center;
    }
    .card {
      width: min(720px, calc(100% - 32px));
      background: #1c1c1c;
      border: 1px solid #2a2a2a;
      border-radius: 12px;
      padding: 18px;
      box-sizing: border-box;
      text-align: left;
    }
    .top { display:flex; justify-content:space-between; align-items:center; margin-bottom: 10px; }
    a { color:#9ecbff; text-decoration:none; font-size:14px; }
    h2 { margin: 0 0 10px 0; }
    h3 { margin: 18px 0 8px 0; font-size: 16px; }
    p { margin: 8px 0; color: #cfcfcf; }
    .small { font-size: 12px; color: #9a9a9a; }
    label { display:block; margin-top: 10px; font-size: 13px; color:#cfcfcf; }
    input[type="text"], input[type="password"], select {
      width: 100%;
      padding: 12px;
      font-size: 16px;
      border-radius: 8px;
      border: none;
      margin-top: 6px;
      box-sizing: border-box;
      background: #2a2a2a;
      color: white;
    }
    button {
      width: 100%;
      padding: 12px;
      font-size: 16px;
      border-radius: 8px;
      border: none;
      margin-top: 12px;
      background: #007bff;
      color: white;
      cursor: pointer;
    }
    button:active { background: #0056b3; }
    .danger { background: #b00020; }
    .danger:active { background: #7a0016; }
    .status {
      margin-top: 10px;
      padding: 10px;
      border: 1px solid #2a2a2a;
      border-radius: 10px;
      background: #171717;
      font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, "Liberation Mono", "Courier New", monospace;
      font-size: 13px;
      line-height: 1.4;
      white-space: pre-wrap;
    }
    .list { margin-top: 12px; display: flex; flex-direction: column; gap: 10px; }
    .item {
      border: 1px solid #2a2a2a;
      background: #161616;
      border-radius: 10px;
      padding: 12px;
    }
    .row { display:flex; justify-content:space-between; align-items:baseline; gap: 10px; }
    .mono { font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, "Liberation Mono", "Courier New", monospace; color: #cfcfcf; }
    .btnrow { display:flex; gap: 10px; margin-top: 10px; }
    .btnrow button { width: 50%; margin-top: 0; }
    .hint { font-size: 12px; margin-top: 10px; color: #9a9a9a; }
    .msg { margin-top: 10px; color: #ffcc80; }
  </style>
</head>
<body>
  <div class="card">
    <div class="top">
      <a href="/">← Back</a>
      <div style="display:flex; gap:12px; align-items:center;">
        <a href="/ap">AP</a>
        <a href="/diag">Diag</a>
        <a href="/hsm">HSM</a>
        <a href="/totp">TOTP</a>
        <a href="/logout">Sign out</a>
      </div>
    </div>

    <h2>Security Key</h2>
    <p class="small">CTAP2/FIDO2 over USB HID is enabled. Use this page for credential inventory and backups.</p>
    <p class="small">Hold BOOT for ~2–4 seconds to unlock admin actions (delete / backup / restore) for about 60 seconds.</p>

    <div class="status" id="status">Loading…</div>
    <div class="msg" id="msg"></div>

    <h3>Credential inventory</h3>
    <div id="list" class="list"></div>

    <h3>Attestation</h3>
    <p class="small">Controls how the device identifies itself to relying parties. Certified-key impersonation is not supported.</p>
    <select id="attest">
      <option value="diy">DIY-S3-Key</option>
      <option value="none">No attestation</option>
    </select>
    <button type="button" onclick="saveAttestation()">Save attestation setting</button>

    <h3>Encrypted backup</h3>
    <p class="small">Exports stored credentials into an encrypted file. Keep your password safe.</p>
    <input type="password" id="bp" placeholder="Backup password">
    <button type="button" onclick="downloadBackup()">Download backup</button>

    <h3>Restore backup</h3>
    <p class="small">Restores credentials from an encrypted backup (replaces current stored credentials).</p>
    <form method="POST" action="/backup/restore" enctype="multipart/form-data">
      <input type="password" name="p" placeholder="Backup password">
      <input type="file" name="f" accept=".bin,application/octet-stream">
      <button class="danger" type="submit">Restore backup</button>
    </form>

    <div class="hint">Tip: pairing token and TOTP secret are not included in backups.</div>
  </div>

  <script>
    function escHtml(s) {
      return (s ?? '').replace(/[&<>"']/g, (c) => {
        if (c === '&') return '&amp;';
        if (c === '<') return '&lt;';
        if (c === '>') return '&gt;';
        if (c === '"') return '&quot;';
        return '&#39;';
      });
    }

    async function api(url, opts) {
      const r = await fetch(url, Object.assign({ cache: 'no-store' }, opts || {}));
      if (r.status === 401) { window.location = '/'; throw new Error('auth'); }
      return r;
    }

    function showMsg(t) {
      const el = document.getElementById('msg');
      el.textContent = t || '';
    }

    function renderList(entries, adminUnlocked) {
      const list = document.getElementById('list');
      list.innerHTML = '';
      if (!entries || entries.length === 0) {
        const d = document.createElement('div');
        d.className = 'small';
        d.textContent = 'No credentials stored.';
        list.appendChild(d);
        return;
      }
      for (const e of entries) {
        const id = e.id || '';
        const idShort = id.length > 16 ? (id.slice(0, 8) + '…' + id.slice(-4)) : id;
        const item = document.createElement('div');
        item.className = 'item';
        item.innerHTML = `
          <div class="row">
            <div>
              <div class="small">rp_id</div>
              <div>${escHtml(e.rp || '')}</div>
            </div>
            <div class="mono">${escHtml(idShort)}</div>
          </div>
          <label>Label</label>
          <input type="text" data-id="${escHtml(id)}" value="${escHtml(e.label || '')}" placeholder="Optional label">
          <div class="btnrow">
            <button type="button" onclick="saveLabel('${escHtml(id)}')">Save label</button>
            <button class="danger" type="button" onclick="deleteKey('${escHtml(id)}')">Delete</button>
          </div>
        `;
        list.appendChild(item);
      }
      if (!adminUnlocked) {
        showMsg('Admin actions locked (hold BOOT ~2–4s to unlock).');
      } else {
        showMsg('Admin actions unlocked.');
      }
    }

    async function refresh() {
      const st = await api('/admin/status');
      const sj = await st.json();

      const kl = await api('/keys/list');
      const kj = await kl.json();

      const lines = [];
      lines.push('admin_unlocked: ' + (sj.admin_unlocked ? 'yes' : 'no'));
      lines.push('admin_seconds_remaining: ' + (sj.admin_seconds_remaining ?? ''));
      lines.push('flash_encryption: ' + (sj.flash_encryption ? 'enabled' : 'disabled'));
      lines.push('credential_count: ' + (kj.count ?? 0));
      document.getElementById('status').textContent = lines.join('\\n');

      if (kj.attestation_profile) {
        document.getElementById('attest').value = kj.attestation_profile;
      }

      renderList(kj.entries || [], sj.admin_unlocked);
    }

    async function saveLabel(id) {
      const el = document.querySelector('input[data-id=\"' + id + '\"]');
      const label = el ? el.value : '';
      const body = new URLSearchParams();
      body.set('id', id);
      body.set('label', label);
      const r = await api('/keys/label', { method: 'POST', headers: {'Content-Type':'application/x-www-form-urlencoded'}, body: body.toString() });
      if (!r.ok) {
        showMsg('Label update was not accepted.');
        return;
      }
      showMsg('Label saved.');
      refresh();
    }

    async function deleteKey(id) {
      const body = new URLSearchParams();
      body.set('id', id);
      const r = await api('/keys/delete', { method: 'POST', headers: {'Content-Type':'application/x-www-form-urlencoded'}, body: body.toString() });
      const txt = await r.text();
      if (!r.ok) {
        showMsg(txt || 'Delete request was not accepted.');
        return;
      }
      showMsg('Deleted.');
      refresh();
    }

    async function saveAttestation() {
      const a = document.getElementById('attest').value;
      const body = new URLSearchParams();
      body.set('a', a);
      const r = await api('/keys/settings', { method: 'POST', headers: {'Content-Type':'application/x-www-form-urlencoded'}, body: body.toString() });
      const txt = await r.text();
      if (!r.ok) {
        showMsg(txt || 'Attestation setting was not accepted.');
        return;
      }
      showMsg('Attestation setting saved.');
      refresh();
    }

    async function downloadBackup() {
      const p = document.getElementById('bp').value;
      const body = new URLSearchParams();
      body.set('p', p);
      const r = await api('/backup/download', { method: 'POST', headers: {'Content-Type':'application/x-www-form-urlencoded'}, body: body.toString() });
      if (!r.ok) {
        const t = await r.text();
        showMsg(t || 'Backup download was not accepted.');
        return;
      }
      const b = await r.blob();
      const url = URL.createObjectURL(b);
      const a = document.createElement('a');
      a.href = url;
      a.download = 'esp32s3-kbm-backup.bin';
      a.click();
      setTimeout(() => URL.revokeObjectURL(url), 2000);
      showMsg('Backup downloaded.');
    }

    const qr = new URLSearchParams(location.search).get('r');
    if (qr === '1') showMsg('Restore completed.');
    else if (qr === '0') showMsg('Restore failed (check password/file).');

    refresh();
    setInterval(refresh, 2000);
  </script>
</body>
</html>
)rawliteral";

static const char ap_html[] PROGMEM = R"rawliteral(
<!DOCTYPE html>
<html>
<head>
  <meta name="viewport" content="width=device-width, initial-scale=1.0, maximum-scale=1.0, user-scalable=no">
  <title>ESP32 AP Management</title>
  <style>
    html, body {
      width: 100%; height: 100%; margin: 0; padding: 0;
      font-family: Arial, sans-serif;
      background: #121212; color: white;
      display: flex; align-items: center; justify-content: center;
    }
    .card {
      width: min(700px, calc(100% - 32px));
      background: #1c1c1c;
      border: 1px solid #2a2a2a;
      border-radius: 12px;
      padding: 18px;
      box-sizing: border-box;
      text-align: left;
    }
    .top { display:flex; justify-content:space-between; align-items:center; margin-bottom: 10px; }
    a { color:#9ecbff; text-decoration:none; font-size:14px; }
    h2 { margin: 0 0 10px 0; }
    p { margin: 8px 0; color: #cfcfcf; }
    .small { font-size: 12px; color: #9a9a9a; }
    .status {
      margin-top: 10px;
      padding: 10px;
      border: 1px solid #2a2a2a;
      border-radius: 10px;
      background: #171717;
      font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, "Liberation Mono", "Courier New", monospace;
      font-size: 13px;
      line-height: 1.4;
      white-space: pre-wrap;
    }
    .row { display:flex; gap: 10px; margin-top: 12px; }
    button {
      width: 50%;
      padding: 12px;
      font-size: 15px;
      border-radius: 8px;
      border: none;
      background: #007bff;
      color: white;
      cursor: pointer;
    }
    button:active { background: #0056b3; }
    .msg { margin-top: 10px; color: #ffcc80; min-height: 20px; }
  </style>
</head>
<body>
  <div class="card">
    <div class="top">
      <a href="/">Back</a>
      <div style="display:flex; gap:12px; align-items:center;">
        <a href="/keys">Keys</a>
        <a href="/diag">Diag</a>
        <a href="/hsm">HSM</a>
        <a href="/totp">TOTP</a>
        <a href="/logout">Sign out</a>
      </div>
    </div>

    <h2>AP Management Mode</h2>
    <p class="small">Management-only mode blocks remote HID actions (`/move`, `/click`, `/type`) and keeps AP for admin pages.</p>
    <p class="small">Changing mode requires admin unlock (hold BOOT ~2-4s).</p>

    <div class="status" id="status">Loading...</div>
    <div class="msg" id="msg"></div>

    <div class="row">
      <button type="button" onclick="setMode('manage')">Enable Management-Only</button>
      <button type="button" onclick="setMode('control')">Enable Full Control</button>
    </div>
  </div>

  <script>
    async function api(url, opts) {
      const r = await fetch(url, Object.assign({ cache: 'no-store' }, opts || {}));
      if (r.status === 401) { window.location = '/'; throw new Error('auth'); }
      return r;
    }

    function showMsg(t) {
      document.getElementById('msg').textContent = t || '';
    }

    function fmtNullable(v) {
      return (v === null || v === undefined || v === '') ? '' : String(v);
    }

    async function refresh() {
      const stR = await api('/admin/status');
      const apR = await api('/ap/status');
      const st = await stR.json();
      const ap = await apR.json();

      const lines = [];
      lines.push('mode: ' + (ap.mode || ''));
      lines.push('ap_ssid: ' + (ap.ssid || ''));
      lines.push('admin_unlocked: ' + (st.admin_unlocked ? 'yes' : 'no'));
      lines.push('admin_seconds_remaining: ' + fmtNullable(st.admin_seconds_remaining));
      lines.push('flash_encryption: ' + (st.flash_encryption ? 'enabled' : 'disabled'));
      lines.push('usb_kbm_hid_enabled: ' + (ap.usb_kbm_hid_enabled ? 'yes' : 'no'));
      document.getElementById('status').textContent = lines.join('\n');
    }

    async function setMode(mode) {
      const body = new URLSearchParams();
      body.set('mode', mode);
      const r = await api('/ap/mode', {
        method: 'POST',
        headers: {'Content-Type':'application/x-www-form-urlencoded'},
        body: body.toString()
      });
      const t = await r.text();
      if (!r.ok) {
        showMsg(t || 'AP mode change failed.');
        return;
      }
      showMsg(t || 'AP mode updated.');
      await refresh();
    }

    refresh();
    setInterval(refresh, 2000);
  </script>
</body>
</html>
)rawliteral";

static const char diag_html[] PROGMEM = R"rawliteral(
<!DOCTYPE html>
<html>
<head>
  <meta name="viewport" content="width=device-width, initial-scale=1.0, maximum-scale=1.0, user-scalable=no">
  <title>ESP32 Diagnostics</title>
  <style>
    html, body {
      width: 100%; height: 100%; margin: 0; padding: 0;
      font-family: Arial, sans-serif;
      background: #121212; color: white;
      display: flex; align-items: center; justify-content: center;
    }
    .card {
      width: min(760px, calc(100% - 24px));
      max-height: calc(100% - 24px);
      overflow: auto;
      background: #1c1c1c;
      border: 1px solid #2a2a2a;
      border-radius: 12px;
      padding: 16px;
      box-sizing: border-box;
      text-align: left;
    }
    .top { display:flex; justify-content:space-between; align-items:center; margin-bottom: 10px; }
    a { color:#9ecbff; text-decoration:none; font-size:14px; }
    h2 { margin: 0 0 10px 0; }
    .small { font-size: 12px; color: #9a9a9a; }
    .status {
      margin-top: 10px;
      padding: 10px;
      border: 1px solid #2a2a2a;
      border-radius: 10px;
      background: #171717;
      font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, "Liberation Mono", "Courier New", monospace;
      font-size: 13px;
      line-height: 1.4;
      white-space: pre-wrap;
      word-break: break-word;
    }
    button {
      width: 100%;
      padding: 12px;
      font-size: 15px;
      border-radius: 8px;
      border: none;
      margin-top: 12px;
      background: #007bff;
      color: white;
      cursor: pointer;
    }
    button:active { background: #0056b3; }
    .msg { margin-top: 10px; color: #ffcc80; min-height: 20px; }
  </style>
</head>
<body>
  <div class="card">
    <div class="top">
      <a href="/">Back</a>
      <div style="display:flex; gap:12px; align-items:center;">
        <a href="/ap">AP</a>
        <a href="/keys">Keys</a>
        <a href="/hsm">HSM</a>
        <a href="/totp">TOTP</a>
        <a href="/logout">Sign out</a>
      </div>
    </div>

    <h2>Diagnostics</h2>
    <p class="small">Live FIDO/CTAP diagnostics for troubleshooting registration/authentication and user-presence flow.</p>
    <div class="status" id="status">Loading...</div>
    <button type="button" onclick="resetDiag()">Reset counters</button>
    <div class="msg" id="msg"></div>
  </div>

  <script>
    async function api(url, opts) {
      const r = await fetch(url, Object.assign({ cache: 'no-store' }, opts || {}));
      if (r.status === 401) { window.location = '/'; throw new Error('auth'); }
      return r;
    }

    function showMsg(t) {
      document.getElementById('msg').textContent = t || '';
    }

    function fmt(v) {
      return (v === null || v === undefined || v === '') ? '' : String(v);
    }

    async function refresh() {
      const adR = await api('/admin/status');
      const dgR = await api('/diag/status');
      const ad = await adR.json();
      const d = await dgR.json();

      const lines = [];
      lines.push('admin_unlocked: ' + (ad.admin_unlocked ? 'yes' : 'no'));
      lines.push('admin_seconds_remaining: ' + fmt(ad.admin_seconds_remaining));
      lines.push('flash_encryption: ' + (ad.flash_encryption ? 'enabled' : 'disabled'));
      lines.push('last_cid: ' + fmt(d.last_cid));
      lines.push('last_hid_cmd: ' + fmt(d.last_hid_cmd) + ' (' + (d.last_hid_cmd_name || '') + ')');
      lines.push('last_ctap_cmd: ' + fmt(d.last_ctap_cmd) + ' (' + (d.last_ctap_cmd_name || '') + ')');
      lines.push('last_ctap_status: ' + fmt(d.last_ctap_status) + ' (' + (d.last_ctap_status_name || '') + ')');
      lines.push('last_hid_error: ' + fmt(d.last_hid_error) + ' (' + (d.last_hid_error_name || '') + ')');
      lines.push('pending_waiting_up: ' + (d.pending_waiting_up ? 'yes' : 'no'));
      lines.push('rx_ms_ago: ' + fmt(d.rx_ms_ago));
      lines.push('tx_ms_ago: ' + fmt(d.tx_ms_ago));
      lines.push('ctap_requests_total: ' + fmt(d.ctap_requests_total));
      lines.push('ctap_ok_total: ' + fmt(d.ctap_ok_total));
      lines.push('ctap_err_total: ' + fmt(d.ctap_err_total));
      lines.push('pin_gate_blocks_total: ' + fmt(d.pin_gate_blocks_total));
      lines.push('up_satisfied_total: ' + fmt(d.up_satisfied_total));
      lines.push('hid_out_callbacks_total: ' + fmt(d.hid_out_callbacks_total));
      lines.push('hid_set_feature_callbacks_total: ' + fmt(d.hid_set_feature_callbacks_total));
      lines.push('hid_get_feature_callbacks_total: ' + fmt(d.hid_get_feature_callbacks_total));
      lines.push('unexpected_report_id_total: ' + fmt(d.unexpected_report_id_total));
      lines.push('dropped_bad_len_total: ' + fmt(d.dropped_bad_len_total));
      lines.push('normalized_packets_total: ' + fmt(d.normalized_packets_total));
      lines.push('last_report_id_seen: ' + fmt(d.last_report_id_seen));
      lines.push('last_report_len_seen: ' + fmt(d.last_report_len_seen));
      lines.push('last_report_id_dropped: ' + fmt(d.last_report_id_dropped));
      lines.push('last_report_len_dropped: ' + fmt(d.last_report_len_dropped));
      document.getElementById('status').textContent = lines.join('\n');
    }

    async function resetDiag() {
      const r = await api('/diag/reset', { method: 'POST' });
      const t = await r.text();
      if (!r.ok) {
        showMsg(t || 'Reset failed.');
        return;
      }
      showMsg(t || 'Diagnostics counters reset.');
      await refresh();
    }

    refresh();
    setInterval(refresh, 1000);
  </script>
</body>
</html>
)rawliteral";

static const char hsm_html[] PROGMEM = R"rawliteral(
<!DOCTYPE html>
<html>
<head>
  <meta name="viewport" content="width=device-width, initial-scale=1.0, maximum-scale=1.0, user-scalable=no">
  <title>ESP32 HSM</title>
  <style>
    html, body {
      width: 100%; height: 100%; margin: 0; padding: 0;
      font-family: Arial, sans-serif;
      background: #121212; color: white;
      display: flex; align-items: center; justify-content: center;
    }
    .card {
      width: min(760px, calc(100% - 24px));
      max-height: calc(100% - 24px);
      overflow: auto;
      background: #1c1c1c;
      border: 1px solid #2a2a2a;
      border-radius: 12px;
      padding: 16px;
      box-sizing: border-box;
      text-align: left;
    }
    .top { display:flex; justify-content:space-between; align-items:center; margin-bottom: 10px; }
    a { color:#9ecbff; text-decoration:none; font-size:14px; }
    h2 { margin: 0 0 10px 0; }
    h3 { margin: 16px 0 8px 0; font-size: 16px; }
    p { margin: 8px 0; color: #cfcfcf; }
    .small { font-size: 12px; color: #9a9a9a; }
    label { display:block; margin-top: 10px; font-size: 13px; color:#cfcfcf; }
    textarea, input[type="text"], input[type="password"], select {
      width: 100%;
      padding: 12px;
      font-size: 14px;
      border-radius: 8px;
      border: none;
      margin-top: 6px;
      box-sizing: border-box;
      background: #2a2a2a;
      color: white;
      font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, "Liberation Mono", "Courier New", monospace;
    }
    button {
      width: 100%;
      padding: 12px;
      font-size: 15px;
      border-radius: 8px;
      border: none;
      margin-top: 12px;
      background: #007bff;
      color: white;
      cursor: pointer;
    }
    button:active { background: #0056b3; }
    .danger { background: #b00020; }
    .danger:active { background: #7a0016; }
    .status {
      margin-top: 10px;
      padding: 10px;
      border: 1px solid #2a2a2a;
      border-radius: 10px;
      background: #171717;
      font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, "Liberation Mono", "Courier New", monospace;
      font-size: 13px;
      line-height: 1.4;
      white-space: pre-wrap;
      word-break: break-all;
    }
    .msg { margin-top: 10px; color: #ffcc80; min-height: 20px; }
    .row { display:flex; gap: 10px; }
    .row button { width: 50%; }
    .hint { margin-top: 10px; color:#9a9a9a; font-size: 12px; }
  </style>
</head>
<body>
  <div class="card">
    <div class="top">
      <a href="/">Back</a>
      <div style="display:flex; gap:12px; align-items:center;">
        <a href="/ap">AP</a>
        <a href="/diag">Diag</a>
        <a href="/keys">Keys</a>
        <a href="/totp">TOTP</a>
        <a href="/logout">Sign out</a>
      </div>
    </div>

    <h2>HSM (P-256 / ES256)</h2>
    <p class="small">Use BOOT presence hold (~0.5-1.2s) plus PIN unlock for signing. Key management also requires admin unlock.</p>

    <div class="status" id="status">Loading...</div>
    <div class="msg" id="msg"></div>

    <h3>PIN</h3>
    <label for="pinCurrent">Current PIN</label>
    <input id="pinCurrent" type="password" placeholder="Current PIN">
    <label for="pinNew">New PIN (4-64 chars)</label>
    <input id="pinNew" type="password" placeholder="New PIN">
    <div class="row">
      <button type="button" onclick="unlockPin()">Unlock PIN</button>
      <button type="button" onclick="setPin()">Set / Change PIN</button>
    </div>
    <button class="danger" type="button" onclick="clearPin()">Clear PIN</button>

    <h3>Key management</h3>
    <div class="row">
      <button type="button" onclick="generateKey()">Generate / Rotate key</button>
      <button class="danger" type="button" onclick="deleteKey()">Delete key</button>
    </div>

    <h3>Sign</h3>
    <label for="fmt">Input format</label>
    <select id="fmt">
      <option value="text">UTF-8 text</option>
      <option value="hex">Hex bytes</option>
      <option value="digesthex">SHA-256 digest (hex, 32 bytes)</option>
    </select>
    <label for="msgIn">Message / bytes</label>
    <textarea id="msgIn" rows="4" placeholder="Example text or hex"></textarea>
    <button type="button" onclick="signNow()">Sign with device key</button>
    <div class="status" id="signOut"></div>

    <h3>Verify</h3>
    <label for="sigIn">Signature DER (hex)</label>
    <textarea id="sigIn" rows="3" placeholder="Paste signature hex here"></textarea>
    <button type="button" onclick="verifyNow()">Verify using current public key</button>
    <div class="status" id="verifyOut"></div>

    <div class="hint">Tip: HSM private key is stored in NVS. Enable flash encryption for stronger at-rest protection.</div>
  </div>

  <script>
    async function api(url, opts) {
      const r = await fetch(url, Object.assign({ cache: 'no-store' }, opts || {}));
      if (r.status === 401) { window.location = '/'; throw new Error('auth'); }
      return r;
    }

    function showMsg(t) {
      document.getElementById('msg').textContent = t || '';
    }

    function fmtNullable(v) {
      return (v === null || v === undefined || v === '') ? '' : String(v);
    }

    async function refresh() {
      const stR = await api('/admin/status');
      const hsR = await api('/hsm/status');
      const st = await stR.json();
      const hs = await hsR.json();

      const lines = [];
      lines.push('admin_unlocked: ' + (st.admin_unlocked ? 'yes' : 'no'));
      lines.push('admin_seconds_remaining: ' + fmtNullable(st.admin_seconds_remaining));
      lines.push('flash_encryption: ' + (st.flash_encryption ? 'enabled' : 'disabled'));
      lines.push('key_present: ' + (hs.key_present ? 'yes' : 'no'));
      lines.push('pin_configured: ' + (hs.pin_configured ? 'yes' : 'no'));
      lines.push('pin_unlocked: ' + (hs.pin_unlocked ? 'yes' : 'no'));
      lines.push('pin_seconds_remaining: ' + fmtNullable(hs.pin_seconds_remaining));
      lines.push('presence_satisfied: ' + (hs.presence_satisfied ? 'yes' : 'no'));
      lines.push('presence_seconds_remaining: ' + fmtNullable(hs.presence_seconds_remaining));
      lines.push('algorithm: ' + (hs.algorithm || ''));
      lines.push('curve: ' + (hs.curve || ''));
      lines.push('created_unix: ' + fmtNullable(hs.created_unix));
      lines.push('sign_count: ' + fmtNullable(hs.sign_count));
      lines.push('pubkey_fingerprint: ' + (hs.pubkey_fingerprint || ''));
      lines.push('public_key_hex: ' + (hs.public_key_hex || ''));
      document.getElementById('status').textContent = lines.join('\n');
    }

    function pinCurrent() { return document.getElementById('pinCurrent').value || ''; }
    function pinNew() { return document.getElementById('pinNew').value || ''; }

    async function unlockPin() {
      const body = new URLSearchParams();
      body.set('p', pinCurrent());
      const r = await api('/hsm/pin/unlock', {
        method: 'POST',
        headers: {'Content-Type':'application/x-www-form-urlencoded'},
        body: body.toString()
      });
      const t = await r.text();
      if (!r.ok) {
        showMsg(t || 'PIN unlock failed.');
        return;
      }
      showMsg('PIN unlocked.');
      await refresh();
    }

    async function setPin() {
      const body = new URLSearchParams();
      body.set('p', pinCurrent());
      body.set('n', pinNew());
      const r = await api('/hsm/pin/set', {
        method: 'POST',
        headers: {'Content-Type':'application/x-www-form-urlencoded'},
        body: body.toString()
      });
      const t = await r.text();
      if (!r.ok) {
        showMsg(t || 'PIN set failed.');
        return;
      }
      document.getElementById('pinCurrent').value = '';
      document.getElementById('pinNew').value = '';
      showMsg('PIN saved.');
      await refresh();
    }

    async function clearPin() {
      if (!confirm('Clear the HSM PIN?')) return;
      const body = new URLSearchParams();
      body.set('p', pinCurrent());
      const r = await api('/hsm/pin/clear', {
        method: 'POST',
        headers: {'Content-Type':'application/x-www-form-urlencoded'},
        body: body.toString()
      });
      const t = await r.text();
      if (!r.ok) {
        showMsg(t || 'PIN clear failed.');
        return;
      }
      document.getElementById('pinCurrent').value = '';
      document.getElementById('pinNew').value = '';
      showMsg('PIN cleared.');
      await refresh();
    }

    async function generateKey() {
      if (!confirm('Generate a new keypair and replace the current key?')) return;
      const r = await api('/hsm/generate', { method: 'POST' });
      const t = await r.text();
      if (!r.ok) {
        showMsg(t || 'Key generation was not accepted.');
        return;
      }
      showMsg('New HSM key generated.');
      await refresh();
    }

    async function deleteKey() {
      if (!confirm('Delete the current HSM key? This cannot be undone.')) return;
      const r = await api('/hsm/delete', { method: 'POST' });
      const t = await r.text();
      if (!r.ok) {
        showMsg(t || 'Delete was not accepted.');
        return;
      }
      showMsg('HSM key deleted.');
      document.getElementById('signOut').textContent = '';
      document.getElementById('verifyOut').textContent = '';
      await refresh();
    }

    async function signNow() {
      const body = new URLSearchParams();
      body.set('fmt', document.getElementById('fmt').value);
      body.set('m', document.getElementById('msgIn').value || '');
      const r = await api('/hsm/sign', {
        method: 'POST',
        headers: {'Content-Type':'application/x-www-form-urlencoded'},
        body: body.toString()
      });
      const t = await r.text();
      if (!r.ok) {
        showMsg(t || 'Sign request failed.');
        return;
      }

      let j = null;
      try { j = JSON.parse(t); } catch (_) {}
      if (!j) {
        showMsg('Sign response parse failed.');
        return;
      }

      const lines = [];
      lines.push('digest_hex: ' + (j.digest_hex || ''));
      lines.push('signature_der_hex: ' + (j.signature_der_hex || ''));
      lines.push('sign_count: ' + fmtNullable(j.sign_count));
      document.getElementById('signOut').textContent = lines.join('\n');
      document.getElementById('sigIn').value = j.signature_der_hex || '';
      showMsg('Signature created.');
      await refresh();
    }

    async function verifyNow() {
      const body = new URLSearchParams();
      body.set('fmt', document.getElementById('fmt').value);
      body.set('m', document.getElementById('msgIn').value || '');
      body.set('sig', document.getElementById('sigIn').value || '');
      const r = await api('/hsm/verify', {
        method: 'POST',
        headers: {'Content-Type':'application/x-www-form-urlencoded'},
        body: body.toString()
      });
      const t = await r.text();
      if (!r.ok) {
        showMsg(t || 'Verify request failed.');
        return;
      }

      let j = null;
      try { j = JSON.parse(t); } catch (_) {}
      if (!j) {
        showMsg('Verify response parse failed.');
        return;
      }

      const lines = [];
      lines.push('valid: ' + (j.valid ? 'yes' : 'no'));
      lines.push('digest_hex: ' + (j.digest_hex || ''));
      document.getElementById('verifyOut').textContent = lines.join('\n');
      showMsg(j.valid ? 'Signature valid.' : 'Signature invalid.');
    }

    refresh();
    setInterval(refresh, 2000);
  </script>
</body>
</html>
)rawliteral";

static inline void send_no_cache_headers() {
  server.sendHeader("Cache-Control", "no-store, no-cache, must-revalidate, max-age=0");
  server.sendHeader("Pragma", "no-cache");
  server.sendHeader("Expires", "0");
}

static inline void send_ui_page() {
  send_no_cache_headers();
  server.send_P(200, "text/html", index_html);
}

static inline void send_login_page() {
  send_no_cache_headers();
  server.send_P(200, "text/html", login_html);
}

static inline void send_totp_page() {
  send_no_cache_headers();
  server.send_P(200, "text/html", totp_html);
}

static inline void send_keys_page() {
  send_no_cache_headers();
  server.send_P(200, "text/html", keys_html);
}

static inline void send_ap_page() {
  send_no_cache_headers();
  server.send_P(200, "text/html", ap_html);
}

static inline void send_diag_page() {
  send_no_cache_headers();
  server.send_P(200, "text/html", diag_html);
}

static inline void send_hsm_page() {
  send_no_cache_headers();
  server.send_P(200, "text/html", hsm_html);
}

static inline void send_ok_minimal() {
  // 204: No Content (smaller + faster than "OK" bodies for high-rate endpoints)
  server.send(204);
}

static inline bool boot_button_down() {
  return digitalRead(BOOT_BUTTON_PIN) == LOW;
}

struct LedRgb {
  uint8_t r = 0;
  uint8_t g = 0;
  uint8_t b = 0;
};

static LedRgb lastLed;

static inline bool led_available() {
  return MODE_LED_PIN >= 0;
}

static void set_led_rgb(uint8_t r, uint8_t g, uint8_t b) {
  if (!led_available()) return;

  // Avoid frequent WS2812 updates (and needless GPIO writes) if nothing changed.
  if (lastLed.r == r && lastLed.g == g && lastLed.b == b) return;
  lastLed = {r, g, b};

  if (MODE_LED_IS_RGB) {
    rgbLedWrite(static_cast<uint8_t>(MODE_LED_PIN), r, g, b);
    return;
  }

  const bool on = (r | g | b) != 0;
  const bool pinLevel = (MODE_LED_ACTIVE_LOW ? !on : on);
  digitalWrite(MODE_LED_PIN, pinLevel ? HIGH : LOW);
}

static inline void led_off() {
  set_led_rgb(0, 0, 0);
}

static void init_led() {
  if (!led_available()) return;
  if (!MODE_LED_IS_RGB) pinMode(MODE_LED_PIN, OUTPUT);
  led_off();
}

static inline bool pairing_active() {
  return pairingActiveUntil != 0 && (static_cast<int32_t>(pairingActiveUntil - millis()) > 0);
}

static inline bool admin_unlocked() {
  return adminUnlockedUntil != 0 && (static_cast<int32_t>(adminUnlockedUntil - millis()) > 0);
}

static inline bool hsm_pin_unlocked() {
  return hsmPinUnlockedUntil != 0 && (static_cast<int32_t>(hsmPinUnlockedUntil - millis()) > 0);
}

static inline bool hsm_presence_satisfied() {
  return hsmPresenceUntil != 0 && (static_cast<int32_t>(hsmPresenceUntil - millis()) > 0);
}

static AttestationProfile load_attestation_profile() {
  prefs.begin("kbm", true);
  const uint8_t raw = prefs.getUChar("att", static_cast<uint8_t>(AttestationProfile::Diy));
  prefs.end();

  return (raw == static_cast<uint8_t>(AttestationProfile::None)) ? AttestationProfile::None : AttestationProfile::Diy;
}

static void save_attestation_profile(AttestationProfile p) {
  prefs.begin("kbm", false);
  prefs.putUChar("att", static_cast<uint8_t>(p));
  prefs.end();
  attestationProfile = p;
}

static bool load_ap_management_mode() {
  prefs.begin("kbm", true);
  const bool v = prefs.getBool("ap_mgmt", false);
  prefs.end();
  return v;
}

static void save_ap_management_mode(const bool enabled) {
  prefs.begin("kbm", false);
  prefs.putBool("ap_mgmt", enabled);
  prefs.end();
  apManagementMode = enabled;
}

static bool build_ap_status_json(String& outJson) {
  outJson = "";
  outJson.reserve(192);
  outJson += "{";
  outJson += "\"mode\":\"";
  outJson += apManagementMode ? "manage" : "control";
  outJson += "\"";
  outJson += ",\"ssid\":\"";
  outJson += AP_SSID;
  outJson += "\"";
  outJson += ",\"usb_kbm_hid_enabled\":";
  outJson += (usb_kbm_hid_enabled() ? "true" : "false");
  outJson += "}";
  return true;
}

static void load_pair_token() {
  prefs.begin("kbm", true);
  const String t = prefs.getString("pair", "");
  prefs.end();

  if (t.length() == 32) {
    memset(pairTokenHex, 0, sizeof(pairTokenHex));
    t.toCharArray(pairTokenHex, sizeof(pairTokenHex));
  } else {
    pairTokenHex[0] = '\0';
  }
}

static void save_pair_token(const char* token) {
  prefs.begin("kbm", false);
  prefs.putString("pair", token);
  prefs.end();
}

static void generate_pair_token() {
  uint8_t b[16];
  esp_fill_random(b, sizeof(b));
  for (size_t i = 0; i < sizeof(b); ++i) {
    snprintf(pairTokenHex + (i * 2), 3, "%02x", b[i]);
  }
  pairTokenHex[32] = '\0';
  save_pair_token(pairTokenHex);
}

static bool cookie_has_valid_token(const char* cookie) {
  if (pairTokenHex[0] == '\0') return false;
  if (cookie == nullptr || cookie[0] == '\0') return false;

  const size_t tokLen = strlen(pairTokenHex);
  const char* p = cookie;
  while ((p = strstr(p, "sid=")) != nullptr) {
    p += 4;
    while (*p == ' ') ++p;
    size_t i = 0;
    for (; i < tokLen; ++i) {
      const char ch = p[i];
      if (ch == '\0' || ch == ';' || ch == ' ') break;
      if (static_cast<char>(tolower(static_cast<unsigned char>(ch))) != pairTokenHex[i]) break;
    }
    if (i == tokLen && (p[i] == '\0' || p[i] == ';' || p[i] == ' ')) return true;
    p += 1;
  }
  return false;
}

static bool is_authenticated_request() {
  const String cookie = server.header("Cookie");
  return cookie_has_valid_token(cookie.c_str());
}

static void set_token_cookie_and_redirect(const char* location) {
  if (pairTokenHex[0] == '\0') {
    server.sendHeader("Location", location, true);
    server.send(303, "text/plain", "");
    return;
  }
  String cookie;
  cookie.reserve(96);
  cookie += "sid=";
  cookie += pairTokenHex;
  cookie += "; Path=/; Max-Age=2592000; SameSite=Lax; HttpOnly";
  server.sendHeader("Set-Cookie", cookie, true);
  server.sendHeader("Location", location, true);
  server.send(303, "text/plain", "");
}

static void clear_token_cookie_and_redirect(const char* location) {
  server.sendHeader("Set-Cookie", "sid=; Path=/; Max-Age=0; SameSite=Lax; HttpOnly", true);
  server.sendHeader("Location", location, true);
  server.send(303, "text/plain", "");
}

static inline bool flash_encryption_enabled() {
  return esp_flash_encryption_enabled();
}

static bool parse_i64(const String& s, int64_t* out) {
  const char* c = s.c_str();
  if (c == nullptr || c[0] == '\0') return false;
  char* end = nullptr;
  const long long v = strtoll(c, &end, 10);
  if (end == c) return false;
  *out = static_cast<int64_t>(v);
  return true;
}

static inline uint16_t read_le_u16(const uint8_t* p) {
  return static_cast<uint16_t>(p[0]) | (static_cast<uint16_t>(p[1]) << 8);
}

static inline uint32_t read_le_u32(const uint8_t* p) {
  return static_cast<uint32_t>(p[0]) | (static_cast<uint32_t>(p[1]) << 8) | (static_cast<uint32_t>(p[2]) << 16) |
         (static_cast<uint32_t>(p[3]) << 24);
}

static inline void write_le_u16(uint8_t* p, const uint16_t v) {
  p[0] = static_cast<uint8_t>(v & 0xFFU);
  p[1] = static_cast<uint8_t>((v >> 8) & 0xFFU);
}

static inline void write_le_u32(uint8_t* p, const uint32_t v) {
  p[0] = static_cast<uint8_t>(v & 0xFFU);
  p[1] = static_cast<uint8_t>((v >> 8) & 0xFFU);
  p[2] = static_cast<uint8_t>((v >> 16) & 0xFFU);
  p[3] = static_cast<uint8_t>((v >> 24) & 0xFFU);
}

static void secure_zero(void* ptr, size_t len) {
  if (ptr == nullptr || len == 0) return;
  volatile uint8_t* p = static_cast<volatile uint8_t*>(ptr);
  while (len--) *p++ = 0;
}

static inline uint8_t hex_nibble(char c) {
  if (c >= '0' && c <= '9') return static_cast<uint8_t>(c - '0');
  if (c >= 'a' && c <= 'f') return static_cast<uint8_t>(10 + (c - 'a'));
  if (c >= 'A' && c <= 'F') return static_cast<uint8_t>(10 + (c - 'A'));
  return 0xFF;
}

static size_t hex_to_bytes(const char* hex, uint8_t* out, const size_t outMax) {
  if (hex == nullptr || out == nullptr) return 0;
  const size_t n = strlen(hex);
  if (n == 0 || (n % 2) != 0) return 0;
  const size_t bytes = n / 2;
  if (bytes > outMax) return 0;

  for (size_t i = 0; i < bytes; ++i) {
    const uint8_t hi = hex_nibble(hex[i * 2]);
    const uint8_t lo = hex_nibble(hex[i * 2 + 1]);
    if (hi == 0xFF || lo == 0xFF) return 0;
    out[i] = static_cast<uint8_t>((hi << 4) | lo);
  }
  return bytes;
}

static void bytes_to_hex(const uint8_t* in, const size_t inLen, char* out, const size_t outLen) {
  static constexpr char kHex[] = "0123456789abcdef";
  if (out == nullptr || outLen == 0) return;
  if (in == nullptr) {
    out[0] = '\0';
    return;
  }
  const size_t need = (inLen * 2) + 1;
  if (outLen < need) {
    out[0] = '\0';
    return;
  }
  for (size_t i = 0; i < inLen; ++i) {
    out[i * 2] = kHex[(in[i] >> 4) & 0x0F];
    out[i * 2 + 1] = kHex[in[i] & 0x0F];
  }
  out[inLen * 2] = '\0';
}

static void json_append_escaped(String& out, const char* s, const size_t len) {
  if (s == nullptr || len == 0) return;
  for (size_t i = 0; i < len; ++i) {
    const char c = s[i];
    if (c == '\\' || c == '"') {
      out += '\\';
      out += c;
    } else if (c == '\r') {
      out += "\\r";
    } else if (c == '\n') {
      out += "\\n";
    } else if (static_cast<unsigned char>(c) < 0x20) {
      out += ' ';
    } else {
      out += c;
    }
  }
}

static inline const char* attestation_profile_name(const AttestationProfile p) {
  return (p == AttestationProfile::None) ? "none" : "diy";
}

static bool cred_store_validate(const uint8_t* data, const size_t len, uint16_t* countOut) {
  static constexpr size_t kStoreHdrLen = 12;
  static constexpr size_t kRecHdrLen = 12;

  if (data == nullptr || len < kStoreHdrLen) return false;
  if (read_le_u32(data) != CRED_STORE_MAGIC) return false;
  if (read_le_u16(data + 4) != CRED_STORE_VERSION) return false;

  const uint16_t count = read_le_u16(data + 6);
  size_t off = kStoreHdrLen;

  for (uint16_t i = 0; i < count; ++i) {
    if (off + kRecHdrLen > len) return false;
    const uint16_t rpLen = read_le_u16(data + off + 0);
    const uint16_t labelLen = read_le_u16(data + off + 2);
    const uint16_t idLen = read_le_u16(data + off + 4);
    const uint16_t secretLen = read_le_u16(data + off + 6);
    off += kRecHdrLen;

    if (rpLen == 0 || rpLen > CRED_MAX_RPID_LEN) return false;
    if (labelLen > CRED_MAX_LABEL_LEN) return false;
    if (idLen == 0 || idLen > CRED_MAX_ID_LEN) return false;
    if (secretLen > CRED_MAX_SECRET_LEN) return false;

    const size_t payload = static_cast<size_t>(rpLen) + static_cast<size_t>(labelLen) + static_cast<size_t>(idLen) +
                           static_cast<size_t>(secretLen);
    if (off + payload > len) return false;
    off += payload;
  }

  if (off != len) return false;
  if (countOut) *countOut = count;
  return true;
}

static void cred_store_clear() {
  prefs.begin("kbm", false);
  prefs.remove("cred");
  prefs.end();
}

static void write_cred_store_header(uint8_t* out, const uint16_t count) {
  write_le_u32(out + 0, CRED_STORE_MAGIC);
  write_le_u16(out + 4, CRED_STORE_VERSION);
  write_le_u16(out + 6, count);
  write_le_u32(out + 8, 0);
}

static bool cred_store_load(uint8_t** outBuf, size_t* outLen, uint16_t* outCount) {
  if (outBuf) *outBuf = nullptr;
  if (outLen) *outLen = 0;
  if (outCount) *outCount = 0;

  prefs.begin("kbm", true);
  const size_t len = prefs.getBytesLength("cred");
  if (len == 0) {
    prefs.end();
    return true;
  }
  if (len > CRED_STORE_MAX_BYTES) {
    prefs.end();
    return false;
  }

  uint8_t* buf = static_cast<uint8_t*>(malloc(len));
  if (!buf) {
    prefs.end();
    return false;
  }

  const size_t got = prefs.getBytes("cred", buf, len);
  prefs.end();

  if (got != len) {
    secure_zero(buf, len);
    free(buf);
    return false;
  }

  uint16_t count = 0;
  if (!cred_store_validate(buf, len, &count)) {
    secure_zero(buf, len);
    free(buf);
    cred_store_clear();
    return true;
  }

  if (outBuf) *outBuf = buf;
  if (outLen) *outLen = len;
  if (outCount) *outCount = count;
  return true;
}

static bool cred_store_save(const uint8_t* data, const size_t len) {
  if (len > CRED_STORE_MAX_BYTES) return false;
  prefs.begin("kbm", false);
  bool ok = false;
  if (data == nullptr || len == 0) ok = prefs.remove("cred");
  else ok = prefs.putBytes("cred", data, len);
  prefs.end();
  return ok;
}

static bool cred_store_delete_id(const uint8_t* id, const size_t idLen) {
  static constexpr size_t kStoreHdrLen = 12;
  static constexpr size_t kRecHdrLen = 12;

  uint8_t* buf = nullptr;
  size_t len = 0;
  uint16_t count = 0;
  if (!cred_store_load(&buf, &len, &count)) return false;
  if (buf == nullptr || len < kStoreHdrLen) return false;

  // First pass: determine new size/count
  size_t off = kStoreHdrLen;
  uint16_t newCount = 0;
  size_t newLen = kStoreHdrLen;
  bool removed = false;

  for (uint16_t i = 0; i < count; ++i) {
    const uint16_t rpLen = read_le_u16(buf + off + 0);
    const uint16_t labelLen = read_le_u16(buf + off + 2);
    const uint16_t curIdLen = read_le_u16(buf + off + 4);
    const uint16_t secretLen = read_le_u16(buf + off + 6);
    const size_t recTotal = kRecHdrLen + static_cast<size_t>(rpLen) + static_cast<size_t>(labelLen) +
                            static_cast<size_t>(curIdLen) + static_cast<size_t>(secretLen);

    const size_t idOff = off + kRecHdrLen + static_cast<size_t>(rpLen) + static_cast<size_t>(labelLen);
    const bool match = (curIdLen == idLen) && (memcmp(buf + idOff, id, idLen) == 0);
    if (match) {
      // Overwrite sensitive bytes in the in-memory buffer as a best-effort.
      const size_t secretOff = idOff + static_cast<size_t>(curIdLen);
      secure_zero(buf + secretOff, secretLen);
      removed = true;
    } else {
      newCount++;
      newLen += recTotal;
    }

    off += recTotal;
  }

  if (!removed) {
    secure_zero(buf, len);
    free(buf);
    return false;
  }

  if (newCount == 0) {
    const bool ok = cred_store_save(nullptr, 0);
    secure_zero(buf, len);
    free(buf);
    return ok;
  }

  if (newLen > CRED_STORE_MAX_BYTES) {
    secure_zero(buf, len);
    free(buf);
    return false;
  }

  uint8_t* out = static_cast<uint8_t*>(malloc(newLen));
  if (!out) {
    secure_zero(buf, len);
    free(buf);
    return false;
  }

  write_cred_store_header(out, newCount);
  size_t w = kStoreHdrLen;
  off = kStoreHdrLen;

  for (uint16_t i = 0; i < count; ++i) {
    const uint16_t rpLen = read_le_u16(buf + off + 0);
    const uint16_t labelLen = read_le_u16(buf + off + 2);
    const uint16_t curIdLen = read_le_u16(buf + off + 4);
    const uint16_t secretLen = read_le_u16(buf + off + 6);
    const size_t recTotal = kRecHdrLen + static_cast<size_t>(rpLen) + static_cast<size_t>(labelLen) +
                            static_cast<size_t>(curIdLen) + static_cast<size_t>(secretLen);

    const size_t idOff = off + kRecHdrLen + static_cast<size_t>(rpLen) + static_cast<size_t>(labelLen);
    const bool match = (curIdLen == idLen) && (memcmp(buf + idOff, id, idLen) == 0);
    if (!match) {
      memcpy(out + w, buf + off, recTotal);
      w += recTotal;
    }
    off += recTotal;
  }

  const bool ok = (w == newLen) && cred_store_save(out, newLen);
  secure_zero(out, newLen);
  free(out);
  secure_zero(buf, len);
  free(buf);
  return ok;
}

static bool cred_store_set_label_id(const uint8_t* id, const size_t idLen, const char* label, size_t labelLen) {
  static constexpr size_t kStoreHdrLen = 12;
  static constexpr size_t kRecHdrLen = 12;

  if (labelLen > CRED_MAX_LABEL_LEN) labelLen = CRED_MAX_LABEL_LEN;

  uint8_t* buf = nullptr;
  size_t len = 0;
  uint16_t count = 0;
  if (!cred_store_load(&buf, &len, &count)) return false;
  if (buf == nullptr || len < kStoreHdrLen) return false;

  // Find record and compute new length
  size_t off = kStoreHdrLen;
  bool found = false;
  uint16_t oldLabelLen = 0;
  size_t newLen = len;

  for (uint16_t i = 0; i < count; ++i) {
    const uint16_t rpLen = read_le_u16(buf + off + 0);
    const uint16_t curLabelLen = read_le_u16(buf + off + 2);
    const uint16_t curIdLen = read_le_u16(buf + off + 4);
    const uint16_t secretLen = read_le_u16(buf + off + 6);
    const size_t recTotal = kRecHdrLen + static_cast<size_t>(rpLen) + static_cast<size_t>(curLabelLen) +
                            static_cast<size_t>(curIdLen) + static_cast<size_t>(secretLen);

    const size_t idOff = off + kRecHdrLen + static_cast<size_t>(rpLen) + static_cast<size_t>(curLabelLen);
    const bool match = (curIdLen == idLen) && (memcmp(buf + idOff, id, idLen) == 0);
    if (match) {
      found = true;
      oldLabelLen = curLabelLen;
      newLen = len - static_cast<size_t>(curLabelLen) + labelLen;
      break;
    }
    off += recTotal;
  }

  if (!found || newLen > CRED_STORE_MAX_BYTES) {
    secure_zero(buf, len);
    free(buf);
    return false;
  }

  uint8_t* out = static_cast<uint8_t*>(malloc(newLen));
  if (!out) {
    secure_zero(buf, len);
    free(buf);
    return false;
  }

  // Copy + rewrite the one record's label
  write_cred_store_header(out, count);
  size_t w = kStoreHdrLen;
  off = kStoreHdrLen;

  for (uint16_t i = 0; i < count; ++i) {
    const uint16_t rpLen = read_le_u16(buf + off + 0);
    const uint16_t curLabelLen = read_le_u16(buf + off + 2);
    const uint16_t curIdLen = read_le_u16(buf + off + 4);
    const uint16_t secretLen = read_le_u16(buf + off + 6);
    const uint32_t createdAt = read_le_u32(buf + off + 8);

    const size_t recPayloadLen = static_cast<size_t>(rpLen) + static_cast<size_t>(curLabelLen) + static_cast<size_t>(curIdLen) +
                                 static_cast<size_t>(secretLen);
    const size_t recTotal = kRecHdrLen + recPayloadLen;

    const uint8_t* rp = buf + off + kRecHdrLen;
    const uint8_t* curLabel = rp + rpLen;
    const uint8_t* curId = curLabel + curLabelLen;
    const uint8_t* curSecret = curId + curIdLen;

    const bool match = (curIdLen == idLen) && (memcmp(curId, id, idLen) == 0);

    if (!match) {
      memcpy(out + w, buf + off, recTotal);
      w += recTotal;
      off += recTotal;
      continue;
    }

    // Write record header
    write_le_u16(out + w + 0, rpLen);
    write_le_u16(out + w + 2, static_cast<uint16_t>(labelLen));
    write_le_u16(out + w + 4, curIdLen);
    write_le_u16(out + w + 6, secretLen);
    write_le_u32(out + w + 8, createdAt);
    w += kRecHdrLen;

    memcpy(out + w, rp, rpLen);
    w += rpLen;
    if (labelLen > 0 && label != nullptr) {
      memcpy(out + w, label, labelLen);
    }
    w += labelLen;
    memcpy(out + w, curId, curIdLen);
    w += curIdLen;
    memcpy(out + w, curSecret, secretLen);
    w += secretLen;

    off += recTotal;
  }

  const bool ok = (w == newLen) && cred_store_save(out, newLen);
  secure_zero(out, newLen);
  free(out);
  // Only clear the old label bytes in memory (best effort).
  if (found && oldLabelLen > 0) {
    // Nothing sensitive here, but keep behavior consistent.
  }
  secure_zero(buf, len);
  free(buf);
  return ok;
}

static bool build_keys_json(String& outJson) {
  static constexpr size_t kStoreHdrLen = 12;
  static constexpr size_t kRecHdrLen = 12;

  uint8_t* buf = nullptr;
  size_t len = 0;
  uint16_t count = 0;
  if (!cred_store_load(&buf, &len, &count)) return false;

  outJson = "";
  outJson.reserve(512);
  outJson += "{";
  outJson += "\"attestation_profile\":\"";
  outJson += attestation_profile_name(attestationProfile);
  outJson += "\",";
  outJson += "\"count\":";
  outJson += String(count);
  outJson += ",\"entries\":[";

  if (buf != nullptr && len >= kStoreHdrLen) {
    size_t off = kStoreHdrLen;
    bool first = true;
    for (uint16_t i = 0; i < count; ++i) {
      const uint16_t rpLen = read_le_u16(buf + off + 0);
      const uint16_t labelLen = read_le_u16(buf + off + 2);
      const uint16_t idLen = read_le_u16(buf + off + 4);
      const uint16_t secretLen = read_le_u16(buf + off + 6);
      const uint32_t createdAt = read_le_u32(buf + off + 8);

      const uint8_t* rp = buf + off + kRecHdrLen;
      const uint8_t* label = rp + rpLen;
      const uint8_t* id = label + labelLen;

      char idHex[(CRED_MAX_ID_LEN * 2) + 1];
      bytes_to_hex(id, idLen, idHex, sizeof(idHex));

      if (!first) outJson += ",";
      first = false;
      outJson += "{";
      outJson += "\"rp\":\"";
      json_append_escaped(outJson, reinterpret_cast<const char*>(rp), rpLen);
      outJson += "\",";
      outJson += "\"label\":\"";
      json_append_escaped(outJson, reinterpret_cast<const char*>(label), labelLen);
      outJson += "\",";
      outJson += "\"id\":\"";
      outJson += idHex;
      outJson += "\",";
      outJson += "\"created\":";
      outJson += String(createdAt);
      outJson += "}";

      const size_t recTotal = kRecHdrLen + static_cast<size_t>(rpLen) + static_cast<size_t>(labelLen) + static_cast<size_t>(idLen) +
                              static_cast<size_t>(secretLen);
      off += recTotal;
    }
  }

  outJson += "]}";

  if (buf != nullptr) {
    secure_zero(buf, len);
    free(buf);
  }
  return true;
}

static bool derive_backup_key(const char* password, const uint8_t* salt, const size_t saltLen, const uint32_t iters, uint8_t outKey[32]) {
  if (password == nullptr || password[0] == '\0') return false;
  if (salt == nullptr || saltLen == 0) return false;
  const size_t plen = strlen(password);
  if (plen < 8) return false;

  const int rc = mbedtls_pkcs5_pbkdf2_hmac_ext(MBEDTLS_MD_SHA256, reinterpret_cast<const unsigned char*>(password), plen, salt,
                                               saltLen, iters, 32, outKey);
  return rc == 0;
}

static bool aes_gcm_encrypt(const uint8_t key[32], const uint8_t iv[12], const uint8_t* plain, const size_t plainLen,
                            uint8_t* cipher, uint8_t tag[16]) {
  if (!key || !iv || !plain || !cipher || !tag) return false;
  mbedtls_gcm_context gcm;
  mbedtls_gcm_init(&gcm);
  const int rc1 = mbedtls_gcm_setkey(&gcm, MBEDTLS_CIPHER_ID_AES, key, 256);
  if (rc1 != 0) {
    mbedtls_gcm_free(&gcm);
    return false;
  }
  const int rc2 = mbedtls_gcm_crypt_and_tag(&gcm, MBEDTLS_GCM_ENCRYPT, plainLen, iv, 12, nullptr, 0, plain, cipher, 16, tag);
  mbedtls_gcm_free(&gcm);
  return rc2 == 0;
}

static bool aes_gcm_decrypt(const uint8_t key[32], const uint8_t iv[12], const uint8_t* cipher, const size_t cipherLen,
                            const uint8_t tag[16], uint8_t* plainOut) {
  if (!key || !iv || !cipher || !plainOut || !tag) return false;
  mbedtls_gcm_context gcm;
  mbedtls_gcm_init(&gcm);
  const int rc1 = mbedtls_gcm_setkey(&gcm, MBEDTLS_CIPHER_ID_AES, key, 256);
  if (rc1 != 0) {
    mbedtls_gcm_free(&gcm);
    return false;
  }
  const int rc2 = mbedtls_gcm_auth_decrypt(&gcm, cipherLen, iv, 12, nullptr, 0, tag, 16, cipher, plainOut);
  mbedtls_gcm_free(&gcm);
  return rc2 == 0;
}

static bool build_backup_plain(uint8_t** out, size_t* outLen) {
  static constexpr uint32_t kPlainMagic = 0x3150424BU; // "KBP1"
  static constexpr uint16_t kPlainVer = 1;
  static constexpr size_t kHdrLen = 12; // magic(4) + ver(2) + profile(1) + rsv(1) + blobLen(4)

  if (out) *out = nullptr;
  if (outLen) *outLen = 0;

  uint8_t* cred = nullptr;
  size_t credLen = 0;
  uint16_t credCount = 0;
  if (!cred_store_load(&cred, &credLen, &credCount)) return false;

  const uint32_t blobLen32 = static_cast<uint32_t>(cred ? credLen : 0);
  const size_t total = kHdrLen + static_cast<size_t>(blobLen32);
  if (total > (CRED_STORE_MAX_BYTES + 64)) {
    if (cred) {
      secure_zero(cred, credLen);
      free(cred);
    }
    return false;
  }

  uint8_t* buf = static_cast<uint8_t*>(malloc(total));
  if (!buf) {
    if (cred) {
      secure_zero(cred, credLen);
      free(cred);
    }
    return false;
  }

  write_le_u32(buf + 0, kPlainMagic);
  write_le_u16(buf + 4, kPlainVer);
  buf[6] = static_cast<uint8_t>(attestationProfile);
  buf[7] = 0;
  write_le_u32(buf + 8, blobLen32);
  if (blobLen32 > 0 && cred != nullptr) {
    memcpy(buf + kHdrLen, cred, blobLen32);
  }

  if (cred) {
    secure_zero(cred, credLen);
    free(cred);
  }

  if (out) *out = buf;
  if (outLen) *outLen = total;
  return true;
}

static bool restore_from_backup_plain(const uint8_t* plain, const size_t plainLen) {
  static constexpr uint32_t kPlainMagic = 0x3150424BU; // "KBP1"
  static constexpr uint16_t kPlainVer = 1;
  static constexpr size_t kHdrLen = 12;

  if (plain == nullptr || plainLen < kHdrLen) return false;
  if (read_le_u32(plain + 0) != kPlainMagic) return false;
  if (read_le_u16(plain + 4) != kPlainVer) return false;

  const uint8_t profRaw = plain[6];
  const uint32_t blobLen = read_le_u32(plain + 8);
  if (static_cast<size_t>(blobLen) != (plainLen - kHdrLen)) return false;
  if (blobLen > CRED_STORE_MAX_BYTES) return false;

  AttestationProfile prof = (profRaw == static_cast<uint8_t>(AttestationProfile::None)) ? AttestationProfile::None : AttestationProfile::Diy;

  if (blobLen == 0) {
    // Clear credentials only; keep other settings.
    if (!cred_store_save(nullptr, 0)) return false;
    save_attestation_profile(prof);
    return true;
  }

  const uint8_t* blob = plain + kHdrLen;
  uint16_t count = 0;
  if (!cred_store_validate(blob, blobLen, &count)) return false;
  if (!cred_store_save(blob, blobLen)) return false;
  save_attestation_profile(prof);
  return true;
}

static bool build_encrypted_backup(const char* password, uint8_t** out, size_t* outLen) {
  static constexpr uint32_t kEncMagic = 0x3142424BU; // "KBB1"
  static constexpr uint16_t kEncVer = 1;
  static constexpr uint32_t kIters = 50000;
  static constexpr size_t kSaltLen = 16;
  static constexpr size_t kIvLen = 12;
  static constexpr size_t kTagLen = 16;
  static constexpr size_t kHdrLen = 4 + 2 + 2 + 4 + kSaltLen + kIvLen + 4;

  if (out) *out = nullptr;
  if (outLen) *outLen = 0;

  uint8_t* plain = nullptr;
  size_t plainLen = 0;
  if (!build_backup_plain(&plain, &plainLen)) return false;

  uint8_t salt[kSaltLen];
  uint8_t iv[kIvLen];
  esp_fill_random(salt, sizeof(salt));
  esp_fill_random(iv, sizeof(iv));

  uint8_t key[32];
  if (!derive_backup_key(password, salt, sizeof(salt), kIters, key)) {
    secure_zero(plain, plainLen);
    free(plain);
    return false;
  }

  const size_t total = kHdrLen + plainLen + kTagLen;
  uint8_t* enc = static_cast<uint8_t*>(malloc(total));
  if (!enc) {
    secure_zero(key, sizeof(key));
    secure_zero(plain, plainLen);
    free(plain);
    return false;
  }

  write_le_u32(enc + 0, kEncMagic);
  write_le_u16(enc + 4, kEncVer);
  write_le_u16(enc + 6, 0);
  write_le_u32(enc + 8, kIters);
  memcpy(enc + 12, salt, kSaltLen);
  memcpy(enc + 12 + kSaltLen, iv, kIvLen);
  write_le_u32(enc + 12 + kSaltLen + kIvLen, static_cast<uint32_t>(plainLen));

  uint8_t* cipher = enc + kHdrLen;
  uint8_t tag[kTagLen];
  const bool okEnc = aes_gcm_encrypt(key, iv, plain, plainLen, cipher, tag);
  secure_zero(key, sizeof(key));
  secure_zero(plain, plainLen);
  free(plain);

  if (!okEnc) {
    secure_zero(enc, total);
    free(enc);
    return false;
  }

  memcpy(enc + kHdrLen + plainLen, tag, kTagLen);

  if (out) *out = enc;
  if (outLen) *outLen = total;
  return true;
}

static bool decrypt_and_restore_backup(const uint8_t* enc, const size_t encLen, const char* password) {
  static constexpr uint32_t kEncMagic = 0x3142424BU; // "KBB1"
  static constexpr uint16_t kEncVer = 1;
  static constexpr size_t kSaltLen = 16;
  static constexpr size_t kIvLen = 12;
  static constexpr size_t kTagLen = 16;
  static constexpr size_t kHdrLen = 4 + 2 + 2 + 4 + kSaltLen + kIvLen + 4;

  if (enc == nullptr || encLen < (kHdrLen + kTagLen)) return false;
  if (read_le_u32(enc + 0) != kEncMagic) return false;
  if (read_le_u16(enc + 4) != kEncVer) return false;

  const uint32_t iters = read_le_u32(enc + 8);
  if (iters < 1000 || iters > 200000) return false;

  const uint8_t* salt = enc + 12;
  const uint8_t* iv = enc + 12 + kSaltLen;
  const uint32_t plainLen32 = read_le_u32(enc + 12 + kSaltLen + kIvLen);
  const size_t plainLen = static_cast<size_t>(plainLen32);
  const size_t need = kHdrLen + plainLen + kTagLen;
  if (need != encLen) return false;
  if (plainLen > (CRED_STORE_MAX_BYTES + 64)) return false;

  uint8_t key[32];
  if (!derive_backup_key(password, salt, kSaltLen, iters, key)) return false;

  uint8_t* plain = static_cast<uint8_t*>(malloc(plainLen));
  if (!plain) {
    secure_zero(key, sizeof(key));
    return false;
  }

  const uint8_t* cipher = enc + kHdrLen;
  const uint8_t* tag = enc + kHdrLen + plainLen;
  const bool okDec = aes_gcm_decrypt(key, iv, cipher, plainLen, tag, plain);
  secure_zero(key, sizeof(key));

  if (!okDec) {
    secure_zero(plain, plainLen);
    free(plain);
    return false;
  }

  const bool okRestore = restore_from_backup_plain(plain, plainLen);
  secure_zero(plain, plainLen);
  free(plain);
  return okRestore;
}

static void reset_restore_upload() {
  if (restoreUpload.buf != nullptr && restoreUpload.cap > 0) {
    secure_zero(restoreUpload.buf, restoreUpload.cap);
    free(restoreUpload.buf);
  }
  restoreUpload.buf = nullptr;
  restoreUpload.len = 0;
  restoreUpload.cap = 0;
  restoreUpload.error = false;
}

static void handle_restore_upload_chunk() {
  // Upload handler for "/backup/restore" (multipart/form-data file).
  HTTPUpload& up = server.upload();

  static constexpr size_t kMaxUpload = CRED_STORE_MAX_BYTES + 256;

  if (up.status == UPLOAD_FILE_START) {
    reset_restore_upload();
    if (!is_authenticated_request() || !admin_unlocked()) {
      restoreUpload.error = true;
      return;
    }
    if (up.totalSize == 0 || up.totalSize > kMaxUpload) {
      restoreUpload.error = true;
      return;
    }
    restoreUpload.cap = up.totalSize;
    restoreUpload.buf = static_cast<uint8_t*>(malloc(restoreUpload.cap));
    if (!restoreUpload.buf) {
      restoreUpload.error = true;
      restoreUpload.cap = 0;
      return;
    }
    restoreUpload.len = 0;
    return;
  }

  if (up.status == UPLOAD_FILE_WRITE) {
    if (restoreUpload.error || restoreUpload.buf == nullptr) return;
    if (restoreUpload.len + up.currentSize > restoreUpload.cap) {
      restoreUpload.error = true;
      return;
    }
    memcpy(restoreUpload.buf + restoreUpload.len, up.buf, up.currentSize);
    restoreUpload.len += up.currentSize;
    return;
  }

  if (up.status == UPLOAD_FILE_ABORTED) {
    restoreUpload.error = true;
    return;
  }

  // UPLOAD_FILE_END: handled by the POST handler.
}

static int base32_value(char c) {
  if (c >= 'A' && c <= 'Z') return c - 'A';
  if (c >= 'a' && c <= 'z') return c - 'a';
  if (c >= '2' && c <= '7') return 26 + (c - '2');
  return -1;
}

static size_t base32_decode(const char* in, uint8_t* out, const size_t outMax) {
  if (in == nullptr || out == nullptr || outMax == 0) return 0;

  uint64_t buffer = 0;
  uint8_t bits = 0;
  size_t outLen = 0;

  for (const char* p = in; *p; ++p) {
    if (*p == '=') break;
    const int v = base32_value(*p);
    if (v < 0) continue;  // skip spaces, dashes, etc

    buffer = (buffer << 5) | static_cast<uint64_t>(v);
    bits = static_cast<uint8_t>(bits + 5);
    while (bits >= 8) {
      bits = static_cast<uint8_t>(bits - 8);
      if (outLen >= outMax) return 0;
      out[outLen++] = static_cast<uint8_t>((buffer >> bits) & 0xFFU);
    }
  }

  return outLen;
}

static void clear_totp_config() {
  totpKeyLen = 0;
  totpDigits = TOTP_DEFAULT_DIGITS;
  totpPeriodS = TOTP_DEFAULT_PERIOD_S;
  totpAppendEnter = false;
}

static void load_totp_config() {
  clear_totp_config();

  prefs.begin("kbm", true);
  const String secret = prefs.getString("totp_s", "");
  totpDigits = prefs.getUChar("totp_d", TOTP_DEFAULT_DIGITS);
  totpPeriodS = prefs.getUInt("totp_p", TOTP_DEFAULT_PERIOD_S);
  totpAppendEnter = prefs.getBool("totp_e", false);
  prefs.end();

  if (totpDigits < 6) totpDigits = 6;
  if (totpDigits > 10) totpDigits = 10;
  if (totpPeriodS < 10) totpPeriodS = 10;
  if (totpPeriodS > 120) totpPeriodS = 120;

  if (secret.length() == 0) return;
  totpKeyLen = base32_decode(secret.c_str(), totpKey, sizeof(totpKey));
  if (totpKeyLen == 0) clear_totp_config();
}

static bool save_totp_config_from_form(const String& secretRaw, const String& digitsRaw, const String& periodRaw, const bool appendEnter) {
  String s = secretRaw;
  s.trim();

  // Normalize secret for storage: keep base32 chars only, uppercase.
  String cleaned;
  cleaned.reserve(s.length());
  for (size_t i = 0; i < s.length(); ++i) {
    const char c = s[i];
    if (c == '=' || c == ' ' || c == '\t' || c == '\r' || c == '\n' || c == '-') continue;
    const int v = base32_value(c);
    if (v < 0) continue;
    cleaned += static_cast<char>(toupper(static_cast<unsigned char>(c)));
  }

  if (cleaned.length() == 0) return false;

  uint8_t decoded[TOTP_KEY_MAX_BYTES];
  const size_t decodedLen = base32_decode(cleaned.c_str(), decoded, sizeof(decoded));
  if (decodedLen == 0) return false;

  uint32_t period = TOTP_DEFAULT_PERIOD_S;
  int64_t tmp = 0;
  if (parse_i64(periodRaw, &tmp) && tmp >= 10 && tmp <= 120) period = static_cast<uint32_t>(tmp);

  uint8_t digits = TOTP_DEFAULT_DIGITS;
  if (parse_i64(digitsRaw, &tmp) && tmp >= 6 && tmp <= 10) digits = static_cast<uint8_t>(tmp);

  prefs.begin("kbm", false);
  prefs.putString("totp_s", cleaned);
  prefs.putUChar("totp_d", digits);
  prefs.putUInt("totp_p", period);
  prefs.putBool("totp_e", appendEnter);
  prefs.end();

  memcpy(totpKey, decoded, decodedLen);
  totpKeyLen = decodedLen;
  totpDigits = digits;
  totpPeriodS = period;
  totpAppendEnter = appendEnter;
  return true;
}

static void clear_totp_prefs() {
  prefs.begin("kbm", false);
  prefs.remove("totp_s");
  prefs.remove("totp_d");
  prefs.remove("totp_p");
  prefs.remove("totp_e");
  prefs.end();
  clear_totp_config();
}

static bool set_time_from_unix_ms(const int64_t unixMs) {
  if (unixMs <= 0) return false;
  const int64_t nowUs = esp_timer_get_time();
  timeOffsetUs = (unixMs * 1000LL) - nowUs;
  timeSynced = true;
  return true;
}

static bool get_unix_seconds(uint64_t* unixSecondsOut) {
  if (!timeSynced) return false;
  const int64_t nowUs = esp_timer_get_time() + timeOffsetUs;
  if (nowUs <= 0) return false;
  *unixSecondsOut = static_cast<uint64_t>(nowUs / 1000000LL);
  return true;
}

static bool ct_equal(const uint8_t* a, const uint8_t* b, const size_t len) {
  if (!a || !b) return false;
  uint8_t diff = 0;
  for (size_t i = 0; i < len; ++i) diff |= static_cast<uint8_t>(a[i] ^ b[i]);
  return diff == 0;
}

static void hsm_mark_presence_now() {
  hsmPresenceUntil = millis() + HSM_PRESENCE_WINDOW_MS;
}

static void hsm_consume_presence() {
  hsmPresenceUntil = 0;
}

static bool fido_pin_hash16_derive(const char* pin, uint8_t outHash16[FIDO_PIN_HASH16_BYTES]) {
  if (!pin || !outHash16) return false;
  const size_t pinLen = strlen(pin);
  if (pinLen < HSM_PIN_MIN_LEN || pinLen > HSM_PIN_MAX_LEN) return false;

  uint8_t full[32] = {0};
  if (mbedtls_sha256(reinterpret_cast<const uint8_t*>(pin), pinLen, full, 0) != 0) return false;
  memcpy(outHash16, full, FIDO_PIN_HASH16_BYTES);
  secure_zero(full, sizeof(full));
  return true;
}

static bool fido_pin_hash16_save(const uint8_t hash16[FIDO_PIN_HASH16_BYTES]) {
  if (!hash16) return false;
  prefs.begin("kbm", false);
  const size_t n = prefs.putBytes("fido_ph", hash16, FIDO_PIN_HASH16_BYTES);
  prefs.end();
  return n == FIDO_PIN_HASH16_BYTES;
}

static bool fido_pin_hash16_set_from_pin(const char* pin) {
  uint8_t h[FIDO_PIN_HASH16_BYTES] = {0};
  if (!fido_pin_hash16_derive(pin, h)) return false;
  if (!fido_pin_hash16_save(h)) {
    secure_zero(h, sizeof(h));
    return false;
  }
  memcpy(fidoPinHash16, h, sizeof(fidoPinHash16));
  fidoPinHash16Valid = true;
  secure_zero(h, sizeof(h));
  return true;
}

static void fido_pin_hash16_clear_local() {
  fidoPinHash16Valid = false;
  secure_zero(fidoPinHash16, sizeof(fidoPinHash16));
}

static bool fido_pin_hash16_load_from_prefs() {
  uint8_t h[FIDO_PIN_HASH16_BYTES] = {0};
  prefs.begin("kbm", true);
  const size_t hl = prefs.getBytesLength("fido_ph");
  if (hl != FIDO_PIN_HASH16_BYTES) {
    prefs.end();
    fido_pin_hash16_clear_local();
    return false;
  }
  const size_t hg = prefs.getBytes("fido_ph", h, sizeof(h));
  prefs.end();
  if (hg != sizeof(h)) {
    fido_pin_hash16_clear_local();
    return false;
  }
  memcpy(fidoPinHash16, h, sizeof(fidoPinHash16));
  fidoPinHash16Valid = true;
  secure_zero(h, sizeof(h));
  return true;
}

static bool hsm_pin_save_hash(const uint8_t salt[HSM_PIN_SALT_BYTES], const uint8_t hash[HSM_PIN_HASH_BYTES]) {
  if (!salt || !hash) return false;
  prefs.begin("kbm", false);
  const size_t sw = prefs.putBytes("hsm_ps", salt, HSM_PIN_SALT_BYTES);
  const size_t hw = prefs.putBytes("hsm_ph", hash, HSM_PIN_HASH_BYTES);
  prefs.end();
  return sw == HSM_PIN_SALT_BYTES && hw == HSM_PIN_HASH_BYTES;
}

static void hsm_pin_clear_local() {
  hsmPinConfigured = false;
  hsmPinUnlockedUntil = 0;
  secure_zero(hsmPinSalt, sizeof(hsmPinSalt));
  secure_zero(hsmPinHash, sizeof(hsmPinHash));
  fido_pin_hash16_clear_local();
}

static void hsm_pin_clear_prefs() {
  prefs.begin("kbm", false);
  prefs.remove("hsm_ps");
  prefs.remove("hsm_ph");
  prefs.remove("fido_ph");
  prefs.end();
  hsm_pin_clear_local();
}

static bool hsm_pin_derive(const char* pin, const uint8_t* salt, const size_t saltLen, uint8_t outHash[HSM_PIN_HASH_BYTES]) {
  if (!pin || !salt || !outHash) return false;
  const size_t pinLen = strlen(pin);
  if (pinLen < HSM_PIN_MIN_LEN || pinLen > HSM_PIN_MAX_LEN) return false;
  const int rc = mbedtls_pkcs5_pbkdf2_hmac_ext(MBEDTLS_MD_SHA256, reinterpret_cast<const unsigned char*>(pin), pinLen, salt, saltLen,
                                               HSM_PIN_PBKDF2_ITERS, HSM_PIN_HASH_BYTES, outHash);
  return rc == 0;
}

static bool hsm_pin_verify(const char* pin) {
  if (!hsmPinConfigured) return false;
  uint8_t derived[HSM_PIN_HASH_BYTES] = {0};
  if (!hsm_pin_derive(pin, hsmPinSalt, sizeof(hsmPinSalt), derived)) return false;
  const bool ok = ct_equal(derived, hsmPinHash, sizeof(derived));
  secure_zero(derived, sizeof(derived));
  return ok;
}

static bool hsm_pin_set(const char* pin) {
  if (!pin) return false;
  uint8_t salt[HSM_PIN_SALT_BYTES] = {0};
  uint8_t hash[HSM_PIN_HASH_BYTES] = {0};
  esp_fill_random(salt, sizeof(salt));
  if (!hsm_pin_derive(pin, salt, sizeof(salt), hash)) {
    secure_zero(hash, sizeof(hash));
    return false;
  }
  if (!hsm_pin_save_hash(salt, hash)) {
    secure_zero(hash, sizeof(hash));
    return false;
  }
  memcpy(hsmPinSalt, salt, sizeof(hsmPinSalt));
  memcpy(hsmPinHash, hash, sizeof(hsmPinHash));
  hsmPinConfigured = true;
  hsmPinUnlockedUntil = millis() + HSM_PIN_UNLOCK_WINDOW_MS;
  (void)fido_pin_hash16_set_from_pin(pin);
  secure_zero(hash, sizeof(hash));
  return true;
}

static bool hsm_pin_load_from_prefs() {
  uint8_t salt[HSM_PIN_SALT_BYTES] = {0};
  uint8_t hash[HSM_PIN_HASH_BYTES] = {0};
  prefs.begin("kbm", true);
  const size_t sl = prefs.getBytesLength("hsm_ps");
  const size_t hl = prefs.getBytesLength("hsm_ph");
  if (sl != HSM_PIN_SALT_BYTES || hl != HSM_PIN_HASH_BYTES) {
    prefs.end();
    hsm_pin_clear_local();
    return false;
  }
  const size_t sg = prefs.getBytes("hsm_ps", salt, sizeof(salt));
  const size_t hg = prefs.getBytes("hsm_ph", hash, sizeof(hash));
  prefs.end();
  if (sg != sizeof(salt) || hg != sizeof(hash)) {
    hsm_pin_clear_prefs();
    return false;
  }
  memcpy(hsmPinSalt, salt, sizeof(hsmPinSalt));
  memcpy(hsmPinHash, hash, sizeof(hsmPinHash));
  hsmPinConfigured = true;
  hsmPinUnlockedUntil = 0;
  (void)fido_pin_hash16_load_from_prefs();
  return true;
}

static bool hsm_pin_unlock_with_pin(const char* pin) {
  if (!hsmPinConfigured) return false;
  if (!hsm_pin_verify(pin)) return false;
  hsmPinUnlockedUntil = millis() + HSM_PIN_UNLOCK_WINDOW_MS;
  if (!fidoPinHash16Valid) {
    (void)fido_pin_hash16_set_from_pin(pin);
  }
  return true;
}

// Shared policy hooks used by HSM and FIDO paths.
bool security_pin_configured() {
  return hsmPinConfigured;
}

bool security_pin_unlocked_now() {
  return (!hsmPinConfigured) || hsm_pin_unlocked();
}

bool security_fido_pin_hash16_get(uint8_t outHash16[16]) {
  if (!outHash16) return false;
  if (!hsmPinConfigured || !fidoPinHash16Valid) return false;
  memcpy(outHash16, fidoPinHash16, 16);
  return true;
}

bool security_presence_satisfied_now() {
  return hsm_presence_satisfied();
}

void security_presence_consume() {
  hsm_consume_presence();
}

static int hsm_mbedtls_rng(void* ctx, unsigned char* out, const size_t len) {
  (void)ctx;
  esp_fill_random(out, len);
  return 0;
}

static void hsm_clear_runtime() {
  secure_zero(hsmState.priv, sizeof(hsmState.priv));
  secure_zero(hsmState.pub, sizeof(hsmState.pub));
  hsmState.loaded = false;
  hsmState.createdAt = 0;
  hsmState.signCount = 0;
  hsmState.lastSignMs = 0;
}

static void hsm_delete_private_key_prefs() {
  prefs.begin("kbm", false);
  prefs.remove("hsm_prv");
  prefs.remove("hsm_ct");
  prefs.end();
}

static bool hsm_store_private_key(const uint8_t priv[HSM_PRIVKEY_BYTES], const uint32_t createdAt) {
  if (!priv) return false;
  prefs.begin("kbm", false);
  const size_t wr = prefs.putBytes("hsm_prv", priv, HSM_PRIVKEY_BYTES);
  prefs.putUInt("hsm_ct", createdAt);
  prefs.end();
  return wr == HSM_PRIVKEY_BYTES;
}

static bool hsm_compute_pub_from_priv(const uint8_t priv[HSM_PRIVKEY_BYTES], uint8_t outPub[HSM_PUBKEY_BYTES]) {
  if (!priv || !outPub) return false;

  mbedtls_ecp_keypair key;
  mbedtls_ecp_keypair_init(&key);

  if (mbedtls_ecp_read_key(MBEDTLS_ECP_DP_SECP256R1, &key, priv, HSM_PRIVKEY_BYTES) != 0) {
    mbedtls_ecp_keypair_free(&key);
    return false;
  }
  if (mbedtls_ecp_keypair_calc_public(&key, hsm_mbedtls_rng, nullptr) != 0) {
    mbedtls_ecp_keypair_free(&key);
    return false;
  }

  uint8_t pub[65] = {0};
  size_t pubLen = 0;
  const int rc = mbedtls_ecp_write_public_key(&key, MBEDTLS_ECP_PF_UNCOMPRESSED, &pubLen, pub, sizeof(pub));
  mbedtls_ecp_keypair_free(&key);
  if (rc != 0 || pubLen != sizeof(pub) || pub[0] != 0x04) return false;

  memcpy(outPub, pub + 1, HSM_PUBKEY_BYTES);
  return true;
}

static bool hsm_set_runtime_key(const uint8_t priv[HSM_PRIVKEY_BYTES], const uint32_t createdAt) {
  uint8_t pub[HSM_PUBKEY_BYTES] = {0};
  if (!hsm_compute_pub_from_priv(priv, pub)) return false;
  memcpy(hsmState.priv, priv, HSM_PRIVKEY_BYTES);
  memcpy(hsmState.pub, pub, HSM_PUBKEY_BYTES);
  hsmState.loaded = true;
  hsmState.createdAt = createdAt;
  hsmState.signCount = 0;
  hsmState.lastSignMs = 0;
  return true;
}

static uint32_t hsm_now_unix_or_zero() {
  uint64_t unixS = 0;
  if (!get_unix_seconds(&unixS)) return 0;
  if (unixS > UINT32_MAX) return 0;
  return static_cast<uint32_t>(unixS);
}

static bool hsm_load_from_prefs() {
  uint8_t priv[HSM_PRIVKEY_BYTES] = {0};

  prefs.begin("kbm", true);
  const size_t len = prefs.getBytesLength("hsm_prv");
  if (len != HSM_PRIVKEY_BYTES) {
    prefs.end();
    hsm_clear_runtime();
    return false;
  }
  const size_t got = prefs.getBytes("hsm_prv", priv, sizeof(priv));
  const uint32_t createdAt = prefs.getUInt("hsm_ct", 0);
  prefs.end();

  if (got != HSM_PRIVKEY_BYTES) {
    secure_zero(priv, sizeof(priv));
    hsm_clear_runtime();
    return false;
  }

  const bool ok = hsm_set_runtime_key(priv, createdAt);
  secure_zero(priv, sizeof(priv));
  if (!ok) {
    hsm_delete_private_key_prefs();
    hsm_clear_runtime();
  }
  return ok;
}

static bool hsm_generate_and_store_key() {
  uint8_t priv[HSM_PRIVKEY_BYTES] = {0};
  uint8_t pub[65] = {0};

  mbedtls_ecp_keypair key;
  mbedtls_ecp_keypair_init(&key);
  const int rc = mbedtls_ecp_gen_key(MBEDTLS_ECP_DP_SECP256R1, &key, hsm_mbedtls_rng, nullptr);
  if (rc != 0) {
    mbedtls_ecp_keypair_free(&key);
    return false;
  }

  size_t privLen = 0;
  if (mbedtls_ecp_write_key_ext(&key, &privLen, priv, sizeof(priv)) != 0 || privLen != sizeof(priv)) {
    mbedtls_ecp_keypair_free(&key);
    secure_zero(priv, sizeof(priv));
    return false;
  }

  size_t pubLen = 0;
  if (mbedtls_ecp_write_public_key(&key, MBEDTLS_ECP_PF_UNCOMPRESSED, &pubLen, pub, sizeof(pub)) != 0 || pubLen != sizeof(pub) ||
      pub[0] != 0x04) {
    mbedtls_ecp_keypair_free(&key);
    secure_zero(priv, sizeof(priv));
    return false;
  }
  mbedtls_ecp_keypair_free(&key);

  const uint32_t createdAt = hsm_now_unix_or_zero();
  const bool stored = hsm_store_private_key(priv, createdAt);
  if (!stored) {
    secure_zero(priv, sizeof(priv));
    return false;
  }

  const bool loaded = hsm_set_runtime_key(priv, createdAt);
  secure_zero(priv, sizeof(priv));
  if (!loaded) {
    hsm_delete_private_key_prefs();
    hsm_clear_runtime();
    return false;
  }
  return true;
}

static bool hsm_delete_key() {
  hsm_delete_private_key_prefs();
  hsm_clear_runtime();
  return true;
}

static bool hsm_digest_from_form_input(const String& fmt, const String& value, uint8_t outDigest[32], size_t* inputLenOut) {
  if (!outDigest) return false;
  if (inputLenOut) *inputLenOut = 0;

  String mode = fmt;
  mode.trim();
  mode.toLowerCase();

  if (mode.length() == 0 || mode == "text") {
    if (value.length() > HSM_SIGN_INPUT_MAX) return false;
    const uint8_t* msg = reinterpret_cast<const uint8_t*>(value.c_str());
    const size_t msgLen = value.length();
    if (mbedtls_sha256(msg, msgLen, outDigest, 0) != 0) return false;
    if (inputLenOut) *inputLenOut = msgLen;
    return true;
  }

  if (mode == "hex") {
    if (value.length() == 0 || (value.length() % 2) != 0) return false;
    uint8_t tmp[HSM_SIGN_INPUT_MAX] = {0};
    const size_t n = hex_to_bytes(value.c_str(), tmp, sizeof(tmp));
    if (n == 0) return false;
    const bool ok = (mbedtls_sha256(tmp, n, outDigest, 0) == 0);
    secure_zero(tmp, sizeof(tmp));
    if (!ok) return false;
    if (inputLenOut) *inputLenOut = n;
    return true;
  }

  if (mode == "digesthex") {
    uint8_t tmp[32] = {0};
    const size_t n = hex_to_bytes(value.c_str(), tmp, sizeof(tmp));
    if (n != sizeof(tmp)) {
      secure_zero(tmp, sizeof(tmp));
      return false;
    }
    memcpy(outDigest, tmp, sizeof(tmp));
    secure_zero(tmp, sizeof(tmp));
    if (inputLenOut) *inputLenOut = 32;
    return true;
  }

  return false;
}

static bool hsm_sign_digest_der(const uint8_t digest[32], uint8_t* sigOut, const size_t sigOutMax, size_t* sigLenOut) {
  if (sigLenOut) *sigLenOut = 0;
  if (!digest || !sigOut || !sigLenOut) return false;
  if (!hsmState.loaded) return false;
  if (sigOutMax < 8) return false;

  const uint32_t now = millis();
  if (hsmState.lastSignMs != 0 &&
      static_cast<int32_t>(now - hsmState.lastSignMs) < static_cast<int32_t>(HSM_SIGN_COOLDOWN_MS)) {
    return false;
  }

  mbedtls_ecp_keypair key;
  mbedtls_ecp_keypair_init(&key);
  if (mbedtls_ecp_read_key(MBEDTLS_ECP_DP_SECP256R1, &key, hsmState.priv, HSM_PRIVKEY_BYTES) != 0) {
    mbedtls_ecp_keypair_free(&key);
    return false;
  }
  if (mbedtls_ecp_keypair_calc_public(&key, hsm_mbedtls_rng, nullptr) != 0) {
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
  const int rc = mbedtls_ecdsa_write_signature(&ecdsa, MBEDTLS_MD_SHA256, digest, 32, sigOut, sigOutMax, &sigLen, hsm_mbedtls_rng,
                                               nullptr);
  mbedtls_ecdsa_free(&ecdsa);
  mbedtls_ecp_keypair_free(&key);
  if (rc != 0 || sigLen == 0 || sigLen > sigOutMax) return false;

  *sigLenOut = sigLen;
  hsmState.lastSignMs = now;
  hsmState.signCount++;
  return true;
}

static bool hsm_verify_digest_der(const uint8_t digest[32], const uint8_t* sigDer, const size_t sigDerLen) {
  if (!digest || !sigDer || sigDerLen == 0) return false;
  if (!hsmState.loaded) return false;

  mbedtls_ecp_keypair key;
  mbedtls_ecp_keypair_init(&key);
  if (mbedtls_ecp_read_key(MBEDTLS_ECP_DP_SECP256R1, &key, hsmState.priv, HSM_PRIVKEY_BYTES) != 0) {
    mbedtls_ecp_keypair_free(&key);
    return false;
  }
  if (mbedtls_ecp_keypair_calc_public(&key, hsm_mbedtls_rng, nullptr) != 0) {
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
  const int rc = mbedtls_ecdsa_read_signature(&ecdsa, digest, 32, sigDer, sigDerLen);
  mbedtls_ecdsa_free(&ecdsa);
  mbedtls_ecp_keypair_free(&key);
  return rc == 0;
}

static void hsm_public_key_uncompressed(uint8_t out65[65]) {
  if (!out65) return;
  memset(out65, 0, 65);
  if (!hsmState.loaded) return;
  out65[0] = 0x04;
  memcpy(out65 + 1, hsmState.pub, HSM_PUBKEY_BYTES);
}

static void hsm_pubkey_hex(char* out, const size_t outLen) {
  uint8_t pub[65] = {0};
  hsm_public_key_uncompressed(pub);
  bytes_to_hex(pub, hsmState.loaded ? sizeof(pub) : 0, out, outLen);
}

static void hsm_pubkey_fingerprint_hex(char* out, const size_t outLen) {
  if (!out || outLen == 0) return;
  out[0] = '\0';
  if (!hsmState.loaded) return;

  uint8_t pub[65] = {0};
  uint8_t hash[32] = {0};
  hsm_public_key_uncompressed(pub);
  if (mbedtls_sha256(pub, sizeof(pub), hash, 0) != 0) return;
  // 8-byte short fingerprint (16 hex chars) for quick visual checks.
  bytes_to_hex(hash, 8, out, outLen);
}

static bool build_hsm_status_json(String& outJson) {
  char pubHex[(65 * 2) + 1] = {0};
  char fpHex[(8 * 2) + 1] = {0};
  uint32_t pinRem = 0;
  if (hsm_pin_unlocked()) {
    const uint32_t now = millis();
    pinRem = static_cast<uint32_t>((hsmPinUnlockedUntil > now) ? ((hsmPinUnlockedUntil - now) / 1000U) : 0U);
  }
  uint32_t presenceRem = 0;
  if (hsm_presence_satisfied()) {
    const uint32_t now = millis();
    presenceRem = static_cast<uint32_t>((hsmPresenceUntil > now) ? ((hsmPresenceUntil - now) / 1000U) : 0U);
  }

  if (hsmState.loaded) {
    hsm_pubkey_hex(pubHex, sizeof(pubHex));
    hsm_pubkey_fingerprint_hex(fpHex, sizeof(fpHex));
  }

  outJson = "";
  outJson.reserve(520);
  outJson += "{";
  outJson += "\"key_present\":";
  outJson += (hsmState.loaded ? "true" : "false");
  outJson += ",\"algorithm\":\"ES256\"";
  outJson += ",\"curve\":\"P-256\"";
  outJson += ",\"created_unix\":";
  outJson += (hsmState.loaded && hsmState.createdAt > 0) ? String(hsmState.createdAt) : String("null");
  outJson += ",\"sign_count\":";
  outJson += String(hsmState.signCount);
  outJson += ",\"pubkey_fingerprint\":\"";
  if (hsmState.loaded) outJson += fpHex;
  outJson += "\"";
  outJson += ",\"public_key_hex\":\"";
  if (hsmState.loaded) outJson += pubHex;
  outJson += "\"";
  outJson += ",\"pin_configured\":";
  outJson += (hsmPinConfigured ? "true" : "false");
  outJson += ",\"pin_unlocked\":";
  outJson += (hsm_pin_unlocked() ? "true" : "false");
  outJson += ",\"pin_seconds_remaining\":";
  outJson += hsm_pin_unlocked() ? String(pinRem) : String("null");
  outJson += ",\"presence_satisfied\":";
  outJson += (hsm_presence_satisfied() ? "true" : "false");
  outJson += ",\"presence_seconds_remaining\":";
  outJson += hsm_presence_satisfied() ? String(presenceRem) : String("null");
  outJson += "}";
  return true;
}

static bool hmac_sha1(const uint8_t* key, const size_t keyLen, const uint8_t* msg, const size_t msgLen, uint8_t out20[20]) {
  const mbedtls_md_info_t* info = mbedtls_md_info_from_type(MBEDTLS_MD_SHA1);
  if (info == nullptr) return false;

  mbedtls_md_context_t ctx;
  mbedtls_md_init(&ctx);
  if (mbedtls_md_setup(&ctx, info, 1) != 0) {
    mbedtls_md_free(&ctx);
    return false;
  }
  if (mbedtls_md_hmac_starts(&ctx, key, keyLen) != 0) {
    mbedtls_md_free(&ctx);
    return false;
  }
  if (mbedtls_md_hmac_update(&ctx, msg, msgLen) != 0) {
    mbedtls_md_free(&ctx);
    return false;
  }
  if (mbedtls_md_hmac_finish(&ctx, out20) != 0) {
    mbedtls_md_free(&ctx);
    return false;
  }
  mbedtls_md_free(&ctx);
  return true;
}

static bool generate_totp(char* out, const size_t outLen, uint32_t* secondsRemainingOut) {
  if (out == nullptr || outLen < 8) return false;
  if (totpKeyLen == 0) return false;

  uint64_t unixSeconds = 0;
  if (!get_unix_seconds(&unixSeconds)) return false;

  const uint32_t period = totpPeriodS;
  const uint64_t counter = unixSeconds / period;
  const uint32_t rem = static_cast<uint32_t>(period - (unixSeconds % period));
  if (secondsRemainingOut) *secondsRemainingOut = rem;

  uint8_t msg[8];
  uint64_t c = counter;
  for (int i = 7; i >= 0; --i) {
    msg[i] = static_cast<uint8_t>(c & 0xFFU);
    c >>= 8;
  }

  uint8_t mac[20];
  if (!hmac_sha1(totpKey, totpKeyLen, msg, sizeof(msg), mac)) return false;

  const int offset = mac[19] & 0x0F;
  const uint32_t bin =
      ((static_cast<uint32_t>(mac[offset]) & 0x7FU) << 24) | (static_cast<uint32_t>(mac[offset + 1]) << 16) |
      (static_cast<uint32_t>(mac[offset + 2]) << 8) | (static_cast<uint32_t>(mac[offset + 3]));

  uint64_t mod = 1;
  for (uint8_t i = 0; i < totpDigits; ++i) mod *= 10ULL;
  const uint64_t otp = static_cast<uint64_t>(bin) % mod;
  snprintf(out, outLen, "%0*llu", static_cast<int>(totpDigits), static_cast<unsigned long long>(otp));
  return true;
}

static void handle_single_tap_action() {
  char code[16];
  uint32_t rem = 0;
  if (!generate_totp(code, sizeof(code), &rem)) {
    Serial.println("Single tap: TOTP not ready (secret/time).");
    return;
  }
  if (!usb_type_text(String(code))) {
    Serial.println("Single tap: USB keyboard HID disabled (FIDO-only mode).");
    return;
  }
  if (totpAppendEnter) {
    (void)usb_type_text("\n");
  }
}

static void start_wifi_control() {
  Serial.println("Starting control mode: Wi-Fi AP");
  WiFi.mode(WIFI_MODE_AP);
  WiFi.softAP(AP_SSID, AP_PASS);
  WiFi.setSleep(false);

  // We use a cookie for the portal session.
  static const char* hdrs[] = {"Cookie"};
  server.collectHeaders(hdrs, 1);

  const IPAddress ip = WiFi.softAPIP();
  dnsServer.start(DNS_PORT, "*", ip);

  Serial.print("Connect to Wi-Fi: ");
  Serial.println(AP_SSID);
  Serial.print("Then open browser to: http://");
  Serial.println(ip);

  // --- WEB SERVER ROUTING ---
  server.on("/", []() {
    if (is_authenticated_request()) {
      if (apManagementMode) send_ap_page();
      else send_ui_page();
    }
    else send_login_page();
  });
  server.on("/generate_204", []() {
    if (is_authenticated_request()) {
      if (apManagementMode) send_ap_page();
      else send_ui_page();
    }
    else send_login_page();
  });
  server.on("/hotspot-detect.html", []() { // iOS/macOS
    if (is_authenticated_request()) {
      if (apManagementMode) send_ap_page();
      else send_ui_page();
    }
    else send_login_page();
  });
  server.on("/connecttest.txt", []() {     // Windows
    if (is_authenticated_request()) {
      if (apManagementMode) send_ap_page();
      else send_ui_page();
    }
    else send_login_page();
  });
  server.on("/favicon.ico", []() { server.send(204); });

  server.on("/login", HTTP_GET, []() { send_login_page(); });

  server.on("/login", HTTP_POST, []() {
    const String t = server.arg("t");
    if (pairTokenHex[0] != '\0' && t.length() > 0 && t.equalsIgnoreCase(pairTokenHex)) {
      set_token_cookie_and_redirect("/");
      return;
    }
    server.sendHeader("Location", "/login?e=1", true);
    server.send(303, "text/plain", "");
  });

  server.on("/logout", HTTP_GET, []() { clear_token_cookie_and_redirect("/"); });

  server.on("/pair", HTTP_GET, []() {
    if (!pairing_active()) {
      server.send(403, "text/plain", "Pairing not active");
      return;
    }
    if (pairingRotateArmed || pairTokenHex[0] == '\0') {
      generate_pair_token();
      pairingRotateArmed = false;
    }
    set_token_cookie_and_redirect("/");
  });

  server.on("/time", HTTP_GET, []() {
    if (!is_authenticated_request()) {
      server.send(401, "text/plain", "Sign in required");
      return;
    }
    if (!server.hasArg("ms")) {
      server.send(400, "text/plain", "Missing ms");
      return;
    }
    int64_t unixMs = 0;
    if (!parse_i64(server.arg("ms"), &unixMs) || !set_time_from_unix_ms(unixMs)) {
      server.send(400, "text/plain", "Invalid ms");
      return;
    }
    send_ok_minimal();
  });

  server.on("/totp", HTTP_GET, []() {
    if (!is_authenticated_request()) {
      send_login_page();
      return;
    }
    send_totp_page();
  });

  server.on("/totp", HTTP_POST, []() {
    if (!is_authenticated_request()) {
      server.send(401, "text/plain", "Sign in required");
      return;
    }
    const String s = server.arg("s");
    const String d = server.arg("d");
    const String p = server.arg("p");
    const bool e = server.hasArg("e");
    if (!save_totp_config_from_form(s, d, p, e)) {
      server.sendHeader("Location", "/totp?e=1", true);
      server.send(303, "text/plain", "");
      return;
    }
    server.sendHeader("Location", "/totp", true);
    server.send(303, "text/plain", "");
  });

  server.on("/totp/clear", HTTP_POST, []() {
    if (!is_authenticated_request()) {
      server.send(401, "text/plain", "Sign in required");
      return;
    }
    clear_totp_prefs();
    server.sendHeader("Location", "/totp", true);
    server.send(303, "text/plain", "");
  });

  server.on("/totp/status", HTTP_GET, []() {
    if (!is_authenticated_request()) {
      server.send(401, "application/json", "{\"error\":\"auth\"}");
      return;
    }

    bool configured = totpKeyLen > 0;
    char code[16] = {0};
    uint32_t rem = 0;
    const bool canCode = configured && generate_totp(code, sizeof(code), &rem);

    String json;
    json.reserve(192);
    json += "{";
    json += "\"configured\":";
    json += (configured ? "true" : "false");
    json += ",\"time_synced\":";
    json += (timeSynced ? "true" : "false");
    json += ",\"flash_encryption\":";
    json += (flash_encryption_enabled() ? "true" : "false");
    json += ",\"code\":\"";
    if (canCode) json += code;
    json += "\"";
    json += ",\"seconds_remaining\":";
    json += canCode ? String(rem) : String("null");
    json += "}";

    server.sendHeader("Cache-Control", "no-store");
    server.send(200, "application/json", json);
  });

  server.on("/keys", HTTP_GET, []() {
    if (!is_authenticated_request()) {
      send_login_page();
      return;
    }
    send_keys_page();
  });

  server.on("/ap", HTTP_GET, []() {
    if (!is_authenticated_request()) {
      send_login_page();
      return;
    }
    send_ap_page();
  });

  server.on("/diag", HTTP_GET, []() {
    if (!is_authenticated_request()) {
      send_login_page();
      return;
    }
    send_diag_page();
  });

  server.on("/diag/status", HTTP_GET, []() {
    if (!is_authenticated_request()) {
      server.send(401, "application/json", "{\"error\":\"auth\"}");
      return;
    }
    String json;
    fido_diag_build_json(json);
    server.sendHeader("Cache-Control", "no-store");
    server.send(200, "application/json", json);
  });

  server.on("/diag/reset", HTTP_POST, []() {
    if (!is_authenticated_request()) {
      server.send(401, "text/plain", "Sign in required");
      return;
    }
    if (!admin_unlocked()) {
      server.send(403, "text/plain", "Admin actions locked (hold BOOT ~2-4s to unlock).");
      return;
    }
    fido_diag_clear();
    server.send(200, "text/plain", "Diagnostics reset");
  });

  server.on("/ap/status", HTTP_GET, []() {
    if (!is_authenticated_request()) {
      server.send(401, "application/json", "{\"error\":\"auth\"}");
      return;
    }
    String json;
    if (!build_ap_status_json(json)) {
      server.send(500, "application/json", "{\"error\":\"ap\"}");
      return;
    }
    server.sendHeader("Cache-Control", "no-store");
    server.send(200, "application/json", json);
  });

  server.on("/ap/mode", HTTP_POST, []() {
    if (!is_authenticated_request()) {
      server.send(401, "text/plain", "Sign in required");
      return;
    }
    if (!admin_unlocked()) {
      server.send(403, "text/plain", "Admin actions locked (hold BOOT ~2-4s to unlock).");
      return;
    }
    const String mode = server.arg("mode");
    if (mode == "manage") {
      save_ap_management_mode(true);
      server.send(200, "text/plain", "AP mode set to management-only");
      return;
    }
    if (mode == "control") {
      save_ap_management_mode(false);
      server.send(200, "text/plain", "AP mode set to full control");
      return;
    }
    server.send(400, "text/plain", "Invalid mode");
  });

  server.on("/hsm", HTTP_GET, []() {
    if (!is_authenticated_request()) {
      send_login_page();
      return;
    }
    send_hsm_page();
  });

  server.on("/hsm/status", HTTP_GET, []() {
    if (!is_authenticated_request()) {
      server.send(401, "application/json", "{\"error\":\"auth\"}");
      return;
    }

    String json;
    if (!build_hsm_status_json(json)) {
      server.send(500, "application/json", "{\"error\":\"hsm\"}");
      return;
    }
    server.sendHeader("Cache-Control", "no-store");
    server.send(200, "application/json", json);
  });

  server.on("/hsm/pin/unlock", HTTP_POST, []() {
    if (!is_authenticated_request()) {
      server.send(401, "text/plain", "Sign in required");
      return;
    }
    if (!hsmPinConfigured) {
      server.send(409, "text/plain", "HSM PIN is not configured");
      return;
    }
    const String pin = server.arg("p");
    if (!hsm_pin_unlock_with_pin(pin.c_str())) {
      server.send(403, "text/plain", "Invalid PIN");
      return;
    }
    server.send(200, "text/plain", "PIN unlocked");
  });

  server.on("/hsm/pin/set", HTTP_POST, []() {
    if (!is_authenticated_request()) {
      server.send(401, "text/plain", "Sign in required");
      return;
    }
    if (!admin_unlocked()) {
      server.send(403, "text/plain", "Admin actions locked (hold BOOT ~2-4s to unlock).");
      return;
    }
    if (!hsm_presence_satisfied()) {
      server.send(428, "text/plain", "Physical presence required (hold BOOT ~0.5-1.2s, then retry).");
      return;
    }

    const String newPin = server.arg("n");
    if (newPin.length() < HSM_PIN_MIN_LEN || newPin.length() > HSM_PIN_MAX_LEN) {
      server.send(400, "text/plain", "PIN length invalid");
      return;
    }
    if (hsmPinConfigured) {
      const String oldPin = server.arg("p");
      if (!hsm_pin_verify(oldPin.c_str())) {
        server.send(403, "text/plain", "Current PIN invalid");
        return;
      }
    }

    if (!hsm_pin_set(newPin.c_str())) {
      server.send(500, "text/plain", "Failed to set PIN");
      return;
    }
    hsm_consume_presence();
    server.send(200, "text/plain", "PIN saved");
  });

  server.on("/hsm/pin/clear", HTTP_POST, []() {
    if (!is_authenticated_request()) {
      server.send(401, "text/plain", "Sign in required");
      return;
    }
    if (!admin_unlocked()) {
      server.send(403, "text/plain", "Admin actions locked (hold BOOT ~2-4s to unlock).");
      return;
    }
    if (!hsmPinConfigured) {
      server.send(409, "text/plain", "HSM PIN is not configured");
      return;
    }
    if (!hsm_presence_satisfied()) {
      server.send(428, "text/plain", "Physical presence required (hold BOOT ~0.5-1.2s, then retry).");
      return;
    }
    const String pin = server.arg("p");
    if (!hsm_pin_verify(pin.c_str())) {
      server.send(403, "text/plain", "Invalid PIN");
      return;
    }
    hsm_pin_clear_prefs();
    hsm_consume_presence();
    server.send(200, "text/plain", "PIN cleared");
  });

  server.on("/hsm/generate", HTTP_POST, []() {
    if (!is_authenticated_request()) {
      server.send(401, "text/plain", "Sign in required");
      return;
    }
    if (!admin_unlocked()) {
      server.send(403, "text/plain", "Admin actions locked (hold BOOT ~2-4s to unlock).");
      return;
    }
    if (!hsmPinConfigured) {
      server.send(428, "text/plain", "Set an HSM PIN first");
      return;
    }
    if (!hsm_pin_unlocked()) {
      server.send(428, "text/plain", "PIN locked. Unlock PIN first.");
      return;
    }
    if (!hsm_presence_satisfied()) {
      server.send(428, "text/plain", "Physical presence required (hold BOOT ~0.5-1.2s, then retry).");
      return;
    }
    if (!hsm_generate_and_store_key()) {
      server.send(500, "text/plain", "HSM key generation failed");
      return;
    }
    hsm_consume_presence();
    server.send(200, "text/plain", "HSM key generated");
  });

  server.on("/hsm/delete", HTTP_POST, []() {
    if (!is_authenticated_request()) {
      server.send(401, "text/plain", "Sign in required");
      return;
    }
    if (!admin_unlocked()) {
      server.send(403, "text/plain", "Admin actions locked (hold BOOT ~2-4s to unlock).");
      return;
    }
    if (!hsmPinConfigured) {
      server.send(428, "text/plain", "Set an HSM PIN first");
      return;
    }
    if (!hsm_pin_unlocked()) {
      server.send(428, "text/plain", "PIN locked. Unlock PIN first.");
      return;
    }
    if (!hsm_presence_satisfied()) {
      server.send(428, "text/plain", "Physical presence required (hold BOOT ~0.5-1.2s, then retry).");
      return;
    }
    if (!hsm_delete_key()) {
      server.send(500, "text/plain", "HSM key delete failed");
      return;
    }
    hsm_consume_presence();
    server.send(200, "text/plain", "HSM key deleted");
  });

  server.on("/hsm/sign", HTTP_POST, []() {
    if (!is_authenticated_request()) {
      server.send(401, "text/plain", "Sign in required");
      return;
    }
    if (!hsmState.loaded) {
      server.send(409, "text/plain", "No HSM key loaded");
      return;
    }
    if (!hsmPinConfigured) {
      server.send(428, "text/plain", "Set an HSM PIN first");
      return;
    }
    if (!hsm_pin_unlocked()) {
      server.send(428, "text/plain", "PIN locked. Unlock PIN first.");
      return;
    }
    if (!hsm_presence_satisfied()) {
      server.send(428, "text/plain", "Physical presence required (hold BOOT ~0.5-1.2s, then retry).");
      return;
    }
    if (!server.hasArg("m")) {
      server.send(400, "text/plain", "Missing m");
      return;
    }

    const String fmt = server.arg("fmt");
    const String m = server.arg("m");
    uint8_t digest[32] = {0};
    size_t inputLen = 0;
    if (!hsm_digest_from_form_input(fmt, m, digest, &inputLen)) {
      server.send(400, "text/plain", "Invalid input. Use fmt=text|hex|digesthex.");
      return;
    }

    uint8_t sig[HSM_SIGNATURE_DER_MAX] = {0};
    size_t sigLen = 0;
    if (!hsm_sign_digest_der(digest, sig, sizeof(sig), &sigLen)) {
      secure_zero(digest, sizeof(digest));
      secure_zero(sig, sizeof(sig));
      server.send(429, "text/plain", "Sign failed or throttled");
      return;
    }

    char digestHex[(32 * 2) + 1] = {0};
    char sigHex[(HSM_SIGNATURE_DER_MAX * 2) + 1] = {0};
    bytes_to_hex(digest, sizeof(digest), digestHex, sizeof(digestHex));
    bytes_to_hex(sig, sigLen, sigHex, sizeof(sigHex));
    secure_zero(digest, sizeof(digest));
    secure_zero(sig, sizeof(sig));

    String json;
    json.reserve(320);
    json += "{";
    json += "\"ok\":true";
    json += ",\"input_len\":";
    json += String(inputLen);
    json += ",\"digest_hex\":\"";
    json += digestHex;
    json += "\"";
    json += ",\"signature_der_hex\":\"";
    json += sigHex;
    json += "\"";
    json += ",\"sign_count\":";
    json += String(hsmState.signCount);
    json += "}";

    hsm_consume_presence();
    server.sendHeader("Cache-Control", "no-store");
    server.send(200, "application/json", json);
  });

  server.on("/hsm/verify", HTTP_POST, []() {
    if (!is_authenticated_request()) {
      server.send(401, "text/plain", "Sign in required");
      return;
    }
    if (!hsmState.loaded) {
      server.send(409, "text/plain", "No HSM key loaded");
      return;
    }
    if (!server.hasArg("m") || !server.hasArg("sig")) {
      server.send(400, "text/plain", "Missing m or sig");
      return;
    }

    const String fmt = server.arg("fmt");
    const String m = server.arg("m");
    const String sigHexIn = server.arg("sig");

    uint8_t digest[32] = {0};
    size_t inputLen = 0;
    if (!hsm_digest_from_form_input(fmt, m, digest, &inputLen)) {
      server.send(400, "text/plain", "Invalid input. Use fmt=text|hex|digesthex.");
      return;
    }

    uint8_t sig[HSM_SIGNATURE_DER_MAX] = {0};
    const size_t sigLen = hex_to_bytes(sigHexIn.c_str(), sig, sizeof(sig));
    if (sigLen == 0) {
      secure_zero(digest, sizeof(digest));
      secure_zero(sig, sizeof(sig));
      server.send(400, "text/plain", "Invalid signature hex");
      return;
    }

    const bool valid = hsm_verify_digest_der(digest, sig, sigLen);
    char digestHex[(32 * 2) + 1] = {0};
    bytes_to_hex(digest, sizeof(digest), digestHex, sizeof(digestHex));
    secure_zero(digest, sizeof(digest));
    secure_zero(sig, sizeof(sig));

    String json;
    json.reserve(160);
    json += "{";
    json += "\"valid\":";
    json += (valid ? "true" : "false");
    json += ",\"input_len\":";
    json += String(inputLen);
    json += ",\"digest_hex\":\"";
    json += digestHex;
    json += "\"";
    json += "}";

    server.sendHeader("Cache-Control", "no-store");
    server.send(200, "application/json", json);
  });

  server.on("/keys/list", HTTP_GET, []() {
    if (!is_authenticated_request()) {
      server.send(401, "application/json", "{\"error\":\"auth\"}");
      return;
    }

    String json;
    if (!build_keys_json(json)) {
      server.send(500, "application/json", "{\"error\":\"store\"}");
      return;
    }

    server.sendHeader("Cache-Control", "no-store");
    server.send(200, "application/json", json);
  });

  server.on("/keys/label", HTTP_POST, []() {
    if (!is_authenticated_request()) {
      server.send(401, "text/plain", "Sign in required");
      return;
    }
    if (!server.hasArg("id")) {
      server.send(400, "text/plain", "Missing id");
      return;
    }

    const String idHex = server.arg("id");
    uint8_t id[CRED_MAX_ID_LEN];
    const size_t idLen = hex_to_bytes(idHex.c_str(), id, sizeof(id));
    if (idLen == 0) {
      server.send(400, "text/plain", "Invalid id");
      return;
    }

    String label = server.arg("label");
    label.trim();
    if (label.length() > CRED_MAX_LABEL_LEN) label.remove(CRED_MAX_LABEL_LEN);

    const bool ok = cred_store_set_label_id(id, idLen, label.c_str(), label.length());
    if (!ok) {
      server.send(400, "text/plain", "Label not saved");
      return;
    }
    send_ok_minimal();
  });

  server.on("/keys/delete", HTTP_POST, []() {
    if (!is_authenticated_request()) {
      server.send(401, "text/plain", "Sign in required");
      return;
    }
    if (!admin_unlocked()) {
      server.send(403, "text/plain", "Admin actions locked (hold BOOT ~2–4s to unlock).");
      return;
    }
    if (!server.hasArg("id")) {
      server.send(400, "text/plain", "Missing id");
      return;
    }

    const String idHex = server.arg("id");
    uint8_t id[CRED_MAX_ID_LEN];
    const size_t idLen = hex_to_bytes(idHex.c_str(), id, sizeof(id));
    if (idLen == 0) {
      server.send(400, "text/plain", "Invalid id");
      return;
    }

    if (!cred_store_delete_id(id, idLen)) {
      server.send(404, "text/plain", "Not found");
      return;
    }

    server.send(200, "text/plain", "Deleted");
  });

  server.on("/keys/settings", HTTP_POST, []() {
    if (!is_authenticated_request()) {
      server.send(401, "text/plain", "Sign in required");
      return;
    }
    if (!admin_unlocked()) {
      server.send(403, "text/plain", "Admin actions locked (hold BOOT ~2–4s to unlock).");
      return;
    }
    const String a = server.arg("a");
    if (a == "none") save_attestation_profile(AttestationProfile::None);
    else if (a == "diy" || a.length() == 0) save_attestation_profile(AttestationProfile::Diy);
    else {
      server.send(400, "text/plain", "Invalid setting");
      return;
    }
    server.send(200, "text/plain", "Saved");
  });

  server.on("/backup/download", HTTP_POST, []() {
    if (!is_authenticated_request()) {
      server.send(401, "text/plain", "Sign in required");
      return;
    }
    if (!admin_unlocked()) {
      server.send(403, "text/plain", "Admin actions locked (hold BOOT ~2–4s to unlock).");
      return;
    }

    const String p = server.arg("p");
    uint8_t* enc = nullptr;
    size_t encLen = 0;
    if (!build_encrypted_backup(p.c_str(), &enc, &encLen)) {
      server.send(400, "text/plain", "Backup not available (check password length).");
      return;
    }

    send_no_cache_headers();
    server.sendHeader("Content-Disposition", "attachment; filename=esp32s3-kbm-backup.bin", true);
    server.setContentLength(encLen);
    server.send(200, "application/octet-stream", "");
    server.sendContent(reinterpret_cast<const char*>(enc), encLen);

    secure_zero(enc, encLen);
    free(enc);
  });

  server.on("/backup/restore", HTTP_POST, []() {
    if (!is_authenticated_request()) {
      reset_restore_upload();
      server.send(401, "text/plain", "Sign in required");
      return;
    }
    if (!admin_unlocked()) {
      reset_restore_upload();
      server.send(403, "text/plain", "Admin actions locked (hold BOOT ~2–4s to unlock).");
      return;
    }

    const String p = server.arg("p");
    if (restoreUpload.error || restoreUpload.buf == nullptr || restoreUpload.len == 0) {
      reset_restore_upload();
      server.sendHeader("Location", "/keys?r=0", true);
      server.send(303, "text/plain", "");
      return;
    }

    const bool ok = decrypt_and_restore_backup(restoreUpload.buf, restoreUpload.len, p.c_str());
    reset_restore_upload();

    server.sendHeader("Location", ok ? "/keys?r=1" : "/keys?r=0", true);
    server.send(303, "text/plain", "");
  }, handle_restore_upload_chunk);

  server.on("/admin/status", HTTP_GET, []() {
    if (!is_authenticated_request()) {
      server.send(401, "application/json", "{\"error\":\"auth\"}");
      return;
    }

    const bool unlocked = admin_unlocked();
    uint32_t remS = 0;
    if (unlocked) {
      const uint32_t now = millis();
      remS = static_cast<uint32_t>((adminUnlockedUntil > now) ? ((adminUnlockedUntil - now) / 1000U) : 0U);
    }

    String json;
    json.reserve(160);
    json += "{";
    json += "\"admin_unlocked\":";
    json += (unlocked ? "true" : "false");
    json += ",\"admin_seconds_remaining\":";
    json += unlocked ? String(remS) : String("null");
    json += ",\"flash_encryption\":";
    json += (flash_encryption_enabled() ? "true" : "false");
    json += "}";

    server.sendHeader("Cache-Control", "no-store");
    server.send(200, "application/json", json);
  });

  server.onNotFound([ip]() {
    server.sendHeader("Location", String("http://") + ip.toString() + "/", true);
    server.send(302, "text/plain", "");
  });

  server.on("/move", []() {
    if (!is_authenticated_request()) {
      server.send(401, "text/plain", "Sign in required");
      return;
    }
    if (apManagementMode) {
      server.send(403, "text/plain", "AP is in management-only mode");
      return;
    }
    if (!usb_kbm_hid_enabled()) {
      server.send(409, "text/plain", "USB keyboard/mouse HID disabled");
      return;
    }
    if (server.hasArg("x") && server.hasArg("y")) {
      int x = server.arg("x").toInt();
      int y = server.arg("y").toInt();
      x = constrain(x, -127, 127);
      y = constrain(y, -127, 127);
      (void)usb_mouse_move(x, y);
    }
    send_ok_minimal();
  });

  server.on("/click", []() {
    if (!is_authenticated_request()) {
      server.send(401, "text/plain", "Sign in required");
      return;
    }
    if (apManagementMode) {
      server.send(403, "text/plain", "AP is in management-only mode");
      return;
    }
    if (!usb_kbm_hid_enabled()) {
      server.send(409, "text/plain", "USB keyboard/mouse HID disabled");
      return;
    }
    if (server.hasArg("b")) {
      const String btn = server.arg("b");
      (void)usb_mouse_click(btn);
    }
    send_ok_minimal();
  });

  server.on("/type", []() {
    if (!is_authenticated_request()) {
      server.send(401, "text/plain", "Sign in required");
      return;
    }
    if (apManagementMode) {
      server.send(403, "text/plain", "AP is in management-only mode");
      return;
    }
    if (!usb_kbm_hid_enabled()) {
      server.send(409, "text/plain", "USB keyboard/mouse HID disabled");
      return;
    }
    if (server.hasArg("t")) {
      String text = server.arg("t");
      if (text.length() > 256) text.remove(256);
      (void)usb_type_text(text);
    }
    send_ok_minimal();
  });

  server.begin();
}

static void poll_boot_button() {
  const uint32_t now = millis();

  // Expire pairing window.
  if (!pairing_active()) {
    pairingActiveUntil = 0;
    pairingRotateArmed = false;
  }

  // Expire admin unlock window.
  if (!admin_unlocked()) {
    adminUnlockedUntil = 0;
  }
  if (!hsm_pin_unlocked()) {
    hsmPinUnlockedUntil = 0;
  }
  if (!hsm_presence_satisfied()) {
    hsmPresenceUntil = 0;
  }

  // While the authenticator is waiting for user presence, avoid interpreting BOOT presses as portal gestures.
  if (fido_waiting_for_user_presence()) {
    pendingSingleTap = false;
    tapCount = 0;
    buttonDown = false;
    buttonDownSince = 0;
    return;
  }

  const bool down = boot_button_down();
  if (down) {
    if (!buttonDown) buttonDownSince = now;
    buttonDown = true;
    return;
  }

  // Handle pending single-tap action when the multi-tap gap expires.
  if (pendingSingleTap && (static_cast<int32_t>(now - pendingSingleTapDue) >= 0)) {
    pendingSingleTap = false;
    tapCount = 0;
    handle_single_tap_action();
  }

  // Released.
  if (!buttonDown) return;

  const uint32_t held = now - buttonDownSince;

  if (held <= TAP_MAX_MS) {
    if (static_cast<int32_t>(now - lastTapAt) > static_cast<int32_t>(TAP_GAP_MS)) {
      tapCount = 0;
    }
    ++tapCount;
    lastTapAt = now;

    if (tapCount >= PAIRING_TAP_COUNT) {
      pairingActiveUntil = now + PAIRING_WINDOW_MS;
      pairingRotateArmed = true;
      tapCount = 0;
      pendingSingleTap = false;
      Serial.println("Pairing window enabled (open the portal and press Pair).");
    } else {
      pendingSingleTap = true;
      pendingSingleTapDue = now + TAP_GAP_MS;
    }
  } else {
    if (held >= HSM_PRESENCE_HOLD_MIN_MS && held <= HSM_PRESENCE_HOLD_MAX_MS) {
      hsm_mark_presence_now();
      Serial.println("HSM/FIDO physical presence window opened.");
    }
    if (held >= ADMIN_UNLOCK_HOLD_MIN_MS && held <= ADMIN_UNLOCK_HOLD_MAX_MS) {
      adminUnlockedUntil = now + ADMIN_UNLOCK_WINDOW_MS;
      Serial.println("Admin actions unlocked (keys + HSM).");
    }
    pendingSingleTap = false;
    tapCount = 0;
  }

  buttonDown = false;
}

static void update_status_led() {
  if (!led_available()) return;

  const uint32_t now = millis();

  // Waiting for user presence (FIDO2) indicator (cyan blink).
  if (fido_waiting_for_user_presence()) {
    const bool on = ((now / 200U) % 2U) == 0U;
    set_led_rgb(0, on ? 32 : 0, on ? 32 : 0);
    return;
  }

  // While BOOT is held, show a brief indicator (useful for long-press actions).
  if (buttonDown) {
    const bool on = ((now / 125U) % 2U) == 0U;
    set_led_rgb(on ? 24 : 0, on ? 24 : 0, on ? 24 : 0);
    return;
  }

  // Pairing window indicator (magenta blink).
  if (pairing_active()) {
    const bool on = ((now / 200U) % 2U) == 0U;
    set_led_rgb(on ? 32 : 0, 0, on ? 32 : 0);
    return;
  }

  // Admin unlock window indicator (yellow blink).
  if (admin_unlocked()) {
    const bool on = ((now / 350U) % 2U) == 0U;
    set_led_rgb(on ? 48 : 0, on ? 32 : 0, 0);
    return;
  }

  // Physical-presence window (green blink).
  if (hsm_presence_satisfied()) {
    const bool on = ((now / 180U) % 2U) == 0U;
    set_led_rgb(0, on ? 36 : 0, 0);
    return;
  }

  // Default indicator: Wi-Fi AP running (blue pulse every 2s).
  const uint32_t t = now % 2000U;
  const bool on = t < 120U;
  set_led_rgb(0, 0, on ? 32 : 0);
}

void setup() {
  Serial.begin(115200);
  pinMode(BOOT_BUTTON_PIN, INPUT_PULLUP);
  init_led();

  // FIDO makeCredential/getAssertion can spend noticeable time in ECC operations.
  // Prevent loop-task watchdog resets from dropping USB during those operations.
  disableLoopWDT();

  load_pair_token();
  load_totp_config();
  attestationProfile = load_attestation_profile();
  apManagementMode = load_ap_management_mode();
  (void)hsm_load_from_prefs();
  (void)hsm_pin_load_from_prefs();

  USB.begin();
  usb_input_begin();
  fido_begin();

  Serial.println("Triple-tap BOOT to enable portal pairing.");
  serial_diag_print_help();
  serial_diag_print_status();

#if FIDO_STABILITY_MODE
  // Disable radio during FIDO transport troubleshooting to minimize USB dropouts.
  WiFi.mode(WIFI_OFF);
  WiFi.setSleep(false);
#else
  start_wifi_control();
#endif
}

void loop() {
  fido_task();
  serial_diag_task();
  poll_boot_button();
  update_status_led();

#if !FIDO_STABILITY_MODE
  dnsServer.processNextRequest();
  server.handleClient();
#endif

  delay(1); // yield to WiFi/USB stacks
}

#line 1 "C:\\Users\\Justin\\Documents\\Arduino\\esp32s3-wifi-kbm\\fido2_ctap2.ino"
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
#define FIDO_REQUIRE_BOOT_BUTTON_FOR_UP 1
#endif
#if !FIDO_REQUIRE_BOOT_BUTTON_FOR_UP
#error "Auto user-presence is disabled in this build; set FIDO_REQUIRE_BOOT_BUTTON_FOR_UP=1."
#endif
static constexpr uint32_t CTAP_UP_MIN_HOLD_MS = 250;

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
  const bool pinGate = security_pin_configured() && !security_pin_unlocked_now();
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
  const bool pinGate = security_pin_configured() && !security_pin_unlocked_now();
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
    // Reset has no pinUvAuthParam field in this implementation; require local unlock window if PIN is configured.
    if (security_pin_configured() && !security_pin_unlocked_now()) {
      fidoDiag.totalPinGateBlocks++;
      FIDO_LOG("Security PIN gate blocked cmd=%s", ctap_cmd_name(ctapCmd));
      fido_send_ctap2_status(cid, CTAP2_ERR_PIN_REQUIRED, nullptr, 0);
      return;
    }
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

