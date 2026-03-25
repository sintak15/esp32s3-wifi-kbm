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
#define USB_ENABLE_KBM_HID 0
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

#define SCREEN_WIDTH 128
#define SCREEN_HEIGHT 64
#define OLED_RESET -1
#define I2C_SDA 12
#define I2C_SCL 13
Adafruit_SSD1306 display(SCREEN_WIDTH, SCREEN_HEIGHT, &Wire, OLED_RESET);

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

  Wire.begin(I2C_SDA, I2C_SCL);
  if(!display.begin(SSD1306_SWITCHCAPVCC, 0x3C)) { 
    Serial.println(F("SSD1306 allocation failed"));
  } else {
    display.clearDisplay();
    display.setTextSize(1);
    display.setTextColor(SSD1306_WHITE);
    display.setCursor(0,0);
    display.println("ESP32-S3 KBM Ready");
    display.display();
  }

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
  static uint32_t lastDisplayUpdate = 0;

  fido_task();
  serial_diag_task();
  poll_boot_button();
  update_status_led();

  if (millis() - lastDisplayUpdate > 500) {
    update_display();
    lastDisplayUpdate = millis();
  }

#if !FIDO_STABILITY_MODE
  dnsServer.processNextRequest();
  server.handleClient();
#endif

  delay(1); // yield to WiFi/USB stacks
}

static void update_display() {
  if (OLED_RESET == -1 && !display.getBufferPtr()) return; // Display not initialized

  display.clearDisplay();
  display.setTextSize(2);
  display.setCursor(0, 0);

  char code[16];
  uint32_t rem = 0;
  if (totpKeyLen > 0 && generate_totp(code, sizeof(code), &rem)) {
    display.setCursor(14, 10);
    // Add a space between 3-digit groups for readability
    if (strlen(code) == 6) {
      char spaced_code[8];
      strncpy(spaced_code, code, 3);
      spaced_code[3] = ' ';
      strncpy(spaced_code + 4, code + 3, 3);
      spaced_code[7] = '\0';
      display.print(spaced_code);
    } else {
      display.print(code);
    }
    
    display.setTextSize(1);
    display.setCursor(0, 40);
    display.print("Code refreshes in ");
    display.print(rem);
    display.println("s");

    int barWidth = map(rem, 0, totpPeriodS, 0, SCREEN_WIDTH);
    display.fillRect(0, SCREEN_HEIGHT - 5, barWidth, 5, SSD1306_WHITE);
  } else {
    display.setTextSize(1);
    display.setCursor(0, 10);
    display.println("TOTP not configured or time not synced.");
  }
  display.display();
}
