#include <WiFi.h>
#include <DNSServer.h>
#include <WebServer.h>
#include <Preferences.h>
#include <NimBLEDevice.h>
#include <esp_system.h>
#include <esp_timer.h>
#include <ctype.h>
#include "esp_flash_encrypt.h"
#include "esp32-hal-rgb-led.h"
#include "mbedtls/md.h"
#include "mbedtls/pkcs5.h"
#include "mbedtls/gcm.h"
#include "USB.h"
#include "USBHIDKeyboard.h"
#include "USBHIDMouse.h"

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

// Admin unlock (physical presence) gating for sensitive actions (delete/export/restore).
// Hold BOOT for a few seconds (but less than the mode-toggle hold) to unlock briefly.
static constexpr uint32_t ADMIN_UNLOCK_WINDOW_MS = 60 * 1000;
static constexpr uint32_t ADMIN_UNLOCK_HOLD_MIN_MS = 1500;
static constexpr uint32_t ADMIN_UNLOCK_HOLD_MAX_MS = 4500;

// Credential inventory store (placeholder for future FIDO2/CTAP integration).
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
// Hold to switch between Wi-Fi AP control and BLE control.
static constexpr uint8_t  BOOT_BUTTON_PIN = 0;
static constexpr uint32_t MODE_TOGGLE_HOLD_MS = 5000;

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

USBHIDKeyboard Keyboard;
USBHIDMouse Mouse;

enum class ControlMode : uint8_t {
  WifiAp = 0,
  Ble = 1,
};

enum class AttestationProfile : uint8_t {
  Diy = 0,
  None = 1,
};

static Preferences prefs;
static ControlMode currentMode = ControlMode::WifiAp;
static uint32_t buttonDownSince = 0;
static bool buttonDown = false;
static bool buttonArmed = false;

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

struct RestoreUploadState {
  uint8_t* buf = nullptr;
  size_t len = 0;
  size_t cap = 0;
  bool error = false;
};

static RestoreUploadState restoreUpload;

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
        <a href="/keys" style="color:#9ecbff; text-decoration:none; font-size:14px;">Keys</a>
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
    <div class="hint">Tip: hold BOOT for 5s to switch to BLE mode.</div>
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
        <a href="/keys">Keys</a>
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
        <a href="/totp">TOTP</a>
        <a href="/logout">Sign out</a>
      </div>
    </div>

    <h2>Security Key</h2>
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

static inline const char* mode_name(ControlMode m) {
  return (m == ControlMode::Ble) ? "BLE" : "Wi-Fi AP";
}

static inline bool pairing_active() {
  return pairingActiveUntil != 0 && (static_cast<int32_t>(pairingActiveUntil - millis()) > 0);
}

static inline bool admin_unlocked() {
  return adminUnlockedUntil != 0 && (static_cast<int32_t>(adminUnlockedUntil - millis()) > 0);
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
  Keyboard.print(code);
  if (totpAppendEnter) Keyboard.print("\n");
}

static ControlMode load_mode() {
  prefs.begin("kbm", true);
  const uint8_t raw = prefs.getUChar("mode", static_cast<uint8_t>(ControlMode::WifiAp));
  prefs.end();
  return (raw == static_cast<uint8_t>(ControlMode::Ble)) ? ControlMode::Ble : ControlMode::WifiAp;
}

static void save_mode(ControlMode m) {
  prefs.begin("kbm", false);
  prefs.putUChar("mode", static_cast<uint8_t>(m));
  prefs.end();
}

static ControlMode toggled_mode(ControlMode m) {
  return (m == ControlMode::WifiAp) ? ControlMode::Ble : ControlMode::WifiAp;
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
    if (is_authenticated_request()) send_ui_page();
    else send_login_page();
  });
  server.on("/generate_204", []() {
    if (is_authenticated_request()) send_ui_page();
    else send_login_page();
  });
  server.on("/hotspot-detect.html", []() { // iOS/macOS
    if (is_authenticated_request()) send_ui_page();
    else send_login_page();
  });
  server.on("/connecttest.txt", []() {     // Windows
    if (is_authenticated_request()) send_ui_page();
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
    if (server.hasArg("x") && server.hasArg("y")) {
      int x = server.arg("x").toInt();
      int y = server.arg("y").toInt();
      x = constrain(x, -127, 127);
      y = constrain(y, -127, 127);
      Mouse.move(x, y);
    }
    send_ok_minimal();
  });

  server.on("/click", []() {
    if (!is_authenticated_request()) {
      server.send(401, "text/plain", "Sign in required");
      return;
    }
    if (server.hasArg("b")) {
      const String btn = server.arg("b");
      if (btn == "left") Mouse.click(MOUSE_LEFT);
      else if (btn == "right") Mouse.click(MOUSE_RIGHT);
    }
    send_ok_minimal();
  });

  server.on("/type", []() {
    if (!is_authenticated_request()) {
      server.send(401, "text/plain", "Sign in required");
      return;
    }
    if (server.hasArg("t")) {
      String text = server.arg("t");
      if (text.length() > 256) text.remove(256);
      Keyboard.print(text);
    }
    send_ok_minimal();
  });

  server.begin();
}

// --- BLE CONTROL (simple command protocol over BLE UART / NUS) ---
static constexpr const char* BLE_DEVICE_NAME = "ESP32-S3 KBM";
static constexpr const char* NUS_SERVICE_UUID = "6E400001-B5A3-F393-E0A9-E50E24DCCA9E";
static constexpr const char* NUS_RX_UUID = "6E400002-B5A3-F393-E0A9-E50E24DCCA9E"; // Write
static constexpr const char* NUS_TX_UUID = "6E400003-B5A3-F393-E0A9-E50E24DCCA9E"; // Notify

static NimBLECharacteristic* bleTx = nullptr;
static bool bleConnected = false;

static void ble_notify(const char* msg) {
  if (!bleConnected || bleTx == nullptr) return;
  bleTx->setValue(msg);
  bleTx->notify();
}

static void handle_command_line(char* line) {
  // Trim leading whitespace
  while (*line == ' ' || *line == '\t' || *line == '\r' || *line == '\n') ++line;
  if (*line == '\0') return;

  // Uppercase first token
  const char verb = static_cast<char>(toupper(static_cast<unsigned char>(line[0])));

  // Commands:
  //   M <dx> <dy>     Mouse move (ints, clamped to [-127,127])
  //   C L|R           Click left/right
  //   T <text...>     Type text (max 256 chars)
  //   PING            Reply PONG
  if (verb == 'P' && strncmp(line, "PING", 4) == 0) {
    ble_notify("PONG\n");
    return;
  }

  if (verb == 'M') {
    char* p = line + 1;
    while (*p == ' ' || *p == '\t') ++p;
    if (*p == '\0') {
      ble_notify("ERR missing dx/dy\n");
      return;
    }
    char* end1 = nullptr;
    long dx = strtol(p, &end1, 10);
    if (end1 == p) {
      ble_notify("ERR bad dx\n");
      return;
    }
    p = end1;
    while (*p == ' ' || *p == '\t') ++p;
    char* end2 = nullptr;
    long dy = strtol(p, &end2, 10);
    if (end2 == p) {
      ble_notify("ERR bad dy\n");
      return;
    }
    dx = constrain(static_cast<int>(dx), -127, 127);
    dy = constrain(static_cast<int>(dy), -127, 127);
    Mouse.move(static_cast<int>(dx), static_cast<int>(dy));
    return;
  }

  if (verb == 'C') {
    char* p = line + 1;
    while (*p == ' ' || *p == '\t') ++p;
    const char which = static_cast<char>(toupper(static_cast<unsigned char>(*p)));
    if (which == 'L') Mouse.click(MOUSE_LEFT);
    else if (which == 'R') Mouse.click(MOUSE_RIGHT);
    else ble_notify("ERR expected C L|R\n");
    return;
  }

  if (verb == 'T') {
    char* p = line + 1;
    while (*p == ' ' || *p == '\t') ++p;
    if (*p == '\0') return;
    String text(p);
    text.replace("\r", "");
    text.replace("\n", "");
    if (text.length() > 256) text.remove(256);
    Keyboard.print(text);
    return;
  }

  ble_notify("ERR unknown cmd\n");
}

class BleServerCallbacks final : public NimBLEServerCallbacks {
  void onConnect(NimBLEServer* s, NimBLEConnInfo& connInfo) override {
    (void)s;
    (void)connInfo;
    bleConnected = true;
    ble_notify("OK connected\n");
  }

  void onDisconnect(NimBLEServer* s, NimBLEConnInfo& connInfo, int reason) override {
    (void)connInfo;
    (void)reason;
    bleConnected = false;
    s->startAdvertising();
  }
};

class BleRxCallbacks final : public NimBLECharacteristicCallbacks {
  void onWrite(NimBLECharacteristic* c, NimBLEConnInfo& connInfo) override {
    (void)connInfo;
    std::string v = c->getValue();
    if (v.empty()) return;

    // Copy into a mutable buffer, strip trailing newlines, then parse.
    static char buf[320];
    size_t n = v.size();
    if (n >= sizeof(buf)) n = sizeof(buf) - 1;
    memcpy(buf, v.data(), n);
    buf[n] = '\0';
    while (n > 0 && (buf[n - 1] == '\r' || buf[n - 1] == '\n')) {
      buf[n - 1] = '\0';
      --n;
    }
    handle_command_line(buf);
  }
};

static void start_ble_control() {
  Serial.println("Starting control mode: BLE (NUS)");
  WiFi.mode(WIFI_OFF);

  NimBLEDevice::init(BLE_DEVICE_NAME);
  NimBLEDevice::setPower(ESP_PWR_LVL_P9);

  NimBLEServer* s = NimBLEDevice::createServer();
  s->setCallbacks(new BleServerCallbacks());

  NimBLEService* svc = s->createService(NUS_SERVICE_UUID);
  bleTx = svc->createCharacteristic(NUS_TX_UUID, NIMBLE_PROPERTY::NOTIFY);
  NimBLECharacteristic* rx =
      svc->createCharacteristic(NUS_RX_UUID, NIMBLE_PROPERTY::WRITE | NIMBLE_PROPERTY::WRITE_NR);
  rx->setCallbacks(new BleRxCallbacks());
  svc->start();

  NimBLEAdvertising* adv = NimBLEDevice::getAdvertising();
  adv->addServiceUUID(NUS_SERVICE_UUID);
  adv->start();
}

static void maybe_toggle_mode_on_boot_hold() {
  if (!boot_button_down()) return;
  const uint32_t start = millis();
  while (boot_button_down() && (millis() - start < MODE_TOGGLE_HOLD_MS)) {
    delay(10);
  }
  if (boot_button_down() && (millis() - start >= MODE_TOGGLE_HOLD_MS)) {
    currentMode = toggled_mode(currentMode);
    save_mode(currentMode);
    Serial.print("Control mode set to: ");
    Serial.println(mode_name(currentMode));
    delay(200);
  }
}

static void poll_mode_toggle_button() {
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

  const bool down = boot_button_down();
  if (down) {
    if (!buttonDown) buttonDownSince = now;
    buttonDown = true;
    buttonArmed = (now - buttonDownSince) >= MODE_TOGGLE_HOLD_MS;
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

  if (held >= MODE_TOGGLE_HOLD_MS) {
    currentMode = toggled_mode(currentMode);
    save_mode(currentMode);
    Serial.print("Switching control mode to: ");
    Serial.println(mode_name(currentMode));
    delay(200);
    ESP.restart();
  } else if (held <= TAP_MAX_MS) {
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
    if (held >= ADMIN_UNLOCK_HOLD_MIN_MS && held <= ADMIN_UNLOCK_HOLD_MAX_MS) {
      adminUnlockedUntil = now + ADMIN_UNLOCK_WINDOW_MS;
      Serial.println("Admin actions unlocked (delete/backup/restore).");
    }
    pendingSingleTap = false;
    tapCount = 0;
  }

  buttonDown = false;
  buttonArmed = false;
}

static void update_mode_led() {
  if (!led_available()) return;

  const uint32_t now = millis();

  // While BOOT is held, show a distinct "pending switch" indicator.
  if (buttonDown) {
    if (buttonArmed) {
      // Ready: solid amber (release to switch)
      set_led_rgb(48, 24, 0);
    } else {
      // Not ready yet: quick white blink
      const bool on = ((now / 125U) % 2U) == 0U;
      set_led_rgb(on ? 24 : 0, on ? 24 : 0, on ? 24 : 0);
    }
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

  // Mode indicators:
  // - Wi-Fi AP: blue pulse every 2s
  // - BLE: green double pulse every 2s; solid green when connected
  if (currentMode == ControlMode::WifiAp) {
    const uint32_t t = now % 2000U;
    const bool on = t < 120U;
    set_led_rgb(0, 0, on ? 32 : 0);
    return;
  }

  if (bleConnected) {
    set_led_rgb(0, 32, 0);
    return;
  }

  const uint32_t t = now % 2000U;
  const bool on = (t < 120U) || (t >= 240U && t < 360U);
  set_led_rgb(0, on ? 32 : 0, 0);
}

void setup() {
  Serial.begin(115200);
  pinMode(BOOT_BUTTON_PIN, INPUT_PULLUP);
  init_led();

  currentMode = load_mode();
  load_pair_token();
  load_totp_config();
  attestationProfile = load_attestation_profile();
  maybe_toggle_mode_on_boot_hold();

  USB.begin();
  Keyboard.begin();
  Mouse.begin();

  Serial.print("Current control mode: ");
  Serial.println(mode_name(currentMode));
  Serial.println("Hold BOOT for ~5s to switch modes.");
  Serial.println("Triple-tap BOOT to enable portal pairing.");

  if (currentMode == ControlMode::Ble) start_ble_control();
  else start_wifi_control();
}

void loop() {
  poll_mode_toggle_button();
  update_mode_led();

  if (currentMode == ControlMode::WifiAp) {
    dnsServer.processNextRequest();
    server.handleClient();
  }

  delay(1); // yield to WiFi/BLE/USB stacks
}
