#include <WiFi.h>
#include <DNSServer.h>
#include <WebServer.h>
#include <Preferences.h>
#include <NimBLEDevice.h>
#include "USB.h"
#include "USBHIDKeyboard.h"
#include "USBHIDMouse.h"

// Wi-Fi credentials for the ESP32-S3 access point
// Recommendation: change these before use.
static constexpr const char* AP_SSID = "ESP32-SuperMini";
static constexpr const char* AP_PASS = "password123";

static constexpr uint8_t  DNS_PORT = 53;
static constexpr uint16_t HTTP_PORT = 80;

// BOOT button is typically GPIO0 on ESP32-S3 dev boards (including many SuperMini variants).
// Hold to switch between Wi-Fi AP control and BLE control.
static constexpr uint8_t  BOOT_BUTTON_PIN = 0;
static constexpr uint32_t MODE_TOGGLE_HOLD_MS = 1000;

DNSServer dnsServer;
WebServer server(HTTP_PORT);

USBHIDKeyboard Keyboard;
USBHIDMouse Mouse;

enum class ControlMode : uint8_t {
  WifiAp = 0,
  Ble = 1,
};

static Preferences prefs;
static ControlMode currentMode = ControlMode::WifiAp;

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
    <h2>ESP32 Input Control</h2>
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

    function sendText() {
      let text = document.getElementById('textInput').value;
      if(text.length > 0) {
        fetch('/type?t=' + encodeURIComponent(text));
        document.getElementById('textInput').value = '';
      }
    }

    function sendClick(btn) {
      fetch('/click?b=' + btn);
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

      fetch('/move?x=' + tx + '&y=' + ty)
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

static inline void send_ui_page() {
  server.sendHeader("Cache-Control", "no-store, no-cache, must-revalidate, max-age=0");
  server.sendHeader("Pragma", "no-cache");
  server.sendHeader("Expires", "0");
  server.send_P(200, "text/html", index_html);
}

static inline void send_ok_minimal() {
  // 204: No Content (smaller + faster than "OK" bodies for high-rate endpoints)
  server.send(204);
}

static inline bool boot_button_down() {
  return digitalRead(BOOT_BUTTON_PIN) == LOW;
}

static inline const char* mode_name(ControlMode m) {
  return (m == ControlMode::Ble) ? "BLE" : "Wi-Fi AP";
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

  const IPAddress ip = WiFi.softAPIP();
  dnsServer.start(DNS_PORT, "*", ip);

  Serial.print("Connect to Wi-Fi: ");
  Serial.println(AP_SSID);
  Serial.print("Then open browser to: http://");
  Serial.println(ip);

  // --- WEB SERVER ROUTING ---
  server.on("/", send_ui_page);
  server.on("/generate_204", send_ui_page);
  server.on("/hotspot-detect.html", send_ui_page); // iOS/macOS
  server.on("/connecttest.txt", send_ui_page);     // Windows
  server.on("/favicon.ico", []() { server.send(204); });

  server.onNotFound([ip]() {
    server.sendHeader("Location", String("http://") + ip.toString() + "/", true);
    server.send(302, "text/plain", "");
  });

  server.on("/move", []() {
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
    if (server.hasArg("b")) {
      const String btn = server.arg("b");
      if (btn == "left") Mouse.click(MOUSE_LEFT);
      else if (btn == "right") Mouse.click(MOUSE_RIGHT);
    }
    send_ok_minimal();
  });

  server.on("/type", []() {
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
  static bool wasDown = false;
  static uint32_t downSince = 0;

  const bool down = boot_button_down();
  if (down && !wasDown) {
    downSince = millis();
  } else if (!down && wasDown) {
    const uint32_t held = millis() - downSince;
    if (held >= MODE_TOGGLE_HOLD_MS) {
      currentMode = toggled_mode(currentMode);
      save_mode(currentMode);
      Serial.print("Switching control mode to: ");
      Serial.println(mode_name(currentMode));
      delay(200);
      ESP.restart();
    }
  }

  wasDown = down;
}

void setup() {
  Serial.begin(115200);
  pinMode(BOOT_BUTTON_PIN, INPUT_PULLUP);

  currentMode = load_mode();
  maybe_toggle_mode_on_boot_hold();

  USB.begin();
  Keyboard.begin();
  Mouse.begin();

  Serial.print("Current control mode: ");
  Serial.println(mode_name(currentMode));
  Serial.println("Hold BOOT for ~1s to switch modes.");

  if (currentMode == ControlMode::Ble) start_ble_control();
  else start_wifi_control();
}

void loop() {
  poll_mode_toggle_button();

  if (currentMode == ControlMode::WifiAp) {
    dnsServer.processNextRequest();
    server.handleClient();
  }

  delay(1); // yield to WiFi/BLE/USB stacks
}
