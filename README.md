# ESP32-S3 WiFi KBM (Keyboard + Mouse)

ESP32-S3 SuperMini sketch that:

- Starts a Wi-Fi Access Point with a captive portal-style redirect
- Serves a simple web UI (text input + trackpad)
- Sends input to the connected USB host via USB HID (keyboard + mouse)

## Control modes

Hold the BOOT button for ~1s to switch modes (the selection is saved and used on the next boot).

- **Wi‑Fi AP mode**: connect to `ESP32-SuperMini`, then open `http://192.168.4.1/`.
- **BLE mode**: advertises as `ESP32-S3 KBM` and accepts simple commands over the Nordic UART Service (NUS).

BLE commands (write to the NUS RX characteristic):

- `M <dx> <dy>`: move mouse (dx/dy are clamped to `-127..127`)
- `C L` / `C R`: left/right click
- `T <text...>`: type text (max 256 chars)
- `PING`: replies `PONG`

## Notes

- Use a strong AP password (8+ chars). The default is only for initial bring-up.
- Only use on systems you own / have explicit permission to control.

## Build

Arduino IDE (ESP32 core) + an ESP32-S3 board with USB device support.

Open `esp32s3-wifi-kbm.ino`, select your ESP32-S3 board + port, then Upload.
