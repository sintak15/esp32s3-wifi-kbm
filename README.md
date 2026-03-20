# ESP32-S3 WiFi KBM (Keyboard + Mouse)

ESP32-S3 SuperMini sketch that:

- Starts a Wi‑Fi Access Point with a captive portal-style redirect
- Serves a simple web UI (text input + trackpad)
- Sends input to the connected USB host via USB HID (keyboard + mouse)

## Notes

- Use a strong AP password (8+ chars). The default is only for initial bring-up.
- Only use on systems you own / have explicit permission to control.

## Build

Arduino IDE (ESP32 core) + an ESP32-S3 board with USB device support.

Open `esp32s3-wifi-kbm.ino`, select your ESP32-S3 board + port, then Upload.

