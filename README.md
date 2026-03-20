# ESP32-S3 WiFi KBM (Keyboard + Mouse)

ESP32-S3 SuperMini sketch that:

- Starts a Wi-Fi Access Point with a captive portal-style redirect
- Serves a web UI (text input + trackpad)
- Sends input to the connected USB host via USB HID (keyboard + mouse)

## Control modes

Hold the BOOT button for ~5s to switch modes (the selection is saved and used on the next boot).

- **Wi-Fi AP mode**: connect to `ESP32-SuperMini`, open `http://192.168.4.1/`, then pair/sign in to access the controls.
- **BLE mode**: advertises as `ESP32-S3 KBM` and accepts simple commands over the Nordic UART Service (NUS).

Portal pairing:

- Triple-tap BOOT to enable pairing for ~60 seconds, then press **Pair** in the portal.
- Pairing uses a token stored in NVS (and is protected at rest only if flash encryption is enabled).

TOTP:

- Configure at `http://192.168.4.1/totp` after signing in.
- Single-tap BOOT to type the current code (opening the control page syncs time automatically).

Keys (credential inventory / backup):

- Open `http://192.168.4.1/keys` after signing in.
- Hold BOOT for ~2–4 seconds to unlock admin actions (delete / backup / restore) for ~60 seconds.

LED indicator (if your board has a built-in LED):

- Wi-Fi AP: blue pulse
- BLE: green double pulse (solid green when connected)
- Pairing window: magenta blink
- Admin unlock window: yellow blink
- While holding BOOT: fast white blink (solid amber when ready to switch)

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
