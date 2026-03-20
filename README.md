# ESP32-S3 WiFi KBM (Keyboard + Mouse)

ESP32-S3 SuperMini sketch that turns the board into a **USB HID keyboard + mouse** that you can control from your phone/tablet over:

- **Wi‑Fi AP + web portal** (trackpad + text input)
- **BLE** (simple command protocol over Nordic UART Service / NUS)

This is intended for legitimate remote-control / lab workflows.

> Only use on systems you own or have explicit permission to control.

## How it works

- Plug the ESP32‑S3 into the **computer you want to control**. It enumerates as a USB keyboard + mouse.
- Connect your phone to the ESP32‑S3 over **Wi‑Fi AP** or **BLE** and send commands.
- The ESP32‑S3 translates those commands into USB HID events on the computer.

## Walkthrough (Wi‑Fi portal mode)

### 0) Flash the firmware

See [Build & Flash](#build--flash).

### 1) Connect everything

1. Plug the ESP32‑S3 into the computer you want to control (USB data cable).
2. On your phone/tablet, join Wi‑Fi `ESP32-SuperMini` (password is defined in the sketch).
3. Open `http://192.168.4.1/` (or accept the captive portal prompt).

### 2) Pair + sign in

The portal requires a pairing token (separate from the Wi‑Fi password).

1. **Triple‑tap** the BOOT button on the board.
   - LED shows a **magenta blink** while pairing is available (~60 seconds).
2. On the login page, press **Pair**.
   - The device creates/rotates a token and sets a session cookie in your browser.
3. You are redirected to the control UI.

Sign‑in notes:

- Pairing is only available shortly after triple‑tapping BOOT.
- Once signed in, the browser cookie keeps you signed in for ~30 days.
- To sign in from another device, repeat the **triple‑tap → Pair** flow.

### 3) Use the controls

- **Type**: enter text and press **Send**.
- **Mouse**: use the trackpad area to move the cursor.
- **Clicks**: use **Left Click** / **Right Click**.

## Switching control modes (Wi‑Fi ↔ BLE)

Hold BOOT for ~5 seconds to switch modes (the selection is saved in NVS and used on the next boot).

While holding BOOT:

- Fast white blink = counting up
- Solid amber = release to switch

Tip: you can also hold BOOT during power-up/boot to switch modes before the portal/BLE starts.

## BLE mode

### Enter BLE mode

Hold BOOT for ~5s to toggle to BLE mode (LED will change to the BLE pattern after reboot).

### Connect

The device advertises as `ESP32-S3 KBM` and uses NUS:

- Service UUID: `6E400001-B5A3-F393-E0A9-E50E24DCCA9E`
- RX (Write): `6E400002-B5A3-F393-E0A9-E50E24DCCA9E`
- TX (Notify): `6E400003-B5A3-F393-E0A9-E50E24DCCA9E`

### Commands

Write ASCII commands to the RX characteristic (newline-terminated is recommended):

- `M <dx> <dy>`: move mouse (`dx`/`dy` clamped to `-127..127`)
- `C L` / `C R`: left/right click
- `T <text...>`: type text (max 256 chars)
- `PING`: replies `PONG`

## TOTP (optional)

TOTP is a convenience feature that can type the current one‑time code into the USB host.

### Configure

1. Sign in to the portal.
2. Open `http://192.168.4.1/totp`.
3. Enter the Base32 shared secret (from the site/app), adjust digits/period if needed, and press **Save**.

### Use

- **Single‑tap** BOOT to type the current code (and optionally Enter).
- Time is synced from your browser when you open the control page (`/`), so TOTP is unavailable until time sync has happened after boot.
- Single-tap runs after a short delay (~0.5s) so triple‑taps can be detected reliably.

## Keys (credential inventory / backup)

Open `http://192.168.4.1/keys` after signing in.

Important:

- This sketch **does not implement CTAP2/FIDO2/WebAuthn** at this time.
- The Keys page manages a local **credential store framework** (inventory/labels/delete/backup) intended for future integration.
- The inventory will likely be empty until something writes credentials into the store.

### Admin unlock (required for sensitive actions)

Delete / backup / restore actions are gated behind physical presence:

- Hold BOOT for ~2–4 seconds to unlock admin actions for ~60 seconds.
- While unlocked, the LED shows a **yellow blink**.

### Inventory & labeling

- The dashboard lists stored entries (Relying Party ID / `rp_id`, an optional label, and an internal ID).
- You can set a friendly label per entry.

### Selective deletion

- While admin unlocked, press **Delete** next to an entry.

### Encrypted backup / restore

Backup contains the stored credentials blob and the attestation setting.
It does **not** include the Wi‑Fi pairing token or the TOTP secret.

- Download backup:
  1. Admin unlock (hold BOOT ~2–4s).
  2. Enter a backup password (minimum 8 characters).
  3. Press **Download backup** (saves `esp32s3-kbm-backup.bin`).
- Restore backup (replaces current stored credentials):
  1. Admin unlock (hold BOOT ~2–4s).
  2. Choose the `.bin` file and enter its password.
  3. Press **Restore backup**.

## Attestation setting

The Keys page includes an attestation profile setting (stored in NVS). Options:

- `DIY-S3-Key`
- `No attestation`

Certified-key/vendor impersonation is not supported.

## LED indicators

If your board has a built‑in LED:

- Wi‑Fi AP: blue pulse
- BLE: green double pulse (solid green when connected)
- Pairing window: magenta blink
- Admin unlock window: yellow blink
- While holding BOOT: fast white blink (solid amber when ready to switch)

## Notes

- Use a strong AP password (8+ chars). The default is only for initial bring-up.
- Pairing token and secrets are stored in NVS. They are protected at rest only if flash encryption is enabled in your firmware configuration.

## Build & Flash

### Arduino IDE

1. Install the ESP32 board package in Arduino IDE (Espressif Systems).
2. Open `esp32s3-wifi-kbm.ino`.
3. Select an ESP32‑S3 board definition (commonly `ESP32S3 Dev Module`).
4. Ensure USB device/HID support is enabled (Arduino ESP32 core uses TinyUSB on S3).
5. Select the correct COM port and Upload.

### arduino-cli (Windows example)

If you prefer the CLI, this is the configuration used in this repo’s build output:

```powershell
$cli  = "$env:LOCALAPPDATA\Programs\Arduino IDE\resources\app\lib\backend\resources\arduino-cli.exe"
$fqbn = "esp32:esp32:esp32s3:USBMode=default,CDCOnBoot=cdc,UploadMode=cdc"
$sketch = (Get-Location).Path

& $cli compile --fqbn $fqbn --export-binaries $sketch
& $cli upload  $sketch -p COM15 --fqbn $fqbn --input-dir "$sketch\build\esp32.esp32.esp32s3" --verify
```

Note: during upload, the port may temporarily switch (example: `COM15` → `COM8` → `COM15`). That is expected with USB‑CDC uploads.

## Troubleshooting

- **Portal doesn’t load**: confirm you’re connected to `ESP32-SuperMini`, then open `http://192.168.4.1/`.
- **Pair says not available**: triple‑tap BOOT and try again (magenta blink indicates pairing is active).
- **TOTP says not ready**: open the control page (`/`) to sync time, then retry the BOOT single‑tap.
- **Admin actions locked**: hold BOOT ~2–4 seconds (yellow blink indicates unlocked).
- **No HID input on the computer**: verify you’re using a USB data cable and the board is enumerating as HID (try a different cable/port).
