# START HERE: ESP32-S3 WiFi KBM

This guide is for first-time users.

Goal: in about 10-20 minutes, you will flash the board and control a computer mouse and keyboard from your phone.

## 1) What You Need

- ESP32-S3 board (for example ESP32-S3 SuperMini)
- USB data cable (not charge-only)
- A target computer (the one the board will control)
- A phone or tablet
- Arduino IDE 2.x on your setup computer

## 2) Install Arduino Support

1. Open Arduino IDE.
2. Go to Board Manager.
3. Install `esp32` by Espressif Systems.
4. Restart Arduino IDE if prompted.

## 3) Open And Flash The Project

1. Open `esp32s3-wifi-kbm.ino`.
2. Select board: `ESP32S3 Dev Module` (or your exact ESP32-S3 model).
3. Select the board COM port.
4. Click Upload.

If upload fails, try:

- Another USB cable
- Another USB port
- Pressing BOOT while upload starts

## 4) First Connection (Phone To Board)

1. Plug the ESP32-S3 into the computer you want to control.
2. On your phone, join Wi-Fi:
   - SSID: `ESP32-SuperMini`
   - Password: `password123` (change in code for production)
3. Open: `http://192.168.4.1`

## 5) Pair And Sign In

The web portal requires pairing.

1. Triple-tap the BOOT button on the board.
2. In the portal, press Pair.
3. You should enter the control page.

If Pair says unavailable, triple-tap BOOT again and retry quickly.

## 6) Basic Use

- Move mouse: drag inside the trackpad area
- Left/right click: use buttons in the portal
- Type text: use text box and press Send

## 7) BOOT Button Quick Reference

- Triple-tap: open pairing window (~60 seconds)
- Single tap: type current TOTP code (if configured)
- Hold about 2-4 seconds: unlock admin actions for Keys page (~60 seconds)
- During WebAuthn/FIDO2 prompt: press and hold briefly to provide user presence

## 8) Optional: Test FIDO2 / WebAuthn

The board also acts as a USB security key.

Basic test flow:

1. Keep board plugged into your target computer.
2. On that computer, open a WebAuthn test page (for example webauthn.io).
3. Register a credential using a security key.
4. When asked for touch/user presence, press BOOT on the board.
5. Try authentication (sign in) and press BOOT again when prompted.

## 9) Optional: Keys Page And Backup

After signing into the portal, open `/keys`:

- View stored credential entries
- Set labels
- Backup/restore encrypted credential store
- Change attestation profile

Sensitive actions require admin unlock (hold BOOT about 2-4 seconds).

## 10) Common Problems

- Phone cannot open portal:
  - Ensure phone is on `ESP32-SuperMini`
  - Browse to `http://192.168.4.1`
- No typing/mouse movement on host computer:
  - Check USB cable is data-capable
  - Try another USB port
- WebAuthn request times out:
  - Press BOOT while request is waiting
  - Retry and hold BOOT slightly longer
- Upload port changes while flashing:
  - This is normal on ESP32-S3 USB CDC uploads

## 11) Next Steps

- Change default AP credentials in `esp32s3-wifi-kbm.ino`
- Enable flash encryption for stronger at-rest protection
- Optionally enable FIDO debug logs by compiling with `-DFIDO_DEBUG=1`
