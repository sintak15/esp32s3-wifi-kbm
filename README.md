# ESP32-S3 WiFi KBM

ESP32-S3 firmware that makes the board appear to a host computer as:

- USB HID keyboard
- USB HID mouse
- USB HID FIDO2 authenticator (CTAP2/WebAuthn)

Control is done from your phone or tablet through a local Wi-Fi web portal hosted by the board.

If you are brand new to this project, start here:

- [START_HERE.md](START_HERE.md)

## Safety

Use this only on systems you own or have explicit permission to control.

## What This Firmware Includes

- Wi-Fi AP + browser control page for mouse and typing
- Pairing token login flow (triple-tap BOOT to allow pairing)
- Optional TOTP typing shortcut
- Keys page for credential inventory, labeling, encrypted backup and restore
- CTAP2/FIDO2/WebAuthn over USB HID with physical user presence (BOOT button)

## Current Scope Notes

- This sketch is currently Wi-Fi portal based.
- BLE control mode is not part of the current code path.

## Beginner Path

1. Follow [START_HERE.md](START_HERE.md).
2. Confirm basic keyboard/mouse control works.
3. Optionally test FIDO2 on a WebAuthn test site.

## Build And Flash (Reference)

### Arduino IDE

1. Install Arduino IDE 2.x.
2. Install board package `esp32` by Espressif Systems.
3. Open `esp32s3-wifi-kbm.ino`.
4. Select an ESP32-S3 board (commonly `ESP32S3 Dev Module`).
5. Upload.

### arduino-cli (Windows example)

```powershell
$cli = "$env:LOCALAPPDATA\Programs\Arduino IDE\resources\app\lib\backend\resources\arduino-cli.exe"
$fqbn = "esp32:esp32:esp32s3:USBMode=default,CDCOnBoot=cdc,UploadMode=cdc"
$sketch = (Get-Location).Path

& $cli compile --fqbn $fqbn --export-binaries $sketch
& $cli upload  $sketch -p COM15 --fqbn $fqbn --input-dir "$sketch\build\esp32.esp32.esp32s3" --verify
```

Note: upload port can temporarily switch during flashing (for example `COM15 -> COM8 -> COM15`).

## Optional FIDO Debug Logs

`fido2_ctap2.ino` supports compile-time tracing.

- Default: `FIDO_DEBUG = 0`
- Enable with build flags: `-DFIDO_DEBUG=1`

## Troubleshooting

- Portal does not load:
  - Confirm phone is connected to the board AP.
  - Open `http://192.168.4.1` directly.
- Pair fails:
  - Triple-tap BOOT, then press Pair within about 60 seconds.
- No HID input on host:
  - Use a data-capable USB cable.
  - Verify the board enumerates on the host.
- WebAuthn times out:
  - Press and hold BOOT briefly when browser asks for user presence.

## License And Responsibility

You are responsible for lawful and authorized use.
