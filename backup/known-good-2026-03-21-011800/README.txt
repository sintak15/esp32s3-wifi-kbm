Known-good snapshot created: 2026-03-21 01:18:00 (America/Chicago)

Context
- Device flow was previously failing with Windows 'Reinsert your security key'.
- This snapshot preserves the firmware state that produced successful WebAuthN events.

Build target
- FQBN: esp32:esp32:esp32s3:USBMode=default,CDCOnBoot=cdc,UploadMode=cdc

Source state
- Base commit: c0b7cc210e96d96041857d620e7b1db5254ce6de
- Branch: main
- Includes working tree changes in two files.

Artifacts
- esp32s3-wifi-kbm.ino
- fido2_ctap2.ino
- working-tree.patch

SHA256
- esp32s3-wifi-kbm.ino: 5884861C7A705B43B564BC82FA4BA2FAC8151A366B389AEEC57DC95BE887DCC6
- fido2_ctap2.ino: C9D2EA850323FB89D8E27FDE6C7BC34B7C12E6C9CB59F47222AE2881757ABB2F
- working-tree.patch: D77237DA721A7CF59ECD5A95FB555465F17F961AD0DD243AF6369E6BF8BEE14A
