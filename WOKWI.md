# CyberDeck — Wokwi ESP32-S3 Simulator

## Purpose

This simulation exercises the **real Rust firmware's boot, GPIO navigation,
ILI9341 display adapter, and simulated SPI microSD** on an ESP32-S3. It is
a development smoke test, **not proof of field hardware functionality**.

The physical-board firmware keeps the ST7789 controller. The Wokwi build
selects ILI9341, because Wokwi currently provides ILI9341 rather than ST7789.
Do not flash the Wokwi build to the physical ST7789 configuration.

## Build and run

From the repository root in a Unix shell or the configured Espressif Rust Docker
container:

```sh
bash tools/build-wokwi.sh
```

The script builds to
`target/wokwi/xtensa-esp32s3-none-elf/debug/cyberdeck`, as configured by
`wokwi.toml`. In VS Code, select **Wokwi: Start Simulator** after the build.
Rebuild with the script after firmware changes. Your existing regular
`cargo build` remains independent and targets the physical ST7789 board.

On the Windows machine hosting Web Bridge, run this inside the configured
ESP32-S3 Docker shell to generate the ELF in the shared project folder:

```sh
source /home/esp/export-esp.sh
bash tools/build-wokwi.sh
```

If the simulator reports that firmware is missing, check that the ELF above
exists in the project folder visible to VS Code. Wokwi does not compile Rust.

## Virtual wiring

| Component | ESP32-S3 GPIO |
| --- | --- |
| ILI9341 SCK | 12 |
| ILI9341 MOSI | 11 |
| ILI9341 CS | 10 |
| ILI9341 D/C | 9 |
| Display reset / backlight | 14 / 13 (not modeled by Wokwi ILI9341) |
| UP / DOWN / SELECT / BACK / HOME | 4 / 5 / 6 / 7 / 15 |
| microSD SCK / DI / DO / CS | 39 / 40 / 41 / 42 |

Buttons are active-low to GND with internal pull-ups. The Wokwi buttons
have these shortcuts when the diagram is focused: **ArrowUp, ArrowDown,
Enter, Escape, H**. The simulated card uses Wokwi's FAT filesystem.

## What is not simulated

- **BLE / Bluetooth:** Wokwi documents no Bluetooth simulation. The firmware
  marks BLE unavailable in simulator builds; it does not fake scan results.
- **USB HID:** Wokwi's ESP32-S3 USB simulation is primarily CDC serial, not an
  end-to-end HID keyboard/mouse test. The firmware marks USB HID unavailable.
- **nRF24, CC1101, GPS, NFC, IR:** not included in this CORE simulation.
- **Wi-Fi:** Wokwi has Wi-Fi support, but the CyberDeck `esp-radio` integration,
  monitor mode, and raw-frame injection must be independently tested; a booting
  simulator does not verify these operations.
- **SD data retention:** Wokwi manages a virtual card, not a physical card.
  Validate real-card compatibility and power-loss recovery separately.

## Validation checklist

- [ ] Build script creates a nonempty simulator ELF.
- [ ] Wokwi diagram displays ESP32-S3, ILI9341, five buttons, and microSD.
- [ ] Simulator boots to the CyberDeck home menu.
- [ ] UP and DOWN move selection; SELECT opens a group or Diagnostics.
- [ ] BACK and HOME return to the home menu without hanging.
- [ ] Diagnostics lists simulated hardware accurately (BLE and HID unavailable).
- [ ] SD mounts, writes, and recovers in Wokwi where supported.
- [ ] Rebuild real ST7789 profile and verify it still compiles.
- [ ] Flash physical board and run hardware acceptance separately.

The simulator visual checks above must remain **unchecked** until they have
actually been observed in Wokwi. There is no simulated success claim without
Wokwi CLI or VS Code execution evidence.

References:
- https://docs.wokwi.com/guides/esp32
- https://docs.wokwi.com/parts/wokwi-ili9341
- https://docs.wokwi.com/parts/wokwi-pushbutton
- https://docs.wokwi.com/parts/wokwi-microsd-card
- https://docs.wokwi.com/vscode/project-config
