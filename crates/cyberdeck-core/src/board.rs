//! Declarative board profiles.
//!
//! A profile describes *possible* support (which radios/buses exist and on which
//! pins). It is never evidence that an optional module is physically attached —
//! that is the job of [`crate::hardware::PeripheralRegistry`].
//!
//! The final CyberDeck carrier board has not been selected (master plan §3), so
//! the CORE profile below is the reference wiring used by the firmware and the
//! hardware-acceptance checklists. Change pins here, not in drivers.

use crate::hardware::DeviceClass;

/// Display controller families the firmware drives natively.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DisplayController {
    /// 240x320/240x240 IPS, the common CyberDeck/Deck-Mini panel.
    St7789,
    /// 240x320 TFT used by several handheld reference builds.
    Ili9341,
}

impl DisplayController {
    pub const fn label(self) -> &'static str {
        match self {
            Self::St7789 => "ST7789",
            Self::Ili9341 => "ILI9341",
        }
    }
}

/// Panel geometry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DisplayGeometry {
    pub width: u16,
    pub height: u16,
}

/// SPI display wiring.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DisplayPins {
    pub sck: u8,
    pub mosi: u8,
    pub cs: u8,
    pub dc: u8,
    pub rst: u8,
    pub backlight: Option<u8>,
}

/// Five-way navigation wiring (active-low buttons to GND).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct InputPins {
    pub up: u8,
    pub down: u8,
    pub select: u8,
    pub back: u8,
    pub home: u8,
}

/// A generic SPI peripheral share of a bus.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SpiPins {
    pub sck: u8,
    pub mosi: u8,
    pub miso: u8,
    pub cs: u8,
}

/// nRF24L01 wiring (shares the SPI bus declared by the board profile).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Nrf24Pins {
    pub sck: u8,
    pub mosi: u8,
    pub miso: u8,
    pub ce: u8,
    pub csn: u8,
}

/// How the two 2.4 GHz radios may be used together.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CoexPolicy {
    /// Wi-Fi and BLE time-slice; long captures should avoid concurrent BLE scans.
    TimeSlicedWifiBle,
    /// nRF24 shares the 2.4 GHz band with Wi-Fi/BLE: never run both at once.
    ExclusiveNrf24,
}

/// Panel mounting orientation; the driver derives MADCTL from this.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DisplayOrientation {
    Rotate0,
    Rotate90,
    Rotate180,
    Rotate270,
}

impl DisplayOrientation {
    /// MADCTL bits: MV = 0x20, MX = 0x40, MY = 0x80.
    pub const fn madctl(self) -> u8 {
        match self {
            Self::Rotate0 => 0x00,
            Self::Rotate90 => 0x60,
            Self::Rotate180 => 0xC0,
            Self::Rotate270 => 0xA0,
        }
    }

    pub const fn label(self) -> &'static str {
        match self {
            Self::Rotate0 => "0°",
            Self::Rotate90 => "90°",
            Self::Rotate180 => "180°",
            Self::Rotate270 => "270°",
        }
    }
}

/// One board/profile.
#[derive(Debug, Clone, Copy)]
pub struct BoardProfile {
    pub id: BoardId,
    pub name: &'static str,
    pub mcu: &'static str,
    pub display_controller: DisplayController,
    pub display_geometry: DisplayGeometry,
    /// How the panel is physically mounted.
    pub display_orientation: DisplayOrientation,
    /// Enable when the panel needs colour inversion (most ST7789 modules do;
    /// the ILI9341 used by the simulator must stay off).
    pub display_inverted: bool,
    pub display: DisplayPins,
    pub input: InputPins,
    pub sd: SpiPins,
    pub nrf24: Option<Nrf24Pins>,
    pub battery: Option<BatteryPins>,
    /// Classes this profile can support at all.
    pub supported: &'static [DeviceClass],
    /// Classes that are enhancements only.
    pub optional: &'static [DeviceClass],
    pub coex: CoexPolicy,
}

/// Battery sense wiring: the ADC pin plus the resistor-divider ratio.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BatteryPins {
    /// GPIO number fed by the divider.
    pub pin: u8,
    /// Pack voltage divided by pin voltage, e.g. `2` for a 1:2 divider.
    pub divider: u16,
}

/// Stable identifiers for build-time board selection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BoardId {
    /// ESP32-S3 DevKitC-1 (WROOM-1, 16 MB flash, octal PSRAM).
    CoreS3DevKit,
    /// CORE plus nRF24L01 and GPS (FIELD profile).
    FieldS3,
}

impl BoardId {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::CoreS3DevKit => "core-s3-devkit",
            Self::FieldS3 => "field-s3",
        }
    }
}

/// CORE: Wi-Fi/BLE/USB/HID plus display, input, SD and battery monitoring.
///
/// GPIO0/3/45/46 are strapping pins and GPIO27..37 are reserved by the octal PSRAM
/// module, so the map below stays clear of both.
pub const CORE_PROFILE: BoardProfile = BoardProfile {
    id: BoardId::CoreS3DevKit,
    name: "CyberDeck CORE (ESP32-S3 DevKitC-1)",
    mcu: "ESP32-S3 WROOM-1 (octal PSRAM)",
    display_controller: DisplayController::Ili9341,
    display_geometry: DisplayGeometry {
        width: 240,
        height: 320,
    },
    display_orientation: DisplayOrientation::Rotate180,
    display_inverted: false,
    display: DisplayPins {
        sck: 12,
        mosi: 11,
        cs: 10,
        dc: 9,
        rst: 14,
        backlight: Some(13),
    },
    input: InputPins {
        up: 4,
        down: 5,
        select: 6,
        back: 7,
        home: 15,
    },
    sd: SpiPins {
        sck: 39,
        mosi: 40,
        miso: 41,
        cs: 42,
    },
    nrf24: None,
    battery: Some(BatteryPins { pin: 8, divider: 2 }),
    supported: &[
        DeviceClass::WifiRadio,
        DeviceClass::BleRadio,
        DeviceClass::UsbDevice,
        DeviceClass::SdCard,
        DeviceClass::Display,
        DeviceClass::Input,
        DeviceClass::BatteryAdc,
    ],
    optional: &[DeviceClass::Nrf24],
    coex: CoexPolicy::TimeSlicedWifiBle,
};

/// FIELD: CORE plus one nRF24L01 module on the shared SPI bus.
pub const FIELD_PROFILE: BoardProfile = BoardProfile {
    id: BoardId::FieldS3,
    name: "CyberDeck FIELD (ESP32-S3 + nRF24L01)",
    mcu: "ESP32-S3 WROOM-1 (octal PSRAM)",
    nrf24: Some(Nrf24Pins {
        sck: 39,
        mosi: 40,
        miso: 41,
        ce: 2,
        csn: 1,
    }),
    supported: &[
        DeviceClass::WifiRadio,
        DeviceClass::BleRadio,
        DeviceClass::UsbDevice,
        DeviceClass::SdCard,
        DeviceClass::Display,
        DeviceClass::Input,
        DeviceClass::BatteryAdc,
        DeviceClass::Nrf24,
    ],
    optional: &[DeviceClass::Gps],
    coex: CoexPolicy::ExclusiveNrf24,
    ..CORE_PROFILE
};

/// All profiles known to this build.
pub const PROFILES: &[BoardProfile] = &[CORE_PROFILE, FIELD_PROFILE];

/// Look up a profile by id.
pub fn profile(id: BoardId) -> &'static BoardProfile {
    PROFILES
        .iter()
        .find(|p| p.id == id)
        .unwrap_or(&CORE_PROFILE)
}

/// Default profile for callers that have no build-time selection (host tests).
/// The firmware picks FIELD/CORE from the `CYBERDECK_BOARD` build variable.
pub fn active_profile() -> &'static BoardProfile {
    &CORE_PROFILE
}

/// The plan-mandated entry point: capabilities *possible* for a board profile.
pub fn capabilities_for_board(id: BoardId) -> CapabilitySet {
    let profile = PROFILES
        .iter()
        .find(|p| p.id == id)
        .unwrap_or(&CORE_PROFILE);
    CapabilitySet {
        supported: profile.supported,
    }
}

/// Set of device classes a profile can support.
#[derive(Debug, Clone, Copy)]
pub struct CapabilitySet {
    supported: &'static [DeviceClass],
}

impl CapabilitySet {
    pub fn supports(&self, class: DeviceClass) -> bool {
        self.supported.contains(&class)
    }

    pub fn iter(&self) -> impl Iterator<Item = DeviceClass> + '_ {
        self.supported.iter().copied()
    }
}

impl BoardProfile {
    pub fn supports(&self, class: DeviceClass) -> bool {
        self.supported.contains(&class)
    }

    /// Pin label used by the wiring documentation and boot diagnostics.
    pub fn wiring_summary(&self) -> alloc::string::String {
        use alloc::format;
        let mut out = format!(
            "{} | {} {}x{} SPI sck{} mosi{} cs{} dc{} rst{}",
            self.name,
            self.display_controller.label(),
            self.display_geometry.width,
            self.display_geometry.height,
            self.display.sck,
            self.display.mosi,
            self.display.cs,
            self.display.dc,
            self.display.rst
        );
        if let Some(nrf) = self.nrf24 {
            out.push_str(&format!(
                " | nRF24 ce{} csn{} sck{} mosi{} miso{}",
                nrf.ce, nrf.csn, nrf.sck, nrf.mosi, nrf.miso
            ));
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn orientation_madctl_bits() {
        use DisplayOrientation::*;
        assert_eq!(Rotate0.madctl(), 0x00);
        assert_eq!(Rotate90.madctl(), 0x60);
        assert_eq!(Rotate180.madctl(), 0xC0);
        assert_eq!(Rotate270.madctl(), 0xA0);
    }

    #[test]
    fn core_profile_supports_deck_groups_but_no_nrf24() {
        let caps = capabilities_for_board(BoardId::CoreS3DevKit);
        assert!(caps.supports(DeviceClass::WifiRadio));
        assert!(caps.supports(DeviceClass::BleRadio));
        assert!(caps.supports(DeviceClass::UsbDevice));
        assert!(!caps.supports(DeviceClass::Nrf24));
    }

    #[test]
    fn field_profile_adds_nrf24_pins() {
        let caps = capabilities_for_board(BoardId::FieldS3);
        assert!(caps.supports(DeviceClass::Nrf24));
        let nrf = FIELD_PROFILE.nrf24.expect("field profile has nRF24");
        // nRF24 shares the SD SPI bus so both fit one SPI peripheral instance.
        assert_eq!(nrf.sck, FIELD_PROFILE.sd.sck);
        assert_eq!(nrf.mosi, FIELD_PROFILE.sd.mosi);
        assert_eq!(nrf.miso, FIELD_PROFILE.sd.miso);
    }

    #[test]
    fn pins_avoid_strapping_and_psram_ranges() {
        for profile in PROFILES {
            let mut pins = alloc::vec::Vec::new();
            pins.extend([
                profile.display.sck,
                profile.display.mosi,
                profile.display.cs,
                profile.display.dc,
                profile.display.rst,
                profile.input.up,
                profile.input.down,
                profile.input.select,
                profile.input.back,
                profile.input.home,
                profile.sd.sck,
                profile.sd.mosi,
                profile.sd.miso,
                profile.sd.cs,
            ]);
            if let Some(nrf) = profile.nrf24 {
                pins.extend([nrf.ce, nrf.csn]);
            }
            if let Some(battery) = profile.battery {
                pins.push(battery.pin);
                assert!(battery.divider >= 1, "divider ratio must be at least 1");
            }
            for pin in pins {
                assert!(!matches!(pin, 0 | 3 | 45 | 46), "strapping pin {pin}");
                assert!(!(27..=37).contains(&pin), "psram pin {pin}");
            }
        }
    }
}
