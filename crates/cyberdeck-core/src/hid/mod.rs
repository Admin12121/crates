//! G04 — USB/HID: keymaps, boot-protocol reports, device profiles and the
//! DuckyScript engine.
//!
//! The USB stack itself (esp-hal OTG device driver) lives in the firmware package;
//! everything protocol- and semantics-related is here and covered by host tests.

pub mod ducky;
pub mod engine;

/// HID modifier bits (boot keyboard report byte 0).
pub mod modifier {
    pub const LEFT_CTRL: u8 = 0x01;
    pub const LEFT_SHIFT: u8 = 0x02;
    pub const LEFT_ALT: u8 = 0x04;
    pub const LEFT_GUI: u8 = 0x08;
    pub const RIGHT_CTRL: u8 = 0x10;
    pub const RIGHT_SHIFT: u8 = 0x20;
    pub const RIGHT_ALT: u8 = 0x40;
    pub const RIGHT_GUI: u8 = 0x80;
}

/// HID keyboard usage IDs (page 0x07) used by the engine and the parser.
pub mod key {
    pub const A: u8 = 0x04;
    pub const Z: u8 = 0x1D;
    pub const ONE: u8 = 0x1E;
    pub const ZERO: u8 = 0x27;
    pub const ENTER: u8 = 0x28;
    pub const ESCAPE: u8 = 0x29;
    pub const BACKSPACE: u8 = 0x2A;
    pub const TAB: u8 = 0x2B;
    pub const SPACE: u8 = 0x2C;
    pub const MINUS: u8 = 0x2D;
    pub const EQUALS: u8 = 0x2E;
    pub const LEFT_BRACKET: u8 = 0x2F;
    pub const RIGHT_BRACKET: u8 = 0x30;
    pub const BACKSLASH: u8 = 0x31;
    pub const SEMICOLON: u8 = 0x33;
    pub const APOSTROPHE: u8 = 0x34;
    pub const GRAVE: u8 = 0x35;
    pub const COMMA: u8 = 0x36;
    pub const PERIOD: u8 = 0x37;
    pub const SLASH: u8 = 0x38;
    pub const CAPS_LOCK: u8 = 0x39;
    pub const F1: u8 = 0x3A;
    pub const F12: u8 = 0x45;
    pub const PRINT_SCREEN: u8 = 0x46;
    pub const SCROLL_LOCK: u8 = 0x47;
    pub const PAUSE: u8 = 0x48;
    pub const INSERT: u8 = 0x49;
    pub const HOME: u8 = 0x4A;
    pub const PAGE_UP: u8 = 0x4B;
    pub const DELETE: u8 = 0x4C;
    pub const END: u8 = 0x4D;
    pub const PAGE_DOWN: u8 = 0x4E;
    pub const RIGHT: u8 = 0x4F;
    pub const LEFT: u8 = 0x50;
    pub const DOWN: u8 = 0x51;
    pub const UP: u8 = 0x52;
    pub const NUM_LOCK: u8 = 0x53;
    pub const KP_DIVIDE: u8 = 0x54;
    pub const KP_MULTIPLY: u8 = 0x55;
    pub const KP_MINUS: u8 = 0x56;
    pub const KP_PLUS: u8 = 0x57;
    pub const KP_ENTER: u8 = 0x58;
    pub const KP_1: u8 = 0x59;
    pub const KP_0: u8 = 0x62;
    pub const KP_PERIOD: u8 = 0x63;
    pub const APPLICATION: u8 = 0x65;
    pub const POWER: u8 = 0x66;
    pub const KP_EQUALS: u8 = 0x67;
}

/// Consumer-control usage IDs (page 0x0C) for media keys.
pub mod media {
    pub const PLAY_PAUSE: u16 = 0x00CD;
    pub const STOP: u16 = 0x00B7;
    pub const NEXT_TRACK: u16 = 0x00B5;
    pub const PREV_TRACK: u16 = 0x00B6;
    pub const MUTE: u16 = 0x00E2;
    pub const VOLUME_UP: u16 = 0x00E9;
    pub const VOLUME_DOWN: u16 = 0x00EA;
    pub const BRIGHTNESS_UP: u16 = 0x006F;
    pub const BRIGHTNESS_DOWN: u16 = 0x0070;
}

/// Keyboard layouts the string engine can synthesize.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Layout {
    /// US ANSI.
    Us,
    /// UK (ISO) — identical to US for the printable ASCII subset except `"`/`@`.
    Uk,
    /// German QWERTZ (subset; unsupported characters are reported, never faked).
    De,
}

impl Layout {
    pub const fn label(self) -> &'static str {
        match self {
            Self::Us => "US",
            Self::Uk => "UK",
            Self::De => "DE",
        }
    }

    pub fn from_code(code: &str) -> Option<Self> {
        match code.to_ascii_lowercase().as_str() {
            "us" | "en" | "en-us" => Some(Self::Us),
            "uk" | "gb" | "en-gb" => Some(Self::Uk),
            "de" | "de-de" => Some(Self::De),
            _ => None,
        }
    }

    pub fn all() -> &'static [Layout] {
        &[Self::Us, Self::Uk, Self::De]
    }

    /// Map a printable character to `(usage id, shift required)`.
    pub fn map_char(self, ch: char) -> Option<(u8, bool)> {
        let lower = ch.to_ascii_lowercase();
        if lower.is_ascii_lowercase() {
            // QWERTZ swaps y and z.
            let mapped = if self == Self::De {
                match lower {
                    'y' => 'z',
                    'z' => 'y',
                    other => other,
                }
            } else {
                lower
            };
            let base = key::A + (mapped as u8 - b'a');
            return Some((base, ch.is_ascii_uppercase()));
        }
        if ch.is_ascii_digit() {
            let base = if ch == '0' {
                key::ZERO
            } else {
                key::ONE + (ch as u8 - b'1')
            };
            return Some((base, false));
        }
        let (code, shift) = match ch {
            ' ' => (key::SPACE, false),
            '\n' | '\r' => (key::ENTER, false),
            '\t' => (key::TAB, false),
            '-' => (key::MINUS, false),
            '_' => (key::MINUS, true),
            '=' => (key::EQUALS, false),
            '+' => (key::EQUALS, true),
            '[' => (key::LEFT_BRACKET, false),
            '{' => (key::LEFT_BRACKET, true),
            ']' => (key::RIGHT_BRACKET, false),
            '}' => (key::RIGHT_BRACKET, true),
            '\\' => (key::BACKSLASH, false),
            '|' => (key::BACKSLASH, true),
            ';' => (key::SEMICOLON, false),
            ':' => (key::SEMICOLON, true),
            '\'' => (key::APOSTROPHE, false),
            '"' => (key::APOSTROPHE, true),
            '`' => (key::GRAVE, false),
            '~' => (key::GRAVE, true),
            ',' => (key::COMMA, false),
            '<' => (key::COMMA, true),
            '.' => (key::PERIOD, false),
            '>' => (key::PERIOD, true),
            '/' => (key::SLASH, false),
            '?' => (key::SLASH, true),
            '!' => (key::ONE, true),
            '@' => (key::ONE + 1, true),
            '#' => (key::ONE + 2, true),
            '$' => (key::ONE + 3, true),
            '%' => (key::ONE + 4, true),
            '^' => (key::ONE + 5, true),
            '&' => (key::ONE + 6, true),
            '*' => (key::ONE + 7, true),
            '(' => (key::ONE + 8, true),
            ')' => (key::ONE + 9, true),
            _ => return None,
        };
        // German layout differences for the shifted symbol row.
        if self == Self::De {
            let remapped = match ch {
                '"' => Some((key::ONE + 1, false)),
                '@' => Some((key::ONE + 10, true)),
                'z' => Some((key::A + 24, false)),
                'Z' => Some((key::A + 24, true)),
                _ => None,
            };
            if let Some(value) = remapped {
                return Some(value);
            }
        }
        Some((code, shift))
    }

    /// Reverse lookup used by the parser for named printable keys.
    pub fn keycode_for(self, name: &str) -> Option<u8> {
        let upper = name.to_ascii_uppercase();
        let code = match upper.as_str() {
            "ENTER" | "RETURN" => key::ENTER,
            "ESC" | "ESCAPE" => key::ESCAPE,
            "BACKSPACE" => key::BACKSPACE,
            "TAB" => key::TAB,
            "SPACE" => key::SPACE,
            "CAPSLOCK" | "CAPS_LOCK" => key::CAPS_LOCK,
            "DELETE" | "DEL" => key::DELETE,
            "INSERT" => key::INSERT,
            "HOME" => key::HOME,
            "END" => key::END,
            "PAGEUP" | "PAGE_UP" => key::PAGE_UP,
            "PAGEDOWN" | "PAGE_DOWN" => key::PAGE_DOWN,
            "UP" | "UPARROW" => key::UP,
            "DOWN" | "DOWNARROW" => key::DOWN,
            "LEFT" | "LEFTARROW" => key::LEFT,
            "RIGHT" | "RIGHTARROW" => key::RIGHT,
            "PRINTSCREEN" | "PRINT_SCREEN" => key::PRINT_SCREEN,
            "SCROLLLOCK" => key::SCROLL_LOCK,
            "PAUSE" | "BREAK" => key::PAUSE,
            "NUMLOCK" => key::NUM_LOCK,
            "MENU" | "APP" => key::APPLICATION,
            "POWER" => key::POWER,
            _ => {
                if let Some(rest) = upper.strip_prefix('F') {
                    if let Ok(n) = rest.parse::<u8>() {
                        if (1..=12).contains(&n) {
                            return Some(key::F1 + (n - 1));
                        }
                    }
                }
                return None;
            }
        };
        Some(code)
    }
}

/// 8-byte boot-protocol keyboard report.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct KeyboardReport {
    pub modifiers: u8,
    pub keycodes: [u8; 6],
}

impl KeyboardReport {
    pub const fn new(modifiers: u8, keycode: u8) -> Self {
        let mut keycodes = [0u8; 6];
        keycodes[0] = keycode;
        Self {
            modifiers,
            keycodes,
        }
    }

    /// Serialize for the HID interrupt endpoint.
    pub fn to_bytes(&self) -> [u8; 8] {
        let mut out = [0u8; 8];
        out[0] = self.modifiers;
        out[1..7].copy_from_slice(&self.keycodes);
        out
    }

    pub const fn is_empty(&self) -> bool {
        self.modifiers == 0 && self.keycodes[0] == 0
    }
}

/// 4-byte boot-protocol mouse report.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct MouseReport {
    pub buttons: u8,
    pub dx: i8,
    pub dy: i8,
    pub wheel: i8,
}

impl MouseReport {
    pub const LEFT_BUTTON: u8 = 0x01;
    pub const RIGHT_BUTTON: u8 = 0x02;
    pub const MIDDLE_BUTTON: u8 = 0x04;

    pub fn to_bytes(&self) -> [u8; 4] {
        [self.buttons, self.dx as u8, self.dy as u8, self.wheel as u8]
    }
}

/// Consumer-control report (16-bit usage).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct ConsumerReport {
    pub usage: u16,
}

impl ConsumerReport {
    pub fn to_bytes(&self) -> [u8; 2] {
        self.usage.to_le_bytes()
    }
}

/// USB composite device profile.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UsbProfile {
    pub vendor_id: u16,
    pub product_id: u16,
    pub manufacturer: &'static str,
    pub product: &'static str,
    pub serial: &'static str,
    pub keyboard: bool,
    pub mouse: bool,
    pub consumer: bool,
    pub cdc: bool,
}

impl UsbProfile {
    /// Keyboard + mouse + consumer control, no CDC.
    pub const HID_COMBO: Self = Self {
        vendor_id: 0x1209, // pid.codes open-source VID
        product_id: 0x0001,
        manufacturer: "CyberDeck",
        product: "CyberDeck HID",
        serial: "CD-HID-0001",
        keyboard: true,
        mouse: true,
        consumer: true,
        cdc: false,
    };

    /// Keyboard only: the lowest-risk profile for host compatibility tests.
    pub const KEYBOARD_ONLY: Self = Self {
        product_id: 0x0002,
        product: "CyberDeck Keyboard",
        mouse: false,
        consumer: false,
        ..Self::HID_COMBO
    };

    /// Keyboard + CDC (console/streaming) composite.
    pub const KEYBOARD_CDC: Self = Self {
        product_id: 0x0003,
        product: "CyberDeck Keyboard + Console",
        mouse: false,
        consumer: false,
        cdc: true,
        ..Self::HID_COMBO
    };

    pub fn all() -> &'static [UsbProfile] {
        &[Self::HID_COMBO, Self::KEYBOARD_ONLY, Self::KEYBOARD_CDC]
    }

    pub const fn label(&self) -> &'static str {
        self.product
    }

    /// Number of HID interfaces in the composite device.
    pub const fn interface_count(&self) -> u8 {
        let mut count = 0;
        if self.keyboard {
            count += 1;
        }
        if self.mouse {
            count += 1;
        }
        if self.consumer {
            count += 1;
        }
        if self.cdc {
            count += 2;
        }
        count
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn us_layout_maps_letters_digits_and_symbols() {
        assert_eq!(Layout::Us.map_char('a'), Some((key::A, false)));
        assert_eq!(Layout::Us.map_char('A'), Some((key::A, true)));
        assert_eq!(Layout::Us.map_char('z'), Some((key::Z, false)));
        assert_eq!(Layout::Us.map_char('1'), Some((key::ONE, false)));
        assert_eq!(Layout::Us.map_char('0'), Some((key::ZERO, false)));
        assert_eq!(Layout::Us.map_char('!'), Some((key::ONE, true)));
        assert_eq!(Layout::Us.map_char('?'), Some((key::SLASH, true)));
        assert_eq!(Layout::Us.map_char('\n'), Some((key::ENTER, false)));
        assert_eq!(Layout::Us.map_char('é'), None);
    }

    #[test]
    fn german_layout_swaps_y_and_z() {
        assert_eq!(Layout::De.map_char('y'), Some((key::A + 25, false)));
        assert_eq!(Layout::De.map_char('z'), Some((key::A + 24, false)));
        assert_eq!(Layout::De.map_char('"'), Some((key::ONE + 1, false)));
    }

    #[test]
    fn named_keys_parse() {
        assert_eq!(Layout::Us.keycode_for("ENTER"), Some(key::ENTER));
        assert_eq!(Layout::Us.keycode_for("f7"), Some(key::F1 + 6));
        assert_eq!(Layout::Us.keycode_for("F13"), None);
        assert_eq!(Layout::Us.keycode_for("nonsense"), None);
    }

    #[test]
    fn keyboard_reports_serialize_as_boot_protocol() {
        let report = KeyboardReport::new(modifier::LEFT_CTRL | modifier::LEFT_ALT, key::DELETE);
        let bytes = report.to_bytes();
        assert_eq!(bytes[0], 0x05);
        assert_eq!(bytes[1], key::DELETE);
        assert!(bytes[2..].iter().all(|b| *b == 0));
        assert!(!report.is_empty());
        assert!(KeyboardReport::default().is_empty());
    }

    #[test]
    fn mouse_and_consumer_reports() {
        let mouse = MouseReport {
            buttons: MouseReport::LEFT_BUTTON,
            dx: 5,
            dy: -3,
            wheel: 1,
        };
        assert_eq!(mouse.to_bytes(), [0x01, 5, 0xFD, 1]);
        let consumer = ConsumerReport { usage: media::MUTE };
        assert_eq!(consumer.to_bytes(), [0xE2, 0x00]);
    }

    #[test]
    fn profiles_report_interface_counts() {
        assert_eq!(UsbProfile::HID_COMBO.interface_count(), 3);
        assert_eq!(UsbProfile::KEYBOARD_ONLY.interface_count(), 1);
        assert_eq!(UsbProfile::KEYBOARD_CDC.interface_count(), 3);
        assert_eq!(UsbProfile::all().len(), 3);
    }

    #[test]
    fn layout_codes_round_trip() {
        for layout in Layout::all() {
            assert_eq!(Layout::from_code(layout.label()), Some(*layout));
        }
        assert_eq!(Layout::from_code("nope"), None);
    }
}
