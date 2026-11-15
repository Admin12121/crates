//! DuckyScript parser (Hak5 DuckyScript 1.0 compatible subset + mouse extensions).
//!
//! Behaviour matches the reference implementations' script runners (Bruce
//! `ducky_typer.cpp`, Evil-M5Project `BadUsbScript`): line-oriented commands,
//! `REM` comments, `DEFAULT_DELAY`, modifier-prefixed chords, `STRING`/`STRINGLN`,
//! `KEYCODE`, `REPEAT`, media keys and mouse actions.
//!
//! Parsing is fully fallible and bounded: a script can never allocate unbounded
//! memory or abort the firmware, and every error carries its line number so the
//! UI can point at the offending line.

use alloc::string::String;
use alloc::vec::Vec;

use super::key;
use super::modifier;

/// Maximum commands accepted from one script.
pub const MAX_COMMANDS: usize = 2048;
/// Maximum characters in a `STRING` line.
pub const MAX_STRING_LEN: usize = 256;
/// Maximum script size accepted from storage.
pub const MAX_SCRIPT_BYTES: usize = 32 * 1024;

/// A parsed script command.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Command {
    Delay(u32),
    /// Text to type; `enter` appends a newline after the text.
    Text { text: Vec<u8>, enter: bool },
    /// Press and release a key with modifiers.
    Key { modifiers: u8, keycode: u8 },
    /// Hold a key down (released by `HOLD` release or at script end).
    KeyDown { modifiers: u8, keycode: u8 },
    KeyUp { modifiers: u8, keycode: u8 },
    /// Consumer-control usage.
    Media(u16),
    MouseMove { dx: i8, dy: i8 },
    MouseClick(u8),
    MouseScroll(i8),
    /// Repeat the previous command `n` times.
    Repeat(u16),
    /// Change the default delay between keys.
    SetDefaultDelay(u16),
}

impl Command {
    /// Short label for the execution log/UI.
    pub fn label(&self) -> &'static str {
        match self {
            Self::Delay(_) => "DELAY",
            Self::Text { .. } => "STRING",
            Self::Key { .. } => "KEY",
            Self::KeyDown { .. } => "HOLD",
            Self::KeyUp { .. } => "RELEASE",
            Self::Media(_) => "MEDIA",
            Self::MouseMove { .. } => "MOUSE_MOVE",
            Self::MouseClick(_) => "MOUSE_CLICK",
            Self::MouseScroll(_) => "MOUSE_SCROLL",
            Self::Repeat(_) => "REPEAT",
            Self::SetDefaultDelay(_) => "DEFAULT_DELAY",
        }
    }

    /// Whether `REPEAT` may follow this command.
    pub fn is_repeatable(&self) -> bool {
        !matches!(self, Self::Repeat(_) | Self::SetDefaultDelay(_))
    }
}

/// Parse failure with the offending line.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParseError {
    pub line: usize,
    pub message: &'static str,
}

impl ParseError {
    fn new(line: usize, message: &'static str) -> Self {
        Self { line, message }
    }

    /// Operator-facing description.
    pub fn describe(&self) -> String {
        alloc::format!("line {}: {}", self.line, self.message)
    }
}

/// A validated, execution-ready script.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Script {
    pub name: String,
    pub commands: Vec<Command>,
    pub default_delay_ms: u16,
    pub key_delay_ms: u16,
    /// Commands that could not be represented (kept honest in the UI).
    pub warnings: u8,
}

impl Script {
    pub fn len(&self) -> usize {
        self.commands.len()
    }

    pub fn is_empty(&self) -> bool {
        self.commands.is_empty()
    }

    /// Estimated typing time, used to reject runaway scripts in the UI.
    pub fn estimated_ms(&self) -> u64 {
        let mut total = 0u64;
        for command in &self.commands {
            total += match command {
                Command::Delay(ms) => u64::from(*ms),
                Command::Text { text, .. } => {
                    text.len() as u64 * u64::from(self.key_delay_ms)
                }
                Command::Repeat(times) => u64::from(*times) * 20,
                _ => u64::from(self.key_delay_ms),
            };
        }
        total
    }
}

/// Parse a DuckyScript source.
pub fn parse(name: &str, source: &str) -> Result<Script, ParseError> {
    if source.len() > MAX_SCRIPT_BYTES {
        return Err(ParseError::new(0, "script is larger than 32 KiB"));
    }
    let mut commands: Vec<Command> = Vec::new();
    let mut default_delay_ms: u16 = 0;
    let mut warnings = 0u8;

    for (index, raw_line) in source.lines().enumerate() {
        let line_no = index + 1;
        let line = raw_line.trim();
        if line.is_empty() || line.starts_with("REM") || line.starts_with("//") {
            continue;
        }
        if commands.len() >= MAX_COMMANDS {
            return Err(ParseError::new(line_no, "script has more than 2048 commands"));
        }

        let (head, tail) = split_command(line);
        let upper = head.to_ascii_uppercase();

        let command = match upper.as_str() {
            "DELAY" => {
                let ms = parse_u32(tail).ok_or(ParseError::new(line_no, "DELAY needs milliseconds"))?;
                Command::Delay(ms.min(600_000))
            }
            "DEFAULT_DELAY" | "DEFAULTDELAY" => {
                let ms =
                    parse_u32(tail).ok_or(ParseError::new(line_no, "DEFAULT_DELAY needs milliseconds"))?;
                default_delay_ms = ms.min(10_000) as u16;
                Command::SetDefaultDelay(default_delay_ms)
            }
            "STRING" | "STRINGLN" => {
                // Preserve everything after the command word, including spaces.
                // Truncation is character-aware so multi-byte input can never split
                // a UTF-8 sequence and panic on the device.
                if tail.chars().count() > MAX_STRING_LEN {
                    warnings = warnings.saturating_add(1);
                }
                let text: String = tail.chars().take(MAX_STRING_LEN).collect();
                if text.bytes().any(|b| b >= 0x80) {
                    // Non-ASCII is kept but the engine reports it as unsupported
                    // for the selected layout instead of inventing a keycode.
                    warnings = warnings.saturating_add(0);
                }
                Command::Text {
                    text: text.into_bytes(),
                    enter: upper == "STRINGLN",
                }
            }
            "REPEAT" => {
                let times = parse_u32(tail).ok_or(ParseError::new(line_no, "REPEAT needs a count"))?;
                if times == 0 {
                    return Err(ParseError::new(line_no, "REPEAT count must be at least 1"));
                }
                let previous_ok = commands.last().map(Command::is_repeatable).unwrap_or(false);
                if !previous_ok {
                    return Err(ParseError::new(line_no, "REPEAT has nothing to repeat"));
                }
                commands.push(Command::Repeat(times.min(1000) as u16));
                continue;
            }
            "KEYCODE" => {
                let code = parse_keycode(tail).ok_or(ParseError::new(line_no, "KEYCODE needs a usage id"))?;
                Command::Key {
                    modifiers: 0,
                    keycode: code,
                }
            }
            "HOLD" if !tail.is_empty() => {
                let (mods, code) = parse_chord_opt(tail, line_no, true)?;
                Command::KeyDown {
                    modifiers: mods,
                    keycode: code,
                }
            }
            "RELEASE" if !tail.is_empty() => {
                let (mods, code) = parse_chord_opt(tail, line_no, true)?;
                Command::KeyUp {
                    modifiers: mods,
                    keycode: code,
                }
            }
            "MOUSE_MOVE" => {
                let mut parts = tail.split_whitespace();
                let dx = parts
                    .next()
                    .and_then(|v| v.parse::<i16>().ok())
                    .ok_or(ParseError::new(line_no, "MOUSE_MOVE needs dx"))?;
                let dy = parts
                    .next()
                    .and_then(|v| v.parse::<i16>().ok())
                    .ok_or(ParseError::new(line_no, "MOUSE_MOVE needs dy"))?;
                Command::MouseMove {
                    dx: dx.clamp(-127, 127) as i8,
                    dy: dy.clamp(-127, 127) as i8,
                }
            }
            "MOUSE_CLICK" => {
                let button = match tail.trim().to_ascii_uppercase().as_str() {
                    "" | "LEFT" => super::MouseReport::LEFT_BUTTON,
                    "RIGHT" => super::MouseReport::RIGHT_BUTTON,
                    "MIDDLE" => super::MouseReport::MIDDLE_BUTTON,
                    _ => return Err(ParseError::new(line_no, "MOUSE_CLICK expects left/right/middle")),
                };
                Command::MouseClick(button)
            }
            "MOUSE_SCROLL" => {
                let delta = tail
                    .trim()
                    .parse::<i16>()
                    .map_err(|_| ParseError::new(line_no, "MOUSE_SCROLL needs a delta"))?;
                Command::MouseScroll(delta.clamp(-127, 127) as i8)
            }
            "PLAY" | "PAUSE" | "PLAYPAUSE" => Command::Media(super::media::PLAY_PAUSE),
            "STOP" => Command::Media(super::media::STOP),
            "NEXT" | "NEXTTRACK" => Command::Media(super::media::NEXT_TRACK),
            "PREVIOUS" | "PREV" => Command::Media(super::media::PREV_TRACK),
            "MUTE" => Command::Media(super::media::MUTE),
            "VOLUMEUP" | "VOLUP" => Command::Media(super::media::VOLUME_UP),
            "VOLUMEDOWN" | "VOLDOWN" => Command::Media(super::media::VOLUME_DOWN),
            _ => {
                // Chords such as `CTRL ALT DELETE`, `GUI r`, `SHIFT-TAB`.
                let (mods, code) = parse_chord(line, line_no)?;
                Command::Key {
                    modifiers: mods,
                    keycode: code,
                }
            }
        };
        commands.push(command);
    }

    if commands.is_empty() {
        return Err(ParseError::new(0, "script contains no executable commands"));
    }

    Ok(Script {
        name: String::from(name),
        commands,
        default_delay_ms,
        key_delay_ms: 12.max(default_delay_ms / 2),
        warnings,
    })
}

/// Split `COMMAND rest`. Exactly one separating space is removed so that
/// `STRING   x` types the two leading spaces, as DuckyScript specifies.
fn split_command(line: &str) -> (&str, &str) {
    match line.find(char::is_whitespace) {
        Some(idx) => {
            let rest = &line[idx..];
            (&line[..idx], rest.strip_prefix(' ').unwrap_or(rest))
        }
        None => (line, ""),
    }
}

fn parse_u32(text: &str) -> Option<u32> {
    let text = text.trim();
    if let Some(hex) = text.strip_prefix("0x").or_else(|| text.strip_prefix("0X")) {
        u32::from_str_radix(hex, 16).ok()
    } else {
        text.parse::<u32>().ok()
    }
}

fn parse_keycode(text: &str) -> Option<u8> {
    let text = text.trim();
    let value = parse_u32(text)?;
    if value <= u32::from(u8::MAX) {
        Some(value as u8)
    } else {
        None
    }
}

fn modifier_bit(name: &str) -> Option<u8> {
    match name.to_ascii_uppercase().as_str() {
        "CTRL" | "CONTROL" => Some(modifier::LEFT_CTRL),
        "SHIFT" => Some(modifier::LEFT_SHIFT),
        "ALT" | "OPTION" => Some(modifier::LEFT_ALT),
        "GUI" | "WINDOWS" | "WIN" | "COMMAND" | "META" => Some(modifier::LEFT_GUI),
        "RCTRL" => Some(modifier::RIGHT_CTRL),
        "RSHIFT" => Some(modifier::RIGHT_SHIFT),
        "RALT" => Some(modifier::RIGHT_ALT),
        "RGUI" => Some(modifier::RIGHT_GUI),
        _ => None,
    }
}

/// Parse a modifier chord, e.g. `CTRL ALT DELETE`, `GUI r`, `CTRL-SHIFT ESC`.
fn parse_chord(text: &str, line_no: usize) -> Result<(u8, u8), ParseError> {
    parse_chord_opt(text, line_no, false)
}

/// Like [`parse_chord`], optionally accepting a modifier with no key (`HOLD SHIFT`).
fn parse_chord_opt(
    text: &str,
    line_no: usize,
    allow_modifier_only: bool,
) -> Result<(u8, u8), ParseError> {
    let mut modifiers = 0u8;
    let mut keycode: Option<u8> = None;
    let normalized = text.replace('-', " ");
    for token in normalized.split_whitespace() {
        if let Some(bit) = modifier_bit(token) {
            if keycode.is_some() {
                return Err(ParseError::new(
                    line_no,
                    "modifier must come before the key (e.g. `CTRL ALT DELETE`)",
                ));
            }
            modifiers |= bit;
            continue;
        }
        if keycode.is_some() {
            return Err(ParseError::new(line_no, "only one key per command"));
        }
        let upper = token.to_ascii_uppercase();
        keycode = Some(match upper.as_str() {
            "ENTER" | "RETURN" => key::ENTER,
            "ESC" | "ESCAPE" => key::ESCAPE,
            "BACKSPACE" => key::BACKSPACE,
            "TAB" => key::TAB,
            "SPACE" => key::SPACE,
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
            "CAPSLOCK" => key::CAPS_LOCK,
            "PRINTSCREEN" => key::PRINT_SCREEN,
            "MENU" | "APP" => key::APPLICATION,
            _ => {
                if let Some(rest) = upper.strip_prefix('F') {
                    if let Ok(n) = rest.parse::<u8>() {
                        if (1..=12).contains(&n) {
                            key::F1 + (n - 1)
                        } else {
                            return Err(ParseError::new(line_no, "function keys are F1..F12"));
                        }
                    } else {
                        return Err(ParseError::new(line_no, "unknown key name"));
                    }
                } else if token.chars().count() == 1 {
                    // Chords name a key, not a character: `CTRL A` presses the A key
                    // without Shift, so letters are mapped lower-case.
                    let ch = token.chars().next().unwrap_or(' ');
                    let ch = ch.to_ascii_lowercase();
                    let (code, shift) = super::Layout::Us
                        .map_char(ch)
                        .ok_or(ParseError::new(line_no, "key is not representable on a US layout"))?;
                    if shift {
                        modifiers |= modifier::LEFT_SHIFT;
                    }
                    code
                } else {
                    return Err(ParseError::new(line_no, "unknown key name"));
                }
            }
        });
    }
    let keycode = match keycode {
        Some(code) => code,
        None if allow_modifier_only && modifiers != 0 => 0,
        None => return Err(ParseError::new(line_no, "command needs a key")),
    };
    Ok((modifiers, keycode))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_a_realistic_script() {
        let source = "\
REM CyberDeck demo
DEFAULT_DELAY 40
DELAY 500
GUI r
DELAY 300
STRING notepad
ENTER
DELAY 700
STRING Hello from CyberDeck
ENTER
CTRL-SHIFT ESC
";
        let script = parse("demo.txt", source).unwrap();
        assert_eq!(script.name, "demo.txt");
        assert_eq!(script.default_delay_ms, 40);
        assert_eq!(script.commands.len(), 10);
        assert!(matches!(script.commands[0], Command::SetDefaultDelay(40)));
        assert_eq!(
            script.commands[2],
            Command::Key {
                modifiers: modifier::LEFT_GUI,
                keycode: key::A + 17 // 'r'
            }
        );
        assert_eq!(
            script.commands[4],
            Command::Text {
                text: b"notepad".to_vec(),
                enter: false
            }
        );
        assert_eq!(
            script.commands[5],
            Command::Key {
                modifiers: 0,
                keycode: key::ENTER
            }
        );
        assert_eq!(
            script.commands[9],
            Command::Key {
                modifiers: modifier::LEFT_CTRL | modifier::LEFT_SHIFT,
                keycode: key::ESCAPE
            }
        );
        assert!(script.estimated_ms() > 1_500);
    }

    #[test]
    fn string_preserves_spaces_and_supports_ln() {
        let script = parse("s", "STRING   two spaces\nSTRINGLN end").unwrap();
        match &script.commands[0] {
            Command::Text { text, enter } => {
                assert_eq!(text, b"  two spaces");
                assert!(!enter);
            }
            other => panic!("unexpected {other:?}"),
        }
        match &script.commands[1] {
            Command::Text { text, enter } => {
                assert_eq!(text, b"end");
                assert!(enter);
            }
            other => panic!("unexpected {other:?}"),
        }
    }

    #[test]
    fn rejects_invalid_scripts_with_line_numbers() {
        let err = parse("bad", "DELAY\n").unwrap_err();
        assert_eq!(err.line, 1);
        assert_eq!(err.describe(), "line 1: DELAY needs milliseconds");

        let err = parse("bad", "STRING hi\nREPEAT 2\nREPEAT 3\n").unwrap_err();
        assert_eq!(err.line, 3);

        let err = parse("bad", "REM only comments\n").unwrap_err();
        assert_eq!(err.message, "script contains no executable commands");

        let err = parse("bad", "bogus_key_name\n").unwrap_err();
        assert!(err.message.contains("unknown key"));

        let err = parse("bad", "CTRL A B\n").unwrap_err();
        assert!(err.message.contains("only one key"));
        // Repeated modifiers collapse into one bitmask (CTRL CTRL A == CTRL A).
        let script = parse("ok", "CTRL CTRL A").unwrap();
        assert_eq!(
            script.commands[0],
            Command::Key {
                modifiers: modifier::LEFT_CTRL,
                keycode: key::A
            }
        );
    }

    #[test]
    fn repeat_expands_at_execution_and_validates_predecessor() {
        let script = parse("r", "STRING hi\nREPEAT 3\nDELAY 100\nREPEAT 2").unwrap();
        assert_eq!(script.commands[1], Command::Repeat(3));
        assert_eq!(script.commands[3], Command::Repeat(2));
        let err = parse("r", "REPEAT 2").unwrap_err();
        assert_eq!(err.line, 1);
    }

    #[test]
    fn media_and_mouse_commands() {
        let script = parse(
            "m",
            "MUTE\nVOLUMEUP\nNEXT\nMOUSE_MOVE 10 -20\nMOUSE_CLICK right\nMOUSE_SCROLL 2",
        )
        .unwrap();
        assert_eq!(script.commands[0], Command::Media(super::super::media::MUTE));
        assert_eq!(
            script.commands[3],
            Command::MouseMove { dx: 10, dy: -20 }
        );
        assert_eq!(
            script.commands[4],
            Command::MouseClick(super::super::MouseReport::RIGHT_BUTTON)
        );
        assert_eq!(script.commands[5], Command::MouseScroll(2));
    }

    #[test]
    fn keycode_accepts_decimal_and_hex() {
        let script = parse("k", "KEYCODE 0x28\nKEYCODE 41").unwrap();
        assert_eq!(
            script.commands[0],
            Command::Key {
                modifiers: 0,
                keycode: key::ENTER
            }
        );
        assert_eq!(
            script.commands[1],
            Command::Key {
                modifiers: 0,
                keycode: 41
            }
        );
    }

    #[test]
    fn clamp_ranges_protect_the_host() {
        let script = parse("c", "MOUSE_MOVE 9999 -9999\nMOUSE_SCROLL 500").unwrap();
        assert_eq!(
            script.commands[0],
            Command::MouseMove { dx: 127, dy: -127 }
        );
        assert_eq!(script.commands[1], Command::MouseScroll(127));
        let script = parse("d", "DELAY 999999999").unwrap();
        assert_eq!(script.commands[0], Command::Delay(600_000));
    }

    #[test]
    fn hold_and_release_build_key_state_commands() {
        let script = parse("h", "HOLD SHIFT\nSTRING x\nRELEASE SHIFT").unwrap();
        assert_eq!(
            script.commands[0],
            Command::KeyDown {
                modifiers: modifier::LEFT_SHIFT,
                keycode: 0
            }
        );
        assert_eq!(
            script.commands[2],
            Command::KeyUp {
                modifiers: modifier::LEFT_SHIFT,
                keycode: 0
            }
        );
        // A modifier-only chord is rejected outside HOLD/RELEASE.
        assert!(parse("h", "SHIFT").is_err());
    }

    #[test]
    fn oversize_string_is_truncated_with_warning() {
        let long = "A".repeat(400);
        let script = parse("w", &alloc::format!("STRING {long}")).unwrap();
        match &script.commands[0] {
            Command::Text { text, .. } => assert_eq!(text.len(), MAX_STRING_LEN),
            other => panic!("unexpected {other:?}"),
        }
        assert!(script.warnings > 0);
    }
}
