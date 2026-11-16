//! DuckyScript execution engine.
//!
//! Turns a parsed [`Script`] into timed HID reports. The engine is a pure state
//! machine: the caller passes the current time and transmits whatever reports come
//! back. That keeps USB delivery strictly separate from script progress (the plan's
//! "distinguish genuine USB delivery from script engine progress" requirement) and
//! makes timing testable without a host.

use alloc::rc::Rc;
use alloc::string::String;
use alloc::vec::Vec;

use super::ducky::{Command, MAX_COMMANDS, Script};
use super::{ConsumerReport, KeyboardReport, Layout, MouseReport, modifier};

/// Legacy expanded-plan limit; compressed plans no longer truncate at this count.
pub const MAX_PLAN: usize = 8192;

/// One report destined for a HID endpoint.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Output {
    Keyboard(KeyboardReport),
    Mouse(MouseReport),
    Consumer(ConsumerReport),
    /// The script finished holding keys; send this to release them.
    ReleaseAll,
}

/// Execution progress snapshot for the UI.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EngineProgress {
    pub command_index: usize,
    pub command_total: usize,
    pub percent: u8,
    pub typed_chars: u32,
    pub keystrokes: u32,
    pub unsupported_chars: u32,
}

/// One stored command plus its execution count; REPEAT never clones text bodies.
#[derive(Debug)]
struct PlanCommand {
    command: Rc<Command>,
    executions: usize,
}

/// Script runner.
#[derive(Debug)]
pub struct HidEngine {
    plan: Vec<PlanCommand>,
    layout: Layout,
    pc: usize,
    repetition: usize,
    command_index: usize,
    command_total: usize,
    /// Index into the current text command.
    text_index: usize,
    /// A key was pressed and its release report is due next tick.
    release_pending: bool,
    release_kind: u8,
    release_modifiers: u8,
    wait_until_ms: u64,
    key_delay_ms: u16,
    held_modifiers: u8,
    typed_chars: u32,
    keystrokes: u32,
    unsupported_chars: u32,
    finished: bool,
    paused: bool,
    stopped: bool,
    release_all_sent: bool,
    plan_truncated: bool,
}

impl HidEngine {
    /// Build an engine from a validated script.
    pub fn new(script: &Script, layout: Layout) -> Self {
        let mut plan: Vec<PlanCommand> = Vec::with_capacity(script.commands.len());
        let mut command_total = 0;
        for command in &script.commands {
            match command {
                Command::Repeat(times) => {
                    if let Some(previous) = plan.last_mut() {
                        previous.executions += usize::from(*times);
                        command_total += usize::from(*times);
                    }
                }
                other => {
                    plan.push(PlanCommand { command: Rc::new(other.clone()), executions: 1 });
                    command_total += 1;
                }
            }
        }
        Self {
            plan,
            layout,
            pc: 0,
            repetition: 0,
            command_index: 0,
            command_total,
            text_index: 0,
            release_pending: false,
            release_kind: 1,
            release_modifiers: 0,
            wait_until_ms: 0,
            key_delay_ms: script.key_delay_ms.max(1),
            held_modifiers: 0,
            typed_chars: 0,
            keystrokes: 0,
            unsupported_chars: 0,
            finished: false,
            paused: false,
            stopped: false,
            release_all_sent: false,
            plan_truncated: false,
        }
    }

    pub fn layout(&self) -> Layout {
        self.layout
    }

    pub fn is_finished(&self) -> bool {
        self.finished
    }

    pub fn plan_truncated(&self) -> bool {
        self.plan_truncated
    }

    pub fn typed_chars(&self) -> u32 {
        self.typed_chars
    }

    pub fn keystrokes(&self) -> u32 {
        self.keystrokes
    }

    pub fn unsupported_chars(&self) -> u32 {
        self.unsupported_chars
    }

    pub fn progress(&self) -> EngineProgress {
        let total = self.command_total;
        let index = self.command_index.min(total);
        let percent = index.checked_mul(100).and_then(|scaled| scaled.checked_div(total))
            .map_or(100, |value| value.min(100) as u8);
        EngineProgress {
            command_index: index,
            command_total: total,
            percent,
            typed_chars: self.typed_chars,
            keystrokes: self.keystrokes,
            unsupported_chars: self.unsupported_chars,
        }
    }

    pub fn set_paused(&mut self, paused: bool) {
        self.paused = paused;
    }

    pub fn is_paused(&self) -> bool {
        self.paused
    }

    /// Abort the script; the next poll releases any held keys.
    pub fn stop(&mut self) {
        self.stopped = true;
    }

    /// Poll for the next report due at `now_ms`.
    ///
    /// Returns `None` while waiting for a delay or when the script is done. Call it
    /// repeatedly (the firmware drives it from the 10 ms input tick).
    pub fn next_report(&mut self, now_ms: u64) -> Option<Output> {
        if self.stopped && !self.release_all_sent {
            self.stopped = true;
            self.release_all_sent = true;
            self.held_modifiers = 0;
            self.finished = true;
            return Some(Output::ReleaseAll);
        }
        if self.paused || self.finished {
            return None;
        }
        if now_ms < self.wait_until_ms {
            return None;
        }

        if self.release_pending {
            self.release_pending = false;
            self.wait_until_ms = now_ms + u64::from(self.key_delay_ms);
            let modifiers = self.release_modifiers & self.held_modifiers;
            self.release_modifiers = 0;
            // Consume any delay that follows the key now, so "type, wait 100 ms,
            // type" lands 100 ms after the release instead of after the next poll.
            self.absorb_idle_commands(now_ms);
            let kind = core::mem::replace(&mut self.release_kind, 1);
            return Some(match kind {
                2 => Output::Consumer(ConsumerReport { usage: 0 }),
                3 => Output::Mouse(MouseReport { buttons: 0, dx: 0, dy: 0, wheel: 0 }),
                _ => Output::Keyboard(KeyboardReport { modifiers, keycodes: [0; 6] }),
            });
        }

        // Bounded loop: a run of zero-report commands (delays/unsupported chars)
        // must not stall the caller.
        for _ in 0..64 {
            if self.pc >= self.plan.len() {
                if self.held_modifiers != 0 || !self.release_all_sent {
                    self.release_all_sent = true;
                    self.held_modifiers = 0;
                    self.finished = true;
                    return Some(Output::ReleaseAll);
                }
                self.finished = true;
                return None;
            }
            let command = Rc::clone(&self.plan[self.pc].command);
            match command.as_ref() {
                Command::Delay(ms) => {
                    self.advance();
                    self.wait_until_ms = self.wait_until_ms.max(now_ms) + u64::from(*ms);
                    return None;
                }
                Command::SetDefaultDelay(ms) => {
                    self.advance();
                    self.key_delay_ms = (ms / 2).max(1);
                }
                Command::Text { text, enter } => {
                    if self.text_index < text.len() {
                        let ch = text[self.text_index] as char;
                        self.text_index += 1;
                        // Advance past the command as soon as its last character is
                        // emitted, so a following DELAY is folded exactly once.
                        let exhausted = self.text_index >= text.len() && !*enter;
                        if let Some((keycode, shift)) = self.layout.map_char(ch) {
                            let modifiers = if shift { modifier::LEFT_SHIFT } else { 0 };
                            self.typed_chars = self.typed_chars.saturating_add(1);
                            self.keystrokes = self.keystrokes.saturating_add(1);
                            self.release_pending = true;
                            self.release_modifiers = modifiers;
                            if exhausted {
                                self.advance();
                                self.text_index = 0;
                            }
                            return Some(Output::Keyboard(KeyboardReport::new(
                                modifiers | self.held_modifiers,
                                keycode,
                            )));
                        }
                        self.unsupported_chars = self.unsupported_chars.saturating_add(1);
                        // Skip the remainder of a multi-byte UTF-8 sequence so one
                        // character is reported once, not once per byte.
                        while self.text_index < text.len() && (text[self.text_index] & 0xC0) == 0x80
                        {
                            self.text_index += 1;
                        }
                        continue;
                    }
                    if *enter {
                        self.advance();
                        self.text_index = 0;
                        self.keystrokes = self.keystrokes.saturating_add(1);
                        self.release_pending = true;
                        self.release_modifiers = 0;
                        return Some(Output::Keyboard(KeyboardReport::new(
                            self.held_modifiers,
                            super::key::ENTER,
                        )));
                    }
                    self.advance();
                    self.text_index = 0;
                }
                Command::Key { modifiers, keycode } => {
                    self.advance();
                    self.keystrokes = self.keystrokes.saturating_add(1);
                    self.release_pending = true;
                    self.release_modifiers = modifiers | self.held_modifiers;
                    return Some(Output::Keyboard(KeyboardReport::new(
                        self.release_modifiers,
                        *keycode,
                    )));
                }
                Command::KeyDown { modifiers, keycode } => {
                    self.advance();
                    self.held_modifiers |= modifiers;
                    if *keycode == 0 {
                        // Modifier-only hold: report the held modifiers.
                        return Some(Output::Keyboard(KeyboardReport {
                            modifiers: self.held_modifiers,
                            keycodes: [0; 6],
                        }));
                    }
                    self.release_pending = true;
                    self.release_modifiers = modifiers & !self.held_modifiers;
                    return Some(Output::Keyboard(KeyboardReport::new(
                        self.held_modifiers,
                        *keycode,
                    )));
                }
                Command::KeyUp { modifiers, keycode } => {
                    self.advance();
                    let _ = keycode;
                    self.held_modifiers &= !modifiers;
                    return Some(Output::Keyboard(KeyboardReport {
                        modifiers: self.held_modifiers,
                        keycodes: [0; 6],
                    }));
                }
                Command::Media(usage) => {
                    self.release_kind = 2;
                    self.advance();
                    self.keystrokes = self.keystrokes.saturating_add(1);
                    self.release_pending = true;
                    self.release_modifiers = 0;
                    return Some(Output::Consumer(ConsumerReport { usage: *usage }));
                }
                Command::MouseMove { dx, dy } => {
                    self.advance();
                    return Some(Output::Mouse(MouseReport {
                        buttons: 0,
                        dx: *dx,
                        dy: *dy,
                        wheel: 0,
                    }));
                }
                Command::MouseClick(button) => {
                    self.release_kind = 3;
                    self.advance();
                    self.release_pending = true;
                    self.release_modifiers = 0;
                    return Some(Output::Mouse(MouseReport {
                        buttons: *button,
                        dx: 0,
                        dy: 0,
                        wheel: 0,
                    }));
                }
                Command::MouseScroll(delta) => {
                    self.advance();
                    return Some(Output::Mouse(MouseReport {
                        buttons: 0,
                        dx: 0,
                        dy: 0,
                        wheel: *delta,
                    }));
                }
                Command::Repeat(_) => {
                    // Repetition counts are stored on the preceding command.
                    self.advance();
                }
            }
        }
        None
    }

    fn advance(&mut self) {
        self.command_index += 1;
        self.text_index = 0;
        self.repetition += 1;
        if self.repetition >= self.plan[self.pc].executions {
            self.pc += 1;
            self.repetition = 0;
        }
    }

    /// Fold leading `DELAY`/`DEFAULT_DELAY` commands into the wait deadline.
    fn absorb_idle_commands(&mut self, now_ms: u64) {
        for _ in 0..64 {
            if self.pc >= self.plan.len() { break; }
            let command = Rc::clone(&self.plan[self.pc].command);
            match command.as_ref() {
                Command::Delay(ms) => {
                    self.advance();
                    self.wait_until_ms = self.wait_until_ms.max(now_ms) + u64::from(*ms);
                }
                Command::SetDefaultDelay(ms) => {
                    self.advance();
                    self.key_delay_ms = (ms / 2).max(1);
                }
                _ => break,
            }
        }
    }

    /// Drain the remaining script, collecting reports (tests and "preview" mode).
    pub fn run_to_end(&mut self, start_ms: u64, step_ms: u64) -> Vec<Output> {
        let mut out = Vec::new();
        let mut now = start_ms;
        // Guard against scripts with long delays: cap simulated time at 10 minutes.
        let limit = start_ms + 600_000;
        while now <= limit {
            if let Some(report) = self.next_report(now) {
                out.push(report);
            }
            if self.is_finished() {
                break;
            }
            now += step_ms.max(1);
        }
        out
    }
}

/// Benign demo scripts shipped in the firmware payload library.
pub const BUILTIN_SCRIPTS: &[(&str, &str)] = &[
    (
        "hid-test.txt",
        "REM Types a HID self-test line into any open text field\n\
         DELAY 800\n\
         STRING Admin12121 HID self-test\n\
         ENTER\n\
         STRING Layout: OK  Keys: OK\n\
         ENTER\n",
    ),
    (
        "notepad.txt",
        "REM Opens Notepad on Windows and writes a short note\n\
         DELAY 600\n\
         GUI r\n\
         DELAY 400\n\
         STRING notepad\n\
         ENTER\n\
         DELAY 900\n\
         STRING Admin12121 payload ran successfully.\n\
         ENTER\n",
    ),
    (
        "media-mouse.txt",
        "REM Explicit volume and pointer test\nDELAY 800\nMUTE\nDELAY 200\nMUTE\nMOUSE_MOVE 20 0\nMOUSE_MOVE -20 0\n",
    ),
    (
        "presenter.txt",
        "REM Presentation remote test: next/previous slide\n\
         DELAY 500\n\
         RIGHT\n\
         DELAY 250\n\
         RIGHT\n\
         DELAY 250\n\
         LEFT\n",
    ),
];

/// Look up a built-in script body by name.
pub fn builtin_script(name: &str) -> Option<&'static str> {
    BUILTIN_SCRIPTS
        .iter()
        .find(|(candidate, _)| candidate.eq_ignore_ascii_case(name))
        .map(|(_, body)| *body)
}

/// Upper bound on user payloads read from storage; bounds the firmware heap.
pub const MAX_EXTERNAL_PAYLOADS: usize = 8;
/// Upper bound on one user payload, in bytes.
pub const MAX_EXTERNAL_PAYLOAD_BYTES: usize = 2048;

/// Storage payloads that are safe to offer, in the order the UI indexes them.
///
/// One predicate for both the picker and the resolver, so a name can never be
/// shown and then resolve to a different script (or to nothing).
fn usable_external(external: &[(String, String)]) -> impl Iterator<Item = &(String, String)> {
    external
        .iter()
        .filter(|(name, body)| {
            !name.is_empty() && !body.is_empty() && body.len() <= MAX_EXTERNAL_PAYLOAD_BYTES
        })
        .take(MAX_EXTERNAL_PAYLOADS)
}

/// Display names for the payload picker: built-ins first, then storage payloads.
pub fn payload_names(external: &[(String, String)]) -> Vec<String> {
    let mut out: Vec<String> = BUILTIN_SCRIPTS
        .iter()
        .map(|(name, _)| String::from(*name))
        .collect();
    out.extend(usable_external(external).map(|(name, _)| name.clone()));
    out
}

/// Resolve a picker index to `(name, script body)` across built-ins and storage.
pub fn resolve_payload(index: usize, external: &[(String, String)]) -> Option<(String, String)> {
    if let Some((name, body)) = BUILTIN_SCRIPTS.get(index) {
        return Some((String::from(*name), String::from(*body)));
    }
    usable_external(external)
        .nth(index - BUILTIN_SCRIPTS.len())
        .map(|(name, body)| (name.clone(), body.clone()))
}

/// Validate a payload file name before it touches storage (no paths, no traversal).
pub fn validate_payload_name(name: &str) -> Result<(), &'static str> {
    if name.is_empty() || name.len() > 64 {
        return Err("payload name must be 1..64 characters");
    }
    if name.contains('/') || name.contains('\\') || name.contains("..") {
        return Err("payload name must not contain a path");
    }
    if !name
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'))
    {
        return Err("payload name may only use letters, digits, '.', '_' and '-'");
    }
    Ok(())
}

/// Full payload catalogue entry for the UI.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PayloadEntry {
    pub name: String,
    pub commands: usize,
    pub estimated_ms: u64,
    pub builtin: bool,
}

/// Build the catalogue from built-ins plus any SD scripts already parsed.
pub fn catalogue(builtins_only: bool) -> Vec<PayloadEntry> {
    let mut out = Vec::new();
    for (name, body) in BUILTIN_SCRIPTS {
        if let Ok(script) = super::ducky::parse(name, body) {
            out.push(PayloadEntry {
                name: String::from(*name),
                commands: script.len(),
                estimated_ms: script.estimated_ms(),
                builtin: true,
            });
        }
    }
    if builtins_only {
        out.truncate(MAX_COMMANDS.min(out.len()));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hid::ducky::parse;
    use crate::hid::key;

    fn engine(source: &str) -> HidEngine {
        let script = parse("t", source).unwrap();
        HidEngine::new(&script, Layout::Us)
    }

    #[test]
    fn types_string_characters_with_press_and_release() {
        let mut engine = engine("DELAY 10\nSTRING ab");
        let reports = engine.run_to_end(0, 5);
        let keyboards: Vec<KeyboardReport> = reports
            .iter()
            .filter_map(|report| match report {
                Output::Keyboard(k) => Some(*k),
                _ => None,
            })
            .collect();
        assert_eq!(keyboards.len(), 4, "2 presses + 2 releases");
        assert_eq!(keyboards[0].keycodes[0], key::A);
        assert_eq!(keyboards[1].keycodes[0], 0, "release between keys");
        assert_eq!(keyboards[2].keycodes[0], key::A + 1);
        assert_eq!(engine.typed_chars(), 2);
        assert!(engine.is_finished());
    }

    #[test]
    fn uppercase_and_symbols_use_shift() {
        let mut engine = engine("STRING A!");
        let reports = engine.run_to_end(0, 5);
        let presses: Vec<KeyboardReport> = reports
            .iter()
            .filter_map(|report| match report {
                Output::Keyboard(k) if k.keycodes[0] != 0 => Some(*k),
                _ => None,
            })
            .collect();
        assert_eq!(presses.len(), 2);
        assert_eq!(
            presses[0].modifiers & modifier::LEFT_SHIFT,
            modifier::LEFT_SHIFT
        );
        assert_eq!(presses[0].keycodes[0], key::A);
        assert_eq!(presses[1].keycodes[0], key::ONE);
    }

    #[test]
    fn delays_are_respected() {
        let mut engine = engine("STRING a\nDELAY 100\nSTRING b");
        // First press at t=0.
        assert!(matches!(engine.next_report(0), Some(Output::Keyboard(_))));
        // Release after the key delay; the following DELAY is folded in immediately.
        assert!(matches!(engine.next_report(12), Some(Output::Keyboard(_))));
        // Second character is held back until release + key delay + 100 ms.
        assert!(engine.next_report(50).is_none());
        assert!(engine.next_report(123).is_none());
        assert!(engine.next_report(124).is_some());
    }

    #[test]
    fn unsupported_characters_are_counted_not_typed() {
        let mut engine = engine("STRING a\u{00e9}b");
        let reports = engine.run_to_end(0, 5);
        let presses = reports
            .iter()
            .filter(|r| matches!(r, Output::Keyboard(k) if k.keycodes[0] != 0))
            .count();
        assert_eq!(presses, 2);
        assert_eq!(engine.unsupported_chars(), 1);
        assert_eq!(engine.typed_chars(), 2);
    }

    #[test]
    fn repeat_expands_and_media_reports_are_emitted() {
        let mut engine = engine("STRING a\nREPEAT 3\nMUTE");
        assert_eq!(engine.progress().command_total, 5);
        let reports = engine.run_to_end(0, 5);
        assert!(reports
            .iter()
            .any(|r| matches!(r, Output::Consumer(ConsumerReport { usage }) if *usage == crate::hid::media::MUTE)));
        assert_eq!(engine.typed_chars(), 4);
    }

    #[test]
    fn mouse_commands_produce_mouse_reports() {
        let mut engine = engine("MOUSE_MOVE 5 -5\nMOUSE_CLICK left\nMOUSE_SCROLL -2");
        let reports = engine.run_to_end(0, 5);
        let mice: Vec<MouseReport> = reports
            .iter()
            .filter_map(|r| match r {
                Output::Mouse(m) => Some(*m),
                _ => None,
            })
            .collect();
        assert_eq!(mice.len(), 4);
        assert_eq!((mice[0].dx, mice[0].dy), (5, -5));
        assert_eq!(mice[1].buttons, MouseReport::LEFT_BUTTON);
        assert_eq!(mice[2].buttons, 0, "release click before scrolling");
        assert_eq!(mice[3].wheel, -2);
    }

    #[test]
    fn stop_releases_keys_and_finishes() {
        let mut engine = engine("STRING hello world");
        assert!(engine.next_report(0).is_some());
        engine.stop();
        assert_eq!(engine.next_report(100), Some(Output::ReleaseAll));
        assert!(engine.is_finished());
        assert!(engine.next_report(200).is_none());
    }

    #[test]
    fn pause_holds_execution() {
        let mut engine = engine("STRING abc");
        engine.set_paused(true);
        assert!(engine.next_report(0).is_none());
        engine.set_paused(false);
        assert!(engine.next_report(0).is_some());
    }

    #[test]
    fn progress_is_monotonic() {
        let mut engine = engine("STRING abc\nDELAY 10\nSTRING d");
        let mut last = 0u8;
        let mut now = 0;
        loop {
            let _ = engine.next_report(now);
            let percent = engine.progress().percent;
            assert!(percent >= last);
            last = percent;
            if engine.is_finished() || now > 5_000 {
                break;
            }
            now += 5;
        }
        assert_eq!(engine.progress().percent, 100);
    }

    #[test]
    fn builtin_scripts_are_valid() {
        for (name, body) in BUILTIN_SCRIPTS {
            let script = parse(name, body).unwrap_or_else(|e| panic!("{name}: {}", e.describe()));
            assert!(!script.is_empty());
            assert!(script.len() < 64);
            assert_eq!(builtin_script(name).map(|s| s.len()), Some(body.len()));
        }
        assert_eq!(catalogue(true).len(), BUILTIN_SCRIPTS.len());
    }

    #[test]
    fn payload_names_are_sanitised() {
        assert!(validate_payload_name("demo.txt").is_ok());
        assert!(validate_payload_name("a-b_c.1").is_ok());
        assert!(validate_payload_name("../evil.txt").is_err());
        assert!(validate_payload_name("dir/demo.txt").is_err());
        assert!(validate_payload_name("").is_err());
        assert!(validate_payload_name(&"x".repeat(65)).is_err());
        assert!(validate_payload_name("bad name.txt").is_err());
    }
    #[test]
    fn stop_while_paused_still_releases_every_held_report() {
        let mut engine = engine("MOUSE_CLICK left");
        assert!(matches!(engine.next_report(0), Some(Output::Mouse(_))));
        engine.set_paused(true);
        engine.stop();
        assert_eq!(engine.next_report(1), Some(Output::ReleaseAll));
        assert!(engine.is_finished());
    }

    #[test]
    fn consumer_and_mouse_release_their_own_report_type() {
        let mut engine = engine("MUTE\nMOUSE_CLICK left");
        assert!(matches!(engine.next_report(0), Some(Output::Consumer(_))));
        assert_eq!(engine.next_report(20), Some(Output::Consumer(ConsumerReport { usage: 0 })));
        assert!(matches!(engine.next_report(40), Some(Output::Mouse(_))));
        assert_eq!(engine.next_report(60), Some(Output::Mouse(MouseReport { buttons: 0, dx: 0, dy: 0, wheel: 0 })));
    }

    #[test]
    fn storage_payloads_extend_the_builtin_catalogue() {
        let external = alloc::vec![(String::from("my-script.txt"), String::from("STRING hi"))];
        let names = payload_names(&external);
        assert_eq!(names.len(), BUILTIN_SCRIPTS.len() + 1);
        assert_eq!(names[0], "hid-test.txt", "built-ins stay first so old indices keep working");
        assert_eq!(names[names.len() - 1], "my-script.txt");
        let (name, body) = resolve_payload(BUILTIN_SCRIPTS.len(), &external).expect("storage payload resolves");
        assert_eq!(name, "my-script.txt");
        assert_eq!(body, "STRING hi");
        assert!(resolve_payload(usize::MAX, &external).is_none());
        assert_eq!(resolve_payload(0, &[]).map(|(name, _)| name), Some(String::from("hid-test.txt")));
    }

    #[test]
    fn oversized_and_excess_storage_payloads_are_ignored_consistently() {
        let mut external = alloc::vec![(
            String::from("too-big.txt"),
            "x".repeat(MAX_EXTERNAL_PAYLOAD_BYTES + 1),
        )];
        for index in 0..(MAX_EXTERNAL_PAYLOADS + 3) {
            external.push((alloc::format!("p{index}.txt"), String::from("ENTER")));
        }
        let names = payload_names(&external);
        assert_eq!(names.len(), BUILTIN_SCRIPTS.len() + MAX_EXTERNAL_PAYLOADS);
        assert!(!names.iter().any(|name| name == "too-big.txt"), "oversized scripts never reach the picker");
        // The last accepted index resolves, the next one does not.
        let last = BUILTIN_SCRIPTS.len() + MAX_EXTERNAL_PAYLOADS - 1;
        assert!(resolve_payload(last, &external).is_some());
        assert!(resolve_payload(last + 1, &external).is_none());
    }

    #[test]
    fn empty_storage_payloads_are_not_offered() {
        let external = alloc::vec![
            (String::from(""), String::from("ENTER")),
            (String::from("blank.txt"), String::new()),
            (String::from("good.txt"), String::from("ENTER")),
        ];
        let names = payload_names(&external);
        assert_eq!(names.len(), BUILTIN_SCRIPTS.len() + 1);
        assert_eq!(names[names.len() - 1], "good.txt");
    }

}
