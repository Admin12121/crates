//! Five-way button input with debounce and hold-repeat.
//!
//! Buttons are wired to GND with internal pull-ups, so a press reads low. The
//! scanner runs from the 30 Hz UI tick; it never blocks and never allocates.

use esp_hal::gpio::{Input, InputConfig, Pull};

/// Logical buttons exposed to the app.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Button {
    Up,
    Down,
    Select,
    Back,
    Home,
}

/// Debounced button bank.
pub struct Buttons<'d> {
    up: Input<'d>,
    down: Input<'d>,
    select: Input<'d>,
    back: Input<'d>,
    home: Input<'d>,
    states: [ButtonState; 5],
}

#[derive(Debug, Clone, Copy, Default)]
struct ButtonState {
    pressed: bool,
    last_change_ms: u64,
    next_repeat_ms: u64,
}

const DEBOUNCE_MS: u64 = 25;
const REPEAT_DELAY_MS: u64 = 450;
const REPEAT_RATE_MS: u64 = 90;

impl<'d> Buttons<'d> {
    pub fn new(
        up: Input<'d>,
        down: Input<'d>,
        select: Input<'d>,
        back: Input<'d>,
        home: Input<'d>,
    ) -> Self {
        let _ = InputConfig::default();
        Self {
            up,
            down,
            select,
            back,
            home,
            states: [ButtonState::default(); 5],
        }
    }

    /// Build the five inputs with the active-low pull-up configuration.
    pub fn from_pins(
        up: impl esp_hal::gpio::InputPin + 'd,
        down: impl esp_hal::gpio::InputPin + 'd,
        select: impl esp_hal::gpio::InputPin + 'd,
        back: impl esp_hal::gpio::InputPin + 'd,
        home: impl esp_hal::gpio::InputPin + 'd,
    ) -> Self {
        let config = InputConfig::default().with_pull(Pull::Up);
        Self::new(
            Input::new(up, config),
            Input::new(down, config),
            Input::new(select, config),
            Input::new(back, config),
            Input::new(home, config),
        )
    }

    /// Raw pressed state for diagnostics: up, down, select, back, home.
    pub fn levels(&self) -> [bool; 5] {
        [
            self.up.is_low(),
            self.down.is_low(),
            self.select.is_low(),
            self.back.is_low(),
            self.home.is_low(),
        ]
    }

    /// Sample all buttons and return at most one event per tick.
    pub fn poll(&mut self, now_ms: u64) -> Option<Button> {
        let levels = [
            self.up.is_low(),
            self.down.is_low(),
            self.select.is_low(),
            self.back.is_low(),
            self.home.is_low(),
        ];
        let buttons = [
            Button::Up,
            Button::Down,
            Button::Select,
            Button::Back,
            Button::Home,
        ];
        let mut event = None;
        for (index, (level, button)) in levels.iter().zip(buttons).enumerate() {
            let state = &mut self.states[index];
            if *level != state.pressed {
                if now_ms.saturating_sub(state.last_change_ms) < DEBOUNCE_MS {
                    continue;
                }
                state.last_change_ms = now_ms;
                state.pressed = *level;
                if *level {
                    state.next_repeat_ms = now_ms + REPEAT_DELAY_MS;
                    if event.is_none() {
                        event = Some(button);
                    }
                }
            }
            // Held navigation keys repeat; Select/Back/Home are edge-triggered.
            if state.pressed
                && matches!(button, Button::Up | Button::Down)
                && now_ms >= state.next_repeat_ms
            {
                state.next_repeat_ms = now_ms + REPEAT_RATE_MS;
                if event.is_none() {
                    event = Some(button);
                }
            }
        }
        event
    }
}
