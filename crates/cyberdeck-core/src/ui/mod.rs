//! Shared UI primitives: canvas abstraction, theme, layout helpers, menus.
//!
//! Feature views draw through [`Canvas`]; the firmware provides the SPI display
//! implementation. Nothing here talks to hardware, so layout and navigation are
//! host-testable while the pixels come from the real panel.

pub mod font;
pub mod menu;

use alloc::string::String;
use alloc::vec::Vec;

/// 16-bit RGB565 colour (native format of the ST7789/ILI9341 panels).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Rgb565(pub u16);

impl Rgb565 {
    pub const fn rgb(r: u8, g: u8, b: u8) -> Self {
        let r = (r as u16 >> 3) & 0x1F;
        let g = (g as u16 >> 2) & 0x3F;
        let b = (b as u16 >> 3) & 0x1F;
        Self((r << 11) | (g << 5) | b)
    }

    pub const fn invert(self) -> Self {
        Self(!self.0)
    }

    pub const fn components(self) -> (u8, u8, u8) {
        let r = ((self.0 >> 11) & 0x1F) as u8;
        let g = ((self.0 >> 5) & 0x3F) as u8;
        let b = (self.0 & 0x1F) as u8;
        ((r << 3) | (r >> 2), (g << 2) | (g >> 4), (b << 3) | (b >> 2))
    }
}

/// Palette used across every screen (high contrast for outdoor use).
pub mod theme {
    use super::Rgb565;

    pub const BACKGROUND: Rgb565 = Rgb565::rgb(0x0B, 0x0F, 0x14);
    pub const SURFACE: Rgb565 = Rgb565::rgb(0x16, 0x1C, 0x24);
    pub const SURFACE_ALT: Rgb565 = Rgb565::rgb(0x21, 0x2A, 0x35);
    pub const TEXT: Rgb565 = Rgb565::rgb(0xE6, 0xED, 0xF3);
    pub const TEXT_DIM: Rgb565 = Rgb565::rgb(0x8B, 0x97, 0xA6);
    pub const ACCENT: Rgb565 = Rgb565::rgb(0x35, 0xB6, 0xFF);
    pub const SUCCESS: Rgb565 = Rgb565::rgb(0x3F, 0xD6, 0x7A);
    pub const WARNING: Rgb565 = Rgb565::rgb(0xF5, 0xB3, 0x3C);
    pub const DANGER: Rgb565 = Rgb565::rgb(0xF2, 0x5F, 0x5F);
    pub const SELECTION: Rgb565 = Rgb565::rgb(0x1F, 0x3A, 0x54);

    /// Font scale for the header.
    pub const HEADER_SCALE: u8 = 2;
    /// Font scale for body rows.
    pub const BODY_SCALE: u8 = 1;
    /// Height of the status bar in pixels.
    pub const STATUS_BAR_H: u16 = 16;
    /// Height of the header in pixels.
    pub const HEADER_H: u16 = 22;

    /// Status colour for a job state label.
    pub fn status_colour(state: crate::job::JobState) -> Rgb565 {
        match state {
            crate::job::JobState::Running | crate::job::JobState::Paused => ACCENT,
            crate::job::JobState::Succeeded => SUCCESS,
            crate::job::JobState::Failed(_) => DANGER,
            crate::job::JobState::Cancelled => WARNING,
            crate::job::JobState::Idle => TEXT_DIM,
        }
    }
}

/// Pixel rectangle.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Rect {
    pub x: i16,
    pub y: i16,
    pub w: u16,
    pub h: u16,
}

impl Rect {
    pub const fn new(x: i16, y: i16, w: u16, h: u16) -> Self {
        Self { x, y, w, h }
    }

    pub const fn right(&self) -> i16 {
        self.x.saturating_add(self.w as i16)
    }

    pub const fn bottom(&self) -> i16 {
        self.y.saturating_add(self.h as i16)
    }

    pub fn contains(&self, x: i16, y: i16) -> bool {
        x >= self.x && x < self.right() && y >= self.y && y < self.bottom()
    }

    pub fn inset(&self, by: u16) -> Self {
        let by = by.min(self.w / 2).min(self.h / 2);
        Self::new(
            self.x.saturating_add(by as i16),
            self.y.saturating_add(by as i16),
            self.w.saturating_sub(by * 2),
            self.h.saturating_sub(by * 2),
        )
    }
}

/// Drawing surface implemented by the display driver and by the test canvas.
pub trait Canvas {
    fn width(&self) -> u16;
    fn height(&self) -> u16;

    /// Fill a rectangle, clipped to the panel.
    fn fill_rect(&mut self, rect: Rect, color: Rgb565);

    /// Draw one glyph with a single windowed write; `bg` is the cell background.
    fn draw_glyph(&mut self, x: i16, y: i16, ch: char, color: Rgb565, bg: Rgb565, scale: u8);

    /// Write a string, advancing by the font metrics.
    fn draw_text(&mut self, x: i16, y: i16, text: &str, color: Rgb565, bg: Rgb565, scale: u8) {
        let mut cursor = x;
        let scale = scale.max(1);
        for ch in text.chars() {
            self.draw_glyph(cursor, y, ch, color, bg, scale);
            cursor = cursor.saturating_add(i16::from(font::ADVANCE) * i16::from(scale));
        }
    }

    /// Horizontal line helper.
    fn draw_hline(&mut self, x: i16, y: i16, w: u16, color: Rgb565) {
        self.fill_rect(Rect::new(x, y, w, 1), color);
    }

    /// Vertical line helper.
    fn draw_vline(&mut self, x: i16, y: i16, h: u16, color: Rgb565) {
        self.fill_rect(Rect::new(x, y, 1, h), color);
    }

    /// Push the framebuffer/backlight update, if the driver buffers.
    fn present(&mut self) {}
}

/// Word-wrap `text` to `max_chars` columns, preserving explicit newlines.
pub fn wrap(text: &str, max_chars: usize) -> Vec<String> {
    let max_chars = max_chars.max(1);
    let mut lines = Vec::new();
    for paragraph in text.split('\n') {
        if paragraph.is_empty() {
            lines.push(String::new());
            continue;
        }
        let mut current = String::new();
        for word in paragraph.split(' ') {
            if current.is_empty() {
                if word.chars().count() <= max_chars {
                    current.push_str(word);
                } else {
                    // Hard-break a word that cannot fit.
                    let mut chunk = String::new();
                    for ch in word.chars() {
                        if chunk.chars().count() == max_chars {
                            lines.push(core::mem::take(&mut chunk));
                        }
                        chunk.push(ch);
                    }
                    current = chunk;
                }
            } else if current.chars().count() + 1 + word.chars().count() <= max_chars {
                current.push(' ');
                current.push_str(word);
            } else {
                lines.push(core::mem::take(&mut current));
                current.push_str(word);
            }
        }
        if !current.is_empty() {
            lines.push(current);
        }
    }
    lines
}

/// Truncate with an ellipsis to fit `max_chars`.
pub fn ellipsize(text: &str, max_chars: usize) -> String {
    if text.chars().count() <= max_chars {
        return String::from(text);
    }
    if max_chars <= 1 {
        return String::from("~");
    }
    let mut out: String = text.chars().take(max_chars - 1).collect();
    out.push('~');
    out
}

/// Render a horizontal progress/level bar.
pub fn draw_bar(
    canvas: &mut impl Canvas,
    rect: Rect,
    fraction_permille: u16,
    color: Rgb565,
) {
    let filled = u32::from(rect.w) * u32::from(fraction_permille.min(1000)) / 1000;
    canvas.fill_rect(rect, theme::SURFACE_ALT);
    if filled > 0 {
        canvas.fill_rect(Rect::new(rect.x, rect.y, filled as u16, rect.h), color);
    }
}

#[cfg(test)]
pub mod testing {
    //! Minimal canvas that records draw calls so views can be asserted on the host.

    use super::*;

    #[derive(Debug, Clone, PartialEq, Eq)]
    pub enum Op {
        Fill(Rect, Rgb565),
        Glyph { x: i16, y: i16, ch: char, scale: u8 },
    }

    #[derive(Debug, Default)]
    pub struct RecordingCanvas {
        pub ops: Vec<Op>,
        pub width: u16,
        pub height: u16,
    }

    impl RecordingCanvas {
        pub fn new(width: u16, height: u16) -> Self {
            Self {
                ops: Vec::new(),
                width,
                height,
            }
        }

        pub fn text(&self) -> String {
            self.ops
                .iter()
                .filter_map(|op| match op {
                    Op::Glyph { ch, .. } => Some(*ch),
                    _ => None,
                })
                .collect()
        }
    }

    impl Canvas for RecordingCanvas {
        fn width(&self) -> u16 {
            self.width
        }

        fn height(&self) -> u16 {
            self.height
        }

        fn fill_rect(&mut self, rect: Rect, color: Rgb565) {
            self.ops.push(Op::Fill(rect, color));
        }

        fn draw_glyph(&mut self, x: i16, y: i16, ch: char, _c: Rgb565, _b: Rgb565, scale: u8) {
            self.ops.push(Op::Glyph { x, y, ch, scale });
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use testing::RecordingCanvas;

    #[test]
    fn rgb565_round_trips_components() {
        let colour = Rgb565::rgb(0x12, 0x34, 0x56);
        let (r, g, b) = colour.components();
        assert!((r as i16 - 0x12).abs() <= 8);
        assert!((g as i16 - 0x34).abs() <= 4);
        assert!((b as i16 - 0x56).abs() <= 8);
        assert_eq!(colour.invert().invert(), colour);
    }

    #[test]
    fn wraps_text_to_width() {
        let lines = wrap("the quick brown fox jumps", 10);
        assert!(lines.iter().all(|line| line.chars().count() <= 10));
        assert_eq!(lines[0], "the quick");
        assert_eq!(wrap("a\nb", 10), alloc::vec![String::from("a"), String::from("b")]);
        assert_eq!(wrap("", 10), alloc::vec![String::new()]);
    }

    #[test]
    fn hard_breaks_long_words() {
        let lines = wrap("abcdefghijkl", 5);
        assert_eq!(lines, alloc::vec![String::from("abcde"), String::from("fghij"), String::from("kl")]);
    }

    #[test]
    fn ellipsizes_long_labels() {
        assert_eq!(ellipsize("short", 10), "short");
        assert_eq!(ellipsize("0123456789", 5), "0123~");
        assert_eq!(ellipsize("abcd", 1), "~");
    }

    #[test]
    fn draws_text_and_bars_within_bounds() {
        let mut canvas = RecordingCanvas::new(240, 320);
        canvas.draw_text(0, 0, "HELLO", theme::TEXT, theme::BACKGROUND, 1);
        assert_eq!(canvas.text(), "HELLO");
        draw_bar(&mut canvas, Rect::new(0, 20, 100, 8), 500, theme::ACCENT);
        assert!(canvas.ops.iter().any(|op| matches!(op, super::testing::Op::Fill(rect, _) if rect.w == 50)));
        draw_bar(&mut canvas, Rect::new(0, 30, 100, 8), 2000, theme::ACCENT);
        assert!(canvas.ops.iter().any(|op| matches!(op, super::testing::Op::Fill(rect, _) if rect.w == 100)));
    }

    #[test]
    fn rect_inset_and_contains() {
        let rect = Rect::new(10, 10, 100, 50);
        assert!(rect.contains(10, 10));
        assert!(!rect.contains(110, 10));
        let inner = rect.inset(5);
        assert_eq!(inner, Rect::new(15, 15, 90, 40));
        assert_eq!(Rect::new(0, 0, 10, 10).inset(50).w, 0);
    }
}
