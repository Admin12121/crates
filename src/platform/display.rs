//! Native ST7789 panel driver (SPI, blocking) implementing the shared `Canvas`.
//!
//! No framebuffer: every primitive writes its own window, which keeps the driver at
//! a few hundred bytes of stack and avoids a 150 KB framebuffer competing with the
//! Wi-Fi/BLE heap. Full-screen repaints are chunked, so the UI stays responsive.

use cyberdeck_core::ui::{Canvas, Rect, Rgb565, font};
use embedded_hal::spi::SpiBus;
use esp_hal::Blocking;
use esp_hal::delay::Delay;
use esp_hal::gpio::Output;
use esp_hal::spi::master::Spi;

use cyberdeck_core::board::{DisplayController, DisplayGeometry, DisplayOrientation};

const CMD_SWRESET: u8 = 0x01;
const CMD_SLPOUT: u8 = 0x11;
const CMD_NORON: u8 = 0x13;
const CMD_INVOFF: u8 = 0x20;
const CMD_INVON: u8 = 0x21;
const CMD_DISPON: u8 = 0x29;
const CMD_CASET: u8 = 0x2A;
const CMD_RASET: u8 = 0x2B;
const CMD_RAMWR: u8 = 0x2C;
const CMD_MADCTL: u8 = 0x36;
const CMD_COLMOD: u8 = 0x3A;
/// MADCTL bit 3 selects blue/green/red order instead of red/green/blue.
const MADCTL_BGR: u8 = 0x08;

/// Display initialisation failure with an actionable message.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DisplayError {
    /// The SPI bus rejected the configured frequency/mode.
    BusConfig,
    /// Controller id read back as something other than ST7789/ILI9341.
    UnsupportedController,
    /// A pixel transfer failed.
    BusWrite,
}

impl DisplayError {
    pub const fn message(self) -> &'static str {
        match self {
            Self::BusConfig => "display SPI bus configuration failed",
            Self::UnsupportedController => "display controller not recognised",
            Self::BusWrite => "display SPI transfer failed",
        }
    }
}

/// One initialised panel.
pub struct Display<'d> {
    spi: Spi<'d, Blocking>,
    dc: Output<'d>,
    cs: Output<'d>,
    _rst: Output<'d>,
    backlight: Option<Output<'d>>,
    delay: Delay,
    width: u16,
    height: u16,
    controller: DisplayController,
    orientation: DisplayOrientation,
    inverted: bool,
    bgr: bool,
}

/// Streams 16-bit pixels in 128-byte chunks, flushing on fill.
struct PixelSink<'a, 'd> {
    spi: &'a mut Spi<'d, Blocking>,
    chunk: [u8; 128],
    used: usize,
}

impl<'a, 'd> PixelSink<'a, 'd> {
    fn new(spi: &'a mut Spi<'d, Blocking>) -> Self {
        Self {
            spi,
            chunk: [0u8; 128],
            used: 0,
        }
    }

    fn flush(&mut self) -> bool {
        if self.used == 0 {
            return true;
        }
        let ok = SpiBus::write(self.spi, &self.chunk[..self.used]).is_ok();
        self.used = 0;
        ok
    }

    fn push(&mut self, bytes: [u8; 2]) -> bool {
        self.chunk[self.used] = bytes[0];
        self.chunk[self.used + 1] = bytes[1];
        self.used += 2;
        if self.used == self.chunk.len() {
            self.flush()
        } else {
            true
        }
    }

    fn repeat(&mut self, bytes: [u8; 2], count: u32) -> bool {
        for _ in 0..count {
            if !self.push(bytes) {
                return false;
            }
        }
        true
    }
}

impl<'d> Display<'d> {
    /// Initialise the panel. `main` builds the SPI bus and GPIOs from the board
    /// profile; the driver never looks at a pin number itself.
    #[allow(clippy::too_many_arguments, reason = "one argument per wired display pin, driven by the board profile")]
    pub fn new(
        spi: Spi<'d, Blocking>,
        dc: Output<'d>,
        cs: Output<'d>,
        rst: Output<'d>,
        backlight: Option<Output<'d>>,
        geometry: DisplayGeometry,
        controller: DisplayController,
        orientation: DisplayOrientation,
        inverted: bool,
        bgr: bool,
    ) -> Result<Self, DisplayError> {
        let mut display = Self {
            spi,
            dc,
            cs,
            _rst: rst,
            backlight,
            delay: Delay::new(),
            width: geometry.width,
            height: geometry.height,
            controller,
            orientation,
            inverted,
            bgr,
        };
        display.reset();
        display.init_sequence()?;
        Ok(display)
    }

    fn reset(&mut self) {
        // The reset pin is driven by a GPIO; hold it low for 20 ms.
        self._rst.set_low();
        self.delay.delay_millis(20);
        self._rst.set_high();
        self.delay.delay_millis(120);
    }

    fn init_sequence(&mut self) -> Result<(), DisplayError> {
        self.command(CMD_SWRESET, &[])?;
        self.delay.delay_millis(150);
        self.command(CMD_SLPOUT, &[])?;
        self.delay.delay_millis(120);
        // 16 bits/pixel, RGB565.
        self.command(CMD_COLMOD, &[0x55])?;
        // Rotation, inversion and colour order come from the board profile, not the
        // driver: an ILI9341 with the BGR bit clear swaps red and blue on screen.
        let madctl = self.orientation.madctl() | if self.bgr { MADCTL_BGR } else { 0 };
        self.command(CMD_MADCTL, &[madctl])?;
        self.command(if self.inverted { CMD_INVON } else { CMD_INVOFF }, &[])?;
        self.command(CMD_NORON, &[])?;
        self.command(CMD_DISPON, &[])?;
        self.delay.delay_millis(20);
        if let Some(backlight) = self.backlight.as_mut() {
            backlight.set_high();
        }
        self.fill_rect(
            Rect::new(0, 0, self.width, self.height),
            cyberdeck_core::ui::theme::BACKGROUND,
        );
        Ok(())
    }

    pub const fn controller(&self) -> DisplayController {
        self.controller
    }

    fn command(&mut self, cmd: u8, data: &[u8]) -> Result<(), DisplayError> {
        self.cs.set_low();
        let result = self.command_held(cmd, data);
        self.cs.set_high();
        result
    }

    /// Same as [`Self::command`] but leaves chip-select asserted by the caller.
    fn command_held(&mut self, cmd: u8, data: &[u8]) -> Result<(), DisplayError> {
        self.dc.set_low();
        let byte = [cmd];
        SpiBus::write(&mut self.spi, &byte).map_err(|_| DisplayError::BusWrite)?;
        self.dc.set_high();
        if !data.is_empty() {
            let mut scratch = [0u8; 32];
            for chunk in data.chunks(scratch.len()) {
                scratch[..chunk.len()].copy_from_slice(chunk);
                SpiBus::write(&mut self.spi, &scratch[..chunk.len()])
                    .map_err(|_| DisplayError::BusWrite)?;
            }
        }
        Ok(())
    }

    fn set_window_held(&mut self, rect: Rect) -> Result<(), DisplayError> {
        let x0 = rect.x.max(0) as u16;
        let y0 = rect.y.max(0) as u16;
        let x1 = (rect.right().max(0) as u16)
            .saturating_sub(1)
            .min(self.width - 1);
        let y1 = (rect.bottom().max(0) as u16)
            .saturating_sub(1)
            .min(self.height - 1);
        self.command_held(
            CMD_CASET,
            &[(x0 >> 8) as u8, x0 as u8, (x1 >> 8) as u8, x1 as u8],
        )?;
        self.command_held(
            CMD_RASET,
            &[(y0 >> 8) as u8, y0 as u8, (y1 >> 8) as u8, y1 as u8],
        )?;
        self.command_held(CMD_RAMWR, &[])?;
        Ok(())
    }
}

impl Canvas for Display<'_> {
    fn width(&self) -> u16 {
        self.width
    }

    fn height(&self) -> u16 {
        self.height
    }

    fn draw_bitmap(&mut self, x: i16, y: i16, src_w: u16, src_h: u16, dst_w: u16, dst_h: u16, pixels: &[u8]) {
        if src_w == 0 || src_h == 0 || dst_w == 0 || dst_h == 0 {
            return;
        }
        let samples = usize::from(src_w) * usize::from(src_h);
        if pixels.len() < samples * 2 {
            return;
        }
        let sample = |sx: usize, sy: usize| -> u16 {
            let at = (sy * usize::from(src_w) + sx) * 2;
            u16::from_be_bytes([pixels[at], pixels[at + 1]])
        };
        for row in 0..u32::from(dst_h) {
            let py = y + row as i16;
            if py < 0 || py >= self.height as i16 {
                continue;
            }
            let sy = (row * u32::from(src_h) / u32::from(dst_h)) as usize;
            // Consecutive opaque pixels share one windowed write; the
            // transparent key splits each row into a handful of runs.
            let mut run: Option<u32> = None; // first column of the open run
            for column in 0..=u32::from(dst_w) {
                let transparent = if column < u32::from(dst_w) {
                    let sx = (column * u32::from(src_w) / u32::from(dst_w)) as usize;
                    sample(sx, sy) == 0x0001
                } else {
                    true // sentinel: flush a run that reaches the right edge
                };
                match (run, transparent) {
                    (None, false) => run = Some(column),
                    (Some(start), true) => {
                        run = None;
                        let len = column - start;
                        self.cs.set_low();
                        let rect = Rect::new(x + start as i16, py, len as u16, 1);
                        if self.set_window_held(rect).is_ok() {
                            let mut sink = PixelSink::new(&mut self.spi);
                            for step in 0..len {
                                let sx = ((start + step) * u32::from(src_w) / u32::from(dst_w)) as usize;
                                sink.push(sample(sx, sy).to_be_bytes());
                            }
                            sink.flush();
                        }
                        self.cs.set_high();
                    }
                    _ => {}
                }
            }
        }
    }

    fn fill_rect(&mut self, rect: Rect, color: Rgb565) {
        if rect.w == 0 || rect.h == 0 {
            return;
        }
        let clipped = Rect::new(
            rect.x.max(0),
            rect.y.max(0),
            rect.w.min(self.width.saturating_sub(rect.x.max(0) as u16)),
            rect.h.min(self.height.saturating_sub(rect.y.max(0) as u16)),
        );
        if clipped.w == 0 || clipped.h == 0 {
            return;
        }
        self.cs.set_low();
        if self.set_window_held(clipped).is_err() {
            self.cs.set_high();
            return;
        }
        let total = u32::from(clipped.w) * u32::from(clipped.h);
        let mut sink = PixelSink::new(&mut self.spi);
        sink.repeat(color.0.to_be_bytes(), total);
        sink.flush();
        self.cs.set_high();
    }

    fn draw_glyph(&mut self, x: i16, y: i16, ch: char, color: Rgb565, bg: Rgb565, scale: u8) {
        let scale = scale.max(1) as u16;
        let glyph = font::glyph(ch);
        let glyph_w = u16::from(font::GLYPH_W);
        let glyph_h = u16::from(font::GLYPH_H);
        let w = glyph_w * scale;
        let h = glyph_h * scale;
        if x < 0 || y < 0 || x as u16 + w > self.width || y as u16 + h > self.height {
            // Partial glyphs would need per-pixel clipping; skip instead of wrapping.
            return;
        }
        self.cs.set_low();
        if self.set_window_held(Rect::new(x, y, w, h)).is_err() {
            self.cs.set_high();
            return;
        }
        let mut row = [0u8; 32]; // up to 16 pixels wide
        let fg = color.0.to_be_bytes();
        let bg_bytes = bg.0.to_be_bytes();
        for py in 0..glyph_h {
            for sx in 0..scale {
                let _ = sx;
                let mut offset = 0usize;
                for px in 0..glyph_w {
                    let bit = glyph[px as usize] & (1 << py) != 0;
                    let bytes = if bit { fg } else { bg_bytes };
                    for _ in 0..scale {
                        if offset + 2 <= row.len() {
                            row[offset] = bytes[0];
                            row[offset + 1] = bytes[1];
                            offset += 2;
                        }
                    }
                }
                if SpiBus::write(&mut self.spi, &row[..offset]).is_err() {
                    self.cs.set_high();
                    return;
                }
            }
        }
        self.cs.set_high();
    }

    /// Batched string rendering: one window for the whole run instead of one per
    /// glyph. Per-glyph windows cost three commands each and make text-dense
    /// screens extremely slow over SPI.
    fn draw_text(&mut self, x: i16, y: i16, text: &str, color: Rgb565, bg: Rgb565, scale: u8) {
        let scale = scale.max(1) as u16;
        let advance = u16::from(font::ADVANCE) * scale;
        let h = u16::from(font::GLYPH_H) * scale;
        if x < 0 || y < 0 || y as u16 + h > self.height || x as u16 >= self.width {
            return;
        }
        // Truncate long diagnostic and menu strings to the remaining pixels.
        // Previously, a single oversized line silently disappeared.
        let count = text
            .chars()
            .count()
            .min(usize::from((self.width - x as u16) / advance));
        if count == 0 {
            return;
        }
        let w = advance * count as u16;
        self.cs.set_low();
        if self.set_window_held(Rect::new(x, y, w, h)).is_err() {
            self.cs.set_high();
            return;
        }
        let fg = color.0.to_be_bytes();
        let bg = bg.0.to_be_bytes();
        let gap = u16::from(font::ADVANCE - font::GLYPH_W);
        let mut sink = PixelSink::new(&mut self.spi);
        for py in 0..u16::from(font::GLYPH_H) {
            for _ in 0..scale {
                for ch in text.chars().take(count) {
                    let glyph = font::glyph(ch);
                    for px in 0..u16::from(font::GLYPH_W) {
                        let bytes = if glyph[px as usize] & (1 << py) != 0 {
                            fg
                        } else {
                            bg
                        };
                        sink.repeat(bytes, u32::from(scale));
                    }
                    sink.repeat(bg, u32::from(gap) * u32::from(scale));
                }
            }
        }
        sink.flush();
        self.cs.set_high();
    }

    fn present(&mut self) {}
}
