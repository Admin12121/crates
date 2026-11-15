//! Native ST7789 panel driver (SPI, blocking) implementing the shared `Canvas`.
//!
//! No framebuffer: every primitive writes its own window, which keeps the driver at
//! a few hundred bytes of stack and avoids a 150 KB framebuffer competing with the
//! Wi-Fi/BLE heap. Full-screen repaints are chunked, so the UI stays responsive.

use cyberdeck_core::ui::{font, Canvas, Rect, Rgb565};
use embedded_hal::spi::SpiBus;
use esp_hal::delay::Delay;
use esp_hal::gpio::Output;
use esp_hal::spi::master::Spi;
use esp_hal::Blocking;

use cyberdeck_core::board::{DisplayController, DisplayGeometry};

const CMD_SWRESET: u8 = 0x01;
const CMD_SLPOUT: u8 = 0x11;
const CMD_NORON: u8 = 0x13;
const CMD_INVON: u8 = 0x21;
const CMD_DISPON: u8 = 0x29;
const CMD_CASET: u8 = 0x2A;
const CMD_RASET: u8 = 0x2B;
const CMD_RAMWR: u8 = 0x2C;
const CMD_MADCTL: u8 = 0x36;
const CMD_COLMOD: u8 = 0x3A;

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
}

impl<'d> Display<'d> {
    /// Initialise the panel. `main` builds the SPI bus and GPIOs from the board
    /// profile; the driver never looks at a pin number itself.
    pub fn new(
        spi: Spi<'d, Blocking>,
        dc: Output<'d>,
        cs: Output<'d>,
        rst: Output<'d>,
        backlight: Option<Output<'d>>,
        geometry: DisplayGeometry,
        controller: DisplayController,
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
        // No mirroring/rotation for the reference panel.
        self.command(CMD_MADCTL, &[0x00])?;
        self.command(CMD_INVON, &[])?;
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
        self.dc.set_low();
        let mut byte = [cmd];
        SpiBus::write(&mut self.spi, &mut byte).map_err(|_| DisplayError::BusWrite)?;
        self.dc.set_high();
        if !data.is_empty() {
            let mut scratch = [0u8; 32];
            for chunk in data.chunks(scratch.len()) {
                scratch[..chunk.len()].copy_from_slice(chunk);
                SpiBus::write(&mut self.spi, &mut scratch[..chunk.len()])
                    .map_err(|_| DisplayError::BusWrite)?;
            }
        }
        self.cs.set_high();
        Ok(())
    }

    fn set_window(&mut self, rect: Rect) -> Result<(), DisplayError> {
        let x0 = rect.x.max(0) as u16;
        let y0 = rect.y.max(0) as u16;
        let x1 = (rect.right().max(0) as u16).saturating_sub(1).min(self.width - 1);
        let y1 = (rect.bottom().max(0) as u16)
            .saturating_sub(1)
            .min(self.height - 1);
        self.command(
            CMD_CASET,
            &[(x0 >> 8) as u8, x0 as u8, (x1 >> 8) as u8, x1 as u8],
        )?;
        self.command(
            CMD_RASET,
            &[(y0 >> 8) as u8, y0 as u8, (y1 >> 8) as u8, y1 as u8],
        )?;
        self.command(CMD_RAMWR, &[])?;
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
        if self.set_window(clipped).is_err() {
            return;
        }
        let pixel = color.0.to_be_bytes();
        // 64-pixel chunks keep the stack use at 128 bytes.
        let mut chunk = [0u8; 128];
        for i in 0..64 {
            chunk[i * 2] = pixel[0];
            chunk[i * 2 + 1] = pixel[1];
        }
        let total = u32::from(clipped.w) * u32::from(clipped.h);
        let mut remaining = total;
        while remaining > 0 {
            let pixels = remaining.min(64) as usize;
            if SpiBus::write(&mut self.spi, &mut chunk[..pixels * 2]).is_err() {
                break;
            }
            remaining -= pixels as u32;
        }
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
        if self.set_window(Rect::new(x, y, w, h)).is_err() {
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
                if SpiBus::write(&mut self.spi, &mut row[..offset]).is_err() {
                    return;
                }
            }
        }
    }

    fn present(&mut self) {}
}
