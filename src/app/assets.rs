//! Embedded splash art: RGB565, row-major, big-endian pixel pairs. A pixel
//! pair of `0x0001` is transparent (the source image background).

/// Splash logo, 96x96 pixels (18,432 B of flash).
pub const LOGO: &[u8] = include_bytes!("../../assets/logo96.rgb565");
pub const LOGO_W: u16 = 96;
pub const LOGO_H: u16 = 96;
