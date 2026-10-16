use qrcode::{EcLevel, QrCode, render::unicode::Dense1x2};

use crate::error::{Error, Result};

/// Terminal color scheme for [`render_qr`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum QrStyle {
    /// Dark modules drawn as filled blocks: for light terminal backgrounds.
    DarkOnLight,
    /// Light modules drawn as filled blocks: for dark terminal backgrounds.
    LightOnDark,
}

/// Renders `data` as a QR code using unicode half blocks (two modules per character
/// row), with a quiet zone.
pub fn render_qr(data: &str, style: QrStyle) -> Result<String> {
    let code = QrCode::with_error_correction_level(data.as_bytes(), EcLevel::M)
        .map_err(|e| Error::InvalidTicket(format!("cannot render qr code: {e}")))?;
    let mut renderer = code.render::<Dense1x2>();
    renderer.quiet_zone(true);
    if style == QrStyle::LightOnDark {
        renderer
            .dark_color(Dense1x2::Light)
            .light_color(Dense1x2::Dark);
    }
    Ok(renderer.build())
}
