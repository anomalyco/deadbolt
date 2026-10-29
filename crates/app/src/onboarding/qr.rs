//! The pairing ticket as a QR code, drawn as vector rectangles so it stays
//! sharp at any scale.

use qrcode::{Color as Module, EcLevel, QrCode};
use rune::{Color, Shape};
use zeroize::Zeroize;

/// A QR code's modules, row by row; they encode the ticket, so they're
/// wiped when dropped.
pub struct Matrix {
    pub width: usize,
    dark: Vec<bool>,
}

impl Matrix {
    /// Error correction M, as the CLI's terminal code uses. `None` if the text
    /// is too long for a QR code.
    pub fn new(text: &str) -> Option<Matrix> {
        let code = QrCode::with_error_correction_level(text.as_bytes(), EcLevel::M).ok()?;
        Some(Matrix {
            width: code.width(),
            dark: code
                .to_colors()
                .into_iter()
                .map(|m| m == Module::Dark)
                .collect(),
        })
    }

    pub fn dark(&self, x: usize, y: usize) -> bool {
        self.dark[y * self.width + x]
    }

    /// The dark modules as rectangles `module` points square, one per run in a
    /// row. Whole-point modules keep every edge on the pixel grid.
    pub fn shape(&self, module: f32, ink: Color) -> Shape {
        let mut shape = Shape::new();
        for y in 0..self.width {
            let mut x = 0;
            while x < self.width {
                if !self.dark(x, y) {
                    x += 1;
                    continue;
                }
                let start = x;
                while x < self.width && self.dark(x, y) {
                    x += 1;
                }
                let (x0, x1) = (start as f32 * module, x as f32 * module);
                let (y0, y1) = (y as f32 * module, (y + 1) as f32 * module);
                shape = shape.fill(vec![[x0, y0], [x1, y0], [x1, y1], [x0, y1]], ink);
            }
        }
        shape
    }
}

impl Drop for Matrix {
    fn drop(&mut self) {
        self.dark.zeroize();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_ticket_fits_and_has_finder_patterns() {
        let ticket = format!("DBPAIR{}", "A".repeat(280));
        let m = Matrix::new(&ticket).unwrap();
        assert!(m.width >= 21 && m.width <= 177);
        // The top-left finder: a dark 7×7 ring around a light ring around a dark 3×3.
        assert!(m.dark(0, 0) && m.dark(6, 6) && !m.dark(1, 1) && m.dark(3, 3));
    }
}
