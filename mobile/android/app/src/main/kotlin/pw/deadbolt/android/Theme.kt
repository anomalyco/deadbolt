package pw.deadbolt.android

import androidx.compose.foundation.isSystemInDarkTheme
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.darkColorScheme
import androidx.compose.material3.lightColorScheme
import androidx.compose.runtime.Composable
import androidx.compose.runtime.CompositionLocalProvider
import androidx.compose.runtime.Immutable
import androidx.compose.runtime.staticCompositionLocalOf
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.ExperimentalTextApi
import androidx.compose.ui.text.TextStyle
import androidx.compose.ui.text.font.Font
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontVariation
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp

/*
 * Deadbolt's look, the same as the desktop app (crates/app, Rune with
 * rune-theme-opencode) and the extension (extension/static/theme.css).
 * Values are copied by hand from:
 *
 * - colours: extension/static/theme.css, which takes the `v2-*` tokens of
 *   themes/opencode/assets/theme.json at the Rune pin in crates/app/Cargo.toml
 *   (rev 3062e9b86b5a02b97c8ed4e8f49fcfc4d6902fc1; theme.json, the theme's
 *   lib.rs and its fonts are byte-identical to rev 1b78719, and the tokens
 *   used here are unchanged since theme.css's rev 29b1361), including
 *   theme.css's two contrast fixes (focus #5b7ef9, faint text #666666 in light);
 * - type, radii and motion: themes/opencode/src/lib.rs (`Type`, `Radius`,
 *   `Motion`) at that rev;
 * - fonts: extension/static/fonts (Inter variable at its 14pt cut, IBM Plex
 *   Mono), converted from WOFF2 to TTF unchanged, under the SIL OFL
 *   (assets/licenses).
 *
 * On a Rune bump, re-read those and update this file with theme.css.
 */

@Immutable
data class Palette(
    val bgDeep: Color,
    val bg: Color,
    val layer01: Color,
    val layer02: Color,
    val layer03: Color,
    val layer04: Color,
    val border: Color,
    val borderMuted: Color,
    val borderStrong: Color,
    val borderWeak: Color,
    val focus: Color,
    val hover: Color,
    val pressed: Color,
    val text: Color,
    val textStrong: Color,
    val muted: Color,
    val faint: Color,
    val textFaint: Color,
    val icon: Color,
    val iconMuted: Color,
    val accent: Color,
    val textAccent: Color,
    val contrast: Color,
    val onContrast: Color,
    val contrastPressed: Color,
    val button: Color,
    val knob: Color,
    val danger: Color,
    val dangerBg: Color,
    val success: Color,
    val textSuccess: Color,
    val successBg: Color,
    val warning: Color,
    val warningBg: Color,
    /** Search field fill: layer_02 in light, layer_01 in dark (vault.css .search-wrap). */
    val search: Color,
)

private val Light = Palette(
    bgDeep = Color(0xFFFAFAFA),
    bg = Color(0xFFFFFFFF),
    layer01 = Color(0xFFFAFAFA),
    layer02 = Color(0xFFF2F2F2),
    layer03 = Color(0xFFEEEEEE),
    layer04 = Color(0xFFDBDBDB),
    border = Color(0x1A000000),
    borderMuted = Color(0x14000000),
    borderStrong = Color(0x33000000),
    borderWeak = Color(0xFFDBDBDB),
    focus = Color(0xFF5B7EF9),
    hover = Color(0x0A000000),
    pressed = Color(0x14000000),
    text = Color(0xFF161616),
    textStrong = Color(0xFF171717),
    muted = Color(0xFF5C5C5C),
    faint = Color(0xFF808080),
    textFaint = Color(0xFF666666),
    icon = Color(0xFF3A3A3A),
    iconMuted = Color(0xFF808080),
    accent = Color(0xFF3B5CF6),
    textAccent = Color(0xFF3B5CF6),
    contrast = Color(0xFF242424),
    onContrast = Color(0xFFFFFFFF),
    contrastPressed = Color(0x3DFFFFFF),
    button = Color(0xFFFFFFFF),
    knob = Color(0xFFF2F2F2),
    danger = Color(0xFFB82D35),
    dangerBg = Color(0xFFFCECEB),
    success = Color(0xFF198B43),
    textSuccess = Color(0xFF167A3B),
    successBg = Color(0xFFE7F9EA),
    warning = Color(0xFFCB9F34),
    warningBg = Color(0xFFFEFAEC),
    search = Color(0xFFF2F2F2),
)

private val Dark = Palette(
    bgDeep = Color(0xFF080808),
    bg = Color(0xFF161616),
    layer01 = Color(0xFF242424),
    layer02 = Color(0xFF2E2E2E),
    layer03 = Color(0xFF3A3A3A),
    layer04 = Color(0xFF5C5C5C),
    border = Color(0x1AFFFFFF),
    borderMuted = Color(0x14FFFFFF),
    borderStrong = Color(0x33FFFFFF),
    borderWeak = Color(0xFF282828),
    focus = Color(0xFF7698FD),
    hover = Color(0x0FFFFFFF),
    pressed = Color(0x1AFFFFFF),
    text = Color(0xFFFAFAFA),
    textStrong = Color(0xFFEDEDED),
    muted = Color(0xFFAEAEAE),
    faint = Color(0xFF808080),
    textFaint = Color(0xFFA3A3A3),
    icon = Color(0xFFDBDBDB),
    iconMuted = Color(0xFF808080),
    accent = Color(0xFF3B5CF6),
    textAccent = Color(0xFFA2BCFF),
    contrast = Color(0xFF5C5C5C),
    onContrast = Color(0xFFFFFFFF),
    contrastPressed = Color(0x66000000),
    button = Color(0x0FFFFFFF),
    knob = Color(0xFFF2F2F2),
    danger = Color(0xFFF17471),
    dangerBg = Color(0xFF461516),
    success = Color(0xFF6BD586),
    textSuccess = Color(0xFF6BD586),
    successBg = Color(0xFF14361D),
    warning = Color(0xFFF2CF76),
    warningBg = Color(0xFF4B4025),
    search = Color(0xFF242424),
)

/** Rune's radii: xs 2, sm 4, md 6, lg 8, xl 10. */
object Radius {
    val sm = 4.dp
    val md = 6.dp
    val lg = 8.dp
    val xl = 10.dp
}

/** Controls settle in about 200 ms, overlays 240 (Rune's critically damped springs). */
object Motion {
    const val CONTROL_MS = 200
    const val OVERLAY_MS = 240
}

@OptIn(ExperimentalTextApi::class)
private fun inter(weight: Int) = Font(
    R.font.inter,
    FontWeight(weight),
    variationSettings = FontVariation.Settings(FontVariation.weight(weight)),
)

private val Inter = FontFamily(inter(400), inter(440), inter(500), inter(530), inter(600))
private val PlexMono = FontFamily(
    Font(R.font.plex_mono_regular, FontWeight.Normal),
    Font(R.font.plex_mono_medium, FontWeight.Medium),
)

/** Rune's `Type` (themes/opencode/src/lib.rs), in sp so system font scaling applies. */
@Immutable
data class Type(
    val ui: TextStyle = TextStyle(fontFamily = Inter, fontSize = 13.sp, fontWeight = FontWeight(440), lineHeight = 20.sp, letterSpacing = (-0.04).sp),
    val uiMedium: TextStyle = ui.copy(fontWeight = FontWeight(530)),
    val small: TextStyle = TextStyle(fontFamily = Inter, fontSize = 11.sp, fontWeight = FontWeight(440), lineHeight = 12.sp, letterSpacing = 0.05.sp),
    val smallMedium: TextStyle = small.copy(fontWeight = FontWeight(530)),
    val textXsmall: TextStyle = TextStyle(fontFamily = Inter, fontSize = 12.sp, fontWeight = FontWeight(400), lineHeight = 18.sp),
    /** The popup's brand and state titles: 15/20 at 600. */
    val title: TextStyle = TextStyle(fontFamily = Inter, fontSize = 15.sp, fontWeight = FontWeight(600), lineHeight = 20.sp, letterSpacing = (-0.04).sp),
    val mono: TextStyle = TextStyle(fontFamily = PlexMono, fontSize = 12.sp, fontWeight = FontWeight.Normal, lineHeight = 18.sp),
    /** A one-time code or pairing code: Plex Mono, larger. */
    val monoLarge: TextStyle = TextStyle(fontFamily = PlexMono, fontSize = 22.sp, fontWeight = FontWeight.Medium, lineHeight = 28.sp),
)

val LocalPalette = staticCompositionLocalOf { Light }
val LocalType = staticCompositionLocalOf { Type() }

object Deadbolt {
    val colors: Palette @Composable get() = LocalPalette.current
    val type: Type @Composable get() = LocalType.current
}

@Composable
fun DeadboltTheme(content: @Composable () -> Unit) {
    val dark = isSystemInDarkTheme()
    val p = if (dark) Dark else Light
    // Material components (text selection, ripples, the system biometric sheet's
    // host) read this scheme; it is the palette above, not Material's.
    val scheme = (if (dark) darkColorScheme() else lightColorScheme()).copy(
        primary = p.accent,
        onPrimary = Color.White,
        background = p.bg,
        onBackground = p.text,
        surface = p.bg,
        onSurface = p.text,
        surfaceVariant = p.layer02,
        onSurfaceVariant = p.muted,
        outline = p.border,
        outlineVariant = p.borderWeak,
        error = p.danger,
    )
    CompositionLocalProvider(LocalPalette provides p, LocalType provides Type()) {
        MaterialTheme(colorScheme = scheme, content = content)
    }
}
