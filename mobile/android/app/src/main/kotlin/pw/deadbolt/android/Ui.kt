package pw.deadbolt.android

import androidx.activity.compose.BackHandler
import androidx.compose.animation.AnimatedContent
import androidx.compose.animation.animateColorAsState
import androidx.compose.animation.core.CubicBezierEasing
import androidx.compose.animation.core.animateDpAsState
import androidx.compose.animation.core.animateFloatAsState
import androidx.compose.animation.core.tween
import androidx.compose.animation.fadeIn
import androidx.compose.animation.fadeOut
import androidx.compose.animation.togetherWith
import androidx.compose.foundation.Canvas
import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.clickable
import androidx.compose.foundation.interaction.MutableInteractionSource
import androidx.compose.foundation.interaction.collectIsFocusedAsState
import androidx.compose.foundation.interaction.collectIsPressedAsState
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.WindowInsets
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.imePadding
import androidx.compose.foundation.layout.navigationBars
import androidx.compose.foundation.layout.offset
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.safeDrawing
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.layout.widthIn
import androidx.compose.foundation.layout.windowInsetsPadding
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.lazy.rememberLazyListState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.text.BasicTextField
import androidx.compose.foundation.text.KeyboardActions
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.foundation.verticalScroll
import androidx.compose.foundation.rememberScrollState
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableLongStateOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.runtime.withFrameNanos
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.alpha
import androidx.compose.ui.draw.clip
import androidx.compose.ui.draw.scale
import androidx.compose.ui.draw.shadow
import androidx.compose.ui.focus.FocusRequester
import androidx.compose.ui.focus.focusRequester
import androidx.compose.ui.geometry.CornerRadius
import androidx.compose.ui.geometry.Offset
import androidx.compose.ui.geometry.Size
import androidx.compose.ui.graphics.Brush
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.SolidColor
import androidx.compose.ui.graphics.drawscope.Stroke
import androidx.compose.ui.semantics.Role
import androidx.compose.ui.semantics.clearAndSetSemantics
import androidx.compose.ui.semantics.contentDescription
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.text.TextStyle
import androidx.compose.ui.text.input.ImeAction
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.text.input.VisualTransformation
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.compose.material3.Text
import kotlinx.coroutines.delay

/** Rune's settle: a critically damped spring's shape (theme.css --settle). */
private val Settle = CubicBezierEasing(0.2f, 0.9f, 0.3f, 1f)

@Composable
fun DeadboltUi(
    vault: Vault,
    onBiometricUnlock: () -> Unit,
    onEnableBiometrics: () -> Unit,
    onAllowApproval: () -> Unit,
) {
    val c = Deadbolt.colors
    Box(
        Modifier
            .fillMaxSize()
            .background(c.bg)
            .windowInsetsPadding(WindowInsets.safeDrawing),
    ) {
        AnimatedContent(
            targetState = Triple(vault.screen::class, vault.detail != null, vault.approval?.id),
            transitionSpec = {
                fadeIn(tween(Motion.OVERLAY_MS, easing = Settle)) togetherWith fadeOut(tween(Motion.CONTROL_MS))
            },
            label = "screen",
        ) { (screen, hasDetail, approvalId) ->
            // Draw the screen this slot stands for, so the outgoing one fades out as
            // itself (and its effects don't run twice) rather than as a second copy
            // of the new one. The data shown is always the current state.
            when (screen) {
                Vault.Screen.Loading::class -> Box(Modifier.fillMaxSize())
                Vault.Screen.Broken::class -> StateScreen("Deadbolt couldn't start", (vault.screen as? Vault.Screen.Broken)?.message) {}
                Vault.Screen.Pair::class -> PairScreen(vault)
                Vault.Screen.Locked::class -> LockedScreen(vault, onBiometricUnlock)
                else -> when {
                    approvalId != null -> ApprovalScreen(vault, onAllowApproval)
                    hasDetail -> DetailScreen(vault)
                    else -> ListScreen(vault, onEnableBiometrics)
                }
            }
        }
    }
}

// Screens.

@Composable
private fun StateScreen(title: String, message: String?, content: @Composable () -> Unit) {
    val c = Deadbolt.colors
    val t = Deadbolt.type
    Column(Modifier.fillMaxSize().imePadding()) {
        TopBar()
        Column(
            Modifier
                .weight(1f)
                .verticalScroll(rememberScrollState())
                .padding(horizontal = 20.dp, vertical = 24.dp)
                .widthIn(max = 480.dp),
            verticalArrangement = Arrangement.spacedBy(8.dp),
        ) {
            LockTile()
            Spacer(Modifier.height(2.dp))
            Text(title, style = t.title, color = c.text)
            if (message != null) Text(message, style = t.ui, color = c.muted)
            Spacer(Modifier.height(4.dp))
            content()
        }
    }
}

@Composable
private fun PairScreen(vault: Vault) {
    val code = vault.pairingCode
    if (code == null) {
        // Plain remember: a passphrase never goes into the saved instance state.
        var passphrase by remember { mutableStateOf("") }
        var again by remember { mutableStateOf("") }
        fun submit() {
            if (passphrase.isEmpty() || again != passphrase || vault.busy) return
            vault.startPairing(passphrase)
            passphrase = ""
            again = ""
        }
        val mismatch = again.isNotEmpty() && again != passphrase
        StateScreen("Set up this phone", "Join the vault you already use on your computer. First, choose a passphrase for this phone.") {
            Field("Passphrase") {
                Input(passphrase, { passphrase = it }, password = true, imeAction = ImeAction.Next, modifier = Modifier.semantics { contentDescription = "Passphrase" })
            }
            Field("Again") {
                Input(again, { again = it }, password = true, onDone = ::submit, modifier = Modifier.semantics { contentDescription = "Passphrase again" })
            }
            if (mismatch) Text("The passphrases don't match.", style = Deadbolt.type.textXsmall, color = Deadbolt.colors.danger)
            Spacer(Modifier.height(4.dp))
            Button(
                "Get a pairing code",
                primary = true,
                enabled = !vault.busy && passphrase.isNotEmpty() && again == passphrase,
            ) { submit() }
            Footnote(vault.error)
        }
    } else {
        StateScreen("Pair with your computer", "On a computer that already has Deadbolt, run:") {
            Command("deadbolt pair $code")
            Spacer(Modifier.height(4.dp))
            Text("Pairing code", style = Deadbolt.type.smallMedium, color = Deadbolt.colors.muted)
            Text(code, style = Deadbolt.type.monoLarge, color = Deadbolt.colors.text)
            Text("Waiting for your computer. The code works once, for 5 minutes.", style = Deadbolt.type.textXsmall, color = Deadbolt.colors.textFaint)
            Spacer(Modifier.height(4.dp))
            Button("Cancel") { vault.cancelPairing() }
        }
    }
}

@Composable
private fun LockedScreen(vault: Vault, onBiometricUnlock: () -> Unit) {
    var passphrase by remember { mutableStateOf("") }
    val focus = remember { FocusRequester() }
    fun submit() {
        if (passphrase.isEmpty() || vault.busy) return
        vault.unlock(passphrase)
        passphrase = ""
    }
    LaunchedEffect(vault.autoPromptTick) {
        Perf.mark("locked screen")
        if (vault.shouldAutoPrompt()) {
            Perf.mark("biometric prompt")
            onBiometricUnlock()
        } else {
            runCatching { focus.requestFocus() }
        }
    }
    StateScreen("Deadbolt is locked", "Enter this phone's passphrase.") {
        Input(
            passphrase,
            { passphrase = it },
            password = true,
            placeholder = "Passphrase",
            modifier = Modifier.focusRequester(focus),
            onDone = ::submit,
        )
        Spacer(Modifier.height(4.dp))
        Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
            Button("Unlock", primary = true, enabled = !vault.busy && passphrase.isNotEmpty()) { submit() }
            if (vault.biometricUsable) Button("Use fingerprint or face", enabled = !vault.busy) { onBiometricUnlock() }
        }
        Footnote(vault.error)
    }
}

@Composable
private fun ListScreen(vault: Vault, onEnableBiometrics: () -> Unit) {
    val c = Deadbolt.colors
    val t = Deadbolt.type
    val listState = rememberLazyListState()
    val listedQuery = remember { arrayOf(vault.query) }
    remember(vault.items) {
        // New results for a different query start at the top, in the same frame,
        // instead of keeping the old first row's place (rows are keyed by id).
        // A sync's refresh of the same query keeps where the person scrolled.
        if (listedQuery[0] != vault.query) {
            listedQuery[0] = vault.query
            listState.requestScrollToItem(0)
        }
    }
    LaunchedEffect(vault.items) {
        if (vault.items.isNotEmpty()) {
            Perf.mark("list shown")
            Perf.shown(vault.query.length, vault.items.size)
            // The frame after the one that drew these rows: an upper bound on when they were visible.
            withFrameNanos {}
            Perf.event("visible len=${vault.query.length} rows=${vault.items.size} since query", System.nanoTime() - vault.searchedAt)
        }
    }
    Column(Modifier.fillMaxSize().imePadding()) {
        TopBar()
        Box(Modifier.padding(start = 14.dp, end = 14.dp, top = 10.dp, bottom = 6.dp)) {
            Search(vault.query, vault::search)
        }
        LazyColumn(
            Modifier.weight(1f),
            state = listState,
            contentPadding = PaddingValues(horizontal = 8.dp, vertical = 4.dp),
            verticalArrangement = Arrangement.spacedBy(2.dp),
        ) {
            if (vault.canEnableBiometrics && vault.query.isEmpty()) {
                item(key = "biometric") {
                    SwitchRow(
                        title = "Unlock with fingerprint or face",
                        sub = "Instead of your passphrase, on this phone.",
                        checked = false,
                        onToggle = onEnableBiometrics,
                    )
                }
            }
            items(vault.items, key = { it.id }) { item ->
                ItemRowView(item) { vault.openItem(item.id) }
            }
            if (vault.items.isEmpty() && vault.screen == Vault.Screen.Unlocked) { // not while fading out on lock
                item(key = "empty") {
                    Text(
                        if (vault.query.isEmpty()) "No items yet." else "Nothing matches “${vault.query}”.",
                        style = t.textXsmall,
                        color = c.muted,
                        modifier = Modifier
                            .padding(6.dp)
                            .fillMaxWidth()
                            .clip(RoundedCornerShape(Radius.lg))
                            .background(c.layer01)
                            .padding(horizontal = 12.dp, vertical = 14.dp),
                    )
                }
            }
        }
        Footer(vault)
    }
}

@Composable
private fun DetailScreen(vault: Vault) {
    val item = vault.detail ?: return
    val c = Deadbolt.colors
    val t = Deadbolt.type
    BackHandler { vault.closeItem() }
    Column(Modifier.fillMaxSize()) {
        TopBar(back = vault::closeItem)
        Column(
            Modifier
                .weight(1f)
                .verticalScroll(rememberScrollState())
                .padding(horizontal = 14.dp, vertical = 14.dp),
            verticalArrangement = Arrangement.spacedBy(14.dp),
        ) {
            Row(verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(10.dp)) {
                Avatar(item.title, size = 36)
                Text(item.title.ifEmpty { "Untitled" }, style = t.title, color = c.text, maxLines = 2, overflow = TextOverflow.Ellipsis)
            }
            Box(
                Modifier
                    .fillMaxWidth()
                    .clip(RoundedCornerShape(Radius.xl))
                    .background(c.layer01)
                    .border(1.dp, c.borderMuted, RoundedCornerShape(Radius.xl)),
            ) {
                Column {
                    var first = true
                    @Composable
                    fun divider() {
                        if (!first) Box(Modifier.fillMaxWidth().height(1.dp).background(c.borderMuted))
                        first = false
                    }
                    if (item.username.isNotEmpty()) {
                        divider()
                        DetailLine("Username", item.username, action = "Copy", actionDescription = "Copy username", onAction = vault::copyUsername)
                    }
                    if (item.hasPassword) {
                        divider()
                        DetailLine("Password", "••••••••••••", valueDescription = "Hidden", action = "Copy", actionDescription = "Copy password", onAction = vault::copyPassword)
                    }
                    if (item.hasOtp) {
                        divider()
                        CodeLine(vault.code, onCopy = vault::copyCode)
                    }
                    if (item.url.isNotEmpty()) {
                        divider()
                        DetailLine("Website", item.url)
                    }
                }
            }
        }
        Footer(vault)
    }
}

/**
 * A computer in the vault asks to read one value. What it signed (its name, the
 * item and field) and the program it checked are shown as facts; what the program
 * says runs it is shown as an unverified hint.
 */
@Composable
private fun ApprovalScreen(vault: Vault, onAllow: () -> Unit) {
    val request = vault.approval ?: return
    val c = Deadbolt.colors
    val t = Deadbolt.type
    val caller = remember(request.caller) { CallerLabel.parse(request.caller) }
    var now by remember { mutableLongStateOf(System.currentTimeMillis() / 1000) }
    LaunchedEffect(request.id) {
        while (true) {
            now = System.currentTimeMillis() / 1000
            delay(1_000)
        }
    }
    BackHandler { vault.denyApproval() }
    Column(Modifier.fillMaxSize()) {
        TopBar()
        Column(
            Modifier
                .weight(1f)
                .verticalScroll(rememberScrollState())
                .padding(horizontal = 14.dp, vertical = 14.dp),
            verticalArrangement = Arrangement.spacedBy(10.dp),
        ) {
            LockTile()
            Text("Allow one read?", style = t.title, color = c.text)
            Text(
                "${request.originName} is asking to read one value from your vault, once.",
                style = t.ui,
                color = c.muted,
            )
            Box(
                Modifier
                    .fillMaxWidth()
                    .clip(RoundedCornerShape(Radius.xl))
                    .background(c.layer01)
                    .border(1.dp, c.borderMuted, RoundedCornerShape(Radius.xl)),
            ) {
                Column {
                    DetailLine("Computer", request.originName)
                    Box(Modifier.fillMaxWidth().height(1.dp).background(c.borderMuted))
                    DetailLine("Item", request.title)
                    Box(Modifier.fillMaxWidth().height(1.dp).background(c.borderMuted))
                    DetailLine("Field", request.field)
                    Box(Modifier.fillMaxWidth().height(1.dp).background(c.borderMuted))
                    Column(Modifier.padding(start = 12.dp, end = 12.dp, top = 8.dp, bottom = 10.dp), verticalArrangement = Arrangement.spacedBy(4.dp)) {
                        Text("Program", style = t.smallMedium, color = c.muted)
                        Text(caller.program, style = t.mono, color = c.text)
                        Text("Checked by ${request.originName}", style = t.small, color = c.textFaint)
                        if (caller.hint != null) {
                            Spacer(Modifier.height(4.dp))
                            Text("Says it runs in ${caller.hint}. Not verified.", style = t.textXsmall, color = c.textFaint)
                        }
                    }
                }
            }
            val left = request.expiresAt - now
            Text(
                if (left > 0) "Expires in $left s" else "Expired",
                style = t.small,
                color = c.textFaint,
            )
            if (!vault.biometricKeyValid) {
                Text("Turn on fingerprint unlock to allow requests.", style = t.textXsmall, color = c.muted)
            }
            Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                Button(
                    "Allow with fingerprint",
                    primary = true,
                    enabled = !vault.approving && vault.biometricKeyValid && left > 0,
                    onClick = onAllow,
                )
                Button("Deny", enabled = !vault.approving) { vault.denyApproval() }
            }
            Footnote(vault.error)
        }
        Footer(vault)
    }
}

// Pieces, drawn as the app's and the extension's.

/** The popup's `.top`: the brand, a hairline under it. */
@Composable
private fun TopBar(back: (() -> Unit)? = null) {
    val c = Deadbolt.colors
    Column {
        Row(
            Modifier.fillMaxWidth().height(52.dp).padding(horizontal = 14.dp),
            verticalAlignment = Alignment.CenterVertically,
            horizontalArrangement = Arrangement.spacedBy(8.dp),
        ) {
            if (back != null) {
                Link("‹ Back", onClick = back)
            } else {
                Text("Deadbolt", style = Deadbolt.type.title, color = c.text)
            }
        }
        Box(Modifier.fillMaxWidth().height(1.dp).background(c.borderWeak))
    }
}

/** The popup's `.bottom`: what's happening on the left, Sync and Lock on the right. */
@Composable
private fun Footer(vault: Vault) {
    val c = Deadbolt.colors
    val t = Deadbolt.type
    var now by remember { mutableLongStateOf(System.currentTimeMillis()) }
    LaunchedEffect(Unit) {
        while (true) {
            delay(15_000)
            now = System.currentTimeMillis()
        }
    }
    LaunchedEffect(vault.notice) {
        if (vault.notice != null) {
            delay(4_000)
            vault.notice = null
        }
    }
    Column(Modifier.windowInsetsPadding(WindowInsets.navigationBars)) {
        Box(Modifier.fillMaxWidth().height(1.dp).background(c.borderWeak))
        Row(
            Modifier.fillMaxWidth().heightIn(min = 44.dp).padding(horizontal = 14.dp),
            verticalAlignment = Alignment.CenterVertically,
            horizontalArrangement = Arrangement.spacedBy(10.dp),
        ) {
            run {
                val (dot, text) = when {
                    vault.notice != null -> c.success to vault.notice!!
                    vault.error != null -> c.danger to vault.error!!
                    vault.syncing -> c.faint to "Syncing…"
                    vault.syncError != null -> c.warning to "Offline. Showing what's on this phone."
                    vault.syncedAt != null -> c.success to "Synced ${ago(now - vault.syncedAt!!)}"
                    else -> c.faint to "Not synced yet"
                }
                Box(Modifier.size(6.dp).clip(RoundedCornerShape(50)).background(dot))
                Text(text, style = t.small, color = c.textFaint, maxLines = 2, overflow = TextOverflow.Ellipsis, modifier = Modifier.weight(1f))
                Link("Sync", enabled = !vault.syncing, onClick = vault::syncNow)
                Link("Lock", onClick = vault::lock)
            }
        }
    }
}

private fun ago(ms: Long) = when {
    ms < 60_000 -> "just now"
    ms < 3_600_000 -> "${ms / 60_000} min ago"
    else -> "${ms / 3_600_000} h ago"
}

@Composable
private fun Footnote(message: String?) {
    if (message != null) Text(message, style = Deadbolt.type.textXsmall, color = Deadbolt.colors.danger)
}

/** rune-kit's Large push button: Neutral, or Contrast with its sheen for the primary action. */
@Composable
private fun Button(text: String, primary: Boolean = false, enabled: Boolean = true, onClick: () -> Unit) {
    val c = Deadbolt.colors
    val interaction = remember { MutableInteractionSource() }
    val pressed by interaction.collectIsPressedAsState()
    val scale by animateFloatAsState(if (pressed) 0.98f else 1f, tween(Motion.CONTROL_MS, easing = Settle), label = "press")
    val shape = RoundedCornerShape(Radius.lg)
    val fill = if (primary) c.contrast else c.button
    val overlay = when {
        !pressed -> Color.Transparent
        primary -> c.contrastPressed
        else -> c.pressed
    }
    Box(
        Modifier
            .scale(scale)
            .alpha(if (enabled) 1f else if (primary) 0.4f else 0.5f)
            .heightIn(min = 40.dp)
            .shadow(if (enabled) 1.dp else 0.dp, shape, clip = false)
            .clip(shape)
            .background(fill)
            .then(if (primary) Modifier.background(Brush.verticalGradient(listOf(Color(0x33FFFFFF), Color(0x00FFFFFF)))) else Modifier)
            .background(overlay)
            .border(0.5.dp, if (primary) c.borderStrong else c.border, shape)
            .clickable(interaction, indication = null, enabled = enabled, role = Role.Button, onClick = onClick)
            .padding(horizontal = 16.dp),
        contentAlignment = Alignment.Center,
    ) {
        Text(
            text,
            style = Deadbolt.type.uiMedium,
            color = if (primary) c.onContrast else c.text,
        )
    }
}

/** theme.css `.link`: muted medium text that darkens when pressed. */
@Composable
private fun Link(text: String, enabled: Boolean = true, description: String? = null, onClick: () -> Unit) {
    val c = Deadbolt.colors
    val interaction = remember { MutableInteractionSource() }
    val pressed by interaction.collectIsPressedAsState()
    val color by animateColorAsState(if (pressed) c.text else c.muted, tween(120), label = "link")
    Box(
        Modifier
            .heightIn(min = 44.dp)
            .widthIn(min = 44.dp)
            .clickable(interaction, indication = null, enabled = enabled, role = Role.Button, onClick = onClick)
            .padding(horizontal = 4.dp),
        contentAlignment = Alignment.Center,
    ) {
        Text(
            text,
            style = Deadbolt.type.textXsmall.copy(fontWeight = Deadbolt.type.uiMedium.fontWeight),
            color = color.copy(alpha = if (enabled) 1f else 0.5f),
            // "Copy" alone is ambiguous to a screen reader on a page of them.
            modifier = if (description != null) Modifier.semantics { contentDescription = description } else Modifier,
        )
    }
}

/** vault.css `.field`: a small medium label over its control. */
@Composable
private fun Field(label: String, content: @Composable () -> Unit) {
    Column(verticalArrangement = Arrangement.spacedBy(5.dp)) {
        Text(label, style = Deadbolt.type.smallMedium, color = Deadbolt.colors.muted)
        content()
    }
}

/** rune-kit's TextInput, large: bg_base, the neutral button's edge, a 1dp focus outline. */
@Composable
private fun Input(
    value: String,
    onChange: (String) -> Unit,
    modifier: Modifier = Modifier,
    password: Boolean = false,
    placeholder: String? = null,
    imeAction: ImeAction = ImeAction.Done,
    onDone: (() -> Unit)? = null,
) {
    val c = Deadbolt.colors
    val interaction = remember { MutableInteractionSource() }
    val focused by interaction.collectIsFocusedAsState()
    val shape = RoundedCornerShape(Radius.md)
    BasicTextField(
        value = value,
        onValueChange = onChange,
        modifier = modifier.fillMaxWidth(),
        singleLine = true,
        textStyle = Deadbolt.type.ui.copy(color = c.text),
        cursorBrush = SolidColor(c.accent),
        interactionSource = interaction,
        visualTransformation = if (password) PasswordVisualTransformation() else VisualTransformation.None,
        keyboardOptions = KeyboardOptions(
            keyboardType = if (password) KeyboardType.Password else KeyboardType.Text,
            autoCorrectEnabled = false,
            imeAction = imeAction,
        ),
        keyboardActions = KeyboardActions(onDone = { onDone?.invoke() }),
        decorationBox = { inner ->
            Box(
                Modifier
                    .heightIn(min = 40.dp)
                    .shadow(1.dp, shape, clip = false)
                    .clip(shape)
                    .background(c.bg)
                    .border(if (focused) 1.dp else 0.5.dp, if (focused) c.focus else c.border, shape)
                    .padding(horizontal = 10.dp),
                contentAlignment = Alignment.CenterStart,
            ) {
                if (value.isEmpty() && placeholder != null) Text(placeholder, style = Deadbolt.type.ui, color = c.textFaint)
                inner()
            }
        },
    )
}

/** The app's search: plain on layer_02 (layer_01 in the dark), an 8dp radius, no ring. */
@Composable
private fun Search(value: String, onChange: (String) -> Unit) {
    val c = Deadbolt.colors
    BasicTextField(
        value = value,
        onValueChange = onChange,
        modifier = Modifier.fillMaxWidth(),
        singleLine = true,
        textStyle = Deadbolt.type.ui.copy(color = c.text),
        cursorBrush = SolidColor(c.accent),
        keyboardOptions = KeyboardOptions(autoCorrectEnabled = false, imeAction = ImeAction.Search),
        decorationBox = { inner ->
            Row(
                Modifier
                    .heightIn(min = 40.dp)
                    .clip(RoundedCornerShape(Radius.lg))
                    .background(c.search)
                    .padding(start = 10.dp, end = 10.dp),
                verticalAlignment = Alignment.CenterVertically,
                horizontalArrangement = Arrangement.spacedBy(8.dp),
            ) {
                SearchGlyph(c.iconMuted)
                Box(Modifier.weight(1f)) {
                    if (value.isEmpty()) Text("Search", style = Deadbolt.type.ui, color = c.textFaint)
                    inner()
                }
            }
        },
    )
}

/** The popup's `.account` row: the avatar tile, title and a faint second line. */
@Composable
private fun ItemRowView(item: ItemRow, onClick: () -> Unit) {
    val c = Deadbolt.colors
    val t = Deadbolt.type
    val interaction = remember { MutableInteractionSource() }
    val pressed by interaction.collectIsPressedAsState()
    Row(
        Modifier
            .fillMaxWidth()
            .heightIn(min = 52.dp)
            .clip(RoundedCornerShape(Radius.lg))
            .background(if (pressed) c.pressed else Color.Transparent)
            .clickable(interaction, indication = null, role = Role.Button, onClick = onClick)
            .padding(start = 10.dp, end = 6.dp),
        verticalAlignment = Alignment.CenterVertically,
        horizontalArrangement = Arrangement.spacedBy(10.dp),
    ) {
        Avatar(item.title)
        Column(Modifier.weight(1f).padding(vertical = 6.dp)) {
            Text(item.title.ifEmpty { "Untitled" }, style = t.ui, color = c.text, maxLines = 1, overflow = TextOverflow.Ellipsis)
            val sub = item.username.ifEmpty { item.kind }
            if (sub.isNotEmpty()) {
                Text(sub, style = t.small.copy(fontSize = t.small.fontSize * 1.05f, lineHeight = t.small.lineHeight * 1.17f, letterSpacing = t.textXsmall.letterSpacing), color = c.textFaint, maxLines = 1, overflow = TextOverflow.Ellipsis)
            }
        }
    }
}

/** theme.css `.avatar`: the title's letter on layer_02, one tone. */
@Composable
private fun Avatar(title: String, size: Int = 32) {
    val c = Deadbolt.colors
    Box(
        // Decoration: the title next to it is what a screen reader should say.
        Modifier.size(size.dp).clip(RoundedCornerShape(Radius.lg)).background(c.layer02).clearAndSetSemantics {},
        contentAlignment = Alignment.Center,
    ) {
        Text(
            title.trim().firstOrNull()?.uppercase() ?: "•",
            style = Deadbolt.type.uiMedium.copy(letterSpacing = Deadbolt.type.mono.letterSpacing),
            color = c.icon,
        )
    }
}

@Composable
private fun DetailLine(
    label: String,
    value: String,
    valueDescription: String? = null,
    action: String? = null,
    actionDescription: String? = null,
    onAction: (() -> Unit)? = null,
) {
    val c = Deadbolt.colors
    Row(
        Modifier.fillMaxWidth().heightIn(min = 56.dp).padding(start = 12.dp, end = 8.dp, top = 8.dp, bottom = 8.dp),
        verticalAlignment = Alignment.CenterVertically,
    ) {
        Column(Modifier.weight(1f), verticalArrangement = Arrangement.spacedBy(4.dp)) {
            Text(label, style = Deadbolt.type.smallMedium, color = c.muted)
            Text(
                value,
                style = Deadbolt.type.ui,
                color = c.text,
                maxLines = 2,
                overflow = TextOverflow.Ellipsis,
                modifier = if (valueDescription != null) Modifier.semantics { contentDescription = valueDescription } else Modifier,
            )
        }
        if (action != null && onAction != null) Link(action, description = actionDescription, onClick = onAction)
    }
}

/** A login's one-time code, counted down locally between fetches. */
@Composable
private fun CodeLine(code: OtpCode?, onCopy: () -> Unit) {
    val c = Deadbolt.colors
    val t = Deadbolt.type
    Row(
        Modifier.fillMaxWidth().heightIn(min = 64.dp).padding(start = 12.dp, end = 8.dp, top = 8.dp, bottom = 8.dp),
        verticalAlignment = Alignment.CenterVertically,
    ) {
        Column(Modifier.weight(1f), verticalArrangement = Arrangement.spacedBy(4.dp)) {
            Text("One-time code", style = t.smallMedium, color = c.muted)
            if (code == null) {
                Text("…", style = t.monoLarge, color = c.textFaint)
            } else {
                Row(verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(10.dp)) {
                    val shown = if (code.code.length == 6) code.code.chunked(3).joinToString(" ") else code.code
                    Text(shown, style = t.monoLarge, color = if (code.remaining <= 5) c.danger else c.text)
                    Countdown(code)
                }
            }
        }
        if (code != null) Link("Copy", description = "Copy one-time code", onClick = onCopy)
    }
}

@Composable
private fun Countdown(code: OtpCode) {
    val c = Deadbolt.colors
    val fraction by animateFloatAsState(
        code.remaining.toFloat() / code.period.coerceAtLeast(1),
        tween(Motion.CONTROL_MS, easing = Settle),
        label = "countdown",
    )
    Row(verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(6.dp)) {
        Canvas(Modifier.size(14.dp)) {
            drawCircle(c.layer03, style = Stroke(2.dp.toPx()))
            drawArc(
                color = if (code.remaining <= 5) c.danger else c.accent,
                startAngle = -90f,
                sweepAngle = 360f * fraction,
                useCenter = false,
                style = Stroke(2.dp.toPx()),
            )
        }
        Text("${code.remaining}s", style = Deadbolt.type.small, color = c.textFaint)
    }
}

/** theme.css `.switch-row` with rune-kit's Mini switch, at touch size. */
@Composable
private fun SwitchRow(title: String, sub: String, checked: Boolean, onToggle: () -> Unit) {
    val c = Deadbolt.colors
    val t = Deadbolt.type
    val interaction = remember { MutableInteractionSource() }
    val pressed by interaction.collectIsPressedAsState()
    Row(
        Modifier
            .fillMaxWidth()
            .clip(RoundedCornerShape(Radius.xl))
            .background(if (pressed) c.layer02 else Color.Transparent)
            .clickable(interaction, indication = null, role = Role.Switch, onClick = onToggle)
            .padding(horizontal = 10.dp, vertical = 10.dp),
        verticalAlignment = Alignment.CenterVertically,
        horizontalArrangement = Arrangement.spacedBy(12.dp),
    ) {
        Column(Modifier.weight(1f), verticalArrangement = Arrangement.spacedBy(2.dp)) {
            Text(title, style = t.uiMedium, color = c.text)
            Text(sub, style = t.textXsmall, color = c.muted)
        }
        MiniSwitch(checked)
    }
}

@Composable
private fun MiniSwitch(checked: Boolean) {
    val c = Deadbolt.colors
    val knobX by animateDpAsState(if (checked) 16.dp else 0.dp, tween(Motion.CONTROL_MS, easing = Settle), label = "knob")
    val track by animateColorAsState(if (checked) c.accent else c.layer04, tween(Motion.CONTROL_MS, easing = Settle), label = "track")
    Box(
        Modifier
            .size(width = 44.dp, height = 20.dp)
            .clip(RoundedCornerShape(50))
            .background(track)
            .border(0.5.dp, c.border, RoundedCornerShape(50))
            .padding(1.dp),
    ) {
        Box(
            Modifier
                .offset(x = knobX)
                .size(width = 26.dp, height = 18.dp)
                .shadow(0.5.dp, RoundedCornerShape(9.dp))
                .clip(RoundedCornerShape(9.dp))
                .background(Brush.verticalGradient(listOf(Color.White, c.knob))),
        )
    }
}

/** The popup's `.command` box. */
@Composable
private fun Command(text: String) {
    val c = Deadbolt.colors
    Text(
        text,
        style = Deadbolt.type.mono,
        color = c.text,
        modifier = Modifier
            .fillMaxWidth()
            .clip(RoundedCornerShape(Radius.lg))
            .background(c.layer01)
            .border(1.dp, c.borderMuted, RoundedCornerShape(Radius.lg))
            .padding(horizontal = 10.dp, vertical = 9.dp),
    )
}

/** The popup's `.state-icon`: 36, layer_02, an 8dp radius, around a padlock. */
@Composable
private fun LockTile() {
    val c = Deadbolt.colors
    Box(
        Modifier.size(36.dp).clip(RoundedCornerShape(Radius.lg)).background(c.layer02),
        contentAlignment = Alignment.Center,
    ) {
        Canvas(Modifier.size(18.dp)) {
            val w = size.width
            val stroke = Stroke(1.5.dp.toPx())
            drawRoundRect(c.icon, Offset(w * 0.18f, w * 0.44f), Size(w * 0.64f, w * 0.46f), CornerRadius(2.dp.toPx()), style = stroke)
            drawArc(c.icon, 180f, 180f, false, Offset(w * 0.3f, w * 0.12f), Size(w * 0.4f, w * 0.5f), style = stroke)
            drawLine(c.icon, Offset(w * 0.3f, w * 0.37f), Offset(w * 0.3f, w * 0.44f), stroke.width)
            drawLine(c.icon, Offset(w * 0.7f, w * 0.37f), Offset(w * 0.7f, w * 0.44f), stroke.width)
        }
    }
}

@Composable
private fun SearchGlyph(color: Color) {
    Canvas(Modifier.size(14.dp)) {
        val w = size.width
        val stroke = Stroke(1.5.dp.toPx())
        drawCircle(color, radius = w * 0.33f, center = Offset(w * 0.42f, w * 0.42f), style = stroke)
        drawLine(color, Offset(w * 0.67f, w * 0.67f), Offset(w * 0.92f, w * 0.92f), stroke.width)
    }
}
