//! Drawing the Security view, the sidebar's risk badge and row dots, the item
//! page's finding callout, and formatted password dates.

use deadbolt_client::protocol::{Finding, FindingKind, RiskLevel};
use rune::{Anim, Color, El, Shadow, Transition, col, el, icon, row, spacer, text};
use rune_kit::{Button, ButtonVariant, ControlSize, Keybind, Kit};

use super::Tab;
use crate::model::App;
use crate::view::theme::{FACT, PAGE_W, TITLE, kind_icon};
use crate::view::{LIST_EDGE, hint, scroll_col, tnum};

const BLEED: f32 = 12.0;

/// Full Security pane in the detail slot (`⇧⌘H` or `⌘K` › Security).
pub fn page(s: &App, k: &Kit) -> El {
    let head = header(s, k);
    let bar = tabs(s, k);
    let body = list(s, k);

    let col_body = col()
        .key("security-col")
        .w_full()
        .max_w(PAGE_W + 2.0 * BLEED)
        .px(BLEED)
        .gap(16.0)
        .child(head)
        .children(s.health.error.as_deref().map(|err| {
            text(err.to_owned())
                .key("health-error")
                .font(k.ty.text_small)
                .color(k.c.danger.fg)
                .wrap()
                .w_full()
        }))
        .child(bar)
        .child(body);

    col()
        .key("security")
        .w_full()
        .h_full()
        .min_h(0.0)
        .child(
            scroll_col("security-scroll")
                .w_full()
                .grow(1.0)
                .min_h(0.0)
                .scroll_margin(LIST_EDGE)
                .child(
                    col()
                        .key("security-page")
                        .w_full()
                        .items_center()
                        .px(40.0 - BLEED)
                        .pt(4.0)
                        .pb(28.0)
                        .child(col_body),
                ),
        )
        .child(foot(s, k))
}

fn header(s: &App, k: &Kit) -> El {
    let sub = match &s.health.report {
        Some(r) if r.breach_last_checked.is_some() => "Checked against Have I Been Pwned",
        Some(r) if r.breach_checks_enabled => "Offline checks · Have I Been Pwned enabled",
        Some(_) => "Offline checks only",
        None => "Checking vault…",
    };
    let check_label = if s.health.checking {
        "Checking…"
    } else {
        "Check breaches"
    };
    row()
        .key("security-head")
        .w_full()
        .gap(16.0)
        .center_y()
        .child(
            col()
                .key("titles")
                .gap(2.0)
                .grow(1.0)
                .shrink()
                .min_w(0.0)
                .child(
                    text("Security")
                        .key("title")
                        .font(TITLE)
                        .color(k.c.text_strong),
                )
                .child(
                    text(sub)
                        .key("sub")
                        .font(FACT.lh(16.0))
                        .color(k.c.text_muted)
                        .truncate_fade(),
                ),
        )
        .child(
            Button::new(check_label)
                .variant(ButtonVariant::Neutral)
                .control_size(ControlSize::Regular)
                .disabled(s.health.checking)
                .on_press(|s: &mut App| s.check_breaches_now())
                .build(k)
                .key("check-breaches"),
        )
}

fn tabs(s: &App, k: &Kit) -> El {
    let list = s.health.tabs();
    let mut bar = row().key("security-tabs").w_full().gap(4.0).center_y();
    for &tab in &list {
        let on = s.health.tab == tab;
        let count = s.health.report.as_ref().map_or(0, |r| tab.count(r));
        let label_ink = if on { k.c.text_strong } else { k.c.text_muted };
        let count_ink = if count == 0 {
            k.c.text_faint
        } else if on && tab == Tab::Risks && s.health.has_danger() {
            k.c.danger.fg
        } else if on {
            k.c.text_base
        } else {
            k.c.text_muted
        };
        bar = bar.child(
            row()
                .key(format!("tab-{}", tab.key()))
                .role("tab")
                .label(format!("{} {}", tab.label(), count))
                .h(28.0)
                .px(9.0)
                .gap(5.0)
                .radius(6.0)
                .continuous_corners()
                .center_y()
                .fill(if on { k.c.layer_03 } else { Color::TRANSPARENT })
                .hover(if on { k.c.layer_03 } else { k.c.hover })
                .hover_motion(Anim::INSTANT, Anim::INSTANT)
                .on_press_tx(move |s: &mut App, tx| {
                    tx.instant();
                    s.select_health_tab(tab);
                })
                .child(text(tab.label()).font(k.ty.small_medium).color(label_ink))
                .child(
                    text(count.to_string())
                        .font(tnum(k.ty.small))
                        .color(count_ink),
                ),
        );
    }
    bar
}

fn list(s: &App, k: &Kit) -> El {
    if s.health.report.is_none() {
        return empty(
            k,
            "loading",
            "Checking passwords…",
            "Scoring passwords and checking directories in the agent.",
        );
    }
    let rows = s.health.rows();
    if rows.is_empty() {
        let (title, body) = empty_copy(s.health.tab);
        return empty(k, "clean", title, body);
    }
    let active = s.health.row.min(rows.len().saturating_sub(1));
    let mut stack = col().key("security-rows").w_full().gap(2.0).pt(4.0);
    for (i, entry) in rows.iter().enumerate() {
        stack = stack.child(finding_row(k, entry, i, i == active));
    }
    stack
}

fn empty_copy(tab: Tab) -> (&'static str, &'static str) {
    match tab {
        Tab::Risks => (
            "No password risks",
            "Saved passwords passed weak, reuse, and site-breach checks.",
        ),
        Tab::Breached => (
            "No breached credentials",
            "No saved password or login site matched known breaches.",
        ),
        Tab::Reused => (
            "No reused passwords",
            "Every saved account uses its own password.",
        ),
        Tab::Weak => (
            "No weak passwords",
            "Every saved password passed strength checks.",
        ),
        Tab::TwoFactor => (
            "No missing authenticator codes",
            "Every saved login on a TOTP-capable site has two-factor authentication.",
        ),
        Tab::Passkeys => (
            "No passkey upgrades waiting",
            "Every passkey-capable login already has a passkey.",
        ),
        Tab::Ignored => ("Nothing ignored", "No warnings are silenced."),
    }
}

fn empty(k: &Kit, key: &str, title: &str, body: &str) -> El {
    col()
        .key(key)
        .w_full()
        .py(20.0)
        .gap(4.0)
        .child(text(title).font(k.ty.ui_medium).color(k.c.text_base))
        .child(
            text(body)
                .font(k.ty.text_small)
                .color(k.c.text_muted)
                .wrap()
                .w_full(),
        )
}

fn finding_row(k: &Kit, entry: &super::RowEntry<'_>, i: usize, on: bool) -> El {
    let id = entry.item.id.clone();
    let kind = entry.finding.kind();
    let is_ignored = entry.is_ignored;
    let summary_ink = if is_ignored {
        k.c.text_muted
    } else {
        match kind {
            FindingKind::Breached | FindingKind::SiteBreach | FindingKind::Reused => k.c.danger.fg,
            FindingKind::Weak => k.c.warning.fg,
            FindingKind::MissingTwoFactor | FindingKind::PasskeyAvailable => k.c.text_muted,
        }
    };
    let dot_ink = (!is_ignored && kind.is_risk()).then(|| match kind {
        FindingKind::Weak => k.c.warning.icon,
        _ => k.c.danger.icon,
    });

    let mut top = row().key("top").gap(6.0).center_y().min_w(0.0);
    top = top.child(
        text(entry.item.label.clone())
            .font(k.ty.ui_medium)
            .color(k.c.text_strong)
            .truncate(),
    );
    if let Some(detail) = &entry.item.detail {
        top = top.child(
            text(detail.clone())
                .font(k.ty.small)
                .color(k.c.text_faint)
                .shrink()
                .truncate(),
        );
    }

    let fix_label = if is_ignored {
        "Restore"
    } else {
        match kind {
            FindingKind::MissingTwoFactor => "Set up 2FA",
            FindingKind::PasskeyAvailable => "Open site",
            _ => "Fix",
        }
    };

    let (fix_id, ignore_id) = (id.clone(), id.clone());
    let mut actions = row().key("actions").gap(6.0).center_y();
    if on {
        if !is_ignored {
            actions = actions.child(
                Button::new("Ignore")
                    .variant(ButtonVariant::GhostMuted)
                    .control_size(ControlSize::Small)
                    .on_press(move |s: &mut App| s.set_health_ignored(&ignore_id, kind, true))
                    .build(k)
                    .key("ignore"),
            );
        }
        actions = actions.child(
            Button::new(fix_label)
                .variant(ButtonVariant::Neutral)
                .control_size(ControlSize::Small)
                .on_press_tx(move |s: &mut App, tx| {
                    if is_ignored {
                        s.set_health_ignored(&fix_id, kind, false);
                    } else {
                        s.fix_finding(&fix_id, Some(kind), tx);
                    }
                })
                .build(k)
                .key("fix"),
        );
    }

    let select_id = id;
    row()
        .key(format!("health-row-{i}"))
        .role("option")
        .label(format!("{}, {}", entry.item.label, entry.finding.summary()))
        .w_full()
        .min_h(52.0)
        .ml(-BLEED)
        .mr(-BLEED)
        .px(BLEED)
        .py(8.0)
        .gap(10.0)
        .radius(10.0)
        .continuous_corners()
        .center_y()
        .fill(if on { k.c.layer_02 } else { Color::TRANSPARENT })
        .hover(if on { k.c.layer_02 } else { k.c.hover })
        .hover_motion(Anim::INSTANT, Anim::INSTANT)
        .on_press_tx(move |s: &mut App, tx| {
            tx.instant();
            if s.health.row == i {
                if is_ignored {
                    s.set_health_ignored(&select_id, kind, false);
                } else {
                    s.fix_finding(&select_id, Some(kind), tx);
                }
            } else {
                s.health.row = i;
            }
        })
        .child(
            icon(kind_icon(&entry.item.kind), 16.0)
                .color(if on { k.c.icon_base } else { k.c.icon_muted }),
        )
        .child(
            col()
                .key("words")
                .gap(2.0)
                .grow(1.0)
                .shrink()
                .min_w(0.0)
                .child(top)
                .child(
                    row()
                        .gap(6.0)
                        .center_y()
                        .min_w(0.0)
                        .children(dot_ink.map(|ink| el().size(6.0, 6.0).radius(3.0).fill(ink)))
                        .child(
                            text(entry.finding.summary())
                                .font(FACT.lh(15.0))
                                .color(summary_ink)
                                .truncate_fade(),
                        ),
                ),
        )
        .child(actions)
}

fn foot(s: &App, k: &Kit) -> El {
    let tab_keys = if s.health.tabs().len() > 6 {
        "1–7"
    } else {
        "1–6"
    };
    let has_rows = !s.health.rows().is_empty();
    let on_ignored = s.health.tab == Tab::Ignored;
    let mut hints = vec![hint(k, "h-tabs", &[tab_keys], "Category")];
    if has_rows {
        hints.push(hint(
            k,
            "h-fix",
            &["⏎"],
            if on_ignored { "Restore" } else { "Fix" },
        ));
        if !on_ignored {
            hints.push(hint(k, "h-open", &["O"], "Open site"));
            hints.push(hint(k, "h-ignore", &["I"], "Ignore"));
        }
    }
    hints.push(hint(k, "h-esc", &["esc"], "Back"));

    row()
        .key("security-hints")
        .w_full()
        .h(36.0)
        .px(20.0)
        .gap(16.0)
        .center_y()
        .child(
            row()
                .key("h-keys")
                .shrink()
                .min_w(0.0)
                .pr(16.0)
                .gap(16.0)
                .center_y()
                .clip_fade(0.0, 0.0, 16.0, 0.0)
                .children(hints),
        )
        .child(spacer())
        .child(hint(k, "h-actions", &["⌘", "K"], "Actions"))
        .child(
            row()
                .key("h-help")
                .label("Shortcuts")
                .child(Keybind::new(&["?"]).build(k)),
        )
}

/// Compact risk indicator inside the fixed-height `vault-head` sidebar row.
/// Returns `None` when risk count is 0 and Security isn't open, causing zero
/// layout shift when health arrives asynchronously after unlock.
pub fn vault_head_badge(s: &App, k: &Kit) -> Option<El> {
    if !s.loaded {
        return None;
    }
    let risks = s.health.risk_count();
    if risks == 0 && !s.security_open() {
        return None;
    }
    let (dot_ink, text_ink, words) = if risks > 0 {
        let danger = s.health.has_danger();
        let dot = if danger {
            k.c.danger.icon
        } else {
            k.c.warning.icon
        };
        let fg = if s.security_open() {
            k.c.text_strong
        } else if danger {
            k.c.danger.fg
        } else {
            k.c.warning.fg
        };
        let noun = if risks == 1 { "risk" } else { "risks" };
        (Some(dot), fg, format!("{risks} {noun}"))
    } else {
        (None, k.c.text_strong, "Security".to_owned())
    };
    Some(
        row()
            .key("vault-risks")
            .role("button")
            .label(format!("{words}, open Security"))
            .gap(5.0)
            .mr(8.0)
            .center_y()
            .on_press_tx(|s: &mut App, tx| {
                tx.instant();
                s.toggle_security();
            })
            .children(dot_ink.map(|ink| el().size(6.0, 6.0).radius(3.0).fill(ink)))
            .child(text(words).font(tnum(k.ty.small_medium)).color(text_ink)),
    )
}

/// Compact finding banner rendered on an item's detail page when the item has
/// an active finding (`Breached`, `SiteBreach`, `Reused`, `Weak`, `MissingTwoFactor`,
/// or `PasskeyAvailable`).
pub fn item_callout(s: &App, k: &Kit, item_id: &str) -> Option<El> {
    let finding: &Finding = s.health.item(item_id)?.findings.first()?;
    let kind = finding.kind();
    let (bg, border, dot_ink, fg) = match kind {
        FindingKind::Breached | FindingKind::SiteBreach | FindingKind::Reused => (
            k.c.danger.bg,
            k.c.danger.border,
            k.c.danger.icon,
            k.c.danger.fg,
        ),
        FindingKind::Weak => (
            k.c.warning.bg,
            k.c.warning.border,
            k.c.warning.icon,
            k.c.warning.fg,
        ),
        FindingKind::MissingTwoFactor | FindingKind::PasskeyAvailable => {
            (k.c.layer_01, k.c.border_weak, k.c.icon_muted, k.c.text_base)
        }
    };
    let primary_label = match kind {
        FindingKind::MissingTwoFactor => "Set up 2FA",
        FindingKind::PasskeyAvailable => "Open site",
        _ => "Change password",
    };
    let (fix_id, ignore_id) = (item_id.to_owned(), item_id.to_owned());
    Some(
        row()
            .key("item-health")
            .role("status")
            .w_full()
            .mb(16.0)
            .padding(12.0)
            .gap(10.0)
            .radius(k.radius.md)
            .continuous_corners()
            .center_y()
            .fill(bg)
            .box_shadow(Shadow {
                spread: 1.0,
                color: border,
                ..Shadow::default()
            })
            .transition(Transition::opacity())
            .child(el().size(6.0, 6.0).radius(3.0).fill(dot_ink))
            .child(
                text(finding.summary())
                    .key("summary")
                    .font(k.ty.text_small_medium)
                    .color(fg)
                    .grow(1.0)
                    .shrink()
                    .min_w(0.0)
                    .wrap(),
            )
            .child(
                Button::new("Ignore")
                    .variant(ButtonVariant::GhostMuted)
                    .control_size(ControlSize::Small)
                    .on_press(move |s: &mut App| s.set_health_ignored(&ignore_id, kind, true))
                    .build(k)
                    .key("health-ignore"),
            )
            .child(
                Button::new(primary_label)
                    .variant(ButtonVariant::Neutral)
                    .control_size(ControlSize::Small)
                    .on_press_tx(move |s: &mut App, tx| s.fix_finding(&fix_id, Some(kind), tx))
                    .build(k)
                    .key("health-fix"),
            ),
    )
}

/// Compact risk dot for a sidebar row, `None` when the item has no active risk.
pub fn row_dot(k: &Kit, risk: Option<RiskLevel>) -> Option<El> {
    let ink = match risk? {
        RiskLevel::Danger => k.c.danger.icon,
        RiskLevel::Caution => k.c.warning.icon,
    };
    Some(
        el().key("risk-dot")
            .size(6.0, 6.0)
            .radius(3.0)
            .fill(ink),
    )
}

/// Formats `YYYY-MM-DD` as `"Oct 30, 2026"`.
pub fn human_date(iso: &str) -> String {
    let mut parts = iso.split('-');
    let (Some(year), Some(month), Some(day)) = (parts.next(), parts.next(), parts.next()) else {
        return iso.to_owned();
    };
    let month_name = match month {
        "01" => "Jan",
        "02" => "Feb",
        "03" => "Mar",
        "04" => "Apr",
        "05" => "May",
        "06" => "Jun",
        "07" => "Jul",
        "08" => "Aug",
        "09" => "Sep",
        "10" => "Oct",
        "11" => "Nov",
        "12" => "Dec",
        _ => return iso.to_owned(),
    };
    let day_num = day.trim_start_matches('0');
    let day_num = if day_num.is_empty() { "0" } else { day_num };
    format!("{month_name} {day_num}, {year}")
}
