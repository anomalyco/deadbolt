//! Password health state, Security view navigation, and Fix flow transitions.
//! The app holds only finding flags, counts, and item references; secret values
//! and password hashes never leave the agent.

pub mod view;

use deadbolt_client::Paths;
use deadbolt_client::protocol::{
    Command, Finding, FindingKind, HealthReport, ItemHealth, Reply, RiskLevel,
};
use rune::{Key, KeyEvent, Tx};

use crate::agent::{Done, Failure, Job};
use crate::keys::{plain, step};
use crate::model::{App, Screen};

/// Category tabs in the Security view (`1`–`6`, plus `7` when items have
/// ignored findings).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum Tab {
    #[default]
    Risks,
    Breached,
    Reused,
    Weak,
    TwoFactor,
    Passkeys,
    Ignored,
}

impl Tab {
    pub fn label(self) -> &'static str {
        match self {
            Self::Risks => "Risks",
            Self::Breached => "Breached",
            Self::Reused => "Reused",
            Self::Weak => "Weak",
            Self::TwoFactor => "2FA",
            Self::Passkeys => "Passkeys",
            Self::Ignored => "Ignored",
        }
    }

    pub fn key(self) -> &'static str {
        match self {
            Self::Risks => "risks",
            Self::Breached => "breached",
            Self::Reused => "reused",
            Self::Weak => "weak",
            Self::TwoFactor => "2fa",
            Self::Passkeys => "passkeys",
            Self::Ignored => "ignored",
        }
    }

    pub fn count(self, r: &HealthReport) -> usize {
        let c = &r.counts;
        match self {
            Self::Risks => c.risk_items,
            Self::Breached => c.breached + c.site_breach,
            Self::Reused => c.reused,
            Self::Weak => c.weak,
            Self::TwoFactor => c.missing_two_factor,
            Self::Passkeys => c.passkeys_available,
            Self::Ignored => c.ignored,
        }
    }

    fn matches(self, f: &Finding) -> bool {
        match self {
            Self::Risks => f.kind().is_risk(),
            Self::Breached => matches!(f.kind(), FindingKind::Breached | FindingKind::SiteBreach),
            Self::Reused => f.kind() == FindingKind::Reused,
            Self::Weak => f.kind() == FindingKind::Weak,
            Self::TwoFactor => f.kind() == FindingKind::MissingTwoFactor,
            Self::Passkeys => f.kind() == FindingKind::PasskeyAvailable,
            Self::Ignored => true,
        }
    }
}

/// One visible row in the Security view's current tab.
#[derive(Clone, Debug)]
pub struct RowEntry<'a> {
    pub item: &'a ItemHealth,
    pub finding: &'a Finding,
    pub is_ignored: bool,
}

#[derive(Default)]
pub struct Health {
    pub open: bool,
    pub tab: Tab,
    pub row: usize,
    pub report: Option<HealthReport>,
    /// An online HIBP check is running.
    pub checking: bool,
    /// Enabling or disabling `breach_checks` in Settings is in flight.
    pub setting_busy: bool,
    pub error: Option<String>,
    /// Item id waiting for `Job::Get` values so `Fix` can open its edit form.
    pub pending_fix: Option<(String, Option<FindingKind>)>,
    seq: u64,
}

impl Health {
    pub(crate) fn forget(&mut self) {
        let seq = self.seq + 1;
        *self = Self {
            seq,
            ..Self::default()
        };
    }

    pub fn risk_count(&self) -> usize {
        self.report.as_ref().map_or(0, |r| r.counts.risk_items)
    }

    pub fn has_danger(&self) -> bool {
        self.report.as_ref().is_some_and(|r| {
            r.counts.breached > 0 || r.counts.site_breach > 0 || r.counts.reused > 0
        })
    }

    pub fn breach_checks_enabled(&self) -> bool {
        self.report
            .as_ref()
            .is_some_and(|r| r.breach_checks_enabled)
    }

    pub fn risk_for(&self, id: &str) -> Option<RiskLevel> {
        self.item(id)?.risk
    }

    pub fn item(&self, id: &str) -> Option<&ItemHealth> {
        self.report.as_ref()?.items.iter().find(|i| i.id == id)
    }

    pub fn primary_risk(&self, id: &str) -> Option<&Finding> {
        self.item(id)?.findings.iter().find(|f| f.kind().is_risk())
    }

    pub fn password_changed_for(&self, id: &str) -> Option<&str> {
        self.item(id)?.password_changed.as_deref()
    }

    pub fn change_url_for(&self, id: &str) -> Option<&str> {
        self.item(id)?.change_url.as_deref()
    }

    pub fn tabs(&self) -> Vec<Tab> {
        let mut out = vec![
            Tab::Risks,
            Tab::Breached,
            Tab::Reused,
            Tab::Weak,
            Tab::TwoFactor,
            Tab::Passkeys,
        ];
        if self.report.as_ref().is_some_and(|r| r.counts.ignored > 0) || self.tab == Tab::Ignored {
            out.push(Tab::Ignored);
        }
        out
    }

    pub fn rows(&self) -> Vec<RowEntry<'_>> {
        let Some(report) = &self.report else {
            return Vec::new();
        };
        let mut out = Vec::new();
        for item in &report.items {
            if self.tab == Tab::Ignored {
                for f in &item.ignored {
                    out.push(RowEntry {
                        item,
                        finding: f,
                        is_ignored: true,
                    });
                }
            } else if self.tab == Tab::Risks {
                if let Some(f) = item.findings.iter().find(|f| f.kind().is_risk()) {
                    out.push(RowEntry {
                        item,
                        finding: f,
                        is_ignored: false,
                    });
                }
            } else {
                for f in item.findings.iter().filter(|f| self.tab.matches(f)) {
                    out.push(RowEntry {
                        item,
                        finding: f,
                        is_ignored: false,
                    });
                }
            }
        }
        out
    }
}

pub fn is_shortcut(ev: &KeyEvent) -> bool {
    ev.is_command('h') && ev.mods.shift && !ev.mods.alt && !ev.mods.ctrl
}

impl App {
    pub fn security_open(&self) -> bool {
        self.health.open
    }

    pub fn open_security(&mut self) {
        if self.screen != Screen::Vault
            || self.panel.is_some()
            || self.installing()
            || self.deleting()
            || !self.leave_edit()
        {
            return;
        }
        self.cancel_delete();
        self.cancel_import();
        self.close_settings();
        self.trash.forget();
        self.health.open = true;
        self.health.error = None;
        self.nav = crate::keys::Nav::default();
        self.search.focused = false;
        if self.health.report.is_none() {
            self.request_health(false);
        }
    }

    pub fn close_security(&mut self) {
        self.health.open = false;
        self.health.row = 0;
        self.health.error = None;
    }

    pub fn toggle_security(&mut self) {
        if self.health.open {
            self.close_security();
            self.search.focused = true;
        } else {
            self.open_security();
        }
    }

    pub fn select_health_tab(&mut self, tab: Tab) {
        if self.health.tab != tab {
            self.health.tab = tab;
            self.health.row = 0;
        }
    }

    pub fn request_health(&mut self, online: bool) {
        if self.panel.is_some() || self.screen != Screen::Vault {
            return;
        }
        self.health.seq += 1;
        if online {
            self.health.checking = true;
            self.health.error = None;
        }
        self.agent.send(Job::Health {
            seq: self.health.seq,
            online,
        });
    }

    pub fn check_breaches_now(&mut self) {
        if !self.health.checking {
            self.request_health(true);
        }
    }

    pub fn toggle_breach_checks(&mut self) {
        if self.health.setting_busy {
            return;
        }
        let next = !self.health.breach_checks_enabled();
        self.health.setting_busy = true;
        self.health.error = None;
        if let Some(r) = &mut self.health.report {
            r.breach_checks_enabled = next;
        }
        self.health.seq += 1;
        self.agent.send(Job::BreachChecksSet {
            enabled: next,
            seq: self.health.seq,
        });
    }

    pub fn set_health_ignored(&mut self, id: &str, kind: FindingKind, ignored: bool) {
        self.health.seq += 1;
        self.health.error = None;
        self.agent.send(Job::HealthIgnore {
            id: id.to_owned(),
            kind,
            ignored,
            seq: self.health.seq,
        });
    }

    pub(crate) fn on_health(
        &mut self,
        seq: u64,
        result: Result<HealthReport, Failure>,
        tx: &mut Tx,
    ) {
        if seq != self.health.seq || !self.accepts_vault_replies() {
            return;
        }
        self.health.checking = false;
        self.health.setting_busy = false;
        match result {
            Ok(report) => {
                let had_ignored = report.counts.ignored > 0;
                self.health.report = Some(report);
                self.health.error = None;
                if self.health.tab == Tab::Ignored && !had_ignored {
                    self.health.tab = Tab::Risks;
                }
                let max_row = self.health.rows().len().saturating_sub(1);
                self.health.row = self.health.row.min(max_row);
            }
            Err(failure) if failure.locked() => self.on_locked(tx),
            Err(failure) => {
                self.health.error = Some(crate::onboarding::sentence(&failure.message));
            }
        }
    }

    pub(crate) fn on_breach_checks_set(
        &mut self,
        seq: u64,
        enabled: bool,
        result: Result<(), Failure>,
        tx: &mut Tx,
    ) {
        if seq != self.health.seq || !self.accepts_vault_replies() {
            return;
        }
        self.health.setting_busy = false;
        match result {
            Ok(()) => {
                if let Some(r) = &mut self.health.report {
                    r.breach_checks_enabled = enabled;
                }
                self.request_health(false);
            }
            Err(failure) if failure.locked() => self.on_locked(tx),
            Err(failure) => {
                if let Some(r) = &mut self.health.report {
                    r.breach_checks_enabled = !enabled;
                }
                self.health.error = Some(crate::onboarding::sentence(&failure.message));
            }
        }
    }

    /// Starts the Fix flow for `id` (for `kind`, or the item's password when
    /// `None`): opens the site's setup docs for 2FA/passkeys, or opens the
    /// item's edit form with a site-rule-aware generated password ready.
    pub fn fix_finding(&mut self, id: &str, kind: Option<FindingKind>, tx: &mut Tx) {
        if !self.leave_edit() {
            return;
        }
        let doc_url = self.health.item(id).and_then(|ih| match kind {
            Some(FindingKind::MissingTwoFactor) => ih
                .findings
                .iter()
                .find_map(|f| match f {
                    Finding::MissingTwoFactor { doc_url } => doc_url.clone(),
                    _ => None,
                })
                .or_else(|| ih.site_url.clone()),
            Some(FindingKind::PasskeyAvailable) => ih
                .findings
                .iter()
                .find_map(|f| match f {
                    Finding::PasskeyAvailable { doc_url, .. } => doc_url.clone(),
                    _ => None,
                })
                .or_else(|| ih.site_url.clone()),
            _ => None,
        });

        if matches!(kind, Some(FindingKind::PasskeyAvailable)) {
            if let Some(url) = doc_url.and_then(|u| crate::keys::safe_web_url(&u))
                && let Err(e) = tx.open_url(&url)
            {
                self.notice = Some(format!("Couldn't open {url}: {e}"));
            }
            return;
        }
        if matches!(kind, Some(FindingKind::MissingTwoFactor))
            && let Some(url) = doc_url.and_then(|u| crate::keys::safe_web_url(&u))
            && let Err(e) = tx.open_url(&url)
        {
            self.notice = Some(format!("Couldn't open {url}: {e}"));
        }

        tx.instant();
        self.close_security();
        self.close_settings();
        if !self.visible().iter().any(|i| i.id == id) {
            self.search.clear();
        }
        self.select_by_hand(id.to_owned(), 0);
        if self.detail.as_ref().is_some_and(|d| d.id == id) {
            self.open_fix_form(kind);
        } else {
            self.health.pending_fix = Some((id.to_owned(), kind));
        }
    }

    pub(crate) fn finish_pending_fix(&mut self, id: &str) {
        if self
            .health
            .pending_fix
            .as_ref()
            .is_some_and(|(want, _)| want == id)
        {
            let (_, kind) = self.health.pending_fix.take().unwrap_or_default();
            self.open_fix_form(kind);
        }
    }

    /// Opens the website or change-password page for `item`.
    pub fn open_health_url(&mut self, id: &str, kind: Option<FindingKind>, tx: &mut Tx) {
        let Some(ih) = self.health.item(id) else {
            return;
        };
        let raw = match kind {
            Some(FindingKind::MissingTwoFactor) => ih
                .findings
                .iter()
                .find_map(|f| match f {
                    Finding::MissingTwoFactor { doc_url } => doc_url.as_deref(),
                    _ => None,
                })
                .or(ih.site_url.as_deref()),
            Some(FindingKind::PasskeyAvailable) => ih
                .findings
                .iter()
                .find_map(|f| match f {
                    Finding::PasskeyAvailable { doc_url, .. } => doc_url.as_deref(),
                    _ => None,
                })
                .or(ih.site_url.as_deref()),
            _ => ih.change_url.as_deref().or(ih.site_url.as_deref()),
        };
        if let Some(url) = raw.and_then(crate::keys::safe_web_url)
            && let Err(e) = tx.open_url(&url)
        {
            self.notice = Some(format!("Couldn't open {url}: {e}"));
        }
    }

    /// Keys while the Security view shows in place of the item pane.
    pub(crate) fn security_key(&mut self, ev: &KeyEvent, tx: &mut Tx) -> bool {
        let tabs = self.health.tabs();
        let rows_len = self.health.rows().len();
        let last = rows_len.saturating_sub(1);
        let at = self.health.row.min(last);

        if ev.key == Key::Escape || is_shortcut(ev) {
            tx.instant();
            self.close_security();
            self.search.focused = true;
            return true;
        }
        if let Some(by) = step(ev, true) {
            tx.instant();
            let next = (at as isize + by).clamp(0, last as isize) as usize;
            self.health.row = next;
            tx.scroll_into_view(format!("health-row-{next}"));
            return true;
        }
        if plain(ev) {
            match &ev.key {
                Key::Text(t) if matches!(t.as_bytes(), [b'1'..=b'7']) => {
                    let idx = (t.as_bytes()[0] - b'1') as usize;
                    if let Some(&tab) = tabs.get(idx) {
                        tx.instant();
                        self.select_health_tab(tab);
                    }
                    return true;
                }
                Key::Left => {
                    if let Some(pos) = tabs.iter().position(|t| *t == self.health.tab) {
                        tx.instant();
                        let prev = pos.checked_sub(1).unwrap_or(tabs.len() - 1);
                        self.select_health_tab(tabs[prev]);
                    }
                    return true;
                }
                Key::Right => {
                    if let Some(pos) = tabs.iter().position(|t| *t == self.health.tab) {
                        tx.instant();
                        self.select_health_tab(tabs[(pos + 1) % tabs.len()]);
                    }
                    return true;
                }
                Key::Text(t) if t == "[" => {
                    if let Some(pos) = tabs.iter().position(|t| *t == self.health.tab) {
                        tx.instant();
                        let prev = pos.checked_sub(1).unwrap_or(tabs.len() - 1);
                        self.select_health_tab(tabs[prev]);
                    }
                    return true;
                }
                Key::Text(t) if t == "]" => {
                    if let Some(pos) = tabs.iter().position(|t| *t == self.health.tab) {
                        tx.instant();
                        self.select_health_tab(tabs[(pos + 1) % tabs.len()]);
                    }
                    return true;
                }
                Key::Enter => {
                    let target = self
                        .health
                        .rows()
                        .get(at)
                        .map(|r| (r.item.id.clone(), r.finding.kind(), r.is_ignored));
                    if let Some((id, kind, is_ignored)) = target {
                        if is_ignored {
                            self.set_health_ignored(&id, kind, false);
                        } else {
                            self.fix_finding(&id, Some(kind), tx);
                        }
                    }
                    return true;
                }
                Key::Text(t) if t == "o" => {
                    let target = self
                        .health
                        .rows()
                        .get(at)
                        .map(|r| (r.item.id.clone(), r.finding.kind()));
                    if let Some((id, kind)) = target {
                        self.open_health_url(&id, Some(kind), tx);
                    }
                    return true;
                }
                Key::Text(t) if t == "i" => {
                    let target = self
                        .health
                        .rows()
                        .get(at)
                        .map(|r| (r.item.id.clone(), r.finding.kind(), r.is_ignored));
                    if let Some((id, kind, is_ignored)) = target {
                        self.set_health_ignored(&id, kind, !is_ignored);
                    }
                    return true;
                }
                Key::Tab => return false,
                _ => {}
            }
        }
        true
    }
}

pub(crate) async fn load(paths: &Paths, seq: u64, online: bool) -> Done {
    let command = Command::Health {
        vault: None,
        online,
    };
    let result = crate::agent::call(paths, command, |r| match r {
        Reply::Health { report } => Some(report),
        _ => None,
    })
    .await;
    Done::Health { seq, result }
}

pub(crate) async fn set_ignored(
    paths: &Paths,
    id: String,
    kind: FindingKind,
    ignored: bool,
    seq: u64,
) -> Done {
    let command = Command::HealthIgnore {
        vault: None,
        query: vec![id],
        kind,
        ignored,
    };
    let result = crate::agent::call(paths, command, |r| match r {
        Reply::Health { report } => Some(report),
        _ => None,
    })
    .await;
    Done::Health { seq, result }
}

pub(crate) async fn set_breach_checks(paths: &Paths, enabled: bool, seq: u64) -> Done {
    let command = Command::BreachChecksSet { enabled };
    let result = deadbolt_client::simple(paths, command)
        .await
        .map(drop)
        .map_err(Failure::from);
    Done::BreachChecksSet {
        seq,
        enabled,
        result,
    }
}
