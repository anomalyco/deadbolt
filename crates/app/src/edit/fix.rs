//! Password-health Fix flow on the item edit form (`App::open_fix_form`),
//! `Copy current password` (`⇧⌘C`), and site-url-aware password generation.

use deadbolt_client::protocol::FindingKind;
use rune::{KeyEvent, Tx};

use super::{Form, editable};
use crate::model::App;

impl Form {
    /// Audited password or passphrase field for `self.kind`, when fixing or generating.
    pub fn fixable_password_field(&self) -> Option<usize> {
        let want = deadbolt_client::protocol::audited_password_field(&self.kind)?;
        self.fields.iter().position(|f| f.name == want)
    }

    /// URL currently in the form (`url` or `admin-console`), used so `Generate`
    /// honors `password-rules.json` site quirks.
    pub fn site_url(&self) -> Option<String> {
        self.fields
            .iter()
            .find(|f| f.name == "url" || f.name == "admin-console")
            .and_then(|f| f.value())
            .map(str::to_owned)
    }

    /// Saved password on `base` before this edit started, if non-empty.
    pub fn base_password(&self) -> Option<(&str, &str)> {
        let base = self.base.as_ref()?;
        let field = deadbolt_client::protocol::audited_password_field(&self.kind)?;
        let val = base.value(field).filter(|v| !v.is_empty())?;
        Some((field, val))
    }

    pub fn has_base_password(&self) -> bool {
        self.base_password().is_some()
    }
}

pub(crate) fn is_copy_current_shortcut(ev: &KeyEvent) -> bool {
    ev.is_command('c') && ev.mods.shift && !ev.mods.alt && !ev.mods.ctrl
}

impl App {
    /// Opens the selected item's edit form tailored to `kind`:
    /// - `MissingTwoFactor`: focuses `otp` without overwriting the saved password.
    /// - Password risk (`Breached`, `SiteBreach`, `Reused`, `Weak`, or `None`):
    ///   marks `form.fixing = true`, focuses the password field, generates a
    ///   site-rule-aware candidate, reveals it, and copies it to the concealed clipboard.
    pub(crate) fn open_fix_form(&mut self, kind: Option<FindingKind>) {
        if self.deleting() {
            return;
        }
        let Some(item) = self
            .detail
            .as_ref()
            .filter(|d| self.selected.as_deref() == Some(d.id.as_str()) && editable(&d.kind))
        else {
            return;
        };
        let mut form = Form::new(&item.kind, &item.label, Some(item));
        form.name.focused = false;
        form.tag_input.focused = false;
        self.edit.delete = None;
        self.search.focused = false;

        if kind == Some(FindingKind::MissingTwoFactor) {
            if let Some(at) = form.fields.iter().position(|f| f.name == "otp") {
                form.fields[at].edit.focused = true;
            }
            self.edit.form = Some(form);
            return;
        }

        form.fixing = true;
        form.copy_generated_once = true;
        if let Some(at) = form.fixable_password_field() {
            form.fields[at].edit.focused = true;
        }
        self.edit.form = Some(form);
        self.generate();
    }

    /// Copies the saved (`base`) password to the concealed clipboard without
    /// overwriting the newly generated candidate in the form (`⇧⌘C`).
    pub fn copy_base_password(&mut self, tx: &mut Tx) -> bool {
        let Some(form) = self.edit.form.as_ref() else {
            return false;
        };
        let Some((field, current)) = form.base_password() else {
            return false;
        };
        let saved = form
            .base
            .as_ref()
            .map(|b| (b.0.id.clone(), b.0.label.clone()));
        let (field_name, secret) = (field.to_owned(), current.to_owned());
        self.copy_value(saved, field_name, secret, tx);
        true
    }

    /// Opens the item's `change-urls.json` page (or its `url`) from inside the Fix form.
    pub fn open_fix_site(&mut self, tx: &mut Tx) {
        let Some(form) = self.edit.form.as_ref() else {
            return;
        };
        let id = form.id.clone();
        if let Some(id) = id {
            if self.health.item(&id).is_some() {
                self.open_health_url(&id, None, tx);
                return;
            }
        }
        if let Some(url) = form.site_url().and_then(|u| crate::keys::safe_web_url(&u))
            && let Err(e) = tx.open_url(&url)
        {
            self.notice = Some(format!("Couldn't open {url}: {e}"));
        }
    }

    /// Label for the Fix form's site button (`"Open github.com"`), if the item has a web URL.
    pub fn fix_site_label(&self, f: &Form) -> Option<String> {
        let raw = f
            .id
            .as_deref()
            .and_then(|id| {
                let ih = self.health.item(id)?;
                ih.change_url.as_deref().or(ih.site_url.as_deref())
            })
            .map(str::to_owned)
            .or_else(|| f.site_url())?;
        let url = crate::keys::safe_web_url(&raw)?;
        let parsed = url::Url::parse(&url).ok()?;
        let host = parsed.host_str()?;
        Some(format!("Open {host}"))
    }
}
