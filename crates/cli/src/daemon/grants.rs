//! Agent sign-ins (`docs/agent-control.md`, "Standing grants"): paired agent
//! clients, such as Browse's relay, and the standing grants the user gave
//! them. A client proves itself with a token on every request; the daemon
//! keeps only the token's SHA-256. A grant names one client, a site, at most
//! one login, the fields it may fill and whether it may sign in with the
//! site's passkeys, and maybe an expiry.
//!
//! Clients and grants live in this device's encrypted store, never in a
//! vault: they don't sync. A token is a credential for this computer's
//! relay, so another device's copy of it would be one more place to steal
//! it from, and every device asks its own user before it trusts a client.

use std::time::Duration;

use anyhow::{Result, anyhow, bail};
use deadbolt_core::Item;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use zeroize::Zeroizing;

use super::autofill;
use super::items::label;
use super::passkeys;
use super::session::{self, Loaded, clean_name, get_json, hex, set_json};
use super::{Conversation, Daemon, ErrorCode, fail};
use crate::browser::host::Bucket;
use crate::client::DaemonError;
use crate::protocol::{
    ActivityEntry, AgentClientInfo, AgentGrantInfo, AgentLogin, AgentPasskey, CallerClass,
    CallerInfo, ClientAuth, Command, Fill, LoginRef, NotGranted, Reply, Secret, SiteValues, Verify,
};
use crate::site::Site;
use crate::webauthn;

const META_CLIENTS: &str = "cli/agent-clients";
const META_GRANTS: &str = "cli/agent-grants";
/// The most clients and grants kept, so a store can't fill up with them.
const MAX_CLIENTS: usize = 32;
const MAX_GRANTS: usize = 256;

#[derive(Debug, Clone, Serialize, Deserialize)]
struct Client {
    id: String,
    name: String,
    /// SHA-256 of the token, hex.
    token_sha256: String,
    created: u64,
    #[serde(default)]
    last_used: Option<u64>,
}

impl Client {
    fn info(&self) -> AgentClientInfo {
        AgentClientInfo {
            id: self.id.clone(),
            name: self.name.clone(),
            created: self.created,
            last_used: self.last_used,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct Grant {
    id: String,
    client_id: String,
    /// A registrable domain, or an exact origin (it has a scheme); `None`
    /// for every site.
    #[serde(default)]
    site: Option<String>,
    login: Option<LoginRef>,
    login_label: Option<String>,
    fields: Vec<Fill>,
    passkeys: bool,
    created: u64,
    expires_at: Option<u64>,
}

impl Grant {
    fn live(&self, now: u64) -> bool {
        self.expires_at.is_none_or(|at| now < at)
    }

    /// Whether the grant is for the page at `origin`: the page's own
    /// origin, a page on the grant's site, or any page for a grant of every
    /// site. Which site a login fills on is still decided by its URLs.
    fn covers_origin(&self, origin: &str) -> bool {
        match &self.site {
            None => true,
            Some(site) if site.contains("://") => {
                canonical_origin(origin).is_some_and(|o| &o == site)
            }
            Some(site) => Site::from_origin(origin).is_ok_and(|s| &s.domain == site),
        }
    }

    /// "kit on github.com", "github.com", "every site".
    fn scope(&self) -> String {
        let site = self.site.as_deref().unwrap_or("every site");
        match &self.login_label {
            Some(login) => format!("{login} on {site}"),
            None => site.to_string(),
        }
    }

    fn covers_login(&self, login: &LoginRef) -> bool {
        self.login.as_ref().is_none_or(|l| l == login)
    }

    fn info(&self, clients: &[Client], now: u64) -> AgentGrantInfo {
        AgentGrantInfo {
            id: self.id.clone(),
            client_id: self.client_id.clone(),
            client_name: clients
                .iter()
                .find(|c| c.id == self.client_id)
                .map(|c| c.name.clone()),
            site: self.site.clone(),
            login: self.login.clone(),
            login_label: self.login_label.clone(),
            fields: self.fields.clone(),
            passkeys: self.passkeys,
            created: self.created,
            expires_at: self.expires_at,
            expired: !self.live(now),
        }
    }
}

fn clients(s: &Loaded) -> Result<Vec<Client>> {
    Ok(get_json(&s.store, META_CLIENTS)?.unwrap_or_default())
}

fn grants(s: &Loaded) -> Result<Vec<Grant>> {
    Ok(get_json(&s.store, META_GRANTS)?.unwrap_or_default())
}

pub(super) fn random_hex<const N: usize>() -> Result<String> {
    let mut bytes = [0u8; N];
    getrandom::fill(&mut bytes).map_err(|e| anyhow!("OS random number generator failed: {e}"))?;
    Ok(hex(&bytes))
}

fn sha256_hex(token: &str) -> String {
    hex(&Sha256::digest(token.as_bytes()))
}

/// Constant-time: every byte is compared, whatever differs first.
fn same(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len() && a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

/// `https://app.example.com` for any URL on that origin.
fn canonical_origin(origin: &str) -> Option<String> {
    let url = url::Url::parse(origin).ok()?;
    let origin = url.origin();
    origin.is_tuple().then(|| origin.ascii_serialization())
}

/// The one id `query` names: the whole id, or a unique prefix of at
/// least 4 characters.
pub(super) fn pick<'a>(
    ids: impl Iterator<Item = &'a str>,
    query: &str,
    what: &str,
) -> Result<String> {
    let query = query.trim().to_ascii_lowercase();
    let found: Vec<&str> = ids
        .filter(|id| *id == query || (query.len() >= 4 && id.starts_with(&query)))
        .collect();
    match found.as_slice() {
        [id] => Ok((*id).to_string()),
        [] => Err(fail(ErrorCode::NotFound, format!("no {what} {query}"))),
        _ => Err(fail(
            ErrorCode::Failed,
            format!("{query} names several {what}s; give more of the id"),
        )),
    }
}

/// Pairs a new client named `name`; returns it and its token.
pub fn add_client(s: &Loaded, name: &str, now: u64) -> Result<(AgentClientInfo, Secret)> {
    let name = clean_name(name);
    if name.is_empty() {
        bail!("an agent client needs a name");
    }
    let mut all = clients(s)?;
    if all.len() >= MAX_CLIENTS {
        bail!("{MAX_CLIENTS} agent clients are paired already; remove one first");
    }
    let token = Secret::new(random_hex::<32>()?);
    let client = Client {
        id: random_hex::<8>()?,
        name,
        token_sha256: sha256_hex(token.expose()),
        created: now,
        last_used: None,
    };
    let info = client.info();
    all.push(client);
    set_json(&s.store, META_CLIENTS, &all)?;
    Ok((info, token))
}

pub fn list_clients(s: &Loaded) -> Result<Vec<AgentClientInfo>> {
    Ok(clients(s)?.iter().map(Client::info).collect())
}

/// Unpairs a client by id (or a unique prefix) and drops its grants.
/// Returns its id and name.
pub fn remove_client(s: &Loaded, id: &str) -> Result<(String, String)> {
    let mut all = clients(s)?;
    let id = pick(all.iter().map(|c| c.id.as_str()), id, "agent client")?;
    let name = all
        .iter()
        .find(|c| c.id == id)
        .map(|c| c.name.clone())
        .unwrap_or_default();
    all.retain(|c| c.id != id);
    let mut kept = grants(s)?;
    kept.retain(|g| g.client_id != id);
    set_json(&s.store, META_GRANTS, &kept)?;
    set_json(&s.store, META_CLIENTS, &all)?;
    Ok((id, name))
}

/// The paired client `auth` proves, else `forbidden`.
pub fn authenticate(s: &Loaded, auth: &ClientAuth) -> Result<AgentClientInfo> {
    let hash = sha256_hex(auth.token.expose());
    clients(s)?
        .iter()
        .find(|c| same(c.id.as_bytes(), auth.id.as_bytes()))
        .filter(|c| same(c.token_sha256.as_bytes(), hash.as_bytes()))
        .map(Client::info)
        .ok_or_else(|| {
            fail(
                ErrorCode::Forbidden,
                "this agent client isn't paired with Deadbolt; pair it again",
            )
        })
}

/// The client `query` names (its id or a unique prefix of it).
fn client(s: &Loaded, query: &str) -> Result<AgentClientInfo> {
    let all = clients(s)?;
    let id = pick(all.iter().map(|c| c.id.as_str()), query, "agent client")?;
    all.iter()
        .find(|c| c.id == id)
        .map(Client::info)
        .ok_or_else(|| fail(ErrorCode::NotFound, format!("no agent client {query}")))
}

/// The name of the client `id`, for Activity.
pub fn client_name(s: &Loaded, id: &str) -> Option<String> {
    clients(s)
        .ok()?
        .into_iter()
        .find(|c| c.id == id)
        .map(|c| c.name)
}

fn used(s: &Loaded, id: &str, now: u64) -> Result<()> {
    let mut all = clients(s)?;
    if let Some(client) = all.iter_mut().find(|c| c.id == id) {
        client.last_used = Some(now);
        set_json(&s.store, META_CLIENTS, &all)?;
    }
    Ok(())
}

/// A grant's site as given: an origin with a scheme stays an exact
/// origin; anything else is a host, kept as its registrable domain.
pub fn grant_site(site: &str) -> Result<String> {
    let site = site.trim().to_ascii_lowercase();
    if site.contains("://") {
        let origin = canonical_origin(&site).ok_or_else(|| anyhow!("{site} isn't an origin"))?;
        Site::from_origin(&origin).map_err(|reason| anyhow!("{site}: {reason}"))?;
        return Ok(origin);
    }
    let host = site.strip_suffix('/').unwrap_or(&site);
    if host.is_empty() || host.contains(['/', '?', '#', '@']) {
        bail!("{site}: a site is a domain (github.com) or an origin (https://github.com)");
    }
    Site::from_origin(&format!("https://{host}"))
        .map(|s| s.domain)
        .map_err(|reason| anyhow!("{site}: {reason}"))
}

/// A page on `site` (a domain or an exact origin), for its logins.
fn page_of(site: &str) -> String {
    if site.contains("://") {
        site.to_string()
    } else {
        format!("https://{site}")
    }
}

/// The username of a login, else its title: how the user names it.
fn login_label(item: &Item) -> String {
    autofill::value(item, "username")
        .map(str::to_string)
        .unwrap_or_else(|| label(item))
}

/// The one login on `site` that `query` names: its `vault:item` ref, its
/// id or a unique prefix of it, else its exact username or title.
fn resolve_login(s: &Loaded, site: &str, query: &str) -> Result<(LoginRef, String)> {
    let page = page_of(site);
    let on_site = Site::from_origin(&page).map_err(|reason| anyhow!("{site}: {reason}"))?;
    let logins: Vec<(LoginRef, Item)> = autofill::logins(s, &on_site)
        .map(|(vault, item)| (autofill::login_ref(&vault, &item.id), item))
        .collect();
    let query = query.trim();
    let lower = query.to_lowercase();
    let by_id: Vec<&(LoginRef, Item)> = logins
        .iter()
        .filter(|(r, _)| {
            format!("{}:{}", r.vault, r.item) == lower
                || r.item == lower
                || (lower.len() >= 4 && r.item.starts_with(&lower))
        })
        .collect();
    let found = if by_id.is_empty() {
        logins
            .iter()
            .filter(|(_, item)| {
                autofill::value(item, "username").is_some_and(|u| u.to_lowercase() == lower)
                    || label(item).to_lowercase() == lower
            })
            .collect()
    } else {
        by_id
    };
    match found.as_slice() {
        [(login, item)] => Ok((login.clone(), login_label(item))),
        [] => Err(fail(
            ErrorCode::NotFound,
            format!("no login {query} is saved for {site}"),
        )),
        _ => Err(fail(
            ErrorCode::Failed,
            format!("{query} names several logins for {site}; give its id"),
        )),
    }
}

/// What `agent-grant-set` asks for.
pub struct NewGrant<'a> {
    pub client_id: &'a str,
    /// `None` for every site.
    pub site: Option<&'a str>,
    pub login: Option<&'a str>,
    pub fields: &'a [Fill],
    pub passkeys: bool,
    pub expires_at: Option<u64>,
}

/// Sets a grant, replacing the client's grant for the same site and login.
pub fn set_grant(s: &Loaded, new: NewGrant, now: u64) -> Result<AgentGrantInfo> {
    let all_clients = clients(s)?;
    let client_id = pick(
        all_clients.iter().map(|c| c.id.as_str()),
        new.client_id,
        "agent client",
    )?;
    let site = new.site.map(grant_site).transpose()?;
    let (login, login_label) = match (new.login, &site) {
        (Some(query), Some(site)) => {
            let (login, label) = resolve_login(s, site, query)?;
            (Some(login), Some(label))
        }
        (Some(_), None) => bail!("a grant for every site covers every login; it can't name one"),
        (None, _) => (None, None),
    };
    let mut fields: Vec<Fill> = Vec::new();
    for fill in new.fields {
        if !fields.contains(fill) {
            fields.push(*fill);
        }
    }
    if fields.is_empty() && !new.passkeys {
        bail!("a grant needs at least one field or passkeys");
    }
    if new.expires_at.is_some_and(|at| at <= now) {
        bail!("that expiry has passed already");
    }
    let mut all = grants(s)?;
    let same_scope = |g: &Grant| g.client_id == client_id && g.site == site && g.login == login;
    let id = match all.iter().find(|g| same_scope(g)) {
        Some(old) => old.id.clone(),
        None => random_hex::<8>()?,
    };
    all.retain(|g| !same_scope(g));
    if all.len() >= MAX_GRANTS {
        bail!("{MAX_GRANTS} grants exist already; revoke some first");
    }
    let grant = Grant {
        id,
        client_id,
        site,
        login,
        login_label,
        fields,
        passkeys: new.passkeys,
        created: now,
        expires_at: new.expires_at,
    };
    let info = grant.info(&all_clients, now);
    all.push(grant);
    set_json(&s.store, META_GRANTS, &all)?;
    Ok(info)
}

pub fn list_grants(s: &Loaded, now: u64) -> Result<Vec<AgentGrantInfo>> {
    let all_clients = clients(s)?;
    Ok(grants(s)?
        .iter()
        .map(|g| g.info(&all_clients, now))
        .collect())
}

/// Removes a grant by id (or a unique prefix). Returns what it covered.
pub fn remove_grant(s: &Loaded, id: &str) -> Result<String> {
    let mut all = grants(s)?;
    let id = pick(all.iter().map(|g| g.id.as_str()), id, "grant")?;
    let what = all
        .iter()
        .find(|g| g.id == id)
        .map(Grant::scope)
        .unwrap_or_default();
    all.retain(|g| g.id != id);
    set_json(&s.store, META_GRANTS, &all)?;
    Ok(what)
}

/// The live grants of `client` for the page at `origin`.
fn covering(s: &Loaded, client: &str, origin: &str, now: u64) -> Result<Vec<Grant>> {
    Ok(grants(s)?
        .into_iter()
        .filter(|g| g.client_id == client && g.live(now) && g.covers_origin(origin))
        .collect())
}

fn not_granted(site: &str, login: Option<String>) -> anyhow::Error {
    let message = match &login {
        Some(login) => format!("agents aren't allowed to use {login} on {site}"),
        None => format!("agents aren't allowed to sign in to {site}"),
    };
    DaemonError {
        code: ErrorCode::NotGranted,
        message: format!("{message}: run `deadbolt agents allow {site}` to allow it"),
        grant: Some(NotGranted {
            site: site.to_string(),
            login,
        }),
        passkeys: None,
    }
    .into()
}

/// Passkeys for the page at `origin`: those whose relying party is its
/// host or a parent of it on its site.
fn site_passkeys<'a>(
    s: &'a Loaded,
    origin: &'a str,
) -> impl Iterator<Item = (LoginRef, Item)> + 'a {
    s.vaults.iter().flat_map(move |(vault, v)| {
        v.items()
            .into_iter()
            .filter(move |item| {
                item.kind == "passkey"
                    && autofill::value(item, "rp-id")
                        .is_some_and(|rp| crate::site::rp_id(origin, Some(rp)).is_ok())
            })
            .map(move |item| (autofill::login_ref(vault, &item.id), item))
    })
}

fn same_user(a: Option<&str>, b: Option<&str>) -> bool {
    match (a, b) {
        (Some(a), Some(b)) => a.trim().eq_ignore_ascii_case(b.trim()),
        _ => false,
    }
}

/// A passkey as an agent client sees it: never its key.
fn agent_passkey(passkey: &LoginRef, item: &Item) -> AgentPasskey {
    AgentPasskey {
        passkey: passkey.clone(),
        username: autofill::value(item, "username").map(str::to_string),
        display_name: autofill::value(item, "display-name").map(str::to_string),
        rp_id: autofill::value(item, "rp-id").unwrap_or_default().into(),
        credential_id: autofill::value(item, "credential-id")
            .unwrap_or_default()
            .into(),
    }
}

/// Which of `found` (passkeys for the page at `origin`) the grants with
/// `passkeys` in `covering` let the client sign in with. A grant for one
/// login covers the passkeys with that login's username.
fn granted_passkeys(
    s: &Loaded,
    covering: &[Grant],
    origin: &str,
    found: Vec<(LoginRef, Item)>,
) -> Vec<(LoginRef, Item)> {
    let granted: Vec<&Grant> = covering.iter().filter(|g| g.passkeys).collect();
    if granted.is_empty() {
        return Vec::new();
    }
    let users: Option<Vec<Option<String>>> = granted
        .iter()
        .map(|g| {
            g.login.as_ref().map(|login| {
                Site::from_origin(origin)
                    .ok()
                    .and_then(|site| autofill::find(s, login, &site).ok())
                    .and_then(|(_, item)| autofill::value(&item, "username").map(str::to_string))
            })
        })
        .collect();
    found
        .into_iter()
        .filter(|(_, item)| {
            users.as_ref().is_none_or(|users| {
                users
                    .iter()
                    .any(|u| same_user(u.as_deref(), autofill::value(item, "username")))
            })
        })
        .collect()
}

/// What `agent-logins` answers: the page's site, whether any live grant
/// covers it, its logins and the passkeys the client may use there.
pub type Listing = (String, bool, Vec<AgentLogin>, Vec<AgentPasskey>);

/// The logins on the site of `origin` that `client` may be shown, what its
/// grants cover of each, and the passkeys it may sign in with. None when no
/// live grant covers the site.
pub fn logins(s: &Loaded, client: &ClientAuth, origin: &str, now: u64) -> Result<Listing> {
    let client = authenticate(s, client)?;
    let site = autofill::site(origin)?;
    let covering = covering(s, &client.id, origin, now)?;
    if covering.is_empty() {
        return Ok((site.domain, false, Vec::new(), Vec::new()));
    }
    let passkeys: Vec<AgentPasskey> =
        granted_passkeys(s, &covering, origin, site_passkeys(s, origin).collect())
            .iter()
            .map(|(passkey, item)| agent_passkey(passkey, item))
            .collect();
    let passkey_users: Vec<Option<String>> = site_passkeys(s, origin)
        .map(|(_, item)| autofill::value(&item, "username").map(str::to_string))
        .collect();
    let (_, listed) = autofill::list(s, origin)?;
    let logins = listed
        .into_iter()
        .map(|login| {
            let grants: Vec<&Grant> = covering
                .iter()
                .filter(|g| g.covers_login(&login.login))
                .collect();
            let mut fields: Vec<Fill> = Vec::new();
            for fill in grants.iter().flat_map(|g| &g.fields) {
                if !fields.contains(fill) {
                    fields.push(*fill);
                }
            }
            AgentLogin {
                has_passkey: passkey_users
                    .iter()
                    .any(|u| same_user(u.as_deref(), login.username.as_deref())),
                passkeys: grants.iter().any(|g| g.passkeys),
                fields,
                title: login.title,
                username: login.username,
                has_password: login.has_password,
                has_totp: login.has_otp,
                sign_in: login.sign_in,
                login: login.login,
            }
        })
        .collect();
    Ok((site.domain, true, logins, passkeys))
}

/// The values `want` names of `login` for the frame at `origin`, if live
/// grants of `client` cover each of them.
pub fn fill(
    s: &Loaded,
    client: &ClientAuth,
    origin: &str,
    login: &LoginRef,
    want: &[Fill],
    now: Duration,
) -> Result<SiteValues> {
    let client = authenticate(s, client)?;
    let site = autofill::site(origin)?;
    let covering = covering(s, &client.id, origin, now.as_secs())?;
    // Nothing about the login to a client with no grant for the site.
    if covering.is_empty() {
        return Err(not_granted(&site.domain, None));
    }
    let (_, item) = autofill::find(s, login, &site)?;
    let granted: Vec<&Grant> = covering.iter().filter(|g| g.covers_login(login)).collect();
    if granted.is_empty()
        || !want
            .iter()
            .all(|fill| granted.iter().any(|g| g.fields.contains(fill)))
    {
        return Err(not_granted(&site.domain, Some(login_label(&item))));
    }
    let values = autofill::fill(s, origin, login, want, now)?;
    used(s, &client.id, now.as_secs())?;
    Ok(values)
}

/// What `agent-passkey-get` asks for.
pub struct PasskeyRequest<'a> {
    pub origin: &'a str,
    pub rp_id: Option<&'a str>,
    pub challenge: &'a str,
    pub allow_credentials: &'a [String],
    pub user_verification: Verify,
    /// The passkey the client chose, from `agent-logins` or a
    /// `choose-passkey` error.
    pub login: Option<&'a LoginRef>,
}

/// Signs for the page at `origin` with a passkey a live grant of `client`
/// covers, without user verification.
pub fn passkey(
    s: &Loaded,
    client: &ClientAuth,
    request: PasskeyRequest,
    now: u64,
) -> Result<passkeys::Assertion> {
    let client = authenticate(s, client)?;
    let origin = request.origin;
    let rp = passkeys::rp_id(origin, request.rp_id)?;
    webauthn::challenge(request.challenge)?;
    let domain = crate::site::registrable_domain(&rp);
    if request.user_verification == Verify::Required {
        bail!("{rp} requires user verification, which an agent sign-in never gives");
    }
    let covering = covering(s, &client.id, origin, now)?;
    if !covering.iter().any(|g| g.passkeys) {
        return Err(not_granted(&domain, None));
    }
    if let Some(login) = request.login {
        // Refused as for the extension: another relying party's passkey.
        passkeys::find(s, login, &rp)?;
    }
    let all: Vec<(LoginRef, Item)> = passkeys::passkeys(s, &rp)
        .map(|(vault, item)| (autofill::login_ref(&vault, &item.id), item))
        .collect();
    if all.is_empty() {
        return Err(fail(
            ErrorCode::NotFound,
            format!("no passkey for {rp} is saved here"),
        ));
    }
    let mut candidates = granted_passkeys(s, &covering, origin, all);
    if !request.allow_credentials.is_empty() {
        candidates.retain(|(_, item)| {
            autofill::value(item, "credential-id")
                .is_some_and(|id| request.allow_credentials.iter().any(|a| a == id))
        });
    }
    let passkey = match request.login {
        Some(login) => match candidates.iter().find(|(p, _)| p == login) {
            Some((passkey, _)) => passkey.clone(),
            None => return Err(not_granted(&domain, None)),
        },
        None => match candidates.as_slice() {
            [(passkey, _)] => passkey.clone(),
            [] => return Err(not_granted(&domain, None)),
            several => {
                return Err(DaemonError {
                    code: ErrorCode::ChoosePasskey,
                    message: format!(
                        "{} passkeys for {rp} could sign in: ask again naming one",
                        several.len()
                    ),
                    grant: None,
                    passkeys: Some(
                        several
                            .iter()
                            .map(|(passkey, item)| agent_passkey(passkey, item))
                            .collect(),
                    ),
                }
                .into());
            }
        },
    };
    let signed = passkeys::sign(s, origin, &rp, &passkey, request.challenge, false)?;
    used(s, &client.id, now)?;
    Ok(signed)
}

/// What one client may ask: a burst of 30, then one a second.
const RATE: (u32, Duration) = (30, Duration::from_secs(1));

/// A client's name for a Touch ID prompt: quoted, so quotes in it go.
fn quoted(name: &str) -> String {
    format!(
        "\"{}\"",
        clean_name(name).replace(['"', '\u{201c}', '\u{201d}'], "'")
    )
}

impl Daemon {
    /// Pairs a client or sets a grant: never for a caller Deadbolt takes
    /// for an AI (or the browser host), and only with the user's proof.
    pub(super) async fn agents_admin(
        &self,
        caller: &CallerInfo,
        command: Command,
        conv: &Conversation,
    ) -> Result<Reply> {
        if matches!(
            caller.class,
            CallerClass::BrowserHost | CallerClass::AutoFill
        ) || super::caller::is_ai(caller)
        {
            let message = if super::caller::is_ai(caller) {
                format!(
                    "{} can't pair agent clients or grant access to secrets. {}.",
                    super::caller::gate_subject(caller),
                    super::caller::not_from_here(caller)
                )
            } else {
                "the browser host and macOS AutoFill can't pair agent clients or grant access to secrets".into()
            };
            return Err(fail(ErrorCode::Forbidden, message));
        }
        if let Command::ExperimentalApproverSet {
            vault,
            device,
            passphrase,
        } = command
        {
            return self
                .experimental_approver_set(vault.as_deref(), device.as_deref(), passphrase, conv)
                .await;
        }
        // Locked fails before anyone is asked anything. The prompt says
        // plainly what is being allowed, the caller-chosen name quoted.
        let (passphrase, reason) = match &command {
            Command::AgentClientAdd { name, passphrase } => {
                self.with(|_| Ok(()))?;
                (
                    passphrase.clone(),
                    format!("pair a NEW agent client {} with Deadbolt", quoted(name)),
                )
            }
            Command::AgentGrantSet {
                client_id,
                site,
                passphrase,
                ..
            } => {
                let name = self.with(|s| client(s, client_id))?.name;
                let site = match site {
                    Some(site) => grant_site(site)?,
                    None => "every site".into(),
                };
                (
                    passphrase.clone(),
                    format!(
                        "let agent client {} use logins for {site} without asking",
                        quoted(&name)
                    ),
                )
            }
            Command::SecretGrantSet {
                vault,
                items,
                passphrase,
                ..
            } => {
                let vault = self.with(|s| {
                    let id = s.resolve(vault.as_deref())?;
                    Ok(s.vault(&id).name().to_string())
                })?;
                let items: Vec<String> = items.iter().map(|i| quoted(i)).collect();
                (
                    passphrase.clone(),
                    format!(
                        "let AI agents use (and so learn) {} (vault {vault}) in commands without asking",
                        items.join(", ")
                    ),
                )
            }
            _ => bail!("not an agent pairing or grant"),
        };
        {
            // Waiting on the user mustn't let the idle lock fire.
            let _busy = self.busy();
            self.prove_user(conv, passphrase, &reason).await?;
        }
        let now = session::now();
        match command {
            Command::AgentClientAdd { name, .. } => {
                let (client, token) = self.with(|s| add_client(s, &name, now))?;
                Ok(Reply::AgentClientAdded { client, token })
            }
            Command::AgentGrantSet {
                client_id,
                site,
                login,
                fields,
                passkeys,
                expires_at,
                ..
            } => {
                let grant = self.with(|s| {
                    set_grant(
                        s,
                        NewGrant {
                            client_id: &client_id,
                            site: site.as_deref(),
                            login: login.as_deref(),
                            fields: &fields,
                            passkeys,
                            expires_at,
                        },
                        now,
                    )
                })?;
                Ok(Reply::AgentGrant { grant })
            }
            Command::SecretGrantSet {
                vault,
                items,
                fields,
                purposes,
                expires_at,
                ..
            } => {
                let grants = self.with(|s| {
                    super::secrets::set_grants(
                        s,
                        super::secrets::NewGrants {
                            vault: vault.as_deref(),
                            items: &items,
                            fields: &fields,
                            purposes: &purposes,
                            expires_at,
                        },
                        now,
                    )
                })?;
                Ok(Reply::SecretGrants { grants })
            }
            _ => bail!("not an agent pairing or grant"),
        }
    }

    /// The user is here: they typed the passphrase, or touched the sensor
    /// for a prompt the daemon raised itself.
    pub(super) async fn prove_user(
        &self,
        conv: &Conversation,
        passphrase: Option<Zeroizing<String>>,
        reason: &str,
    ) -> Result<()> {
        match passphrase {
            Some(passphrase) => {
                let turn = self.guesses.turn()?;
                // The KDF is slow: run it on a copy, never under the
                // session's lock, so fills and the app carry on.
                let check = self.with(|s| Ok(s.store.passphrase_check()?))?;
                let right =
                    tokio::task::spawn_blocking(move || check.matches(passphrase.as_bytes()))
                        .await?;
                turn.settle(right);
                if !right {
                    return Err(fail(ErrorCode::Failed, "wrong passphrase"));
                }
                Ok(())
            }
            None if self.can_verify() => {
                self.verify_user(conv, Verify::Required, reason).await?;
                Ok(())
            }
            None => Err(fail(
                ErrorCode::Failed,
                "this needs your passphrase (Touch ID is off or not set up): run it in a terminal, or pass --passphrase-stdin",
            )),
        }
    }

    /// A paired client's request: proved by its token, then within its
    /// rate limit.
    pub(super) fn agent_client(&self, command: Command) -> Result<Reply> {
        let client = match &command {
            Command::AgentLogins { client, .. }
            | Command::AgentFill { client, .. }
            | Command::AgentPasskeyGet { client, .. } => client,
            _ => bail!("not an agent client's request"),
        };
        let id = self.with(|s| authenticate(s, client))?.id;
        {
            let mut rates = self.agent_rates.lock().unwrap_or_else(|e| e.into_inner());
            let now = std::time::Instant::now();
            if !rates
                .entry(id)
                .or_insert_with(|| Bucket::new(RATE, now))
                .take(now)
            {
                return Err(fail(
                    ErrorCode::RateLimited,
                    "too many requests from this agent client; try again shortly",
                ));
            }
        }
        match command {
            Command::AgentLogins { client, origin } => {
                let (site, granted, logins, passkeys) =
                    self.with(|s| logins(s, &client, &origin, session::now()))?;
                Ok(Reply::AgentLogins {
                    site,
                    granted,
                    logins,
                    passkeys,
                })
            }
            Command::AgentFill {
                client,
                origin,
                login,
                want,
            } => Ok(Reply::SiteFill {
                values: self.with(|s| {
                    fill(
                        s,
                        &client,
                        &origin,
                        &login,
                        &want,
                        crate::config::wall_clock(),
                    )
                })?,
            }),
            Command::AgentPasskeyGet {
                client,
                origin,
                rp_id,
                login,
                challenge,
                allow_credentials,
                user_verification,
            } => {
                let signed = self.with(|s| {
                    passkey(
                        s,
                        &client,
                        PasskeyRequest {
                            origin: &origin,
                            rp_id: rp_id.as_deref(),
                            challenge: &challenge,
                            allow_credentials: &allow_credentials,
                            user_verification,
                            login: login.as_ref(),
                        },
                        session::now(),
                    )
                })?;
                Ok(Reply::PasskeyAssertion {
                    credential_id: signed.credential_id,
                    client_data_json: signed.client_data_json,
                    authenticator_data: signed.authenticator_data,
                    signature: signed.signature,
                    user_handle: signed.user_handle,
                    verified: false,
                })
            }
            _ => bail!("not an agent client's request"),
        }
    }

    /// Names an agent request's Activity entry: the client's name for its
    /// id, and the login's title beside the page.
    pub(super) fn name_agent_entry(&self, entry: &mut ActivityEntry) {
        let Some(id) = entry.client.clone() else {
            return;
        };
        let named = self.with(|s| {
            if let Some(name) = client_name(s, &id) {
                entry.client = Some(name);
            }
            for item in &mut entry.items {
                let (Some(vault), Some(id)) = (&item.vault, &item.id) else {
                    continue;
                };
                let login = LoginRef {
                    vault: vault.clone(),
                    item: id.clone(),
                };
                if let Some(title) = login_title(s, &login) {
                    item.title = format!("{title} ({})", item.title);
                }
            }
            Ok(())
        });
        drop(named);
    }

    /// Forgets a removed client's rate limit.
    pub(super) fn forget_agent_client(&self, id: &str) {
        self.agent_rates
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .remove(id);
    }
}

/// A login's title, for Activity.
fn login_title(s: &Loaded, login: &LoginRef) -> Option<String> {
    s.vaults.iter().find_map(|(vault, v)| {
        if hex(vault.as_bytes()) != login.vault {
            return None;
        }
        v.items()
            .into_iter()
            .find(|item| hex(item.id.as_bytes()) == login.item)
            .map(|item| label(&item))
    })
}

#[cfg(test)]
mod tests;
