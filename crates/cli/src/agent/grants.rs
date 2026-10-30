//! Agent sign-ins (`docs/agent-control.md`, "Standing grants"): paired agent
//! clients, such as Browse's relay, and the standing grants the user gave
//! them. A client proves itself with a token on every request; the agent
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
use super::{Agent, Conversation, ErrorCode, fail};
use crate::browser::host::Bucket;
use crate::client::AgentError;
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
    AgentError {
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
                return Err(AgentError {
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

impl Agent {
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
                    "an AI agent can't pair agent clients or grant access to secrets. {}.",
                    super::caller::not_from_here(caller)
                )
            } else {
                "the browser host and macOS AutoFill can't pair agent clients or grant access to secrets".into()
            };
            return Err(fail(ErrorCode::Forbidden, message));
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
    /// for a prompt the agent raised itself.
    async fn prove_user(
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
mod tests {
    use p256::ecdsa::signature::Verifier;
    use p256::ecdsa::{Signature, VerifyingKey};
    use p256::pkcs8::DecodePublicKey;

    use super::*;
    use crate::protocol::FieldInput;

    const OTP: &str = "JBSWY3DPEHPK3PXP";

    fn loaded(dir: &std::path::Path) -> Loaded {
        let params = deadbolt_store::KdfParams {
            m_cost_kib: 64,
            t_cost: 1,
            p_cost: 1,
        };
        let mut loaded = Loaded::setup(dir, b"test", "test", params).unwrap();
        loaded.create_vault("personal").unwrap();
        loaded
    }

    fn login(s: &mut Loaded, name: &str, fields: &[(&str, &str)]) -> LoginRef {
        let vault = s.resolve(None).unwrap();
        let inputs = fields
            .iter()
            .map(|(name, value)| FieldInput {
                name: (*name).into(),
                kind: None,
                value: (*value).into(),
            })
            .collect();
        let info =
            super::super::items::create(s, None, "login", Some(name.into()), inputs).unwrap();
        LoginRef {
            vault: hex(vault.as_bytes()),
            item: info.id,
        }
    }

    fn code(error: &anyhow::Error) -> Option<ErrorCode> {
        error.downcast_ref::<AgentError>().map(|e| e.code)
    }

    fn auth(info: &AgentClientInfo, token: &Secret) -> ClientAuth {
        ClientAuth {
            id: info.id.clone(),
            token: token.clone(),
        }
    }

    fn allow<'a>(client: &'a str, site: &'a str, fields: &'a [Fill]) -> NewGrant<'a> {
        NewGrant {
            client_id: client,
            site: Some(site),
            login: None,
            fields,
            passkeys: false,
            expires_at: None,
        }
    }

    const NOW: u64 = 1_800_000_000;
    const FILL_NOW: Duration = Duration::from_secs(NOW);

    #[test]
    fn a_paired_client_fills_only_what_is_granted() {
        let dir = tempfile::tempdir().unwrap();
        let mut s = loaded(dir.path());
        let github = login(
            &mut s,
            "GitHub",
            &[
                ("username", "kit"),
                ("password", "hunter2"),
                ("url", "https://github.com/login"),
                ("otp", OTP),
            ],
        );
        let (client, token) = add_client(&s, "browse", NOW).unwrap();
        let me = auth(&client, &token);
        assert_eq!(token.expose().len(), 64);
        // Only the token's hash is stored.
        let stored =
            String::from_utf8(s.store.meta_get(META_CLIENTS).unwrap().unwrap().to_vec()).unwrap();
        assert!(!stored.contains(token.expose()), "{stored}");

        // Nothing granted: not-granted, naming the site and nothing more.
        let error = fill(
            &s,
            &me,
            "https://github.com",
            &github,
            &[Fill::Password],
            FILL_NOW,
        )
        .unwrap_err();
        assert_eq!(code(&error), Some(ErrorCode::NotGranted));
        let detail = error
            .downcast_ref::<AgentError>()
            .unwrap()
            .grant
            .clone()
            .unwrap();
        assert_eq!((detail.site.as_str(), detail.login), ("github.com", None));
        let (site, granted, listed, _) = logins(&s, &me, "https://github.com", NOW).unwrap();
        assert_eq!(
            (site.as_str(), granted, listed.len()),
            ("github.com", false, 0)
        );

        set_grant(
            &s,
            allow(
                &client.id,
                "www.github.com",
                &[Fill::Username, Fill::Password],
            ),
            NOW,
        )
        .unwrap();
        let (_, granted, listed, _) = logins(&s, &me, "https://github.com", NOW).unwrap();
        assert!(granted);
        assert_eq!(listed[0].fields, [Fill::Username, Fill::Password]);
        assert!(listed[0].has_totp && !listed[0].passkeys);
        let values = fill(
            &s,
            &me,
            "https://github.com",
            &github,
            &[Fill::Username, Fill::Password],
            FILL_NOW,
        )
        .unwrap();
        assert_eq!(values.username.as_deref(), Some("kit"));
        assert_eq!(values.password.unwrap().expose(), "hunter2");
        assert_eq!(list_clients(&s).unwrap()[0].last_used, Some(NOW));

        // The code isn't granted: not-granted names the login.
        let error = fill(
            &s,
            &me,
            "https://github.com",
            &github,
            &[Fill::Totp],
            FILL_NOW,
        )
        .unwrap_err();
        let detail = error
            .downcast_ref::<AgentError>()
            .unwrap()
            .grant
            .clone()
            .unwrap();
        assert_eq!(detail.login.as_deref(), Some("kit"));

        // Granting the code gives the current one, never the secret.
        let mut grant = allow(&client.id, "github.com", &[Fill::Totp]);
        grant.login = Some("kit");
        set_grant(&s, grant, NOW).unwrap();
        let values = fill(
            &s,
            &me,
            "https://github.com",
            &github,
            &[Fill::Totp],
            FILL_NOW,
        )
        .unwrap();
        let expected = deadbolt_core::totp::Totp::parse(OTP).unwrap().code(NOW);
        assert_eq!(values.totp.unwrap().expose(), expected);
    }

    #[test]
    fn other_origins_tokens_and_removed_clients_are_refused() {
        let dir = tempfile::tempdir().unwrap();
        let mut s = loaded(dir.path());
        let github = login(
            &mut s,
            "GitHub",
            &[
                ("username", "kit"),
                ("password", "hunter2"),
                ("url", "github.com"),
            ],
        );
        let (client, token) = add_client(&s, "browse", NOW).unwrap();
        let me = auth(&client, &token);
        set_grant(&s, allow(&client.id, "github.com", &[Fill::Password]), NOW).unwrap();

        // Another site's frame gets nothing, whatever it names.
        let error = fill(
            &s,
            &me,
            "https://evil.com",
            &github,
            &[Fill::Password],
            FILL_NOW,
        )
        .unwrap_err();
        assert_eq!(code(&error), Some(ErrorCode::NotGranted));
        // A grant for evil.com doesn't make the GitHub login evil.com's.
        set_grant(&s, allow(&client.id, "evil.com", &[Fill::Password]), NOW).unwrap();
        let error = fill(
            &s,
            &me,
            "https://evil.com",
            &github,
            &[Fill::Password],
            FILL_NOW,
        )
        .unwrap_err();
        assert_eq!(code(&error), Some(ErrorCode::DomainMismatch));
        // An exact-origin grant covers that origin only.
        let (other, other_token) = add_client(&s, "other", NOW).unwrap();
        let them = auth(&other, &other_token);
        set_grant(
            &s,
            allow(&other.id, "https://github.com", &[Fill::Password]),
            NOW,
        )
        .unwrap();
        assert!(
            fill(
                &s,
                &them,
                "https://github.com",
                &github,
                &[Fill::Password],
                FILL_NOW
            )
            .is_ok()
        );
        let error = fill(
            &s,
            &them,
            "https://gist.github.com",
            &github,
            &[Fill::Password],
            FILL_NOW,
        )
        .unwrap_err();
        assert_eq!(code(&error), Some(ErrorCode::NotGranted));

        // A wrong token, or a removed client, is forbidden.
        let wrong = ClientAuth {
            id: client.id.clone(),
            token: Secret::new("0".repeat(64)),
        };
        let error = fill(
            &s,
            &wrong,
            "https://github.com",
            &github,
            &[Fill::Password],
            FILL_NOW,
        )
        .unwrap_err();
        assert_eq!(code(&error), Some(ErrorCode::Forbidden));
        remove_client(&s, &client.id).unwrap();
        let error = fill(
            &s,
            &me,
            "https://github.com",
            &github,
            &[Fill::Password],
            FILL_NOW,
        )
        .unwrap_err();
        assert_eq!(code(&error), Some(ErrorCode::Forbidden));
        // Its grants went with it.
        assert!(
            list_grants(&s, NOW)
                .unwrap()
                .iter()
                .all(|g| g.client_id == other.id)
        );
    }

    #[test]
    fn grants_expire_and_name_sites_and_logins_strictly() {
        let dir = tempfile::tempdir().unwrap();
        let mut s = loaded(dir.path());
        let github = login(
            &mut s,
            "GitHub",
            &[
                ("username", "kit"),
                ("password", "hunter2"),
                ("url", "github.com"),
            ],
        );
        let (client, token) = add_client(&s, "browse", NOW).unwrap();
        let me = auth(&client, &token);
        let mut grant = allow(&client.id, "github.com", &[Fill::Password]);
        grant.expires_at = Some(NOW + 60);
        let made = set_grant(&s, grant, NOW).unwrap();
        assert!(!made.expired);
        assert!(
            fill(
                &s,
                &me,
                "https://github.com",
                &github,
                &[Fill::Password],
                FILL_NOW
            )
            .is_ok()
        );
        let later = Duration::from_secs(NOW + 60);
        let error = fill(
            &s,
            &me,
            "https://github.com",
            &github,
            &[Fill::Password],
            later,
        )
        .unwrap_err();
        assert_eq!(code(&error), Some(ErrorCode::NotGranted));
        assert!(list_grants(&s, NOW + 60).unwrap()[0].expired);

        for bad in ["github.io", "github.com/login", "", "ftp://github.com"] {
            assert!(grant_site(bad).is_err(), "{bad}");
        }
        assert_eq!(grant_site("WWW.GitHub.com").unwrap(), "github.com");
        assert_eq!(
            grant_site("https://App.Example.com/login").unwrap(),
            "https://app.example.com"
        );
        let mut unknown = allow(&client.id, "github.com", &[Fill::Password]);
        unknown.login = Some("someone-else");
        assert_eq!(
            code(&set_grant(&s, unknown, NOW).unwrap_err()),
            Some(ErrorCode::NotFound)
        );
        assert!(set_grant(&s, allow(&client.id, "github.com", &[]), NOW).is_err());
        let mut past = allow(&client.id, "github.com", &[Fill::Password]);
        past.expires_at = Some(NOW);
        assert!(set_grant(&s, past, NOW).is_err());
        // Setting it again replaces it.
        set_grant(&s, allow(&client.id, "github.com", &[Fill::Username]), NOW).unwrap();
        let all = list_grants(&s, NOW).unwrap();
        assert_eq!(all.len(), 1);
        assert_eq!(
            (all[0].id.as_str(), all[0].fields.as_slice()),
            (made.id.as_str(), &[Fill::Username][..])
        );
        remove_grant(&s, &made.id[..6]).unwrap();
        assert!(list_grants(&s, NOW).unwrap().is_empty());
    }

    fn register(s: &mut Loaded, origin: &str, rp: Option<&str>, user: &str) -> passkeys::Created {
        let new = passkeys::check_create(
            s,
            origin,
            rp,
            &webauthn::b64(&[5; 32]),
            &webauthn::b64(user.as_bytes()),
            user,
            &[],
        )
        .unwrap();
        let new = passkeys::NewPasskey {
            display_name: passkeys::user_text(&format!("{user} (display)\n")),
            ..new
        };
        passkeys::create_passkey(s, &new, false, 1_798_000_000).unwrap()
    }

    #[test]
    fn passkeys_sign_with_presence_never_verification_and_only_when_granted() {
        let dir = tempfile::tempdir().unwrap();
        let mut s = loaded(dir.path());
        let kit = login(
            &mut s,
            "Example",
            &[
                ("username", "kit"),
                ("password", "pw"),
                ("url", "example.com"),
            ],
        );
        let made = register(&mut s, "https://example.com", None, "kit");
        let (client, token) = add_client(&s, "browse", NOW).unwrap();
        let me = auth(&client, &token);
        let challenge = webauthn::b64(&[9; 32]);
        let request = |uv| PasskeyRequest {
            origin: "https://example.com",
            rp_id: None,
            challenge: &challenge,
            allow_credentials: &[],
            user_verification: uv,
            login: None,
        };
        // A grant for the password doesn't cover the passkey.
        set_grant(&s, allow(&client.id, "example.com", &[Fill::Password]), NOW).unwrap();
        let error = passkey(&s, &me, request(Verify::Preferred), NOW)
            .err()
            .unwrap();
        assert_eq!(code(&error), Some(ErrorCode::NotGranted));

        let mut grant = allow(&client.id, "example.com", &[]);
        grant.passkeys = true;
        grant.login = Some(&kit.item);
        set_grant(&s, grant, NOW).unwrap();
        let (_, _, listed, keys) = logins(&s, &me, "https://example.com", NOW).unwrap();
        assert!(listed[0].has_passkey && listed[0].passkeys);
        assert_eq!(keys.len(), 1);
        assert_eq!(keys[0].username.as_deref(), Some("kit"));
        assert_eq!(keys[0].passkey, made.passkey);
        let signed = passkey(&s, &me, request(Verify::Preferred), NOW).unwrap();
        let data = webauthn::unb64(&signed.authenticator_data).unwrap();
        assert_eq!(data[32] & 0x01, 0x01, "user present");
        assert_eq!(data[32] & 0x04, 0, "never user verified");
        let client_data = webauthn::unb64(&signed.client_data_json).unwrap();
        let parsed: serde_json::Value = serde_json::from_slice(&client_data).unwrap();
        assert_eq!(parsed["origin"], "https://example.com");
        let key =
            VerifyingKey::from_public_key_der(&webauthn::unb64(&made.public_key).unwrap()).unwrap();
        let mut signed_data = data.clone();
        signed_data.extend_from_slice(&Sha256::digest(&client_data));
        let signature = Signature::from_der(&webauthn::unb64(&signed.signature).unwrap()).unwrap();
        assert!(key.verify(&signed_data, &signature).is_ok());

        // A site that requires verification gets nothing; nor does another
        // relying party, or a credential list naming none here.
        assert!(passkey(&s, &me, request(Verify::Required), NOW).is_err());
        let mut evil = request(Verify::Preferred);
        evil.origin = "https://evil.com";
        assert!(passkey(&s, &me, evil, NOW).is_err());
        let other = [webauthn::b64(&[1; 16])];
        let mut elsewhere = request(Verify::Preferred);
        elsewhere.allow_credentials = &other;
        assert_eq!(
            code(&passkey(&s, &me, elsewhere, NOW).err().unwrap()),
            Some(ErrorCode::NotGranted)
        );
        // A second user's passkey isn't covered by a grant for kit's login.
        let bob = register(&mut s, "https://example.com", None, "bob");
        let only_bob = [bob.credential_id];
        let mut as_bob = request(Verify::Preferred);
        as_bob.allow_credentials = &only_bob;
        assert_eq!(
            code(&passkey(&s, &me, as_bob, NOW).err().unwrap()),
            Some(ErrorCode::NotGranted)
        );
        assert!(passkey(&s, &me, request(Verify::Discouraged), NOW).is_ok());
    }

    #[test]
    fn a_grant_for_every_site_still_fills_each_login_only_on_its_own() {
        let dir = tempfile::tempdir().unwrap();
        let mut s = loaded(dir.path());
        let github = login(
            &mut s,
            "GitHub",
            &[
                ("username", "kit"),
                ("password", "hunter2"),
                ("url", "github.com"),
            ],
        );
        let (client, token) = add_client(&s, "browse", NOW).unwrap();
        let me = auth(&client, &token);
        let mut every = allow(
            &client.id,
            "x",
            &[Fill::Username, Fill::Password, Fill::Totp],
        );
        every.site = None;
        every.passkeys = true;
        let made = set_grant(&s, every, NOW).unwrap();
        assert_eq!(made.site, None);
        assert!(
            fill(
                &s,
                &me,
                "https://github.com",
                &github,
                &[Fill::Password],
                FILL_NOW
            )
            .is_ok()
        );
        let (_, granted, listed, _) = logins(&s, &me, "https://example.org", NOW).unwrap();
        assert!(granted && listed.is_empty());
        // Every site, but the GitHub login is still GitHub's.
        let error = fill(
            &s,
            &me,
            "https://evil.com",
            &github,
            &[Fill::Password],
            FILL_NOW,
        )
        .unwrap_err();
        assert_eq!(code(&error), Some(ErrorCode::DomainMismatch));
        // It can't name a login, and it is revoked like any other.
        let mut named = allow(&client.id, "x", &[Fill::Password]);
        named.site = None;
        named.login = Some("kit");
        assert!(set_grant(&s, named, NOW).is_err());
        assert_eq!(remove_grant(&s, &made.id).unwrap(), "every site");
        assert!(
            fill(
                &s,
                &me,
                "https://github.com",
                &github,
                &[Fill::Password],
                FILL_NOW
            )
            .is_err()
        );
    }

    #[test]
    fn several_passkeys_are_chosen_by_ref_within_the_grant() {
        let dir = tempfile::tempdir().unwrap();
        let mut s = loaded(dir.path());
        let kit = register(&mut s, "https://example.com", None, "kit");
        let bob = register(&mut s, "https://example.com", None, "bob");
        let (client, token) = add_client(&s, "browse", NOW).unwrap();
        let me = auth(&client, &token);
        let mut grant = allow(&client.id, "example.com", &[]);
        grant.passkeys = true;
        set_grant(&s, grant, NOW).unwrap();
        let challenge = webauthn::b64(&[9; 32]);
        fn get<'a>(
            challenge: &'a str,
            login: Option<&'a LoginRef>,
            allow: &'a [String],
        ) -> PasskeyRequest<'a> {
            PasskeyRequest {
                origin: "https://example.com",
                rp_id: None,
                challenge,
                allow_credentials: allow,
                user_verification: Verify::Preferred,
                login,
            }
        }
        let request = |login, allow| get(&challenge, login, allow);
        // Both listed, with their user names and refs.
        let (_, _, _, keys) = logins(&s, &me, "https://example.com", NOW).unwrap();
        let mut users: Vec<_> = keys.iter().map(|k| k.username.clone().unwrap()).collect();
        users.sort();
        assert_eq!(users, ["bob", "kit"]);
        assert!(
            keys.iter()
                .any(|k| k.display_name.as_deref() == Some("kit (display)"))
        );

        // Unnamed with two candidates: choose-passkey lists them, no secrets.
        let error = passkey(&s, &me, request(None, &[]), NOW).err().unwrap();
        let refused = error.downcast_ref::<AgentError>().unwrap();
        assert_eq!(refused.code, ErrorCode::ChoosePasskey);
        let choices = refused.passkeys.clone().unwrap();
        assert_eq!(choices.len(), 2);
        assert!(choices.iter().any(|c| c.passkey == kit.passkey));
        let json = serde_json::to_string(&choices).unwrap();
        assert!(!json.contains("private"), "{json}");

        // The chosen ref is the one that signs.
        let signed = passkey(&s, &me, request(Some(&bob.passkey), &[]), NOW).unwrap();
        assert_eq!(signed.credential_id, bob.credential_id);
        // allowCredentials narrows the candidates to one: no choice needed.
        let only_kit = [kit.credential_id.clone()];
        let signed = passkey(&s, &me, request(None, &only_kit), NOW).unwrap();
        assert_eq!(signed.credential_id, kit.credential_id);
        // A chosen ref outside allowCredentials, or outside the grant, is refused.
        let error = passkey(&s, &me, request(Some(&bob.passkey), &only_kit), NOW)
            .err()
            .unwrap();
        assert_eq!(code(&error), Some(ErrorCode::NotGranted));
        let mut kit_only = allow(&client.id, "example.com", &[]);
        kit_only.passkeys = true;
        let mut s2 = s;
        let kit_login = login(
            &mut s2,
            "Example",
            &[
                ("username", "kit"),
                ("password", "pw"),
                ("url", "example.com"),
            ],
        );
        kit_only.login = Some(&kit_login.item);
        // Replace the site-wide passkey grant with one for kit's login.
        let site_wide = list_grants(&s2, NOW).unwrap()[0].id.clone();
        remove_grant(&s2, &site_wide).unwrap();
        set_grant(&s2, kit_only, NOW).unwrap();
        let error = passkey(&s2, &me, request(Some(&bob.passkey), &[]), NOW)
            .err()
            .unwrap();
        assert_eq!(code(&error), Some(ErrorCode::NotGranted));
        let signed = passkey(&s2, &me, request(None, &[]), NOW).unwrap();
        assert_eq!(signed.credential_id, kit.credential_id);
        // Another relying party's passkey, named by ref, is refused as such.
        let other = register(&mut s2, "https://other.com", None, "kit");
        let error = passkey(&s2, &me, request(Some(&other.passkey), &[]), NOW)
            .err()
            .unwrap();
        assert_eq!(code(&error), Some(ErrorCode::DomainMismatch));
    }

    mod agent {
        use std::sync::Arc;
        use std::sync::atomic::{AtomicUsize, Ordering};

        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        use tokio::net::UnixStream;

        use super::super::super::passkeys::tests::agent::{conversation, unlocked};
        use super::*;
        use crate::protocol::{Claim, MAX_LINE, Message, Outcome, PROTOCOL_VERSION, Request};

        fn kit() -> CallerInfo {
            CallerInfo::unverified("Ghostty › zsh › deadbolt")
        }

        fn add(passphrase: Option<&str>) -> Command {
            Command::AgentClientAdd {
                name: "browse".into(),
                passphrase: passphrase.map(|p| Zeroizing::new(p.into())),
            }
        }

        fn code(error: &anyhow::Error) -> Option<ErrorCode> {
            error.downcast_ref::<AgentError>().map(|e| e.code)
        }

        async fn ask(agent: &Arc<Agent>, claimed: Option<Claim>, command: Command) -> Message {
            let (server, mut client) = UnixStream::pair().unwrap();
            let mut line = serde_json::to_vec(&Request {
                v: PROTOCOL_VERSION,
                claimed,
                command,
            })
            .unwrap();
            line.push(b'\n');
            client.write_all(&line).await.unwrap();
            agent.clone().handle(server, MAX_LINE).await.unwrap();
            let mut reply = String::new();
            client.read_to_string(&mut reply).await.unwrap();
            serde_json::from_str(&reply).unwrap()
        }

        #[tokio::test]
        async fn pairing_needs_the_user_and_never_an_ai() {
            let f = unlocked().await;
            let (conv, _closed) = conversation();
            let taps = Arc::new(AtomicUsize::new(0));
            let (key, seen) = (f.key, taps.clone());
            *f.agent.biometric_hook.lock().unwrap() = Some(Arc::new(move |_| {
                seen.fetch_add(1, Ordering::SeqCst);
                Ok(Zeroizing::new(key))
            }));
            let clients = || f.agent.with(|s| list_clients(s)).unwrap().len();

            // An AI is refused, passphrase or not, before anyone is asked.
            let mut ai = kit();
            ai.claimed = Some(Claim {
                caller: None,
                opencode_session: Some("ses_1".into()),
            });
            for command in [add(None), add(Some("test"))] {
                let error = f.agent.agents_admin(&ai, command, &conv).await.unwrap_err();
                assert_eq!(code(&error), Some(ErrorCode::Forbidden));
            }
            let mut opencode = kit();
            opencode.ancestry = vec![crate::protocol::Ancestor {
                pid: 9,
                name: "opencode".into(),
                path: None,
            }];
            let grant = Command::AgentGrantSet {
                client_id: "x".into(),
                site: Some("github.com".into()),
                login: None,
                fields: vec![Fill::Password],
                passkeys: false,
                expires_at: None,
                passphrase: Some(Zeroizing::new("test".into())),
            };
            let error = f
                .agent
                .agents_admin(&opencode, grant, &conv)
                .await
                .unwrap_err();
            assert_eq!(code(&error), Some(ErrorCode::Forbidden));
            assert_eq!((taps.load(Ordering::SeqCst), clients()), (0, 0));

            // Touch ID, raised by the agent.
            let reply = f
                .agent
                .agents_admin(&kit(), add(None), &conv)
                .await
                .unwrap();
            assert!(matches!(reply, Reply::AgentClientAdded { .. }), "{reply:?}");
            assert_eq!((taps.load(Ordering::SeqCst), clients()), (1, 1));
            // Or the passphrase, checked.
            let error = f
                .agent
                .agents_admin(&kit(), add(Some("wrong")), &conv)
                .await
                .unwrap_err();
            assert_eq!(error.to_string(), "wrong passphrase");
            f.agent
                .agents_admin(&kit(), add(Some("test")), &conv)
                .await
                .unwrap();
            assert_eq!((taps.load(Ordering::SeqCst), clients()), (1, 2));
            // Without Touch ID, nothing but the passphrase will do.
            *f.agent.touch_id_available_override.lock().unwrap() = Some(false);
            let error = f
                .agent
                .agents_admin(&kit(), add(None), &conv)
                .await
                .unwrap_err();
            assert!(
                error.to_string().contains("needs your passphrase"),
                "{error}"
            );

            // Over the socket, a claim to be an OpenCode session is refused
            // and recorded as refused.
            let refused = ask(
                &f.agent,
                Some(Claim {
                    caller: None,
                    opencode_session: Some("ses_1".into()),
                }),
                add(Some("test")),
            )
            .await;
            assert!(
                matches!(
                    refused,
                    Message::Error {
                        code: ErrorCode::Forbidden,
                        ..
                    }
                ),
                "{refused:?}"
            );
            assert_eq!(clients(), 2);

            // Locked: nothing is asked.
            f.agent.lock().await;
            let error = f
                .agent
                .agents_admin(&kit(), add(None), &conv)
                .await
                .unwrap_err();
            assert_eq!(code(&error), Some(ErrorCode::Locked));
        }

        /// The KDF runs off the session's lock: the vault answers while a
        /// passphrase is checked, and a second check meanwhile is refused.
        #[test]
        fn a_passphrase_check_never_holds_the_vault() {
            use std::future::Future;
            use std::task::Poll;

            tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .max_blocking_threads(1)
                .build()
                .unwrap()
                .block_on(async {
                    let f = unlocked().await;
                    // Occupy the blocking pool so the real KDF queues until
                    // released. No assumption about Argon2 speed or when a
                    // loaded CI runner will schedule a 20 ms timer.
                    let (release, wait) = std::sync::mpsc::channel::<()>();
                    let (started, ready) = tokio::sync::oneshot::channel();
                    let blocker = tokio::task::spawn_blocking(move || {
                        started.send(()).unwrap();
                        // Dropping release also unblocks this on assertion failure.
                        wait.recv().unwrap_or_default();
                    });
                    ready.await.unwrap();
                    let (conv, _closed) = conversation();
                    let me = kit();
                    let mut checking =
                        std::pin::pin!(f.agent.agents_admin(&me, add(Some("wrong")), &conv));
                    std::future::poll_fn(|cx| {
                        assert!(checking.as_mut().poll(cx).is_pending());
                        Poll::Ready(())
                    })
                    .await;
                    // A regression must fail, not deadlock on the session lock.
                    assert!(f.agent.session.try_lock().is_ok());
                    f.agent.with(|s| list_clients(s)).unwrap();
                    let mut second =
                        std::pin::pin!(f.agent.agents_admin(&me, add(Some("test")), &conv));
                    let error = std::future::poll_fn(|cx| {
                        let result = second.as_mut().poll(cx);
                        assert!(
                            result.is_ready(),
                            "a concurrent check must be refused immediately"
                        );
                        result
                    })
                    .await
                    .unwrap_err();
                    assert_eq!(code(&error), Some(ErrorCode::RateLimited));
                    release.send(()).unwrap();
                    blocker.await.unwrap();
                    let error = checking.await.unwrap_err();
                    assert_eq!(error.to_string(), "wrong passphrase");
                });
        }

        #[tokio::test]
        async fn wrong_passphrases_back_off() {
            let f = unlocked().await;
            *f.agent.touch_id_available_override.lock().unwrap() = Some(false);
            let (conv, _closed) = conversation();
            let me = kit();
            let try_with = |passphrase| f.agent.agents_admin(&me, add(Some(passphrase)), &conv);
            for _ in 0..super::super::super::guesses::FREE_FAILURES - 1 {
                assert!(try_with("wrong").await.is_err());
            }
            // A right one resets the count.
            try_with("test").await.unwrap();
            for _ in 0..super::super::super::guesses::FREE_FAILURES {
                let error = try_with("wrong").await.unwrap_err();
                assert_eq!(error.to_string(), "wrong passphrase");
            }
            // Now even the right one waits.
            let error = try_with("test").await.unwrap_err();
            assert_eq!(code(&error), Some(ErrorCode::RateLimited), "{error}");
        }

        #[tokio::test]
        async fn a_client_is_rate_limited_locked_out_and_in_activity() {
            let f = unlocked().await;
            let (conv, _closed) = conversation();
            let reply = f
                .agent
                .agents_admin(&kit(), add(Some("test")), &conv)
                .await
                .unwrap();
            let Reply::AgentClientAdded { client, token } = reply else {
                unreachable!()
            };
            let me = ClientAuth {
                id: client.id.clone(),
                token,
            };
            let logins = || Command::AgentLogins {
                client: me.clone(),
                origin: "https://github.com".into(),
            };
            let reply = ask(&f.agent, None, logins()).await;
            assert!(matches!(reply, Message::Ok { .. }), "{reply:?}");
            let entries = f
                .agent
                .with(|s| Ok(s.store.activity_list(0, None, 10)?))
                .unwrap();
            let last: ActivityEntry = serde_json::from_slice(&entries.rows[0].bytes).unwrap();
            assert_eq!(last.command, "agent-logins");
            assert_eq!(last.client.as_deref(), Some("browse"));
            assert_eq!(last.tier, crate::protocol::Tier::Agent);

            let mut answered = 1;
            let limited = loop {
                match f.agent.agent_client(logins()) {
                    Ok(_) => answered += 1,
                    Err(error) => break error,
                }
                assert!(answered < 100, "never limited");
            };
            assert_eq!(code(&limited), Some(ErrorCode::RateLimited));
            assert!(answered >= RATE.0, "limited after {answered}");
            // Another client has a budget of its own; a wrong token none.
            let wrong = ClientAuth {
                id: client.id.clone(),
                token: Secret::new("f".repeat(64)),
            };
            let error = f
                .agent
                .agent_client(Command::AgentLogins {
                    client: wrong,
                    origin: "https://github.com".into(),
                })
                .unwrap_err();
            assert_eq!(code(&error), Some(ErrorCode::Forbidden));

            // Locked, every agent request is `locked`, and its entry says so.
            f.agent.lock().await;
            let reply = ask(&f.agent, None, logins()).await;
            assert!(
                matches!(
                    reply,
                    Message::Error {
                        code: ErrorCode::Locked,
                        ..
                    }
                ),
                "{reply:?}"
            );
            let held = f.agent.activity.lock().unwrap().take_held();
            assert_eq!(held.last().map(|e| e.outcome), Some(Outcome::Locked));
        }
    }
}
