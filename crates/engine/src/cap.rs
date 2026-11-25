//! Capabilities: what a caller may do, granted on purpose and never
//! ambient. Connecting to the daemon as the same user proves nothing; a
//! request that needs more than the caller's standing names a [`CapId`],
//! minted by a human gesture, scoped to one verb, and gone when it expires,
//! runs out of uses, is revoked or the device locks (the table lives in the
//! [`crate::Engine`], which a lock drops).
//!
//! An id is 32 random bytes, wiped on drop, left out of `Debug`, and looked
//! up by comparing it in constant time against every grant, so neither a
//! timing nor a log reveals one.

use std::fmt;

use anyhow::{Result, bail};
use subtle::ConstantTimeEq;
use zeroize::Zeroize;

use crate::Clock;

/// The most grants alive at once; past it, minting fails.
pub const MAX_GRANTS: usize = 1024;

/// A capability's id: 32 random bytes, wiped on drop.
#[derive(Clone)]
pub struct CapId([u8; 32]);

impl Drop for CapId {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

impl CapId {
    /// A fresh random id.
    pub fn random() -> Result<Self> {
        let mut bytes = [0u8; 32];
        getrandom::fill(&mut bytes).map_err(|e| anyhow::anyhow!("drawing a capability id: {e}"))?;
        let id = Self(bytes);
        bytes.zeroize();
        Ok(id)
    }

    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl PartialEq for CapId {
    fn eq(&self, other: &Self) -> bool {
        self.0.ct_eq(&other.0).into()
    }
}

impl Eq for CapId {}

impl fmt::Debug for CapId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("CapId(<redacted>)")
    }
}

/// Where a [`CapVerb::Use`] may act, without revealing the secret it uses.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UseScope {
    /// Fill a login on this origin only.
    Fill { origin: String },
    /// Sign with this item for this target: a WebAuthn RP, an SSH host or
    /// a Git commit.
    Sign { item_id: String, target: String },
    /// Inject this reference into this brokered route.
    Inject { ref_uri: String, route: String },
}

/// What a capability allows.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CapVerb {
    /// Vault and item titles and other metadata, never a secret.
    Meta,
    /// Use a secret where it belongs without handing it over.
    Use(UseScope),
    /// Read exactly these references' values.
    Reveal { refs: Vec<String> },
}

/// What a request needs, checked against a grant's [`CapVerb`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CapCheck {
    Meta,
    Use(UseScope),
    /// Every one of these must be among the grant's references.
    Reveal {
        refs: Vec<String>,
    },
}

/// The gesture that minted a capability, kept for the audit trail.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GestureKind {
    Biometric,
    Passphrase,
    AppApproval,
    CliForeground,
}

/// One live capability.
#[derive(Debug, Clone)]
pub struct CapGrant {
    pub id: CapId,
    pub verb: CapVerb,
    /// Who it was minted for, a label (`deadbolt run`'s id, an app).
    pub subject: String,
    /// Unix milliseconds.
    pub issued_ms: u64,
    pub expires_ms: u64,
    /// `None`: any number of uses until it expires.
    pub max_uses: Option<u32>,
    pub uses: u32,
    pub minted_by: GestureKind,
}

impl CapGrant {
    fn expired(&self, now_ms: u64) -> bool {
        now_ms >= self.expires_ms
    }

    fn exhausted(&self) -> bool {
        self.max_uses.is_some_and(|max| self.uses >= max)
    }

    fn live(&self, now_ms: u64) -> bool {
        !self.expired(now_ms) && !self.exhausted()
    }
}

/// A use that [`CapTable::authorize`] allowed: what to record, never the id.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CapAudit {
    pub verb: CapVerb,
    pub subject: String,
    pub minted_by: GestureKind,
    /// Uses so far, this one included.
    pub uses: u32,
    /// Uses left, `None` for unlimited.
    pub remaining: Option<u32>,
}

/// Why a capability didn't allow a request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CapError {
    /// The request named no capability, and needs one.
    Required,
    /// No live grant has this id.
    Invalid,
    Expired,
    /// A grant of limited uses was used up.
    Exhausted,
    /// The grant is for something else.
    ScopeMismatch,
}

impl fmt::Display for CapError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Required => "this needs a capability",
            Self::Invalid => "no such capability",
            Self::Expired => "the capability expired",
            Self::Exhausted => "the capability was used up",
            Self::ScopeMismatch => "the capability doesn't allow this",
        })
    }
}

impl std::error::Error for CapError {}

fn now_ms(clock: &dyn Clock) -> u64 {
    u64::try_from(clock.now().as_millis()).unwrap_or(u64::MAX)
}

/// Whether `verb` allows `check`. Verbs never imply one another: a
/// `Reveal` doesn't list titles, and `Meta` reveals nothing.
fn allows(verb: &CapVerb, check: &CapCheck) -> bool {
    match (verb, check) {
        (CapVerb::Meta, CapCheck::Meta) => true,
        (CapVerb::Use(granted), CapCheck::Use(wanted)) => granted == wanted,
        (CapVerb::Reveal { refs: granted }, CapCheck::Reveal { refs: wanted }) => {
            !wanted.is_empty() && wanted.iter().all(|r| granted.contains(r))
        }
        _ => false,
    }
}

/// The live capabilities, in daemon memory only.
#[derive(Debug, Default)]
pub struct CapTable {
    grants: Vec<CapGrant>,
}

impl CapTable {
    pub fn new() -> Self {
        Self::default()
    }

    /// Grants `verb` to `subject` for `ttl_ms` and at most `max_uses` uses.
    pub fn mint(
        &mut self,
        clock: &dyn Clock,
        verb: CapVerb,
        subject: &str,
        ttl_ms: u64,
        max_uses: Option<u32>,
        minted_by: GestureKind,
    ) -> Result<CapId> {
        if ttl_ms == 0 {
            bail!("a capability needs a lifetime");
        }
        if max_uses == Some(0) {
            bail!("a capability needs at least one use");
        }
        if let CapVerb::Reveal { refs } = &verb
            && refs.is_empty()
        {
            bail!("a reveal capability names its references");
        }
        self.prune(clock);
        if self.grants.len() >= MAX_GRANTS {
            bail!("too many capabilities are live");
        }
        let issued_ms = now_ms(clock);
        let id = CapId::random()?;
        self.grants.push(CapGrant {
            id: id.clone(),
            verb,
            subject: subject.into(),
            issued_ms,
            expires_ms: issued_ms.saturating_add(ttl_ms),
            max_uses,
            uses: 0,
            minted_by,
        });
        Ok(id)
    }

    /// The index of `id`'s grant, comparing it with every grant in
    /// constant time and never stopping early.
    fn find(&self, id: &CapId) -> Option<usize> {
        let mut found = None;
        for (index, grant) in self.grants.iter().enumerate() {
            if bool::from(grant.id.0.ct_eq(&id.0)) {
                found = Some(index);
            }
        }
        found
    }

    /// Allows `required` under `id` and counts the use, or says why not.
    /// An expired or used-up grant goes as it is found; a grant whose last
    /// use this was goes too.
    pub fn authorize(
        &mut self,
        clock: &dyn Clock,
        id: &CapId,
        required: &CapCheck,
    ) -> Result<CapAudit, CapError> {
        let now = now_ms(clock);
        let index = self.find(id).ok_or(CapError::Invalid)?;
        let grant = &mut self.grants[index];
        if grant.expired(now) {
            self.grants.swap_remove(index);
            return Err(CapError::Expired);
        }
        if grant.exhausted() {
            self.grants.swap_remove(index);
            return Err(CapError::Exhausted);
        }
        if !allows(&grant.verb, required) {
            return Err(CapError::ScopeMismatch);
        }
        grant.uses = grant.uses.saturating_add(1);
        let audit = CapAudit {
            verb: grant.verb.clone(),
            subject: grant.subject.clone(),
            minted_by: grant.minted_by,
            uses: grant.uses,
            remaining: grant.max_uses.map(|max| max.saturating_sub(grant.uses)),
        };
        if grant.exhausted() {
            self.grants.swap_remove(index);
        }
        Ok(audit)
    }

    /// Ends `id`'s grant; whether there was one.
    pub fn revoke(&mut self, id: &CapId) -> bool {
        self.find(id)
            .map(|index| self.grants.swap_remove(index))
            .is_some()
    }

    /// Ends every grant minted for `subject`; how many.
    pub fn revoke_subject(&mut self, subject: &str) -> usize {
        let before = self.grants.len();
        self.grants.retain(|grant| grant.subject != subject);
        before - self.grants.len()
    }

    /// Ends every grant, as the device locks. The ids are wiped as they drop.
    pub fn clear(&mut self) {
        self.grants.clear();
    }

    /// Drops expired and used-up grants.
    pub fn prune(&mut self, clock: &dyn Clock) {
        let now = now_ms(clock);
        self.grants.retain(|grant| grant.live(now));
    }

    /// The grants still usable now.
    pub fn active_count(&self, clock: &dyn Clock) -> usize {
        let now = now_ms(clock);
        self.grants.iter().filter(|grant| grant.live(now)).count()
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::*;
    use crate::clock::FixedClock;
    use crate::testing::NOW;

    fn at(ms: u64) -> FixedClock {
        FixedClock(NOW + Duration::from_millis(ms))
    }

    fn reveal(refs: &[&str]) -> CapVerb {
        CapVerb::Reveal {
            refs: refs.iter().map(|r| (*r).to_string()).collect(),
        }
    }

    fn reveal_check(refs: &[&str]) -> CapCheck {
        CapCheck::Reveal {
            refs: refs.iter().map(|r| (*r).to_string()).collect(),
        }
    }

    fn fill(origin: &str) -> UseScope {
        UseScope::Fill {
            origin: origin.into(),
        }
    }

    #[test]
    fn a_grant_lives_until_its_ttl_and_then_is_gone() {
        let mut caps = CapTable::new();
        let id = caps
            .mint(
                &at(0),
                CapVerb::Meta,
                "run",
                1_000,
                None,
                GestureKind::CliForeground,
            )
            .unwrap();
        assert_eq!(caps.active_count(&at(0)), 1);
        let audit = caps.authorize(&at(999), &id, &CapCheck::Meta).unwrap();
        assert_eq!((audit.uses, audit.remaining), (1, None));
        assert_eq!(audit.minted_by, GestureKind::CliForeground);
        assert_eq!(caps.active_count(&at(1_000)), 0);
        assert_eq!(
            caps.authorize(&at(1_000), &id, &CapCheck::Meta),
            Err(CapError::Expired)
        );
        // Evicted as it was found.
        assert_eq!(
            caps.authorize(&at(0), &id, &CapCheck::Meta),
            Err(CapError::Invalid)
        );
    }

    #[test]
    fn a_one_shot_grant_allows_exactly_one_use() {
        let mut caps = CapTable::new();
        let verb = reveal(&["deadbolt://GitHub/token"]);
        let id = caps
            .mint(&at(0), verb, "run", 60_000, Some(1), GestureKind::Biometric)
            .unwrap();
        let check = reveal_check(&["deadbolt://GitHub/token"]);
        let audit = caps.authorize(&at(1), &id, &check).unwrap();
        assert_eq!((audit.uses, audit.remaining), (1, Some(0)));
        assert_eq!(caps.active_count(&at(1)), 0);
        assert_eq!(caps.authorize(&at(2), &id, &check), Err(CapError::Invalid));
    }

    #[test]
    fn a_limited_grant_is_exhausted_after_its_uses() {
        let mut caps = CapTable::new();
        let id = caps
            .mint(
                &at(0),
                CapVerb::Meta,
                "app",
                60_000,
                Some(3),
                GestureKind::AppApproval,
            )
            .unwrap();
        for used in 1..=3 {
            let audit = caps.authorize(&at(used), &id, &CapCheck::Meta).unwrap();
            assert_eq!(audit.remaining, Some(3 - u32::try_from(used).unwrap()));
        }
        assert_eq!(
            caps.authorize(&at(4), &id, &CapCheck::Meta),
            Err(CapError::Invalid)
        );
    }

    #[test]
    fn scopes_never_stretch() {
        let mut caps = CapTable::new();
        let clock = at(0);
        let gesture = GestureKind::Passphrase;
        let a = caps
            .mint(
                &clock,
                CapVerb::Use(fill("https://a.com")),
                "x",
                60_000,
                None,
                gesture,
            )
            .unwrap();
        let meta = caps
            .mint(&clock, CapVerb::Meta, "x", 60_000, None, gesture)
            .unwrap();
        let one = caps
            .mint(
                &clock,
                reveal(&["deadbolt://ref1"]),
                "x",
                60_000,
                None,
                gesture,
            )
            .unwrap();

        let mismatch = Err(CapError::ScopeMismatch);
        assert_eq!(
            caps.authorize(&clock, &a, &CapCheck::Use(fill("https://b.com"))),
            mismatch
        );
        assert!(
            caps.authorize(&clock, &a, &CapCheck::Use(fill("https://a.com")))
                .is_ok()
        );
        assert_eq!(caps.authorize(&clock, &a, &CapCheck::Meta), mismatch);
        assert_eq!(
            caps.authorize(&clock, &meta, &reveal_check(&["deadbolt://ref1"])),
            mismatch
        );
        assert_eq!(
            caps.authorize(&clock, &one, &reveal_check(&["deadbolt://ref2"])),
            mismatch
        );
        assert_eq!(
            caps.authorize(
                &clock,
                &one,
                &reveal_check(&["deadbolt://ref1", "deadbolt://ref2"])
            ),
            mismatch
        );
        assert_eq!(caps.authorize(&clock, &one, &reveal_check(&[])), mismatch);
        assert_eq!(caps.authorize(&clock, &one, &CapCheck::Meta), mismatch);
        assert!(
            caps.authorize(&clock, &one, &reveal_check(&["deadbolt://ref1"]))
                .is_ok()
        );
        let sign = UseScope::Sign {
            item_id: "k".into(),
            target: "github.com".into(),
        };
        assert_eq!(caps.authorize(&clock, &a, &CapCheck::Use(sign)), mismatch);
        // A mismatch spends no use.
        assert_eq!(caps.active_count(&clock), 3);
    }

    #[test]
    fn unknown_ids_are_invalid_and_revocation_ends_grants() {
        let mut caps = CapTable::new();
        let clock = at(0);
        let gesture = GestureKind::AppApproval;
        let forged = CapId::from_bytes([9; 32]);
        assert_eq!(
            caps.authorize(&clock, &forged, &CapCheck::Meta),
            Err(CapError::Invalid)
        );
        let a = caps
            .mint(&clock, CapVerb::Meta, "one", 60_000, None, gesture)
            .unwrap();
        let b = caps
            .mint(&clock, CapVerb::Meta, "two", 60_000, None, gesture)
            .unwrap();
        caps.mint(&clock, CapVerb::Meta, "two", 60_000, None, gesture)
            .unwrap();
        assert_ne!(a, b);
        assert!(caps.revoke(&a));
        assert!(!caps.revoke(&a));
        assert_eq!(caps.revoke_subject("two"), 2);
        assert_eq!(
            caps.authorize(&clock, &b, &CapCheck::Meta),
            Err(CapError::Invalid)
        );
    }

    #[test]
    fn locking_wipes_every_grant() {
        let mut engine = crate::testing::engine();
        let clock = at(0);
        let id = engine
            .caps
            .mint(
                &clock,
                CapVerb::Meta,
                "x",
                60_000,
                None,
                GestureKind::Biometric,
            )
            .unwrap();
        engine
            .caps
            .mint(
                &clock,
                reveal(&["deadbolt://a"]),
                "y",
                60_000,
                None,
                GestureKind::Biometric,
            )
            .unwrap();
        engine.lock();
        assert_eq!(engine.caps.active_count(&clock), 0);
        assert_eq!(
            engine.caps.authorize(&clock, &id, &CapCheck::Meta),
            Err(CapError::Invalid)
        );
    }

    #[test]
    fn prune_drops_only_dead_grants() {
        let mut caps = CapTable::new();
        let gesture = GestureKind::CliForeground;
        caps.mint(&at(0), CapVerb::Meta, "short", 10, None, gesture)
            .unwrap();
        let long = caps
            .mint(&at(0), CapVerb::Meta, "long", 10_000, None, gesture)
            .unwrap();
        caps.prune(&at(10));
        assert_eq!(caps.grants.len(), 1);
        assert!(caps.authorize(&at(11), &long, &CapCheck::Meta).is_ok());
    }

    #[test]
    fn nonsense_grants_are_refused() {
        let mut caps = CapTable::new();
        let gesture = GestureKind::CliForeground;
        assert!(
            caps.mint(&at(0), CapVerb::Meta, "x", 0, None, gesture)
                .is_err()
        );
        assert!(
            caps.mint(&at(0), CapVerb::Meta, "x", 1, Some(0), gesture)
                .is_err()
        );
        assert!(
            caps.mint(&at(0), reveal(&[]), "x", 1, None, gesture)
                .is_err()
        );
    }

    #[test]
    fn debug_never_shows_an_id() {
        let mut caps = CapTable::new();
        let id = caps
            .mint(
                &at(0),
                CapVerb::Meta,
                "x",
                1_000,
                None,
                GestureKind::Biometric,
            )
            .unwrap();
        let hex = crate::hex(id.as_bytes());
        for shown in [format!("{id:?}"), format!("{caps:?}")] {
            assert!(
                shown.contains("<redacted>") && !shown.contains(&hex),
                "{shown}"
            );
        }
    }
}
