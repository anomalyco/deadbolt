//! Sites that share sign-in credentials, from Apple's
//! `quirks/shared-credentials.json` (bundled as `data/health/shared.json`).
//!
//! Apple's entries are one of two kinds:
//!
//! - `shared`: sites with one account system. A login saved on any of them
//!   is offered on all of them.
//! - `from` and `to`: a login saved on a `from` site is offered on its `to`
//!   sites, never the reverse, and two `from` (or two `to`) sites of one
//!   entry share nothing with each other. `fromDomainsAreObsoleted` says the
//!   `from` sites no longer sign anyone in; it changes nothing here.
//!
//! Every domain is folded to its registrable domain and kept only if it is
//! a site of its own: never an IP address, `localhost`, a `.localhost` or
//! `.test` host, or a public suffix. Apple asks that a login offered this
//! way always says which site it was saved for, so callers rank these after
//! every login of the page's own site (see [`super::Closeness::Shared`]).

use std::collections::{BTreeSet, HashMap};
use std::sync::LazyLock;

use serde::Deserialize;

use super::{is_dotted_quad, registrable_domain, valid_domain};

/// One entry of the shared-credentials list, its sites sorted and deduped.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Group {
    /// Sites with one account system.
    Shared(Vec<String>),
    /// Sites whose logins are offered on `to`, and not the reverse.
    Moved { from: Vec<String>, to: Vec<String> },
}

#[derive(Deserialize)]
struct Raw {
    #[serde(default)]
    shared: Vec<String>,
    #[serde(default)]
    from: Vec<String>,
    #[serde(default)]
    to: Vec<String>,
}

static GROUPS: LazyLock<Vec<Group>> =
    LazyLock::new(|| parse(include_str!("../../data/health/shared.json")));

/// The page's site, to the other sites whose logins it is offered.
static OFFERED: LazyLock<HashMap<String, BTreeSet<String>>> = LazyLock::new(|| offers(&GROUPS));

/// The bundled shared-credentials list.
pub fn groups() -> &'static [Group] {
    &GROUPS
}

/// Whether a login saved on the site `saved` is offered on a page on the
/// site `page` because the two share credentials. Both are registrable
/// domains (see [`registrable_domain`]); a site never shares with itself.
pub fn offered(page: &str, saved: &str) -> bool {
    OFFERED.get(page).is_some_and(|sites| sites.contains(saved))
}

/// Parses Apple's list, dropping what isn't a site of its own, and groups
/// left with nothing to share.
pub(crate) fn parse(json: &str) -> Vec<Group> {
    let raw: Vec<Raw> = serde_json::from_str(json).unwrap_or_default();
    let mut groups = Vec::new();
    for entry in raw {
        let shared = sites(&entry.shared);
        if shared.len() > 1 {
            groups.push(Group::Shared(shared));
        }
        let (from, to) = (sites(&entry.from), sites(&entry.to));
        if !from.is_empty() && !to.is_empty() {
            groups.push(Group::Moved { from, to });
        }
    }
    groups
}

fn offers(groups: &[Group]) -> HashMap<String, BTreeSet<String>> {
    let mut map: HashMap<String, BTreeSet<String>> = HashMap::new();
    let mut offer = |page: &String, saved: &String| {
        if page != saved {
            map.entry(page.clone()).or_default().insert(saved.clone());
        }
    };
    for group in groups {
        match group {
            Group::Shared(sites) => {
                for page in sites {
                    sites.iter().for_each(|saved| offer(page, saved));
                }
            }
            Group::Moved { from, to } => {
                for page in to {
                    from.iter().for_each(|saved| offer(page, saved));
                }
            }
        }
    }
    map
}

fn sites(domains: &[String]) -> Vec<String> {
    let mut out: Vec<String> = domains.iter().filter_map(|d| site(d)).collect();
    out.sort();
    out.dedup();
    out
}

/// The registrable domain of `domain`, if it is a site of its own.
fn site(domain: &str) -> Option<String> {
    let site = registrable_domain(domain.trim());
    let local = site == "localhost" || site.ends_with(".localhost") || site.ends_with(".test");
    let address = is_dotted_quad(&site) || site.contains(':');
    (!local && !address && valid_domain(&site)).then_some(site)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_bundled_list_has_only_sites_of_their_own() {
        assert!(groups().len() > 100, "{}", groups().len());
        for group in groups() {
            let sites: Vec<&String> = match group {
                Group::Shared(sites) => sites.iter().collect(),
                Group::Moved { from, to } => from.iter().chain(to).collect(),
            };
            for site in sites {
                assert_eq!(registrable_domain(site), *site, "{group:?}");
                assert!(valid_domain(site) && !is_dotted_quad(site), "{site}");
                assert_ne!(site, "localhost");
            }
        }
    }

    #[test]
    fn shared_sites_share_both_ways() {
        assert!(offered("themeforest.net", "envato.com"));
        assert!(offered("envato.com", "themeforest.net"));
        assert!(offered("codecanyon.net", "themeforest.net"));
        assert!(!offered("envato.com", "envato.com"));
        assert!(!offered("envato.com", "evil-envato.com"));
        assert!(!offered("evil-envato.com", "envato.com"));
    }

    #[test]
    fn moved_sites_share_one_way_only() {
        // {"from":["twitter.com"],"to":["x.com"],"fromDomainsAreObsoleted":true}
        assert!(offered("x.com", "twitter.com"));
        assert!(!offered("twitter.com", "x.com"));
        // {"from":["hbo.com","hbomax.com","hbonow.com"],"to":["max.com"],...}
        assert!(offered("max.com", "hbo.com") && offered("max.com", "hbomax.com"));
        assert!(!offered("hbo.com", "hbomax.com"));
        assert!(!offered("hbomax.com", "hbo.com"));
        // {"from":["adobelogin.com","behance.net"],"to":["adobe.com"]}: no
        // fromDomainsAreObsoleted, still one way.
        assert!(offered("adobe.com", "behance.net"));
        assert!(!offered("behance.net", "adobe.com"));
        assert!(!offered("behance.net", "adobelogin.com"));
        // Several `to` sites share nothing with each other.
        assert!(offered("rtlplus.de", "tvnow.de") && offered("rtlplus.com", "tvnow.de"));
        assert!(!offered("rtlplus.de", "rtlplus.com"));
    }

    #[test]
    fn subdomains_fold_and_non_sites_drop() {
        let groups = parse(
            r#"[
                {"shared": ["www.Example.com", "login.example.org", "example.com"]},
                {"shared": ["localhost", "127.0.0.1", "co.uk", "github.io", "app.test", "a.localhost", "solo.com"]},
                {"from": ["10.0.0.1", "old.example.net"], "to": ["id.example.com"], "fromDomainsAreObsoleted": true},
                {"from": ["co.uk"], "to": ["example.com"]},
                {"nonsense": true}
            ]"#,
        );
        assert_eq!(
            groups,
            [
                Group::Shared(vec!["example.com".into(), "example.org".into()]),
                Group::Moved {
                    from: vec!["example.net".into()],
                    to: vec!["example.com".into()],
                },
            ]
        );
        let map = offers(&groups);
        assert_eq!(map["example.com"].len(), 2);
        assert_eq!(map["example.org"].len(), 1);
        assert!(!map.contains_key("example.net"));
        assert!(parse("not json").is_empty());
    }
}
