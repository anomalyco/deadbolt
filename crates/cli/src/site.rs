//! Which saved logins belong to a web page, for browser autofill.
//!
//! The rules follow those of Foyer, the autofill extension by Ryan Vogel
//! that Deadbolt's extension learned from (no code is shared):
//!
//! - A page's site is its registrable domain under the full Public Suffix
//!   List, private section included, so `alice.github.io` and
//!   `bob.github.io` are different sites. A page on a public suffix itself
//!   (`github.io`) has no site and gets nothing.
//! - A saved URL belongs to the site `domain` when its host is `domain`, a
//!   subdomain of it, or has `domain` as its registrable domain. A URL
//!   without a scheme is read as https. The port and path don't matter.
//! - Logins are offered only to https pages, or http ones on local
//!   development hosts.

use url::Url;

/// The site of a web page that asked for logins.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Site {
    /// The page's registrable domain, lowercase.
    pub domain: String,
}

impl Site {
    /// The site of the page at `origin`, if Deadbolt fills logins there.
    pub fn from_origin(origin: &str) -> Result<Self, &'static str> {
        let host = fillable_host(origin).ok_or("not a secure web page")?;
        let domain = registrable_domain(&host);
        if !valid_domain(&domain) {
            return Err("the page is not on a site of its own");
        }
        Ok(Self { domain })
    }

    /// Whether any of `urls` belongs to this site.
    pub fn matches<'a>(&self, urls: impl IntoIterator<Item = &'a str>) -> bool {
        urls.into_iter().any(|url| self.matches_url(url))
    }

    pub fn matches_url(&self, url: &str) -> bool {
        url_host(url).is_some_and(|host| host_matches(&host, &self.domain))
    }
}

/// A URL's host as WHATWG URL parsing gives it (lowercase, IDNs in
/// punycode, no port), without IPv6 brackets. A URL without `://` is read
/// as https.
pub fn url_host(url: &str) -> Option<String> {
    let raw = url.trim();
    if raw.is_empty() {
        return None;
    }
    let parsed = if raw.contains("://") {
        Url::parse(raw)
    } else {
        Url::parse(&format!("https://{raw}"))
    };
    let host = parsed.ok()?.host_str()?.to_lowercase();
    let host = host.strip_prefix('[').unwrap_or(&host);
    let host = host.strip_suffix(']').unwrap_or(host);
    (!host.is_empty()).then(|| host.to_string())
}

/// `host` is `domain` or under it, ignoring case and a trailing dot.
fn host_within(host: &str, domain: &str) -> bool {
    let host = host.to_lowercase();
    let domain = domain.to_lowercase();
    let host = host.strip_suffix('.').unwrap_or(&host);
    let domain = domain.strip_suffix('.').unwrap_or(&domain);
    host == domain
        || host
            .strip_suffix(domain)
            .is_some_and(|rest| rest.ends_with('.'))
}

/// `host` belongs to the site `domain`.
pub fn host_matches(host: &str, domain: &str) -> bool {
    host_within(host, domain) || registrable_domain(host) == domain.to_lowercase()
}

/// The registrable domain of `host` under the full Public Suffix List; an
/// IPv4 address, `localhost` or a single label is its own. A host that is a
/// public suffix itself is returned as it is.
pub fn registrable_domain(host: &str) -> String {
    let host = host.to_lowercase();
    let host = host.strip_prefix("*.").unwrap_or(&host);
    let host = host.strip_suffix('.').unwrap_or(host);
    if is_dotted_quad(host) || host == "localhost" || !host.contains('.') {
        return host.to_string();
    }
    psl::domain(host.as_bytes())
        .and_then(|d| std::str::from_utf8(d.as_bytes()).ok())
        .unwrap_or(host)
        .to_string()
}

fn is_dotted_quad(host: &str) -> bool {
    let parts: Vec<&str> = host.split('.').collect();
    parts.len() == 4
        && parts
            .iter()
            .all(|p| !p.is_empty() && p.bytes().all(|b| b.is_ascii_digit()))
}

/// A lowercase site name that isn't a public suffix itself.
fn valid_domain(domain: &str) -> bool {
    if domain.is_empty()
        || !domain
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'.' || b == b'-')
        || domain.starts_with('.')
        || domain.ends_with('.')
        || domain.contains("..")
    {
        return false;
    }
    if domain == "localhost" {
        return true;
    }
    let probe = format!("x.{domain}");
    registrable_domain(&probe) != probe
}

/// The relying party id a page at `origin` may use for a passkey: `rp_id`
/// if it is the page's host or a parent of it on the same site, else the
/// host when the page names none. Never a public suffix (`github.io`,
/// `co.uk`), an IP address, or another site, as WebAuthn requires.
pub fn rp_id(origin: &str, rp_id: Option<&str>) -> Result<String, &'static str> {
    let host = fillable_host(origin).ok_or("not a secure web page")?;
    let host = host.strip_suffix('.').unwrap_or(&host);
    if is_dotted_quad(host) || host.contains(':') {
        return Err("an IP address has no relying party id");
    }
    let site = registrable_domain(host);
    if !valid_domain(&site) {
        return Err("the page is not on a site of its own");
    }
    let Some(rp_id) = rp_id else {
        return Ok(host.to_string());
    };
    let rp_id = rp_id.to_ascii_lowercase();
    let within = rp_id == host
        || host
            .strip_suffix(rp_id.as_str())
            .is_some_and(|rest| rest.ends_with('.'));
    if !valid_domain(&rp_id) || !within || registrable_domain(&rp_id) != site {
        return Err("the relying party id isn't this page's host or its site");
    }
    Ok(rp_id)
}

/// A URL a page offers to save, trimmed: whole (with a scheme) and on a
/// page Deadbolt fills, by the rule for origins.
pub fn page_url(url: &str) -> Result<&str, &'static str> {
    let url = url.trim();
    if url.chars().any(|c| c.is_whitespace() || c.is_control()) {
        return Err("a URL has no spaces");
    }
    fillable_host(url).ok_or("not the URL of a secure web page")?;
    Ok(url)
}

/// The host of `origin` if Deadbolt fills logins there: https, or http on
/// `localhost`, `127.0.0.1`, `*.localhost` or `*.test`.
fn fillable_host(origin: &str) -> Option<String> {
    let url = Url::parse(origin).ok()?;
    let host = url.host_str()?.to_lowercase();
    let bare = host.strip_suffix('.').unwrap_or(&host);
    let local = bare == "localhost"
        || bare == "127.0.0.1"
        || bare.ends_with(".localhost")
        || bare.ends_with(".test");
    match url.scheme() {
        "https" => Some(host),
        "http" if local => Some(host),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn site(origin: &str) -> Site {
        Site::from_origin(origin).unwrap()
    }

    #[test]
    fn hosts_parse_like_whatwg_urls() {
        assert_eq!(
            url_host("https://GitHub.com/login").as_deref(),
            Some("github.com")
        );
        assert_eq!(url_host("github.com").as_deref(), Some("github.com"));
        assert_eq!(url_host("  github.com/x  ").as_deref(), Some("github.com"));
        assert_eq!(
            url_host("https://github.com:8443/").as_deref(),
            Some("github.com")
        );
        assert_eq!(url_host("localhost:3000").as_deref(), Some("localhost"));
        assert_eq!(url_host("http://[::1]:8080/").as_deref(), Some("::1"));
        assert_eq!(
            url_host("https://user:pw@github.com").as_deref(),
            Some("github.com")
        );
        assert_eq!(
            url_host("https://bücher.de").as_deref(),
            Some("xn--bcher-kva.de")
        );
        assert_eq!(
            url_host("https://github.com.").as_deref(),
            Some("github.com.")
        );
        // Without "://" a scheme-looking prefix is userinfo, as in Foyer.
        assert_eq!(url_host("mailto:a@b.com").as_deref(), Some("b.com"));
        assert_eq!(url_host(""), None);
        assert_eq!(url_host("   "), None);
        assert_eq!(url_host("https://"), None);
        assert_eq!(url_host("https://exa mple.com"), None);
        assert_eq!(url_host("not a url"), None);
        assert_eq!(url_host("file:///etc/passwd"), None);
    }

    #[test]
    fn registrable_domains_use_the_whole_suffix_list() {
        assert_eq!(registrable_domain("gist.github.com"), "github.com");
        assert_eq!(registrable_domain("GitHub.COM."), "github.com");
        assert_eq!(registrable_domain("*.github.com"), "github.com");
        assert_eq!(registrable_domain("www.bbc.co.uk"), "bbc.co.uk");
        assert_eq!(registrable_domain("alice.github.io"), "alice.github.io");
        assert_eq!(registrable_domain("x.alice.github.io"), "alice.github.io");
        assert_eq!(registrable_domain("github.io"), "github.io");
        assert_eq!(registrable_domain("co.uk"), "co.uk");
        assert_eq!(
            registrable_domain("app.example.unknowntld"),
            "example.unknowntld"
        );
        assert_eq!(registrable_domain("192.168.1.10"), "192.168.1.10");
        // Not "1.10" by the list's default rule, as if 10 were a TLD.
        assert_eq!(registrable_domain("10.0.1.10"), "10.0.1.10");
        assert_eq!(registrable_domain("localhost"), "localhost");
        assert_eq!(registrable_domain("intranet"), "intranet");
        assert_eq!(registrable_domain("::1"), "::1");
    }

    #[test]
    fn a_site_owns_its_host_and_subdomains() {
        let github = site("https://github.com");
        assert!(github.matches_url("https://github.com"));
        assert!(github.matches_url("https://github.com/login?next=/"));
        assert!(github.matches_url("github.com"));
        assert!(github.matches_url("https://gist.github.com"));
        assert!(github.matches_url("https://a.b.github.com"));
        assert!(github.matches_url("https://GITHUB.com"));
        assert!(github.matches_url("https://github.com.:443/"));
        assert!(github.matches_url("https://github.com:8443"));
        assert!(github.matches_url("http://github.com"));
        assert!(github.matches_url("ssh://git@github.com"));
    }

    #[test]
    fn lookalikes_are_other_sites() {
        let github = site("https://github.com");
        for url in [
            "https://github.com.evil.com",
            "https://evilgithub.com",
            "https://github.co",
            "https://github.com-login.net",
            "https://xn--gthub-n4a.com",
            "https://gíthub.com",
            "https://evil.com/github.com",
            "https://evil.com?github.com",
            "https://github.com@evil.com",
            "https://evil.com#github.com",
            "",
            "   ",
            "github",
            "https://",
            "https://exa mple.com",
        ] {
            assert!(
                !github.matches_url(url),
                "{url:?} must not match github.com"
            );
        }
    }

    #[test]
    fn private_suffixes_split_sites() {
        let alice = site("https://alice.github.io");
        assert!(alice.matches_url("https://alice.github.io"));
        assert!(alice.matches_url("https://www.alice.github.io"));
        assert!(!alice.matches_url("https://bob.github.io"));
        assert!(!alice.matches_url("https://github.io"));
        let bbc = site("https://www.bbc.co.uk");
        assert!(bbc.matches_url("https://www.bbc.co.uk"));
        assert!(!bbc.matches_url("https://itv.co.uk"));
        assert!(!bbc.matches_url("https://co.uk"));
    }

    #[test]
    fn addresses_and_local_hosts_match_only_themselves() {
        let ip = site("https://192.168.1.10:8443");
        assert!(ip.matches_url("https://192.168.1.10:8443/admin"));
        assert!(ip.matches_url("192.168.1.10"));
        assert!(!ip.matches_url("https://192.168.1.11"));
        assert!(!ip.matches_url("https://10.192.168.1.10"));
        let ten = site("https://10.0.1.10");
        assert_eq!(ten.domain, "10.0.1.10");
        assert!(ten.matches_url("https://10.0.1.10/login"));
        for other in [
            "https://9.0.1.10",
            "https://1.10",
            "https://0.1.10",
            "https://10.0.1.1",
        ] {
            assert!(!ten.matches_url(other), "{other}");
        }
        let local = site("http://localhost:3000");
        assert!(local.matches_url("http://localhost:5173"));
        assert!(local.matches_url("http://app.localhost"));
        assert!(!local.matches_url("https://localhost.evil.com"));
        assert!(!local.matches_url("https://127.0.0.1"));
    }

    #[test]
    fn any_saved_url_can_match() {
        let github = site("https://github.com");
        assert!(github.matches([
            "https://gitlab.com",
            "",
            "nonsense url",
            "https://github.com"
        ]));
        assert!(!github.matches(["https://gitlab.com", "https://github.com.evil.com"]));
        assert!(!github.matches([]));
    }

    #[test]
    fn a_page_gets_its_registrable_domain() {
        assert_eq!(site("https://github.com").domain, "github.com");
        assert_eq!(site("https://Gist.GitHub.com:8443").domain, "github.com");
        assert_eq!(site("https://github.com.").domain, "github.com");
        assert_eq!(site("https://alice.github.io").domain, "alice.github.io");
        assert_eq!(site("https://www.bbc.co.uk").domain, "bbc.co.uk");
        assert_eq!(site("https://bücher.de").domain, "xn--bcher-kva.de");
        assert_eq!(
            site("https://app.example.unknowntld").domain,
            "example.unknowntld"
        );
        assert_eq!(site("https://192.168.1.10").domain, "192.168.1.10");
        assert_eq!(site("http://localhost:3000").domain, "localhost");
        assert_eq!(site("http://app.localhost").domain, "app.localhost");
        assert_eq!(site("http://myapp.test").domain, "myapp.test");
        assert_eq!(site("http://127.0.0.1:8080").domain, "127.0.0.1");
        assert_eq!(site("http://localhost.:3000").domain, "localhost");
        assert_eq!(site("http://myapp.test.").domain, "myapp.test");
        assert_eq!(site("http://app.localhost.").domain, "app.localhost");
    }

    #[test]
    fn saved_page_urls_are_whole_and_secure() {
        assert_eq!(
            page_url("  https://github.com/login \n"),
            Ok("https://github.com/login")
        );
        assert_eq!(
            page_url("http://localhost:3000/"),
            Ok("http://localhost:3000/")
        );
        for url in [
            "github.com",
            "http://github.com",
            "javascript:alert(1)",
            "data:text/html,hi",
            "ftp://github.com",
            "file:///etc/passwd",
            "https://github.com/a b",
            "https://github.com/a\tb",
            "https://github.com/\u{7}",
            "",
        ] {
            assert!(page_url(url).is_err(), "{url:?}");
        }
    }

    #[test]
    fn only_secure_pages_with_a_site_get_logins() {
        for origin in [
            "http://github.com",
            "http://192.168.1.10",
            "http://evil.com/localhost",
            "http://localhost.evil.com",
            "http://test.evil.com",
            "github.com",
            "",
            "ftp://github.com",
            "javascript:alert(1)",
            "data:text/html,hi",
            "file:///etc/passwd",
            "chrome-extension://abcdefghijklmnopabcdefghijklmnop/",
            "https://github.io",
            "https://co.uk",
            "https://com",
            "https://[::1]",
            "https://intranet",
        ] {
            assert!(
                Site::from_origin(origin).is_err(),
                "{origin:?} must not get logins"
            );
        }
    }

    #[test]
    fn a_relying_party_id_is_the_host_or_a_parent_on_its_site() {
        let ok = |origin: &str, rp: Option<&str>, want: &str| {
            assert_eq!(rp_id(origin, rp).as_deref(), Ok(want), "{origin} {rp:?}");
        };
        ok("https://github.com", None, "github.com");
        ok("https://GitHub.com:8443", None, "github.com");
        ok("https://github.com", Some("github.com"), "github.com");
        ok("https://gist.github.com", Some("GitHub.com"), "github.com");
        ok(
            "https://a.b.github.com",
            Some("b.github.com"),
            "b.github.com",
        );
        ok(
            "https://alice.github.io",
            Some("alice.github.io"),
            "alice.github.io",
        );
        ok(
            "https://login.example.co.uk",
            Some("example.co.uk"),
            "example.co.uk",
        );
        ok("http://localhost:3000", None, "localhost");
        ok("http://localhost:3000", Some("localhost"), "localhost");
        ok(
            "http://app.localhost",
            Some("app.localhost"),
            "app.localhost",
        );

        for (origin, rp) in [
            // A public suffix, from the ICANN and the private section.
            ("https://alice.github.io", Some("github.io")),
            ("https://example.co.uk", Some("co.uk")),
            ("https://github.com", Some("com")),
            ("https://github.io", None),
            // Another site, a lookalike, a child, a sibling.
            ("https://github.com", Some("gitlab.com")),
            ("https://github.com", Some("hub.com")),
            ("https://github.com", Some("evil.github.com")),
            ("https://gist.github.com", Some("api.github.com")),
            ("https://alice.github.io", Some("bob.github.io")),
            ("https://github.com.evil.com", Some("github.com")),
            // Not a domain.
            ("https://github.com", Some("github.com.")),
            ("https://github.com", Some("")),
            ("https://github.com", Some("github.com:443")),
            ("https://github.com", Some("https://github.com")),
            ("https://xn--gthub-zsa.com", Some("github.com")),
            // Pages that get no passkeys.
            ("http://github.com", None),
            ("https://127.0.0.1", None),
            ("http://127.0.0.1", Some("127.0.0.1")),
            ("https://[::1]", None),
            ("null", None),
            ("chrome-extension://abcdefghijklmnopabcdefghijklmnop", None),
        ] {
            assert!(
                rp_id(origin, rp).is_err(),
                "{origin} {rp:?} must be refused"
            );
        }
    }
}
