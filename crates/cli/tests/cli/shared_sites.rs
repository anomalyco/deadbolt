//! Logins offered across sites that share credentials, through the real
//! daemon and `deadbolt browser-host` (see `deadbolt_core::site::shared`).

use super::*;

#[test]
fn browser_host_offers_logins_of_sites_sharing_credentials_after_the_pages_own() {
    let a = Device::new();
    a.run(&["init", "--device-name", "alpha"]);
    for (username, url, password) in [
        // envato.com and themeforest.net are one Apple `shared` group.
        ("envato", "https://envato.com", "envato-pw"),
        ("forest", "https://www.themeforest.net", "forest-pw"),
        ("plain", "http://envato.com", "plain-pw"),
        ("evil", "https://evil-envato.com", "evil-pw"),
        // twitter.com moved to x.com: one way only.
        ("bird", "https://twitter.com", "bird-pw"),
        ("xuser", "https://x.com", "x-pw"),
    ] {
        new(
            &a,
            &[
                "login",
                &format!("username={username}"),
                &format!("url={url}"),
                &format!("password={password}"),
            ],
        );
    }
    let mut host = Host::start(&a);
    let usernames = |reply: &serde_json::Value| -> Vec<String> {
        reply["accounts"]
            .as_array()
            .unwrap()
            .iter()
            .map(|a| a["username"].as_str().unwrap().to_string())
            .collect()
    };

    // The page's own login first, though "envato.com" sorts before
    // "themeforest.net" by title; never the http one or the lookalike.
    let forest = list(&mut host, "https://www.themeforest.net/login");
    assert_eq!(forest["site"], "themeforest.net");
    assert_eq!(usernames(&forest), ["forest", "envato"], "{forest}");
    let accounts = forest["accounts"].as_array().unwrap();
    assert_eq!(
        accounts[1]["urls"],
        serde_json::json!(["https://envato.com"]),
        "a shared login says the site it was saved for"
    );
    let envato_ref = accounts[1]["ref"].as_str().unwrap().to_string();
    let fill = host.ask(serde_json::json!({
        "type": "fill", "origin": "https://www.themeforest.net", "ref": envato_ref,
        "want": ["password"],
    }));
    assert_eq!(fill["password"], "envato-pw", "{fill}");

    let envato = list(&mut host, "https://account.envato.com");
    assert_eq!(
        usernames(&envato),
        ["envato", "plain", "forest"],
        "{envato}"
    );

    let x = list(&mut host, "https://x.com/i/flow/login");
    assert_eq!(usernames(&x), ["xuser", "bird"], "{x}");
    let [xuser_ref, bird_ref] = <[String; 2]>::try_from(refs(&x)).unwrap();
    let fill = host.ask(serde_json::json!({
        "type": "fill", "origin": "https://x.com", "ref": bird_ref, "want": ["password"],
    }));
    assert_eq!(fill["password"], "bird-pw", "{fill}");
    assert_eq!(
        usernames(&list(&mut host, "https://mobile.twitter.com")),
        ["bird"]
    );

    // Nowhere else, and the fill gate holds the same line.
    assert_eq!(
        usernames(&list(&mut host, "https://evil-envato.com")),
        ["evil"]
    );
    assert!(refs(&list(&mut host, "https://github.com")).is_empty());
    for (origin, login) in [
        ("https://github.com", &envato_ref),
        ("https://evil-envato.com", &envato_ref),
        ("https://x.com", &envato_ref),
        ("https://envato.com", &bird_ref),
        ("https://twitter.com", &xuser_ref),
    ] {
        let reply = host.ask(serde_json::json!({
            "type": "fill", "origin": origin, "ref": login, "want": ["password"],
        }));
        assert_error(&reply, "domain_mismatch");
        assert!(!reply.to_string().contains("-pw"), "{reply}");
    }
    host.close();
}
