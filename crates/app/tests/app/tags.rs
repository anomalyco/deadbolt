//! Favorites (`⌘D`), `#tag` and `is:favorite` search, clickable tag chips,
//! `⌘K` tag filtering, and form tag/favorite editing.

use std::sync::mpsc::{Receiver, Sender};

use deadbolt_app::agent::{Agent, Done, Job};
use deadbolt_app::model::App;
use deadbolt_app::palette::{self, Action};
use rune::{Env, Key, KeyEvent, Mods, Runtime};

const FRAME: f64 = 1.0 / 60.0;

struct Rig {
    rt: Runtime<App>,
    jobs: Receiver<Job>,
    replies: Sender<Done>,
}

fn rig(scene: &str) -> Rig {
    let app = rune::tooling::initial_state(&deadbolt_app::spec(), Some(scene));
    let mut rt = Runtime::new(
        app,
        deadbolt_app::view::app,
        (820.0, 540.0),
        Env {
            system_dark: true,
            scale: 1.0,
        },
    );
    rt.poll = Some(|s, now, tx| s.poll(now, tx));
    rt.on_key = Some(|s, ev, tx| s.on_key(ev, tx));
    let (agent, jobs, replies) = Agent::scripted();
    rt.state.agent = agent;
    for _ in 0..30 {
        rt.frame(FRAME);
    }
    while jobs.try_recv().is_ok() {}
    Rig { rt, jobs, replies }
}

impl Rig {
    fn sent(&self) -> Vec<Job> {
        self.jobs.try_iter().collect()
    }

    fn key(&mut self, key: Key, mods: Mods) {
        self.rt.key(KeyEvent { key, mods });
        self.rt.frame(FRAME);
        self.rt.frame(FRAME);
    }

    fn tap(&mut self, key: Key) {
        self.key(key, Mods::default());
    }

    fn command(&mut self, c: char) {
        self.key(
            Key::Command(c),
            Mods {
                cmd: true,
                ..Mods::default()
            },
        );
    }

    fn type_text(&mut self, s: &str) {
        for ch in s.chars() {
            self.tap(Key::Text(ch.into()));
        }
    }

    fn click(&mut self, key: &str) {
        let (x, y) = self.rt.find(key).unwrap_or_else(|| panic!("no {key}"));
        self.rt.pointer_down(x, y);
        self.rt.pointer_up(x, y);
        self.rt.frame(FRAME);
        self.rt.frame(FRAME);
    }

    fn visible_labels(&self) -> Vec<String> {
        self.rt
            .state
            .visible()
            .into_iter()
            .map(|i| i.label.clone())
            .collect()
    }
}

#[test]
fn cmd_d_toggles_favorite_and_resorts_immediately_even_on_passkeys() {
    let mut r = rig("vault");
    // Cloudflare and github.com start as favorites, sorted ahead of fly.io.
    assert_eq!(
        &r.visible_labels()[..3],
        ["Cloudflare", "github.com", "fly.io"]
    );
    let github_id = r.rt.state.selected.clone().unwrap();

    // Unstarring github.com drops it into alphabetical order while keeping it selected.
    r.command('d');
    assert_eq!(r.rt.state.selected.as_deref(), Some(github_id.as_str()));
    assert!(!r.rt.state.selected_item().unwrap().favorite);
    assert_eq!(
        &r.visible_labels()[..4],
        ["Cloudflare", "fly.io", "github.com", "gitlab.com"]
    );
    match r.sent().as_slice() {
        [
            Job::Favorite {
                id,
                favorite: false,
                ..
            },
        ] => assert_eq!(id, &github_id),
        other => panic!("expected Job::Favorite(false), got {}", other.len()),
    }

    // Passkeys cannot open in ⌘E, yet ⌘D stars them too (ranking alongside
    // Cloudflare and the github.com login at the top of the list).
    let mut pk = rig("passkey");
    let pk_id = pk.rt.state.selected.clone().unwrap();
    assert!(!pk.rt.state.selected_item().unwrap().favorite);
    pk.command('d');
    assert!(pk.rt.state.selected_item().unwrap().favorite);
    let top_three: Vec<String> = pk.rt.state.visible()[..3]
        .iter()
        .map(|i| i.id.clone())
        .collect();
    assert!(top_three.contains(&pk_id), "{top_three:?}");
}

#[test]
fn hash_tags_is_favorite_and_chip_clicks_filter_immediately() {
    let mut r = rig("vault");

    // Clicking `#work/aws` on github.com filters to items matching `work/aws`,
    // and clicking it again clears the filter.
    r.click("tag-work/aws");
    assert_eq!(r.rt.state.search.text, "#work/aws ");
    assert_eq!(r.visible_labels(), ["github.com"]);
    r.click("tag-work/aws");
    assert_eq!(r.rt.state.search.text, "");
    assert_eq!(r.visible_labels().len(), 7);

    // Mid-typing `#`, `#wo`, and `#work ` never flashes "No matches" and matches
    // hierarchical children (`work/infra`, `work/aws`, `work`).
    r.type_text("#");
    assert_eq!(
        r.visible_labels(),
        ["Cloudflare", "github.com", "Hetzner", "Linear"]
    );
    r.type_text("wo");
    assert_eq!(
        r.visible_labels(),
        ["Cloudflare", "github.com", "Hetzner", "Linear"]
    );
    r.type_text("rk/infra ");
    assert_eq!(r.visible_labels(), ["Cloudflare", "Hetzner"]);

    // `is:favorite` narrows to starred items.
    r.tap(Key::Escape);
    r.type_text("is:favorite");
    assert_eq!(r.visible_labels(), ["Cloudflare", "github.com"]);

    // Plain words also match tag names (`aws` finds `github.com`).
    r.tap(Key::Escape);
    r.type_text("aws");
    assert_eq!(r.visible_labels(), ["github.com"]);
}

#[test]
fn palette_filter_by_tag_narrows_and_steps_back_on_escape() {
    let mut r = rig("vault");
    r.command('k');
    let pos = palette::actions(&r.rt.state)
        .iter()
        .position(|a| *a == Action::FilterTag)
        .expect("FilterTag action");
    for _ in 0..pos {
        r.tap(Key::Down);
    }
    r.tap(Key::Enter);
    assert!(r.rt.state.nav.palette_tags);

    // Esc steps back one level to the action list without closing ⌘K.
    r.tap(Key::Escape);
    assert!(!r.rt.state.nav.palette_tags);
    assert!(r.rt.state.nav.palette.is_some());

    // Enter again reopens tags; typing "infra" and pressing Enter filters the vault.
    r.tap(Key::Enter);
    r.type_text("infra");
    r.tap(Key::Enter);
    assert!(r.rt.state.nav.palette.is_none());
    assert_eq!(r.rt.state.search.text, "#work/infra ");
    assert_eq!(r.visible_labels(), ["Cloudflare", "Hetzner"]);
}

#[test]
fn form_edits_tags_and_favorite_and_sends_only_deltas() {
    let mut r = rig("vault");
    let github_id = r.rt.state.selected.clone().unwrap();
    r.command('e');
    assert!(r.rt.state.editing());
    {
        let form = r.rt.state.edit.form.as_ref().unwrap();
        assert!(form.favorite);
        assert_eq!(form.tags, ["dev", "work/aws"]);
    }

    // Scroll `field-tags` into view, remove `dev`, flip favorite with ⌘D,
    // and add `Tax 2026` via the tag input.
    r.rt.update(|s, tx| {
        tx.scroll_into_view("field-tags");
        let form = s.edit.form.as_mut().unwrap();
        form.name.focused = false;
        for f in &mut form.fields {
            f.edit.focused = false;
        }
        form.tag_input.focused = true;
    });
    for _ in 0..10 {
        r.rt.frame(FRAME);
    }
    r.rt.update(|s, _| s.remove_form_tag(0));
    r.command('d');
    r.type_text("Tax 2026");
    r.tap(Key::Enter);
    {
        let form = r.rt.state.edit.form.as_ref().unwrap();
        assert!(!form.favorite);
        assert_eq!(form.tags, ["Tax 2026", "work/aws"]);
        assert!(form.tag_input.text.is_empty());
    }

    // Saving on empty tag input submits `Job::Save` with exact tag/favorite deltas.
    r.sent();
    r.tap(Key::Enter);
    match r.sent().pop() {
        Some(Job::Save {
            id,
            favorite,
            add_tags,
            remove_tags,
            fields,
            unset,
            seq,
            ..
        }) => {
            assert_eq!(id, github_id);
            assert_eq!(favorite, Some(false));
            assert_eq!(add_tags, ["Tax 2026"]);
            assert_eq!(remove_tags, ["dev"]);
            assert!(fields.is_empty() && unset.is_empty());
            let mut updated = r.rt.state.detail.clone().unwrap();
            updated.favorite = false;
            updated.tags = vec!["Tax 2026".into(), "work/aws".into()];
            r.replies
                .send(Done::Saved {
                    seq,
                    result: Ok(updated),
                })
                .unwrap();
            for _ in 0..10 {
                r.rt.frame(FRAME);
            }
        }
        _ => panic!("expected Job::Save"),
    }
}
