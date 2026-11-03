//! Secret form fields, concealed clipboard copies, kept multi-line keys,
//! wrapping public keys and one-time passwords.

use deadbolt_app::daemon::{Done, Job};
use deadbolt_app::model::Screen;
use deadbolt_client::protocol::AppAction;
use rune::{Key, KeyEvent, Mods};
use zeroize::Zeroizing;

use super::{FRAME, Rig, alt, cmd, ctrl, pairs, rig, shift};

const NEW_KEY: &str =
    "-----BEGIN OPENSSH PRIVATE KEY-----\nnew\n-----END OPENSSH PRIVATE KEY-----\n";

/// Verifies `⌘X` neither cuts nor copies on a focused secret `field`, and `⌘C`
/// copies `expected` concealed and clears after the 1 s countdown.
fn assert_secret_copy_clears(r: &mut Rig, field: &str, expected: &str) {
    let board = rune::clipboard::memory();
    r.rt.use_clipboard(&board);
    r.rt.state.clear_after = 1.0;
    let text = || board.text().map(|t| t.as_str().to_owned());
    r.command('a');
    r.command('x');
    assert_eq!(r.value(field), expected, "⌘X cuts nothing");
    assert_eq!(text(), None, "nor copies anything");
    r.command('c');
    let copy = r.rt.state.copy.as_ref().expect("a secret copy");
    assert_eq!(copy.field, field);
    assert!(copy.copied.is_some());
    assert_eq!(text().as_deref(), Some(expected));
    r.settle(1.5);
    assert_eq!(text(), None, "cleared after the countdown");
}

/// Generated (and so revealed) the password field stays secure: its value
/// is drawn in place, never carried as text in the tree. Not while shown,
/// nor when another replaces it, it's hidden, the form closes or the vault
/// locks; and whatever closes the form masks every field.
#[test]
fn a_shown_password_never_lingers_in_plain_text() {
    let generate = |r: &mut Rig, password: &str| {
        let seq = r.take_generate();
        r.replies
            .send(Done::Generated {
                seq,
                result: Ok(Zeroizing::new(password.into())),
            })
            .unwrap();
        r.rt.frame(FRAME);
        r.rt.frame(FRAME);
    };
    let mut r = rig("vault");
    r.sent();
    r.new_item();
    generate(&mut r, "first-Generated-1");
    assert!(r.plaintext("first-Generated-1").is_empty(), "shown");
    let form = r.rt.state.edit.form.as_ref().unwrap();
    assert!(
        form.fields
            .iter()
            .filter(|f| f.secret())
            .all(|f| f.edit.is_secure())
    );
    assert!(form.fields[1].edit.is_revealed());

    r.rt.update(|s, _| s.generate());
    generate(&mut r, "second-Generated-2");
    assert!(r.plaintext("first-Generated-1").is_empty(), "replaced");
    assert!(r.plaintext("second-Generated-2").is_empty(), "shown");

    r.rt.key(KeyEvent {
        key: Key::Escape,
        mods: Mods::default(),
    });
    r.rt.frame(FRAME);
    assert!(r.plaintext("second-Generated-2").is_empty(), "cancelled");

    r.new_item();
    generate(&mut r, "third-Generated-3");
    let revealed = |r: &Rig| r.input("password").edit.is_revealed();
    r.rt.update(|s, _| s.toggle_shown(1));
    r.rt.frame(FRAME);
    assert!(!revealed(&r) && r.plaintext("third-Generated-3").is_empty());
    r.rt.update(|s, _| s.toggle_shown(1));
    r.rt.frame(FRAME);
    assert!(revealed(&r) && r.plaintext("third-Generated-3").is_empty());
    r.replies.send(Done::Locked(Ok(()))).unwrap();
    r.rt.frame(FRAME);
    r.rt.frame(FRAME);
    assert_eq!(r.rt.state.screen, Screen::Locked);
    assert!(r.plaintext("third-Generated-3").is_empty(), "locked");
}

/// ⌘C in a password field copies through the secret path: concealed, and
/// cleared after the countdown.
#[test]
fn copying_from_a_password_field_clears_after_the_countdown() {
    for revealed in [false, true] {
        let mut r = rig("vault");
        r.command('e');
        r.focus("password");
        r.rt.update(move |s, _| {
            s.edit
                .form
                .as_mut()
                .unwrap()
                .fields
                .iter_mut()
                .find(|f| f.name == "password")
                .unwrap()
                .edit
                .set_revealed(revealed);
        });
        r.settle(0.05);
        assert_secret_copy_clears(&mut r, "password", "correct-horse-battery-staple");
    }
}

/// ⌘C in a saved item's password field is a copy of that item's password,
/// reported for Activity like any other.
#[test]
fn copying_from_a_saved_password_field_is_reported() {
    let mut r = rig("vault");
    let board = rune::clipboard::memory();
    r.rt.use_clipboard(&board);
    r.command('e');
    let item = r.rt.state.detail.as_ref().unwrap();
    let (id, title) = (item.id.clone(), item.label.clone());
    r.focus("password");
    r.command('a');
    drop(r.sent());
    r.command('c');
    assert!(r.rt.state.copy.is_some(), "copied");
    let reports: Vec<_> = r
        .sent()
        .into_iter()
        .filter_map(|job| match job {
            Job::Report {
                action,
                item,
                title,
                field,
            } => Some((action, item, title, field)),
            _ => None,
        })
        .collect();
    assert_eq!(
        reports,
        [(AppAction::Copy, id, title, "password".to_string())]
    );
}

/// Add offers a secure note and an SSH key. A note's body is a secure text
/// area: ⏎ breaks the line, a paste keeps its line breaks (CRLF as LF), and
/// what's saved is exactly what was typed, hidden or shown.
#[test]
fn add_offers_a_secure_note_whose_body_keeps_its_lines() {
    let mut r = rig("vault");
    r.command('n');
    assert!(r.shows("Secure note") && r.shows("SSH key"));
    r.rt.update(|s, _| s.choose_type("note"));
    r.settle(0.05);
    let form = r.rt.state.edit.form.as_ref().unwrap();
    assert_eq!(form.kind, "note");
    let names: Vec<&str> = form.fields.iter().map(|f| f.name.as_str()).collect();
    assert_eq!(names, ["notes"]);
    assert!(r.input("notes").edit.is_secure());

    r.focus("notes");
    assert!(r.rt.has_secure_focus());
    r.sent();
    r.type_text("Front door: 4417");
    r.tap(Key::Enter);
    r.type_text("Garage: 0932");
    r.tap(Key::Enter);
    r.rt.paste("Shed: 1111\r\nGate:\t2222\r\n");
    r.settle(0.05);
    let body = "Front door: 4417\nGarage: 0932\nShed: 1111\nGate:\t2222\n";
    assert_eq!(r.value("notes"), body);
    assert!(r.rt.state.editing() && r.sent().is_empty() && r.plaintext("4417").is_empty());
    r.rt.update(|s, _| s.toggle_shown(0));
    r.settle(0.05);
    assert!(r.input("notes").edit.is_revealed() && r.plaintext("4417").is_empty());

    r.command('s');
    let (_, kind, _, fields) = r.take_create();
    assert_eq!(kind, "note");
    assert_eq!(pairs(&fields), [("notes", body)]);
}

/// Picking another type keeps what both have, but a secret never moves into
/// a plain field, and plain text moving into a secret is masked.
#[test]
fn picking_a_type_never_moves_a_secret_into_plain_text() {
    let mut r = rig("vault");
    r.new_item();
    r.fill("notes", "plain words");
    assert!(!r.plaintext("plain words").is_empty());
    r.rt.update(|s, _| s.choose_type("note"));
    r.settle(0.5);
    assert_eq!(r.value("notes"), "plain words");
    assert!(r.input("notes").edit.is_secure() && r.plaintext("plain words").is_empty());

    r.fill("notes", "Front door: 4417");
    r.rt.update(|s, _| s.choose_type("card"));
    r.settle(0.5);
    assert_eq!(r.value("notes"), "", "the secret stays behind");
    assert!(!r.input("notes").edit.is_secure() && r.plaintext("4417").is_empty());
    r.rt.update(|s, _| s.choose_type("login"));
    r.settle(0.5);
    assert!(r.plaintext("4417").is_empty());
}

/// An SSH key's private key is a secure text area too. Hidden, the saved
/// key isn't in it: left empty, it's kept and not sent (an edit sends only
/// what changed); what's pasted or typed into it replaces it, its line
/// breaks and final newline saved as they came.
#[test]
fn an_ssh_keys_private_key_is_edited_in_place() {
    let mut r = rig("ssh");
    r.command('e');
    assert_eq!(r.rt.state.edit.form.as_ref().unwrap().kind, "ssh");
    assert_eq!(r.value("private-key"), "", "kept, not loaded");
    assert!(r.input("private-key").keeps() && r.input("private-key").edit.is_secure());
    assert!(!r.rt.state.edit.form.as_ref().unwrap().changed());
    r.fill("comment", "ci@anoma.ly");
    r.sent();
    r.command('s');
    let (_, _, _, fields, unset) = r.take_save();
    assert_eq!(pairs(&fields), [("comment", "ci@anoma.ly")]);
    assert!(unset.is_empty(), "{unset:?}");

    let mut r = rig("ssh");
    r.command('e');
    r.focus("private-key");
    let pasted = "-----BEGIN OPENSSH PRIVATE KEY-----\r\nb3BlbnNzaC1rZXktdjEAAAAABG5vbmU\r\n-----END OPENSSH PRIVATE KEY-----\r\n";
    r.rt.paste(pasted);
    r.settle(0.05);
    let typed = pasted.replace("\r\n", "\n");
    assert_eq!(r.value("private-key"), typed);
    assert!(r.plaintext("b3BlbnNz").is_empty());
    r.sent();
    r.press(Key::Enter, cmd());
    assert_eq!(pairs(&r.take_save().3), [("private-key", typed.as_str())]);
}

/// In a secret's text area ⏎ (and ⇧⏎, ⌥⏎) breaks the line, ⌘⏎ and ⌘S save,
/// other ⌘ and ⌃ chords do nothing, and esc cancels.
#[test]
fn keys_in_a_secret_text_area() {
    let mut r = rig("vault");
    r.new_item();
    r.rt.update(|s, _| s.choose_type("ssh"));
    r.focus("private-key");
    r.sent();
    r.type_text("a");
    for mods in [Mods::default(), shift(), alt()] {
        r.press(Key::Enter, mods);
    }
    r.type_text("b");
    assert_eq!(r.value("private-key"), "a\n\n\nb");
    for mods in [
        ctrl(),
        Mods {
            cmd: true,
            shift: true,
            ..Mods::default()
        },
    ] {
        r.press(Key::Enter, mods);
    }
    assert_eq!(r.value("private-key"), "a\n\n\nb");
    assert!(r.rt.state.editing() && r.sent().is_empty() && r.rt.state.copy.is_none());

    r.command('s');
    let (_, kind, _, fields) = r.take_create();
    assert_eq!(kind, "ssh");
    assert_eq!(pairs(&fields), [("private-key", "a\n\n\nb")]);

    let mut r = rig("vault");
    r.new_item();
    r.rt.update(|s, _| s.choose_type("note"));
    r.focus("notes");
    r.type_text("x");
    r.tap(Key::Escape);
    assert!(!r.rt.state.editing(), "esc cancels");
}

/// ⌘C in a secret's text area copies its selection through the secret
/// path, hidden or shown; ⌘X cuts nothing.
#[test]
fn copying_from_a_secret_text_area_clears_after_the_countdown() {
    for revealed in [false, true] {
        let mut r = rig("ssh");
        r.command('e');
        r.focus("private-key");
        if revealed {
            r.rt.update(|s, _| s.toggle_shown(0));
        } else {
            r.rt.paste("-----BEGIN PRIVATE KEY-----\nnew\n");
        }
        r.settle(0.05);
        let key = r.value("private-key");
        assert!(key.starts_with("-----BEGIN PRIVATE KEY-----\n"), "{key:?}");
        assert_secret_copy_clears(&mut r, "private-key", &key);
    }
}

/// A private key shown in the form is drawn in place, never carried as
/// text: not shown, hidden, cancelled, nor after a lock.
#[test]
fn a_shown_private_key_never_lingers_in_plain_text() {
    let mut r = rig("ssh");
    r.command('e');
    let secret = "MC4CAQAw";
    assert!(r.plaintext(secret).is_empty(), "hidden");
    r.rt.update(|s, _| s.toggle_shown(0));
    r.settle(0.05);
    assert!(r.input("private-key").edit.is_revealed() && r.plaintext(secret).is_empty());
    r.rt.update(|s, _| s.toggle_shown(0));
    r.rt.frame(FRAME);
    assert!(r.plaintext(secret).is_empty(), "hidden again");
    r.rt.update(|s, _| s.toggle_shown(0));
    r.rt.frame(FRAME);
    r.tap(Key::Escape);
    assert!(!r.rt.state.editing() && r.plaintext(secret).is_empty());

    r.command('e');
    r.rt.update(|s, _| s.toggle_shown(0));
    r.rt.frame(FRAME);
    r.replies.send(Done::Locked(Ok(()))).unwrap();
    r.rt.frame(FRAME);
    r.rt.frame(FRAME);
    assert_eq!(r.rt.state.screen, Screen::Locked);
    assert!(r.plaintext(secret).is_empty(), "locked");
}

/// A public key is one line that wraps where it runs long, and ⏎ there
/// saves rather than breaking it.
#[test]
fn a_public_key_wraps_in_the_form_and_enter_saves() {
    let mut r = rig("ssh");
    r.command('e');
    assert!(
        r.height("field-public-key") > r.height("field-comment") + 10.0,
        "the public key wraps"
    );
    r.fill("public-key", "ssh-ed25519 AAAAnew ci@anoma.ly");
    r.focus("public-key");
    r.sent();
    r.tap(Key::Enter);
    assert_eq!(r.value("public-key"), "ssh-ed25519 AAAAnew ci@anoma.ly");
    assert_eq!(
        pairs(&r.take_save().3),
        [("public-key", "ssh-ed25519 AAAAnew ci@anoma.ly")]
    );
}

/// A kept key is replaced by what's typed or pasted into it, even in the
/// frame it's clicked into: there's nothing in it to add to.
#[test]
fn a_kept_key_is_replaced_by_what_goes_into_it() {
    let key = "field-private-key/value";
    let mut r = rig("ssh");
    r.command('e');
    r.click_at(key);
    r.rt.paste(NEW_KEY);
    r.settle(0.1);
    assert_eq!(r.value("private-key"), NEW_KEY);
    r.sent();
    r.command('s');
    assert_eq!(pairs(&r.take_save().3), [("private-key", NEW_KEY)]);

    let mut r = rig("ssh");
    r.command('e');
    r.click_at(key);
    for c in "ab".chars() {
        r.rt.key(KeyEvent {
            key: Key::Text(c.into()),
            mods: Mods::default(),
        });
    }
    r.settle(0.1);
    assert_eq!(r.value("private-key"), "ab");
}

/// Keys that select or move in a kept key change nothing: it's still kept,
/// and nothing is sent.
#[test]
fn selecting_in_a_kept_key_changes_nothing() {
    let mut r = rig("ssh");
    r.command('e');
    r.focus("private-key");
    let shift = shift();
    let ctrl_shift = Mods {
        ctrl: true,
        shift: true,
        ..Mods::default()
    };
    r.command('a');
    for (key, mods) in [
        (Key::Left, shift),
        (Key::End, shift),
        (Key::Left, ctrl_shift),
        (Key::Command('a'), ctrl_shift),
        (Key::Command('e'), ctrl_shift),
        (Key::Home, Mods::default()),
    ] {
        r.press(key, mods);
    }
    assert!(r.rt.state.editing() && r.input("private-key").keeps());
    assert!(!r.rt.state.edit.form.as_ref().unwrap().changed());
    r.sent();
    r.command('s');
    assert!(!r.rt.state.editing() && r.sent().is_empty());
}

/// A new item's key is typed as it comes, however fast.
#[test]
fn a_new_key_keeps_every_character_typed() {
    let mut r = rig("vault");
    r.new_item();
    r.rt.update(|s, _| s.choose_type("ssh"));
    r.settle(0.1);
    r.click_at("field-private-key/value");
    for c in "abcdef".chars() {
        r.rt.key(KeyEvent {
            key: Key::Text(c.into()),
            mods: Mods::default(),
        });
        r.rt.frame(FRAME);
    }
    r.settle(0.1);
    assert_eq!(r.value("private-key"), "abcdef");
}

/// Show loads a kept key to edit in place. Hidden again unchanged, it's kept
/// again and not sent; hidden after an edit, the edit stays, whole.
#[test]
fn show_loads_a_kept_key_and_hide_keeps_an_edit() {
    let mut r = rig("ssh");
    let saved =
        r.rt.state
            .detail
            .as_ref()
            .and_then(|d| d.fields.iter().find(|f| f.name == "private-key"))
            .map(|f| f.value.clone())
            .unwrap();
    r.command('e');
    r.rt.update(|s, _| s.toggle_shown(0));
    r.settle(0.1);
    assert_eq!(r.value("private-key"), saved, "loaded to show");
    r.rt.update(|s, _| s.toggle_shown(0));
    r.settle(0.1);
    assert_eq!(r.value("private-key"), "", "unchanged, kept again");
    assert!(r.input("private-key").keeps());
    r.fill("comment", "ci@anoma.ly");
    r.sent();
    r.command('s');
    assert_eq!(r.take_save().3.len(), 1, "the key isn't sent");

    let mut r = rig("ssh");
    r.command('e');
    r.rt.update(|s, _| s.toggle_shown(0));
    r.settle(0.1);
    r.type_text("x");
    let edited = format!("{saved}x");
    assert_eq!(r.value("private-key"), edited);
    r.rt.update(|s, _| s.toggle_shown(0));
    r.settle(0.1);
    let key = r.input("private-key");
    assert!(!key.edit.is_revealed() && !key.edit.is_pristine());
    assert_eq!(r.value("private-key"), edited, "hidden, the edit stays");
    r.type_text("y");
    let expected = format!("{edited}y");
    assert_eq!(r.value("private-key"), expected);
    r.sent();
    r.command('s');
    assert_eq!(
        pairs(&r.take_save().3),
        [("private-key", expected.as_str())]
    );
}

/// Reveals field 0, selects all, deletes it, and attempts to save.
fn reveal_clear_and_save(r: &mut Rig, expected_before_clear: Option<&str>) {
    r.rt.update(|s, _| s.toggle_shown(0));
    r.settle(0.1);
    if let Some(expected) = expected_before_clear {
        assert_eq!(r.value("notes"), expected);
    }
    r.command('a');
    r.tap(Key::Backspace);
    r.sent();
    r.command('s');
}

/// A note's body is removed on purpose: Show, select all, delete. A private
/// key can't be.
#[test]
fn a_shown_note_cleared_on_purpose_is_removed() {
    let mut r = rig("note");
    r.command('e');
    r.focus("notes");
    reveal_clear_and_save(&mut r, None);
    let (_, _, _, fields, unset) = r.take_save();
    assert!(fields.is_empty() && unset == ["notes"]);

    let mut r = rig("ssh");
    r.command('e');
    r.focus("private-key");
    reveal_clear_and_save(&mut r, None);
    assert!(r.sent().is_empty());
    assert!(
        r.rt.state
            .edit
            .form
            .as_ref()
            .unwrap()
            .problem_for("private-key")
            .is_some()
    );
}

/// Typed into while kept, then shown and emptied on purpose, a note is
/// removed and a private key is refused: shown, it's no longer kept.
#[test]
fn a_kept_secret_typed_into_then_shown_and_emptied_isnt_kept() {
    let mut r = rig("note");
    r.command('e');
    r.focus("notes");
    r.type_text("draft");
    reveal_clear_and_save(&mut r, Some("draft"));
    let (_, _, _, fields, unset) = r.take_save();
    assert!(fields.is_empty() && unset == ["notes"]);

    let mut r = rig("ssh");
    r.command('e');
    r.focus("private-key");
    r.type_text("x");
    reveal_clear_and_save(&mut r, None);
    assert!(r.sent().is_empty());
    assert!(
        r.rt.state
            .edit
            .form
            .as_ref()
            .unwrap()
            .problem_for("private-key")
            .is_some()
    );
}

/// Only whitespace typed into a kept secret, unseen behind the mask, keeps
/// the saved value rather than removing it.
#[test]
fn whitespace_typed_into_a_kept_secret_keeps_it() {
    let mut r = rig("note");
    r.command('e');
    r.focus("notes");
    r.type_text(" ");
    r.tap(Key::Enter);
    assert!(r.input("notes").keeps());
    r.rt.update(|s, _| {
        s.edit.form.as_mut().unwrap().name.replace_text("Renamed");
        s.form_changed();
    });
    r.settle(0.05);
    r.sent();
    r.command('s');
    let (_, _, _, fields, unset) = r.take_save();
    assert!(unset.is_empty() && fields.iter().all(|(name, _)| name != "notes"));
}

/// Show and Hide focus their field, and only it.
#[test]
fn show_and_hide_focus_the_field_alone() {
    fn focused(r: &Rig) -> Vec<&str> {
        let s = &r.rt.state;
        let form = s.edit.form.as_ref().unwrap();
        let mut on: Vec<&str> = form
            .fields
            .iter()
            .filter(|f| f.edit.focused)
            .map(|f| f.name.as_str())
            .collect();
        if form.name.focused {
            on.push("name");
        }
        if s.search.focused {
            on.push("search");
        }
        on
    }
    let r = rig("edit-ssh-revealed");
    assert_eq!(focused(&r), ["private-key"]);

    let reveal = "field-private-key/value/secret-lines/actions/reveal";
    let mut r = rig("ssh");
    r.command('e');
    assert_eq!(focused(&r), ["name"]);
    for shown in [true, false] {
        r.click_at(reveal);
        r.settle(0.1);
        assert_eq!(r.input("private-key").edit.is_revealed(), shown);
        assert_eq!(focused(&r), ["private-key"], "shown {shown}");
        assert!(r.rt.has_secure_focus());
    }
}

/// A public key that came with line breaks (from the CLI or an import) is
/// kept as it came: the form isn't changed on open, and saving something
/// else leaves it alone.
#[test]
fn a_public_key_left_alone_is_kept_as_it_came() {
    let mut r = rig("ssh");
    let came = "ssh-ed25519 AAAAC3Nz\naC1lZDI1 ci@anoma.ly\n";
    r.rt.update(move |s, _| {
        s.detail
            .as_mut()
            .unwrap()
            .fields
            .iter_mut()
            .find(|f| f.name == "public-key")
            .unwrap()
            .value = came.into();
    });
    r.command('e');
    assert_eq!(r.value("public-key"), came);
    assert!(!r.rt.state.edit.form.as_ref().unwrap().changed());
    r.fill("comment", "ci@anoma.ly");
    r.sent();
    r.command('s');
    assert_eq!(pairs(&r.take_save().3), [("comment", "ci@anoma.ly")]);
    assert_eq!(r.value("public-key"), came);
}

/// A wrapping one-line value (a public key, a fingerprint) keeps to one
/// line: a hard-wrapped paste loses its line breaks, which would hide among
/// the soft wraps.
#[test]
fn a_pasted_public_key_keeps_to_one_line() {
    let mut r = rig("ssh");
    r.command('e');
    r.focus("public-key");
    r.command('a');
    r.rt.paste("ssh-ed25519 AAAAC3Nz\r\naC1lZDI1\nNTE5 ci@anoma.ly\n");
    r.settle(0.05);
    assert_eq!(
        r.value("public-key"),
        "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5 ci@anoma.ly"
    );
    r.type_text("!");
    assert!(r.value("public-key").ends_with("ci@anoma.ly!"));
    r.focus("fingerprint");
    r.command('a');
    r.type_text(&"SHA256:Fx7tQ2mVb9yLr4cWkP0sN8hJd3aZe6uGo1iTq5XwYnE".repeat(2));
    r.settle(0.05);
    assert!(r.height("field-fingerprint") > r.height("field-comment") + 10.0);
    r.focus("public-key");
    r.sent();
    r.tap(Key::Enter);
    let (_, _, _, fields, _) = r.take_save();
    let (_, key) = fields
        .iter()
        .find(|(name, _)| name == "public-key")
        .unwrap();
    assert_eq!(key, "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5 ci@anoma.ly!");
}

/// The daemon keeps a login's one-time password back, so the form never has
/// it: left empty it stays, and typed into, it's replaced.
#[test]
fn an_edit_keeps_a_one_time_password_it_never_sees() {
    let shows = |r: &Rig| -> Vec<String> {
        r.rt.elements()
            .iter()
            .filter(|e| !e.exiting)
            .filter_map(|e| e.label.clone())
            .filter(|l| l.starts_with("Show "))
            .collect()
    };
    let mut r = rig("vault");
    r.command('e');
    assert_eq!(r.value("otp"), "");
    assert_eq!(shows(&r), ["Show Password"], "nothing to show");
    r.sent();
    r.command('s');
    assert!(!r.rt.state.editing() && r.sent().is_empty());

    r.command('e');
    r.fill("otp", "JBSWY3DPEHPK3PXP");
    assert_eq!(shows(&r).len(), 2, "a typed one shows: {:?}", shows(&r));
    r.command('s');
    let (_, _, _, fields, unset) = r.take_save();
    assert_eq!(pairs(&fields), [("otp", "JBSWY3DPEHPK3PXP")]);
    assert!(unset.is_empty(), "{unset:?}");
}
