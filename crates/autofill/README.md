# deadbolt-autofill

Deadbolt's own autofill engine: from a value-free snapshot of a page, which
fields hold a username, email, phone, password, new password, one-time code
or captcha, and what each form is for (login, sign-up, change password,
reset, two-step code, newsletter or nothing).

Phase 1 of the plan in the clean-room spec (§8.8): the snapshot model, the
normaliser, clue tables ported from `extension/src/content/clues.ts` and the
classification passes, proved on the corpus against `detect.ts`. The
extension doesn't use it yet; phase 2 wraps it in wasm.

## Design

- **Pure.** `Engine::analyze(&Snapshot) -> Analysis` reads no DOM, clock,
  network or secret, so a snapshot always gives the same answer. No `unsafe`,
  no wasm dependencies.
- **No values.** A snapshot says whether a field has a value, never what it
  is. `Snapshot::from_json` caps every string and list and rejects dangling
  references; the page is untrusted.
- **Data, not code, for vocabulary.** Words and weights live in
  `rules/*.toml`; code holds only structural rules (form shape, confirmation
  passwords, split codes, a login's partner field).
- **Explained.** Every field and form result carries its trace: each rule id,
  channel and score change that produced it.

Passes, per frame (`src/classify/`):

1. `gate`: visible text-like fields only; fields, forms or pages marked
   `data-deadbolt-ignore` (and the common vendor markers) are dropped; a text
   box drawn as dots (`-webkit-text-security`) counts as a password box.
   Builds each field's display text (labels, aria-label, placeholder, title,
   else the nearest text before it) and code text (id, name, class, test ids).
2. `fields`: one Aho-Corasick pass over both texts for every type's clues,
   then autocomplete tokens, element type and input mode.
3. `group`: real `<form>`s, and virtual forms for runs of fields outside any.
4. `forms`: each group's kind from its text, form id/name/action and frame
   URL, and the mix of fields it holds.
5. `context`: a password after a password is a confirmation; roles that
   depend on the form's kind; the identifier of a login with one password.
6. Pick: the best type at or above `FIELD_THRESHOLD` (3), ties to the earlier
   type in `FieldType::ALL`; the same for forms with `FORM_THRESHOLD`.

`FrameAnalysis::kind` is the kind of the group holding the frame's most
important field, as `scanPage()` reports it (newsletter and none map to null).
Roles are serialised with the extension's `FieldRole` names.

## Clue tables

- `rules/fields/<type>.toml`: one per field type (`type = "username"`), with
  `include = [...]` for shared lists.
- `rules/fields/<name>.toml` with `name = "..."`: shared lists
  (`not-a-login-field`, `non-login-autocomplete`).
- `rules/forms/<kind>.toml`: one per form kind (`kind = "login"`).

A clue:

```toml
[[clue]]
phrase = "user name"        # written readably; normalised at load
langs = ["benutzername"]    # optional alternatives; the entry counts once
score = 5                   # small signed integer
channel = "both"            # display | code | both (default both)
mode = "word"               # word (default) | sanitised
why = "Why it's here, or the site that needed it"
```

- `word`: whole words in display text. In code text, phrases of four or more
  letters also match inside run-together names (`txtpassword`); shorter ones
  need a word boundary (`user_pwd`, `userPwd`). Han, kana and Hangul match
  anywhere.
- `sanitised`: letters and digits only, anywhere (`signin` in `/auth/sign-in`).
- Field tables also take `[[autocomplete]]` (`token`, `-*` suffix for a
  prefix), `[[element]]` (`element`, `*` for every other element) and
  `[[inputmode]]` entries, each with a `score` and a `why`.

To add a clue: add the entry with a `why` naming the site or reason, keep the
score in single digits (tens only for disqualifiers), run
`cargo test -p deadbolt-autofill` (every entry needs a `why`; a table may not
match the same text twice on one channel) and replay the corpus.

## Replaying the corpus

`src/bin/replay.rs` reads a directory of snapshot JSON files and prints one
JSON line per file (`--trace` keeps the traces):

```sh
cargo run -p deadbolt-autofill --bin replay -- <crawl>/snapshots --trace
```

The crawler saves a snapshot per page (`extension/corpus/snapshot.ts`
collects it in each frame), and `compare.ts` replays a crawl and compares the
engine with `detect.ts` and the pages' own markup:

```sh
cd extension
bun corpus/crawl.ts --top 1000 --out $TMPDIR/opencode/deadbolt-corpus/engine-top
bun corpus/compare.ts --out $TMPDIR/opencode/deadbolt-corpus/engine-top   # compare.md, compare.json
```
