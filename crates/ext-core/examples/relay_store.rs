//! Offline preparation/verification for the opt-in private browser relay harness.
//! Operates only on copies of that harness's locked, synthetic OPFS stores.
use deadbolt_core::{Change, DataOp, DeviceSecret, Entry, Field, FieldType, Vault, VersionStatus};
use deadbolt_store::Unlocked;
use std::{collections::BTreeSet, error::Error, path::Path};

type Result<T> = std::result::Result<T, Box<dyn Error>>;
const PASS: &[u8] = b"synthetic-relay-fixture";
const N: usize = 2_000;

fn load(path: &Path) -> Result<(Unlocked, Vault)> {
    let store = deadbolt_store::unlock(path, PASS)?;
    let mut hashes = BTreeSet::new();
    let mut entries = Vec::new();
    for record in store.iter_all()? {
        let e = Entry::decode(&record?)?;
        assert!(hashes.insert(e.hash()), "duplicate signed entry on disk");
        entries.push(e);
    }
    let v = Vault::load(entries)?;
    assert_eq!(v.name(), "private-relay-fixture");
    Ok((store, v))
}

fn file(i: u8) -> Field {
    let value = deadbolt_core::item::file_value("fixture.bin", &vec![i; 64 * 1024]);
    Field::new(FieldType::File, value.as_str())
}

fn backlog(root: &Path) -> Result<()> {
    let (store, mut v) = load(root)?;
    let author = DeviceSecret::from_bytes(store.device_secret());
    let mut batch = Vec::new();
    for i in 0..N {
        // Separate signed entries, not a single bulk-import entry containing N items.
        let entry = v.write(
            &author,
            vec![DataOp::create(
                "login",
                Some(format!("Backlog {i}")),
                [
                    (
                        "notes".into(),
                        Field::new(FieldType::Note, "s".repeat(2048)),
                    ),
                    (
                        "password".into(),
                        Field::new(FieldType::Secret, format!("fixture-{i}")),
                    ),
                ],
            )],
        )?;
        batch.push(entry.encode());
    }
    for i in 0..2 {
        let (_, entry) = v.create_item(
            &author,
            "document",
            Some(format!("File {i}")),
            [("file".into(), file(i))],
        )?;
        batch.push(entry.encode());
    }
    println!(
        "backlog entries={} encoded_bytes={}",
        batch.len(),
        batch.iter().map(|e| e.len()).sum::<usize>()
    );
    store.append_batch(batch.iter().map(|e| e.as_slice()))?;
    Ok(())
}

fn verify(root: &Path, removed: bool) -> Result<()> {
    let mut previous = None;
    for name in ["a", "b", "c"] {
        let (_, v) = load(&root.join(name))?;
        let items = v.items();
        let titles: BTreeSet<_> = items.iter().filter_map(|i| i.name.clone()).collect();
        assert_eq!(titles.len(), items.len(), "duplicate or missing title");
        // Shared login, six latency probes (edits to one probe login), two flap markers.
        let survivor = removed && name != "c";
        assert_eq!(items.len(), N + 2 + 4 + if survivor { 2 } else { 0 });
        // Preserve every hash of the independently frozen source, not just the
        // visible winning items. Native and browser creates may legitimately
        // use different numbers of signed bookkeeping operations.
        let run = root.parent().ok_or("missing fixture parent")?;
        let prior = if removed {
            run.join("verify").join(name)
        } else {
            run.join("source")
        };
        let (_, before) = load(&prior)?;
        let hashes: BTreeSet<_> = v.entries().iter().map(|e| e.hash()).collect();
        assert!(
            before.entries().iter().all(|e| hashes.contains(&e.hash())),
            "lost signed entries"
        );
        if removed && name == "c" {
            let old: BTreeSet<_> = before.entries().iter().map(|e| e.hash()).collect();
            assert!(
                v.entries().iter().all(|e| old.contains(&e.hash())
                    || matches!(e.payload(), deadbolt_core::Payload::Membership(_))),
                "removed device received new signed data"
            );
        }
        for marker in ["After removal", "B private before refresh"] {
            assert_eq!(titles.contains(marker), survivor);
        }
        assert!(!survivor || v.members().count() == 2);
        for i in 0..N {
            assert!(titles.contains(&format!("Backlog {i}")));
        }
        for i in 0..2 {
            let name = format!("File {i}");
            let doc = items
                .iter()
                .find(|it| it.name.as_ref() == Some(&name))
                .ok_or("missing attachment")?;
            assert_eq!(doc.fields["file"], file(i));
        }
        let shared = items
            .iter()
            .find(|i| i.name.as_deref() == Some("Shared"))
            .ok_or("missing shared login")?;
        let edits: Vec<_> = v
            .history(&shared.id)
            .into_iter()
            .filter_map(|e| match e.change {
                Change::Set { field, value }
                    if field == "password" && value.value.starts_with("isolated-") =>
                {
                    Some((value, e.author, e.status))
                }
                _ => None,
            })
            .collect();
        assert_eq!(edits.len(), 2);
        assert_ne!(edits[0].1, edits[1].1);
        assert!(edits.iter().any(|e| e.2 == VersionStatus::Conflicted));
        assert!(edits.iter().any(|e| e.2 == VersionStatus::Current));
        let state = (
            v.heads(),
            items,
            v.entries()
                .iter()
                .map(|e| e.hash())
                .collect::<BTreeSet<_>>(),
        );
        println!(
            "verified {name} signed_entries={} items={} encrypted_bytes={}",
            state.2.len(),
            state.1.len(),
            std::fs::metadata(root.join(name).join("store.redb"))?.len()
        );
        if removed && name == "c" {
            continue;
        }
        if let Some(prior) = &previous {
            assert!(
                prior == &state,
                "durable heads, signed log or complete items differ"
            );
        } else {
            previous = Some(state);
        }
    }
    Ok(())
}

fn main() -> Result<()> {
    let args: Vec<_> = std::env::args_os().skip(1).collect();
    match args.as_slice() {
        [mode, path] if mode == "heads" => {
            let (_, v) = load(Path::new(path))?;
            println!(
                "signed_entries={} items={} heads={:?}",
                v.entries().len(),
                v.items().len(),
                v.heads()
            );
            Ok(())
        }
        [mode, path] if mode == "backlog" => backlog(Path::new(path)),
        [mode, path] if mode == "verify" => verify(Path::new(path), false),
        [mode, path] if mode == "removed" => verify(Path::new(path), true),
        _ => Err("usage: relay_store {backlog|heads|verify|removed} <fixture directory>".into()),
    }
}
