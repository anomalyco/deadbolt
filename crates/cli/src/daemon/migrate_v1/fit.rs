//! DELETABLE(v1-migrate): remove once existing v1 users have migrated to v2.
//!
//! Fits v1 items to v2's caps. Every v1 write was held to the same caps,
//! but two devices' concurrent edits could together leave one item holding
//! more than [`item::MAX_FILE`] of files or more than [`tag::MAX_TAGS`]
//! tags, which v2 refuses in any write, now or when another device syncs.
//! Such an item keeps the files that fit, and each file over goes to a
//! document item of its own beside it, so nothing is lost; tags past the
//! cap are dropped (the alphabetically last ones).

use std::collections::BTreeMap;

use deadbolt_core::item::{self, valid_item_name};
use deadbolt_core::{DataOp, Field, FieldType, ItemId, tag};

use super::replay::{V1Item, V1Vault};

const SPLIT_CONTEXT: &str = "deadbolt 2026-11-26 v1 migrate split file";
// The vault writer's per-operation budget (including field/operation overhead).
pub(super) const MAX_OP_LEN: usize = 14 * 1024 * 1024;

/// `vault` with every item within v2's caps.
pub(super) fn vault(mut vault: V1Vault) -> V1Vault {
    let mut split = BTreeMap::new();
    for (id, item) in &mut vault.items {
        if item.tags.len() > tag::MAX_TAGS {
            tracing::warn!(item = %id, tags = item.tags.len(), "dropping tags past v2's cap");
            let keep: Vec<String> = item.tags.iter().take(tag::MAX_TAGS).cloned().collect();
            item.tags = keep.into_iter().collect();
        }
        for (field, part) in files_over(item) {
            split.insert(part_id(id, &field), part);
        }
        for (field, part) in fields_over(*id, item) {
            split.insert(part_id(id, &field), part);
        }
    }
    vault.items.extend(split);
    vault
}

/// Takes the file fields past `MAX_FILE` out of `item`, each as a document.
fn files_over(item: &mut V1Item) -> Vec<(String, V1Item)> {
    if item::files_size(item.fields.values()) <= item::MAX_FILE {
        return Vec::new();
    }
    let mut total = 0;
    let mut over = Vec::new();
    // A document's required `file` wins the budget over every extra file,
    // including names that sort before it (such as `attachment`).
    let mut files: Vec<_> = item.fields.iter().collect();
    files.sort_by_key(|(name, _)| !(item.kind == "document" && *name == "file"));
    for (name, field) in files {
        if field.kind != FieldType::File {
            continue;
        }
        let size = item::files_size([field]);
        if total + size <= item::MAX_FILE {
            total += size;
        } else {
            over.push(name.clone());
        }
    }
    let base = item.name.clone().unwrap_or_else(|| item.kind.clone());
    over.into_iter()
        .filter_map(|name| {
            let file = item.fields.remove(&name)?;
            let mut title = format!("{base} ({name})");
            if !valid_item_name(&title) {
                title = name.clone();
            }
            let part = V1Item {
                kind: "document".into(),
                name: Some(title),
                fields: BTreeMap::from([("file".to_owned(), file)]),
                source: None,
                favorite: false,
                tags: item.tags.clone(),
                password_changed: None,
                ignored: BTreeMap::new(),
                password_entry: None,
                deleted: item.deleted,
            };
            Some((name, part))
        })
        .collect()
}

/// A single field may not fit even as an Edit. Preserve its complete bytes
/// in numbered documents; leave a short preview for a required text field.
fn fields_over(id: ItemId, item: &mut V1Item) -> Vec<(String, V1Item)> {
    let required_len = DataOp::create_with(
        item.kind.clone(),
        item.name.clone(),
        item.fields
            .iter()
            .filter(|(name, _)| required(item, name))
            .map(|(name, field)| (name.clone(), field.clone())),
        item.source.clone(),
        item.favorite,
        item.tags.clone(),
    )
    .encoded_len();
    let names: Vec<_> = item
        .fields
        .iter()
        .filter(|(name, field)| {
            DataOp::set(id, (*name).clone(), (*field).clone()).encoded_len() > MAX_OP_LEN
                || (required(item, name) && required_len > MAX_OP_LEN)
        })
        .map(|(name, _)| name.clone())
        .collect();
    let mut parts = Vec::new();
    for name in names {
        let Some(field) = item.fields.remove(&name) else {
            continue;
        };
        let base = item.name.as_deref().unwrap_or(&item.kind);
        for (i, bytes) in field.value.as_bytes().chunks(item::MAX_FILE).enumerate() {
            let label = format!("{name} part {}", i + 1);
            let title = format!("{base} ({label})");
            let title = if valid_item_name(&title) {
                title
            } else {
                label.clone()
            };
            let value = item::file_value(&format!("value.part{}", i + 1), bytes);
            parts.push((
                format!("field/{name}/{}", i + 1),
                V1Item {
                    kind: "document".into(),
                    name: Some(title),
                    fields: BTreeMap::from([(
                        "file".into(),
                        Field::new(FieldType::File, value.as_str()),
                    )]),
                    source: None,
                    favorite: false,
                    tags: item.tags.clone(),
                    password_changed: None,
                    ignored: BTreeMap::new(),
                    password_entry: None,
                    deleted: item.deleted,
                },
            ));
        }
        if required(item, &name)
            || matches!(
                field.kind,
                FieldType::Note | FieldType::Secret | FieldType::Text
            )
        {
            let end = field.value.floor_char_boundary(1024);
            let preview = format!(
                "{}\n[Full {name} saved in numbered document parts.]",
                &field.value[..end]
            );
            item.fields
                .insert(name, Field::new(field.kind.clone(), preview));
        }
    }
    if !parts.is_empty() && item.name.is_none() && item.fields.is_empty() {
        item.name = Some(format!("{} (moved)", item.kind));
    }
    parts
}

fn required(item: &V1Item, name: &str) -> bool {
    item::schema(&item.kind)
        .and_then(|s| s.field(name))
        .is_some_and(|f| f.required)
}

/// Required fields must be present at creation. Optional fields that would
/// overflow its operation go in individual Edits, before metadata/deletion.
pub(super) fn operations(id: ItemId, item: &V1Item) -> (DataOp, Vec<DataOp>) {
    let mut create = DataOp::create_with(
        item.kind.clone(),
        item.name.clone(),
        item.fields.clone(),
        item.source.clone(),
        item.favorite,
        item.tags.clone(),
    );
    let mut edits = Vec::new();
    let mut optional: Vec<_> = item
        .fields
        .iter()
        .filter(|(name, _)| !required(item, name))
        .collect();
    optional.sort_by_key(|(_, field)| std::cmp::Reverse(field.value.len()));
    for (name, _) in optional {
        if create.encoded_len() <= MAX_OP_LEN {
            break;
        }
        if let DataOp::Create { fields, .. } = &mut create
            && let Some(value) = fields.remove(name)
        {
            edits.push(DataOp::set(id, name, value));
        }
    }
    if let DataOp::Create { name, fields, .. } = &mut create
        && name.is_none()
        && fields.is_empty()
        && !edits.is_empty()
    {
        *name = Some("_".into());
        edits.push(DataOp::name(id, None));
    }
    (create, edits)
}

/// The id of the document holding `field` of item `id`, the same every try.
fn part_id(id: &ItemId, field: &str) -> ItemId {
    let material = [id.as_bytes().as_slice(), field.as_bytes()].concat();
    let key = blake3::derive_key(SPLIT_CONTEXT, &material);
    let mut part = [0; 16];
    part.copy_from_slice(&key[..16]);
    ItemId::from_bytes(part)
}

#[cfg(test)]
mod tests {
    use deadbolt_core::Field;

    use super::*;

    fn file(name: &str, len: usize) -> Field {
        Field {
            kind: FieldType::File,
            value: item::file_value(name, &vec![7; len]).as_str().into(),
        }
    }

    fn document(fields: BTreeMap<String, Field>, tags: usize) -> V1Item {
        V1Item {
            kind: "document".into(),
            name: Some("Scans".into()),
            fields,
            source: None,
            favorite: true,
            tags: (0..tags).map(|i| format!("t{i:03}")).collect(),
            password_changed: None,
            ignored: BTreeMap::new(),
            password_entry: None,
            deleted: None,
        }
    }

    fn one(item: V1Item) -> V1Vault {
        V1Vault {
            id: [1; 32],
            name: "personal".into(),
            items: BTreeMap::from([(ItemId::from_bytes([3; 16]), item)]),
        }
    }

    #[test]
    fn items_within_the_caps_stay_as_they_are() {
        let six = item::MAX_FILE / 2 - 1024;
        let fields = BTreeMap::from([
            ("file".to_owned(), file("a.bin", six)),
            ("more".to_owned(), file("b.bin", six)),
        ]);
        let item = document(fields, tag::MAX_TAGS);
        let fitted = vault(one(item.clone()));
        assert_eq!(fitted.items.len(), 1);
        assert_eq!(fitted.items.values().next(), Some(&item));
    }

    #[test]
    fn files_over_the_cap_move_to_documents_beside_it() {
        let six = item::MAX_FILE * 6 / 10;
        let fields = BTreeMap::from([
            ("file".to_owned(), file("a.bin", six)),
            ("more".to_owned(), file("b.bin", six)),
            (
                "notes".to_owned(),
                Field {
                    kind: FieldType::Note,
                    value: "two scans".into(),
                },
            ),
        ]);
        let fitted = vault(one(document(fields.clone(), 2)));
        assert_eq!(fitted.items.len(), 2);
        let main = &fitted.items[&ItemId::from_bytes([3; 16])];
        assert_eq!(main.fields.keys().collect::<Vec<_>>(), ["file", "notes"]);
        let part = fitted
            .items
            .iter()
            .find(|(id, _)| **id != ItemId::from_bytes([3; 16]))
            .map(|(_, part)| part)
            .unwrap();
        assert_eq!(part.name.as_deref(), Some("Scans (more)"));
        assert_eq!(part.fields["file"], fields["more"]);
        assert_eq!(part.tags, main.tags);
        // Both fit v2's rules as they are now.
        for item in fitted.items.values() {
            let check = item::check_create_with(
                &item.kind,
                item.name.as_deref(),
                &item.fields,
                None,
                &item.tags,
            );
            assert!(check.is_ok(), "{check:?}");
        }
    }

    #[test]
    fn tags_past_the_cap_are_dropped() {
        let fitted = vault(one(document(BTreeMap::new(), tag::MAX_TAGS + 6)));
        let item = fitted.items.values().next().unwrap();
        assert_eq!(item.tags.len(), tag::MAX_TAGS);
        assert!(item.tags.contains("t000") && !item.tags.contains("t069"));
    }

    #[test]
    fn a_documents_required_file_has_first_claim_on_the_budget() {
        let fields = BTreeMap::from([
            (
                "attachment".into(),
                file("extra.bin", item::MAX_FILE / 2 + 1),
            ),
            ("file".into(), file("main.bin", item::MAX_FILE / 2 + 1)),
        ]);
        let fitted = vault(one(document(fields.clone(), 0)));
        let main = &fitted.items[&ItemId::from_bytes([3; 16])];
        assert_eq!(main.fields["file"], fields["file"]);
        assert!(!main.fields.contains_key("attachment"));
        assert_eq!(fitted.items.len(), 2);
    }

    fn build_and_verify(vault: &V1Vault) {
        let dir = tempfile::tempdir().unwrap();
        let plan = super::super::build::Plan {
            device_name: "laptop",
            default: None,
            vaults: std::slice::from_ref(vault),
        };
        let fast = crate::disk::KdfParams {
            m_cost_kib: 64,
            t_cost: 1,
            p_cost: 1,
        };
        super::super::build::build(&dir.path().join("store"), b"pass", fast, &plan).unwrap();
    }

    #[test]
    fn a_large_document_splits_its_create_without_losing_fields() {
        let fields = BTreeMap::from([
            ("file".into(), file("main.bin", item::MAX_FILE)),
            (
                "notes".into(),
                Field::new(FieldType::Note, "n".repeat(700 * 1024)),
            ),
        ]);
        let fitted = vault(one(document(fields.clone(), 0)));
        let id = ItemId::from_bytes([3; 16]);
        assert_eq!(fitted.items[&id].fields, fields);
        let (create, edits) = operations(id, &fitted.items[&id]);
        assert!(create.encoded_len() <= MAX_OP_LEN);
        assert_eq!(edits.len(), 1);
        assert!(edits[0].encoded_len() <= MAX_OP_LEN);
        build_and_verify(&fitted);
    }

    #[test]
    fn a_note_larger_than_one_operation_keeps_all_bytes_in_documents() {
        let text = "é".repeat((MAX_OP_LEN + 100 * 1024) / 2);
        let mut note = document(
            BTreeMap::from([("notes".into(), Field::new(FieldType::Secret, text.clone()))]),
            0,
        );
        note.kind = "note".into();
        let fitted = vault(one(note));
        let id = ItemId::from_bytes([3; 16]);
        let mut recovered = Vec::new();
        for i in 1..=2 {
            let part = &fitted.items[&part_id(&id, &format!("field/notes/{i}"))];
            let (_, bytes) = item::file_parts(part.fields["file"].value.as_str());
            recovered.extend(
                data_encoding::BASE64
                    .decode(bytes.unwrap().as_bytes())
                    .unwrap(),
            );
        }
        assert_eq!(recovered, text.as_bytes());
        build_and_verify(&fitted);
    }

    #[test]
    fn an_unnamed_item_can_move_its_only_field_to_an_edit() {
        let id = ItemId::from_bytes([3; 16]);
        let mut item = document(BTreeMap::new(), tag::MAX_TAGS);
        item.kind = "login".into();
        item.name = None;
        let overhead = DataOp::set(id, "notes", Field::new(FieldType::Note, "")).encoded_len();
        item.fields.insert(
            "notes".into(),
            Field::new(FieldType::Note, "x".repeat(MAX_OP_LEN - overhead)),
        );
        let fitted = vault(one(item.clone()));
        assert_eq!(fitted.items[&id], item);
        let (create, edits) = operations(id, &item);
        assert!(
            matches!(create, DataOp::Create { name: Some(_), ref fields, .. } if fields.is_empty())
        );
        assert_eq!(edits.len(), 2);
        assert_eq!(edits.last(), Some(&DataOp::name(id, None)));
        build_and_verify(&fitted);
    }

    #[test]
    fn an_unnamed_oversized_url_keeps_its_bytes_and_a_nonempty_parent() {
        let id = ItemId::from_bytes([3; 16]);
        let text = format!("https://example.com/{}", "x".repeat(15 * 1024 * 1024));
        let mut item = document(
            BTreeMap::from([("url".into(), Field::new(FieldType::Url, &text))]),
            0,
        );
        item.kind = "login".into();
        item.name = None;
        let fitted = vault(one(item));
        assert!(fitted.items[&id].name.is_some());
        let mut recovered = Vec::new();
        for i in 1..=2 {
            let part = &fitted.items[&part_id(&id, &format!("field/url/{i}"))];
            let (_, bytes) = item::file_parts(part.fields["file"].value.as_str());
            recovered.extend(
                data_encoding::BASE64
                    .decode(bytes.unwrap().as_bytes())
                    .unwrap(),
            );
        }
        assert_eq!(recovered, text.as_bytes());
        build_and_verify(&fitted);
    }

    #[test]
    fn required_fields_also_leave_room_for_create_overhead() {
        let mut item = document(
            BTreeMap::from([(
                "private-key".into(),
                Field::new(FieldType::Secret, "x".repeat(MAX_OP_LEN - 80)),
            )]),
            0,
        );
        item.kind = "ssh".into();
        let id = ItemId::from_bytes([3; 16]);
        assert!(
            DataOp::set(id, "private-key", item.fields["private-key"].clone()).encoded_len()
                <= MAX_OP_LEN
        );
        assert!(operations(id, &item).0.encoded_len() > MAX_OP_LEN);
        let fitted = vault(one(item));
        assert_eq!(fitted.items.len(), 3);
        assert!(operations(id, &fitted.items[&id]).0.encoded_len() <= MAX_OP_LEN);
        build_and_verify(&fitted);
    }
}
