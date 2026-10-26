//! Item commands on the client side: parsing `field[:type]=value`
//! assignments, filling in missing input, and printing.

use anyhow::{Result, anyhow, bail};
use clap::Subcommand;
use deadbolt_core::{FieldType, schema, schemas};

use crate::paths::Paths;
use crate::prompt;
use crate::protocol::{Command, FieldInput, ItemInfo, Reply};

#[derive(Subcommand)]
pub enum ItemCommand {
    /// Create an item and print its short id. A login without `password=`
    /// gets a generated one.
    ///
    /// Example: deadbolt new login username=dax url=github.com
    New {
        /// Item type: login, card, note, ssh or identity.
        #[arg(value_name = "TYPE")]
        kind: String,
        /// `field[:type]=value`; `field=-` reads the value from stdin.
        #[arg(value_name = "FIELD=VALUE")]
        fields: Vec<String>,
        /// An optional label; need not be unique.
        #[arg(long)]
        name: Option<String>,
        /// Length of a generated password.
        #[arg(long, default_value_t = 24)]
        length: usize,
        /// Generate a password of letters and digits only.
        #[arg(long)]
        no_symbols: bool,
    },
    /// Print one field's raw value (default: login password, card number,
    /// note body, SSH private key, identity email).
    Get {
        /// Words that must all match, or an id prefix.
        #[arg(required = true, value_name = "QUERY")]
        query: Vec<String>,
        #[arg(short, long)]
        field: Option<String>,
    },
    /// Print the current one-time code from an item's otp field.
    Code {
        #[arg(required = true, value_name = "QUERY")]
        query: Vec<String>,
    },
    /// Show an item's fields, secrets masked.
    Show {
        #[arg(required = true, value_name = "QUERY")]
        query: Vec<String>,
        /// Show secret values.
        #[arg(long)]
        reveal: bool,
    },
    /// List items: short id, label, and username, card expiry, SSH key
    /// comment or fingerprint, or identity email or phone.
    Ls {
        #[arg(value_name = "QUERY")]
        query: Vec<String>,
        /// Only items of this type.
        #[arg(long = "type", value_name = "TYPE")]
        kind: Option<String>,
    },
    /// Set fields and/or the name. Arguments containing `=` are
    /// assignments, the others are the query.
    ///
    /// Example: deadbolt set github dax password=- url=github.com
    Set {
        #[arg(required = true, value_name = "QUERY|FIELD=VALUE")]
        args: Vec<String>,
        /// Set the name; an empty name clears it.
        #[arg(long)]
        name: Option<String>,
    },
    /// Remove a field that is not required.
    Unset {
        #[arg(required = true, value_name = "QUERY")]
        query: Vec<String>,
        #[arg(short, long)]
        field: String,
    },
    /// Delete an item.
    Rm {
        #[arg(required = true, value_name = "QUERY")]
        query: Vec<String>,
    },
}

/// `short<TAB>label[<TAB>detail]`, as `ls` prints it.
pub fn line(item: &ItemInfo) -> String {
    match &item.detail {
        Some(detail) => format!("{}\t{}\t{detail}", item.short, item.label),
        None => format!("{}\t{}", item.short, item.label),
    }
}

/// `month` of a 2- or 4-digit `year` (20YY) as `YYYY-MM`. The month is not
/// range-checked here; the item rules do that. Shared by the agent's input
/// normalization and the importer.
pub fn format_month(month: u8, year: &str) -> Option<String> {
    let year = year.trim();
    if !year.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    let year = match year.len() {
        2 => format!("20{year}"),
        4 => year.to_string(),
        _ => return None,
    };
    Some(format!("{year}-{month:02}"))
}

/// A URL without a scheme gets `https://`.
pub fn with_scheme(url: String) -> String {
    if url.is_empty() || url.contains("://") {
        url
    } else {
        format!("https://{url}")
    }
}

fn parse(arg: &str) -> Result<FieldInput> {
    let (lhs, value) = arg
        .split_once('=')
        .ok_or_else(|| anyhow!("expected field[:type]=value, got {arg:?}"))?;
    let (name, kind) = match lhs.split_once(':') {
        Some((name, kind)) => (name, Some(kind.to_string())),
        None => (lhs, None),
    };
    Ok(FieldInput {
        name: name.into(),
        kind,
        value: value.into(),
    })
}

/// The field type known before talking to the agent: explicit, or from the
/// item type's schema.
fn known_type(kind: Option<&str>, input: &FieldInput) -> Option<FieldType> {
    match &input.kind {
        Some(k) => Some(FieldType::parse(k)),
        None => schema(kind?)?.field(&input.name).map(|f| f.kind.clone()),
    }
}

/// Parses assignments and fills `field=-` values: from stdin (at most one),
/// or asked for on a terminal, without echo unless the field is known not
/// to be secret. `kind` is the item type, if known.
fn assignments<'a>(
    args: impl IntoIterator<Item = &'a String>,
    kind: Option<&str>,
) -> Result<Vec<FieldInput>> {
    let mut inputs: Vec<FieldInput> = args.into_iter().map(|a| parse(a)).collect::<Result<_>>()?;
    let interactive = prompt::interactive();
    if !interactive && inputs.iter().filter(|i| i.value == "-").count() > 1 {
        bail!("only one field can read its value from stdin");
    }
    for input in inputs.iter_mut().filter(|i| i.value == "-") {
        let value = if interactive {
            let hidden = known_type(kind, input).is_none_or(|t| t.is_secret());
            prompt::ask_value(&input.name, hidden)?
        } else {
            prompt::stdin_value()?
        };
        input.value = value.to_string();
    }
    Ok(inputs)
}

/// Required fields of `kind` that were not given: asked for on a terminal,
/// else an error. A login's password is generated instead.
fn fill_required(kind: &str, inputs: &mut Vec<FieldInput>) -> Result<()> {
    let Some(schema) = schema(kind) else {
        let known: Vec<&str> = schemas().iter().map(|s| s.kind).collect();
        bail!("unknown item type {kind:?} (known: {})", known.join(", "));
    };
    for field in schema.fields.iter().filter(|f| f.required) {
        if inputs.iter().any(|i| i.name == field.name) {
            continue;
        }
        let value = prompt::fill(
            None,
            prompt::interactive(),
            || prompt::ask_value(field.name, field.kind.is_secret()),
            || {
                anyhow!(
                    "missing required field {}: pass {}=...",
                    field.name,
                    field.name
                )
            },
        )?;
        inputs.push(FieldInput {
            name: field.name.into(),
            kind: None,
            value: value.to_string(),
        });
    }
    Ok(())
}

async fn item(paths: &Paths, command: Command, from_stdin: bool) -> Result<ItemInfo> {
    match crate::request(paths, command, from_stdin).await? {
        Reply::Item { item } => Ok(item),
        _ => bail!("unexpected reply"),
    }
}

fn mask(item: &ItemInfo, field: &crate::protocol::FieldInfo) -> String {
    if !FieldType::parse(&field.kind).is_secret() {
        return field.value.clone();
    }
    if item.kind == "card" && field.name == "number" {
        let last = &field.value[field.value.len().saturating_sub(4)..];
        return format!("•••• {last}");
    }
    "••••••••".into()
}

fn show(item: &ItemInfo, reveal: bool) {
    let mut rows: Vec<(&str, String)> = vec![
        ("type", item.kind.clone()),
        ("label", item.label.clone()),
        ("id", item.short.clone()),
    ];
    for field in &item.fields {
        let value = if reveal {
            field.value.clone()
        } else {
            mask(item, field)
        };
        rows.push((&field.name, value));
    }
    let width = rows
        .iter()
        .map(|(k, _)| k.chars().count())
        .max()
        .unwrap_or(0);
    for (key, value) in rows {
        let mut lines = value.lines();
        println!("{key:width$}  {}", lines.next().unwrap_or_default());
        for line in lines {
            println!("{:width$}  {line}", "");
        }
    }
}

pub async fn run(
    paths: &Paths,
    command: ItemCommand,
    vault: Option<String>,
    from_stdin: bool,
) -> Result<()> {
    match command {
        ItemCommand::New {
            kind,
            fields,
            name,
            length,
            no_symbols,
        } => {
            let mut fields = assignments(&fields, Some(&kind))?;
            fill_required(&kind, &mut fields)?;
            if kind == "login" && !fields.iter().any(|f| f.name == "password") {
                fields.push(FieldInput {
                    name: "password".into(),
                    kind: None,
                    value: prompt::generate_password(length, !no_symbols)?.to_string(),
                });
            }
            let command = Command::ItemNew {
                vault,
                kind,
                name,
                fields,
            };
            println!("{}", item(paths, command, from_stdin).await?.short);
        }
        ItemCommand::Get { query, field } => {
            let command = Command::ItemGet { vault, query };
            let item = item(paths, command, from_stdin).await?;
            let name = match field.as_deref() {
                Some(name) => name,
                None => crate::protocol::primary_field(&item.kind)
                    .ok_or_else(|| anyhow!("{} items have no default field; pass -f", item.kind))?,
            };
            let field = item
                .fields
                .iter()
                .find(|f| f.name == name)
                .ok_or_else(|| anyhow!("{} has no field {name}", item.label))?;
            println!("{}", field.value);
        }
        ItemCommand::Code { query } => {
            let command = Command::ItemCode { vault, query };
            let Reply::Code { code } = crate::request(paths, command, from_stdin).await? else {
                bail!("unexpected reply");
            };
            println!("{}", code.code.as_str());
        }
        ItemCommand::Show { query, reveal } => {
            let command = Command::ItemGet { vault, query };
            show(&item(paths, command, from_stdin).await?, reveal);
        }
        ItemCommand::Ls { query, kind } => {
            let command = Command::ItemList { vault, query, kind };
            let Reply::Items { items } = crate::request(paths, command, from_stdin).await? else {
                bail!("unexpected reply");
            };
            for item in &items {
                println!("{}", line(item));
            }
        }
        ItemCommand::Set { args, name } => {
            let (assigns, query): (Vec<&String>, Vec<&String>) =
                args.iter().partition(|a| a.contains('='));
            if query.is_empty() {
                bail!("set needs a query to find the item");
            }
            if assigns.is_empty() && name.is_none() {
                bail!("nothing to change: give field=value assignments or --name");
            }
            let command = Command::ItemSet {
                vault,
                query: query.into_iter().cloned().collect(),
                fields: assignments(assigns, None)?,
                name,
            };
            println!("{}", item(paths, command, from_stdin).await?.short);
        }
        ItemCommand::Unset { query, field } => {
            let command = Command::ItemUnset {
                vault,
                query,
                field,
            };
            println!("{}", item(paths, command, from_stdin).await?.short);
        }
        ItemCommand::Rm { query } => {
            let command = Command::ItemRemove { vault, query };
            println!("{}", item(paths, command, from_stdin).await?.short);
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_assignments() {
        let input = parse("url:url=https://a=b").unwrap();
        assert_eq!(
            (
                input.name.as_str(),
                input.kind.as_deref(),
                input.value.as_str()
            ),
            ("url", Some("url"), "https://a=b")
        );
        let input = parse("password=").unwrap();
        assert_eq!((input.kind, input.value.as_str()), (None, ""));
        assert!(parse("nope").is_err());
    }

    #[test]
    fn hides_prompts_for_secret_or_unknown_types() {
        let input = |kind: Option<&str>| FieldInput {
            name: "pin".into(),
            kind: kind.map(Into::into),
            value: "-".into(),
        };
        assert_eq!(
            known_type(Some("card"), &input(None)),
            Some(FieldType::Secret)
        );
        assert_eq!(known_type(None, &input(None)), None);
        assert_eq!(
            known_type(None, &input(Some("text"))),
            Some(FieldType::Text)
        );
    }
}
