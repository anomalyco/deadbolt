//! Item commands on the client side: parsing `field[:type]=value`
//! assignments, filling in missing input, and printing. A file field's
//! value is a path: the client reads the file and sends its name and
//! contents (`deadbolt_core::item::file_value`).

use std::io::{IsTerminal, Write};
use std::path::{Path, PathBuf};

use anyhow::{Result, anyhow, bail};
use clap::Subcommand;
use deadbolt_core::{FieldType, schema, schemas};
use zeroize::Zeroizing;

use crate::paths::Paths;
use crate::prompt;
use crate::protocol::{Code, Command, FieldInput, ItemInfo, Reply, code_field, sign_in_name};

#[derive(Subcommand)]
pub enum ItemCommand {
    /// Create an item and print its short id. A login without `password=`
    /// gets a generated one. A file field takes a path (at most 10 MiB);
    /// any item can carry files as `name:file=PATH`.
    ///
    /// Types: login, card, note, ssh, identity, api, database, server, wifi,
    /// license, bank, document, passport, driver-license, membership, crypto,
    /// id-document.
    ///
    /// Examples: deadbolt new login username=dax url=github.com
    ///           deadbolt new api credential=- username=deploy-bot type=bearer
    ///           deadbolt new document file=./passport.pdf --name Passport scan
    New {
        /// Item type (see above).
        #[arg(value_name = "TYPE")]
        kind: String,
        /// `field[:type]=value`; `field=-` reads the value from stdin; a
        /// file field's value is a path.
        #[arg(value_name = "FIELD=VALUE")]
        fields: Vec<String>,
        /// An optional label; need not be unique.
        #[arg(long)]
        name: Option<String>,
        /// Length of a generated password.
        #[arg(long, default_value_t = deadbolt_core::password::DEFAULT_LENGTH)]
        length: usize,
        /// Generate a password of letters and digits only.
        #[arg(long)]
        no_symbols: bool,
    },
    /// Print one field's raw value. Default: login, database, server or
    /// Wi-Fi password, card or ID number, note body, SSH private key,
    /// identity email, API credential, license key, bank account number,
    /// membership id, wallet recovery phrase, a document's file. A file's
    /// contents go to --output, or to stdout when it isn't a terminal.
    Get {
        /// Words that must all match, or an id prefix.
        #[arg(required = true, value_name = "QUERY")]
        query: Vec<String>,
        #[arg(short, long)]
        field: Option<String>,
        /// Write a file field's contents here (mode 0600).
        #[arg(short, long, value_name = "FILE")]
        output: Option<PathBuf>,
    },
    /// Print the current one-time code from an item's otp field.
    Code {
        #[arg(required = true, value_name = "QUERY")]
        query: Vec<String>,
    },
    /// Show an item's fields, secrets masked and its one-time password as
    /// the current code.
    Show {
        #[arg(required = true, value_name = "QUERY")]
        query: Vec<String>,
        /// Show secret values.
        #[arg(long)]
        reveal: bool,
    },
    /// List items: short id, label, and what tells it apart (username,
    /// card expiry, SSH key comment, identity email, a document's size, ...).
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
    ///          deadbolt set github recovery:file=./codes.pdf
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

/// A file field's value for the file at `path`: its name and contents.
fn read_file(path: &str) -> Result<String> {
    Ok(deadbolt_client::file::read(Path::new(path))?.to_string())
}

/// Parses assignments and fills `field=-` values: from stdin (at most one),
/// or asked for on a terminal, without echo unless the field is known not
/// to be secret. A file field's path becomes the file. `kind` is the item
/// type, if known.
fn assignments<'a>(
    args: impl IntoIterator<Item = &'a String>,
    kind: Option<&str>,
) -> Result<Vec<FieldInput>> {
    let mut inputs: Vec<FieldInput> = args.into_iter().map(|a| parse(a)).collect::<Result<_>>()?;
    for input in &mut inputs {
        if known_type(kind, input) == Some(FieldType::File) {
            input.value = read_file(&input.value)?;
        }
    }
    let interactive = prompt::interactive();
    if !interactive && inputs.iter().filter(|i| i.value == "-").count() > 1 {
        bail!("only one field can read its value from stdin");
    }
    for input in inputs
        .iter_mut()
        .filter(|i| i.value == "-" && known_type(kind, i) != Some(FieldType::File))
    {
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
        let file = field.kind == FieldType::File;
        let value = prompt::fill(
            None,
            prompt::interactive(),
            || prompt::ask_value(field.name, field.kind.is_secret()),
            || {
                anyhow!(
                    "missing required field {}: pass {}={}",
                    field.name,
                    field.name,
                    if file { "PATH" } else { "..." }
                )
            },
        )?;
        let value = if file {
            Zeroizing::new(read_file(&value)?)
        } else {
            value
        };
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

/// `code` stands in for the code field's masked value. `account` is the
/// label of the login `sign-in-account` names, if it is here: then
/// `sign-in-with` reads "Google · dax@example.com" and the id is left out.
fn show(item: &ItemInfo, reveal: bool, code: Option<String>, account: Option<String>) {
    let code_field = code_field(&item.fields);
    let mut rows: Vec<(&str, String)> = vec![
        ("type", item.kind.clone()),
        ("label", item.label.clone()),
        ("id", item.short.clone()),
    ];
    let mut code = code;
    let sign_in = item.kind == "login";
    for (i, field) in item.fields.iter().enumerate() {
        let value = match code.take_if(|_| code_field == Some(i)) {
            Some(code) => code,
            None if sign_in && field.name == "sign-in-with" => {
                let provider = sign_in_name(&field.value).to_string();
                match &account {
                    Some(account) => format!("{provider} · {account}"),
                    None => provider,
                }
            }
            None if sign_in && field.name == "sign-in-account" && account.is_some() => continue,
            None if reveal => field.value.clone(),
            None => mask(item, field),
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

/// One field's raw value and type, the item's default field without
/// `field`. One-time password secrets and files' contents come only for the
/// field asked: `-f otp` and a document's file ask up front, and another
/// field turns out to be of type otp (empty) or file (its name alone) only
/// once it comes back, so that item is asked for again by id.
async fn get(
    vault: Option<String>,
    query: Vec<String>,
    field: Option<&str>,
    mut fetch: impl AsyncFnMut(Command) -> Result<ItemInfo>,
) -> Result<(Zeroizing<String>, String)> {
    let otp = field == Some("otp");
    let command = Command::ItemGet {
        vault: vault.clone(),
        query,
        otp,
        files: false,
    };
    let mut item = fetch(command).await?;
    let name = match field {
        Some(name) => name.to_owned(),
        None => crate::protocol::primary_field(&item.kind)
            .ok_or_else(|| anyhow!("{} items have no default field; pass -f", item.kind))?
            .to_owned(),
    };
    let find = |item: &mut ItemInfo| {
        let label = item.label.clone();
        item.fields
            .iter_mut()
            .find(|f| f.name == name)
            .map(|f| {
                let withheld = (f.kind == "otp" && f.value.is_empty())
                    || (f.kind == "file" && !deadbolt_client::file::has_contents(&f.value));
                (
                    withheld,
                    Zeroizing::new(std::mem::take(&mut f.value)),
                    f.kind.clone(),
                )
            })
            .ok_or_else(|| anyhow!("{label} has no field {name}"))
    };
    let (withheld, mut value, mut kind) = find(&mut item)?;
    if withheld && !(otp && kind == "otp") {
        let command = Command::ItemGet {
            vault,
            query: vec![item.id.clone()],
            otp: kind == "otp",
            files: kind == "file",
        };
        (_, value, kind) = find(&mut fetch(command).await?)?;
    }
    Ok((value, kind))
}

/// Writes a file field's contents to `output`, else to stdout unless it is
/// a terminal.
fn write_file(value: &str, output: Option<&Path>) -> Result<()> {
    use deadbolt_client::file;
    match output {
        Some(path) => file::write(value, path)?,
        None if std::io::stdout().is_terminal() => {
            bail!(
                "{} is a file; pass -o FILE, or redirect stdout",
                file::name(value)
            )
        }
        None => std::io::stdout()
            .lock()
            .write_all(&file::contents(value)?)?,
    }
    Ok(())
}

async fn code(
    paths: &Paths,
    vault: Option<String>,
    query: Vec<String>,
    from_stdin: bool,
) -> Result<Code> {
    let command = Command::ItemCode { vault, query };
    let Reply::Code { code } = crate::request(paths, command, from_stdin).await? else {
        bail!("unexpected reply");
    };
    Ok(code)
}

/// The username, else the label, of the item with id `id`, if it is in
/// the vault: never its other values.
async fn sign_in_account(
    paths: &Paths,
    vault: Option<String>,
    id: String,
    from_stdin: bool,
) -> Option<String> {
    let command = Command::ItemList {
        vault,
        query: vec![id.clone()],
        kind: None,
    };
    let Ok(Reply::Items { items }) = crate::request(paths, command, from_stdin).await else {
        return None;
    };
    let item = items.into_iter().find(|i| i.id == id)?;
    Some(
        item.detail
            .filter(|d| !d.starts_with("Sign in with "))
            .unwrap_or(item.label),
    )
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
                let command = Command::Generate {
                    length,
                    symbols: !no_symbols,
                };
                let Reply::Password { password } =
                    crate::request(paths, command, from_stdin).await?
                else {
                    bail!("unexpected reply");
                };
                fields.push(FieldInput {
                    name: "password".into(),
                    kind: None,
                    value: password.to_string(),
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
        ItemCommand::Get {
            query,
            field,
            output,
        } => {
            let fetch = async |command| item(paths, command, from_stdin).await;
            let (value, kind) = get(vault, query, field.as_deref(), fetch).await?;
            if kind == "file" {
                write_file(&value, output.as_deref())?;
            } else if output.is_some() {
                bail!("--output is for file fields");
            } else {
                println!("{}", value.as_str());
            }
        }
        ItemCommand::Code { query } => {
            println!(
                "{}",
                code(paths, vault, query, from_stdin).await?.code.as_str()
            );
        }
        ItemCommand::Show { query, reveal } => {
            let command = Command::ItemGet {
                vault: vault.clone(),
                query,
                otp: reveal,
                files: false,
            };
            let item = item(paths, command, from_stdin).await?;
            let code = match code_field(&item.fields) {
                Some(_) if !reveal => {
                    // By id, so it's this item's code even if the vault changed.
                    let id = vec![item.id.clone()];
                    match code(paths, vault.clone(), id, from_stdin).await {
                        Ok(code) => Some(format!(
                            "{} ({}s left)",
                            code.code.as_str(),
                            code.remaining_ms.div_ceil(1000)
                        )),
                        Err(error) => Some(format!("•••••••• (no code: {error:#})")),
                    }
                }
                _ => None,
            };
            let account = match item.fields.iter().find(|f| f.name == "sign-in-account") {
                Some(id) if item.kind == "login" => {
                    sign_in_account(paths, vault, id.value.clone(), from_stdin).await
                }
                _ => None,
            };
            show(&item, reveal, code, account);
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
            let query: Vec<String> = query.into_iter().cloned().collect();
            // The item's type says which fields take a file's path.
            let list = Command::ItemList {
                vault: vault.clone(),
                query: query.clone(),
                kind: None,
            };
            let kind = match crate::request(paths, list, from_stdin).await? {
                Reply::Items { items } if items.len() == 1 => Some(items[0].kind.clone()),
                _ => None,
            };
            let command = Command::ItemSet {
                vault,
                query,
                fields: assignments(assigns, kind.as_deref())?,
                name,
                unset: Vec::new(),
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

    /// `get` asks for one-time password secrets only for a field of type
    /// otp: `-f otp` up front, another such field by id once it's seen.
    #[tokio::test]
    async fn get_asks_for_otp_secrets_only_for_an_otp_field() {
        use crate::protocol::FieldInfo;
        let field = |name: &str, kind: &str, value: &str| FieldInfo {
            name: name.into(),
            kind: kind.into(),
            value: value.into(),
        };
        // The agent's side: otp values only when asked.
        let agent = |otp: bool| ItemInfo {
            id: "c0ffee".into(),
            short: "c0ff".into(),
            kind: "login".into(),
            label: "github.com".into(),
            detail: Some("dax".into()),
            fields: [
                field("password", "secret", "pw"),
                field("username", "text", "dax"),
                field("otp", "otp", "JBSWY3DPEHPK3PXP"),
                field("backup", "otp", "KRSXG5CTMVRXEZLU"),
            ]
            .into_iter()
            .map(|mut f| {
                if f.kind == "otp" && !otp {
                    f.value.clear();
                }
                f
            })
            .collect(),
            source: None,
        };
        let cases = [
            (None, "pw", vec![("github", false)]),
            (Some("username"), "dax", vec![("github", false)]),
            (Some("otp"), "JBSWY3DPEHPK3PXP", vec![("github", true)]),
            (
                Some("backup"),
                "KRSXG5CTMVRXEZLU",
                vec![("github", false), ("c0ffee", true)],
            ),
        ];
        for (name, value, asked) in cases {
            let mut sent = Vec::new();
            let fetch = async |command| {
                let Command::ItemGet { query, otp, .. } = command else {
                    bail!("not a get");
                };
                sent.push((query.join(" "), otp));
                Ok(agent(otp))
            };
            let (got, _) = get(None, vec!["github".into()], name, fetch).await.unwrap();
            assert_eq!(got.as_str(), value, "{name:?}");
            let asked: Vec<_> = asked.into_iter().map(|(q, o)| (q.to_owned(), o)).collect();
            assert_eq!(sent, asked, "{name:?}");
        }
    }

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
        assert_eq!((input.kind.as_deref(), input.value.as_str()), (None, ""));
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
