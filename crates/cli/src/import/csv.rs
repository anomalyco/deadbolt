//! CSV exports: Apple Passwords', 1Password's, and any other with
//! recognizable columns, such as a browser's. Rows are logins.

use std::collections::BTreeSet;

use anyhow::{Context, Result, anyhow, bail};
use deadbolt_core::FieldType;

use super::{
    ARCHIVED, BAD_OTP, Builder, COLUMN, FAVORITE, Imported, NO_PASSWORD, SUPPORTED, Summary, TAG,
    item_name,
};
use crate::protocol::ImportSource;

/// Apple Passwords' header (macOS 15+, and Safari's before it).
const APPLE: &str = "Title,URL,Username,Password,Notes,OTPAuth";
/// 1Password 8's CSV header.
const ONEPASSWORD: &str = "Title,Url,Username,Password,OTPAuth,Favorite,Archived,Tags,Notes";

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum Column {
    Title,
    Url,
    Username,
    Password,
    Notes,
    /// An `otpauth://` URI.
    OtpAuth,
    /// A one-time password secret in any form.
    Totp,
    Favorite,
    Archived,
    Tags,
    Other,
}

impl Column {
    fn of(header: &str) -> Self {
        match header.trim().to_lowercase().as_str() {
            "title" | "name" => Self::Title,
            "url" | "website" | "login_uri" => Self::Url,
            "username" | "login" | "login_username" => Self::Username,
            "password" | "login_password" => Self::Password,
            "notes" | "note" => Self::Notes,
            "otpauth" => Self::OtpAuth,
            "totp" | "login_totp" => Self::Totp,
            "favorite" => Self::Favorite,
            "archived" => Self::Archived,
            "tags" => Self::Tags,
            _ => Self::Other,
        }
    }
}

/// A row's values, by column. Empty values are left out.
#[derive(Default)]
struct Row {
    title: Option<String>,
    urls: Vec<String>,
    username: Option<String>,
    password: Option<String>,
    notes: Option<String>,
    otp: Option<(String, bool)>,
    favorite: bool,
    archived: bool,
    tags: Vec<String>,
    empty: bool,
}

fn truthy(value: &str) -> bool {
    ["true", "yes", "1"]
        .iter()
        .any(|t| value.trim().eq_ignore_ascii_case(t))
}

/// A CSV error by position only: the csv crate's could quote a value.
fn error(error: &::csv::Error) -> anyhow::Error {
    match error.position() {
        Some(position) => anyhow!("unreadable CSV at line {}; {SUPPORTED}", position.line()),
        None => anyhow!("unreadable CSV; {SUPPORTED}"),
    }
}

/// Maps a CSV export.
pub fn export(text: &str) -> Result<(Vec<Imported>, Summary)> {
    let mut reader = ::csv::ReaderBuilder::new()
        .flexible(true)
        .from_reader(text.as_bytes());
    let headers = reader.headers().map_err(|e| error(&e))?.clone();
    let header = headers.iter().map(str::trim).collect::<Vec<_>>().join(",");
    let source = match header.as_str() {
        APPLE => ImportSource::ApplePasswords,
        ONEPASSWORD => ImportSource::OnePassword,
        _ => ImportSource::Csv,
    };
    let mut seen = BTreeSet::new();
    let columns: Vec<Column> = headers
        .iter()
        .map(|h| match Column::of(h) {
            Column::Url => Column::Url,
            column if seen.insert(column) => column,
            _ => Column::Other,
        })
        .collect();
    if !columns.contains(&Column::Password) {
        bail!("not a known CSV export: it has no password column; {SUPPORTED}");
    }
    let mut summary = Summary::new(source);
    let mut used = vec![false; columns.len()];
    let mut tags = BTreeSet::new();
    let mut record = ::csv::StringRecord::new();
    let mut out = Vec::new();
    let mut n = 0;
    while reader.read_record(&mut record).map_err(|e| error(&e))? {
        n += 1;
        let mut row = Row {
            empty: true,
            ..Row::default()
        };
        for (i, value) in record.iter().enumerate() {
            if value.trim().is_empty() {
                continue;
            }
            row.empty = false;
            let column = columns.get(i).copied().unwrap_or(Column::Other);
            let trimmed = || Some(value.trim().to_string());
            match column {
                Column::Title => row.title = trimmed(),
                Column::Url => row.urls.push(value.trim().into()),
                Column::Username => row.username = trimmed(),
                Column::Password => row.password = Some(value.into()),
                Column::Notes => row.notes = Some(value.into()),
                Column::OtpAuth => row.otp = Some((value.trim().into(), true)),
                Column::Totp => row.otp = Some((value.trim().into(), false)),
                Column::Favorite => row.favorite = truthy(value),
                Column::Archived => row.archived = truthy(value),
                Column::Tags => {
                    row.tags = value.split([',', ';']).map(|t| t.trim().into()).collect()
                }
                Column::Other => {
                    if let Some(used) = used.get_mut(i) {
                        *used = true;
                    }
                }
            }
        }
        if row.empty {
            continue;
        }
        if row.archived {
            summary.skip(ARCHIVED);
            continue;
        }
        let favorite = row.favorite;
        let row_tags = std::mem::take(&mut row.tags);
        let Some(item) = login(row, &mut summary)
            .transpose()
            .with_context(|| format!("mapping row {n}"))?
        else {
            continue;
        };
        if favorite {
            summary.drop_some(FAVORITE, 1);
        }
        tags.extend(row_tags.into_iter().filter(|t| !t.is_empty()));
        summary.add(&item);
        out.push(item);
    }
    let unused = columns
        .iter()
        .zip(&used)
        .filter(|(c, used)| **c == Column::Other && **used)
        .count();
    summary.drop_some(COLUMN, unused);
    summary.drop_some(TAG, tags.len());
    Ok((out, summary))
}

/// A login from a row; `None` if it has no password.
fn login(row: Row, summary: &mut Summary) -> Option<Result<Imported>> {
    let Some(password) = row.password else {
        summary.skip(NO_PASSWORD);
        return None;
    };
    let mut b = Builder::new("login");
    b.known("password", Some(password));
    b.known("username", row.username);
    match row.otp {
        Some((otp, true)) if !otp.to_lowercase().starts_with("otpauth://") => {
            b.extra("otp", FieldType::Secret, otp);
            summary.warn(BAD_OTP);
        }
        Some((otp, _)) => b.known_or_extra("otp", Some(otp), BAD_OTP, summary),
        None => {}
    }
    b.known("notes", row.notes);
    b.urls(row.urls, summary);
    Some(b.finish("login", item_name(row.title)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::import::parse;
    use crate::import::tests::{fields, lines};

    #[test]
    fn maps_an_apple_passwords_export() {
        let export = "Title,URL,Username,Password,Notes,OTPAuth
example.com (dax),https://example.com/login,dax,\"apple,pw,1\",\"line one
line two, with \"\"quotes\"\"\",otpauth://totp/Example:dax?secret=JBSWY3DPEHPK3PXP
Site,site.example,,apple-pw-2,,JBSWY3DPEHPK3PXP
No password,https://nopw.example,someone,,,
,,,apple-pw-3,,
,,,,,
";
        let (items, report) = parse(export).unwrap();
        assert_eq!(report.source, ImportSource::ApplePasswords);
        assert_eq!(items.len(), 3);
        assert_eq!(items[0].name.as_deref(), Some("example.com (dax)"));
        assert_eq!(
            fields(&items[0]),
            [
                ("notes", "note", "line one\nline two, with \"quotes\""),
                (
                    "otp",
                    "otp",
                    "otpauth://totp/Example:dax?secret=JBSWY3DPEHPK3PXP"
                ),
                ("password", "secret", "apple,pw,1"),
                ("url", "url", "https://example.com/login"),
                ("username", "text", "dax"),
            ]
        );
        assert_eq!(
            fields(&items[1]),
            [
                ("otp-2", "secret", "JBSWY3DPEHPK3PXP"),
                ("password", "secret", "apple-pw-2"),
                ("url", "url", "https://site.example"),
            ]
        );
        assert_eq!(items[2].name, None);
        assert_eq!(fields(&items[2]), [("password", "secret", "apple-pw-3")]);
        assert_eq!(
            lines(&report),
            [
                "imported 3 from Apple Passwords (logins 3, cards 0)",
                "skipped 1 login without password",
                "warning: 1 invalid one-time password secret kept as an extra field",
            ]
        );
    }

    #[test]
    fn maps_a_1password_csv_export() {
        let export = "Title,Url,Username,Password,OTPAuth,Favorite,Archived,Tags,Notes
GitHub,https://github.com,dax,op-csv-pw,,true,false,\"work,dev\",a note
Old,https://old.example,dax,op-old-pw,,false,true,,
";
        let (items, report) = parse(export).unwrap();
        assert_eq!(report.source, ImportSource::OnePassword);
        assert_eq!(
            fields(&items[0]),
            [
                ("notes", "note", "a note"),
                ("password", "secret", "op-csv-pw"),
                ("url", "url", "https://github.com"),
                ("username", "text", "dax"),
            ]
        );
        assert_eq!(
            lines(&report),
            [
                "imported 1 from 1Password (logins 1, cards 0)",
                "skipped 1 archived item",
                "dropped: 1 favorite, 2 tags",
            ]
        );
    }

    #[test]
    fn maps_browser_exports() {
        let chrome = "name,url,username,password,note\r\n\
            Example,https://example.com/,dax,chrome-pw,\r\n\
            ,android://abc@com.example.app/,,chrome-pw-2,hi\r\n";
        let (items, report) = parse(chrome).unwrap();
        assert_eq!(report.source, ImportSource::Csv);
        assert_eq!(
            fields(&items[0]),
            [
                ("password", "secret", "chrome-pw"),
                ("url", "url", "https://example.com/"),
                ("username", "text", "dax"),
            ]
        );
        assert_eq!(
            fields(&items[1]),
            [
                ("notes", "note", "hi"),
                ("password", "secret", "chrome-pw-2"),
                ("url", "url", "android://abc@com.example.app/"),
            ]
        );
        assert_eq!(lines(&report), ["imported 2 from CSV (logins 2, cards 0)"]);
        let firefox = "\"url\",\"username\",\"password\",\"httpRealm\",\"formActionOrigin\",\"guid\",\"timeCreated\"
\"https://example.com\",\"dax\",\"ff-pw\",,\"https://example.com\",\"{abc}\",\"1700000000000\"
";
        let (items, report) = parse(firefox).unwrap();
        assert_eq!(items.len(), 1);
        assert_eq!(
            lines(&report),
            [
                "imported 1 from CSV (logins 1, cards 0)",
                "dropped: 3 unrecognized columns",
            ]
        );
    }

    #[test]
    fn errors_name_no_values() {
        let error = format!("{:#}", parse("hunter2,swordfish\n").err().unwrap());
        assert!(error.contains("no password column"), "{error}");
        assert!(!error.contains("hunter2"), "{error}");
    }
}
