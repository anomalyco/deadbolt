//! Reading an export for [`Command::Import`](crate::protocol::Command::Import).
//!
//! Clients only turn the file into text; the agent detects the format and
//! maps it. A 1Password `.1pux` is a zip: its `export.data`, and of the
//! files under `files/` only the attachments and documents `export.data`
//! names (by `documentId`), not its icons and avatars. An attachment larger
//! than [`MAX_FILE`], or one past what fits in the request, is left out
//! (the agent counts it as dropped). Anything else must be UTF-8 text.
//! Buffers holding the text and files are wiped, and errors never quote the
//! file.

use std::fs::File;
use std::io::{self, Cursor, Read, Seek};
use std::path::{Path, PathBuf};

use zeroize::Zeroizing;
use zip::ZipArchive;
use zip::result::ZipError;

pub use crate::file::MAX_FILE;
use crate::protocol::{ExportFile, MAX_LINE};

/// An export's text, and a `.1pux`'s attachments.
#[derive(Debug, Default)]
pub struct Export {
    pub text: Zeroizing<String>,
    pub files: Vec<ExportFile>,
}

impl Export {
    fn text(text: Zeroizing<String>) -> Self {
        Self {
            text,
            files: Vec::new(),
        }
    }

    /// A digest of the text and the files, to tell when an export changed.
    pub fn digest(&self) -> blake3::Hash {
        let mut h = blake3::Hasher::new();
        h.update(self.text.as_bytes());
        for file in &self.files {
            for part in [&file.name, &file.data] {
                h.update(&(part.len() as u64).to_le_bytes());
                h.update(part.as_bytes());
            }
        }
        h.finalize()
    }
}

/// The largest export text: a request carrying it stays under [`MAX_LINE`]
/// after JSON escaping.
pub const MAX_TEXT: usize = 32 * 1024 * 1024;
/// The largest `.1pux` read from a stream. Files are read in place, so
/// attachments in them cost nothing.
const MAX_ARCHIVE: usize = 1024 * 1024 * 1024;
/// Room in the request line for everything but the export.
const ENVELOPE: usize = 64 * 1024;
const ZIP: &[u8] = b"PK\x03\x04";
const BOM: &[u8] = b"\xef\xbb\xbf";
const EXPORT_DATA: &str = "export.data";

#[derive(Debug, thiserror::Error)]
pub enum ExportError {
    #[error("reading {}", .0.display())]
    Read(PathBuf, #[source] io::Error),
    #[error("reading the export")]
    Io(#[source] io::Error),
    #[error("the export is empty")]
    Empty,
    #[error("the export is larger than {} MiB", MAX_TEXT >> 20)]
    TooLarge,
    #[error(
        "a .1pux read from a pipe can be at most {} MiB; pass the file itself",
        MAX_ARCHIVE >> 20
    )]
    ArchiveTooLarge,
    #[error("not a text file: export as CSV or JSON (UTF-8), or from 1Password as 1PUX")]
    NotText,
    #[error(
        "this zip file has no export.data, so it is not a 1Password export; export from 1Password as 1PUX"
    )]
    NotOnePux,
    #[error("unreadable 1Password export (.1pux)")]
    Zip(#[source] ZipError),
}

/// Reads an export file: a `.1pux` in place, anything else as text. A
/// pipe or other file that can't seek, such as `<(...)` or `/dev/stdin`,
/// is read as a stream.
pub fn read(path: &Path) -> Result<Export, ExportError> {
    let error = |e| ExportError::Read(path.into(), e);
    let mut file = File::open(path).map_err(error)?;
    let metadata = file.metadata().map_err(error)?;
    if !metadata.is_file() {
        return read_from(file).map_err(|e| match e {
            ExportError::Io(e) => error(e),
            e => e,
        });
    }
    let mut magic = [0; 4];
    let mut len = 0;
    while len < magic.len() {
        match file.read(&mut magic[len..]) {
            Ok(0) => break,
            Ok(n) => len += n,
            Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
            Err(e) => return Err(error(e)),
        }
    }
    if magic[..len] == *ZIP {
        return onepux(file);
    }
    file.rewind().map_err(error)?;
    if metadata.len() > MAX_TEXT as u64 + BOM.len() as u64 {
        return Err(ExportError::TooLarge);
    }
    let buffer = Zeroizing::new(Vec::with_capacity(
        usize::try_from(metadata.len()).unwrap_or(MAX_TEXT),
    ));
    let bytes = bounded(file, MAX_TEXT + BOM.len(), buffer)
        .map_err(error)?
        .ok_or(ExportError::TooLarge)?;
    text(bytes).map(Export::text)
}

/// Reads an export from a stream, such as stdin.
pub fn read_from(mut reader: impl Read) -> Result<Export, ExportError> {
    let head = bounded(
        (&mut reader).take(ZIP.len() as u64),
        ZIP.len(),
        Zeroizing::new(Vec::new()),
    )
    .map_err(ExportError::Io)?
    .ok_or(ExportError::TooLarge)?;
    if head.starts_with(ZIP) {
        let bytes = bounded(reader, MAX_ARCHIVE, head)
            .map_err(ExportError::Io)?
            .ok_or(ExportError::ArchiveTooLarge)?;
        return onepux(Cursor::new(&bytes[..]));
    }
    let bytes = bounded(reader, MAX_TEXT + BOM.len(), head)
        .map_err(ExportError::Io)?
        .ok_or(ExportError::TooLarge)?;
    text(bytes).map(Export::text)
}

/// The export of a file's bytes; `bytes` is wiped.
pub fn decode(bytes: Vec<u8>) -> Result<Export, ExportError> {
    let bytes = Zeroizing::new(bytes);
    if bytes.starts_with(ZIP) {
        return onepux(Cursor::new(&bytes[..]));
    }
    text(bytes).map(Export::text)
}

/// Reads at most `max` bytes onto `buffer`, or `None` if there are more.
fn bounded(
    mut reader: impl Read,
    max: usize,
    mut buffer: Zeroizing<Vec<u8>>,
) -> io::Result<Option<Zeroizing<Vec<u8>>>> {
    let mut chunk = Zeroizing::new([0; 16 * 1024]);
    loop {
        let n = match reader.read(&mut chunk[..]) {
            Ok(0) => return Ok(Some(buffer)),
            Ok(n) => n,
            Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(e),
        };
        if buffer.len() + n > max {
            return Ok(None);
        }
        append(&mut buffer, &chunk[..n], max);
    }
}

/// Appends `bytes` to a buffer of secrets. It grows by copying into a new
/// buffer (to at most `max`, unless `bytes` need more) and wiping the old
/// one, so no reallocation leaves a copy behind.
pub fn append(buffer: &mut Zeroizing<Vec<u8>>, bytes: &[u8], max: usize) {
    if buffer.capacity() - buffer.len() < bytes.len() {
        let needed = buffer.len() + bytes.len();
        let capacity = (buffer.capacity() * 2).min(max).max(needed);
        let mut grown = Zeroizing::new(Vec::with_capacity(capacity));
        grown.extend_from_slice(buffer);
        *buffer = grown;
    }
    buffer.extend_from_slice(bytes);
}

/// The `export.data` of a 1Password `.1pux`, and the attachments it names.
fn onepux(reader: impl Read + Seek) -> Result<Export, ExportError> {
    let mut archive = ZipArchive::new(reader).map_err(ExportError::Zip)?;
    let mut entry = match archive.by_name(EXPORT_DATA) {
        Ok(entry) => entry,
        Err(ZipError::FileNotFound) => return Err(ExportError::NotOnePux),
        Err(e) => return Err(ExportError::Zip(e)),
    };
    let size = entry.size();
    if size > MAX_TEXT as u64 {
        return Err(ExportError::TooLarge);
    }
    let buffer = Zeroizing::new(Vec::with_capacity(size as usize));
    // The declared size is only a hint; the limit holds whatever it says.
    let bytes = bounded(&mut entry, MAX_TEXT, buffer)
        .map_err(ExportError::Io)?
        .ok_or(ExportError::TooLarge)?;
    drop(entry);
    let text = text(bytes)?;
    let files = attachments(&mut archive, &text)?;
    Ok(Export { text, files })
}

/// The `documentId`s `export.data` names, from its documents and file
/// fields. Untyped JSON, so an error can't quote a value; unparsable text
/// names none (the agent says why it can't read it).
fn document_ids(text: &str) -> Vec<String> {
    fn walk(value: &serde_json::Value, ids: &mut Vec<String>) {
        match value {
            serde_json::Value::Object(map) => {
                for (key, value) in map {
                    match value {
                        serde_json::Value::String(id) if key == "documentId" => {
                            ids.push(id.clone());
                        }
                        _ => walk(value, ids),
                    }
                }
            }
            serde_json::Value::Array(values) => values.iter().for_each(|v| walk(v, ids)),
            _ => {}
        }
    }
    let mut ids = Vec::new();
    if let Ok(value) = serde_json::from_str::<serde_json::Value>(text) {
        walk(&value, &mut ids);
    }
    ids.sort();
    ids.dedup();
    ids
}

/// The archive's attachments `text` names, in base64, while they fit in the
/// request beside the text; each at most [`MAX_FILE`].
fn attachments<R: Read + Seek>(
    archive: &mut ZipArchive<R>,
    text: &str,
) -> Result<Vec<ExportFile>, ExportError> {
    let ids = document_ids(text);
    if ids.is_empty() {
        return Ok(Vec::new());
    }
    let mut room = (MAX_LINE - ENVELOPE).saturating_sub(escaped_len(text));
    let names: Vec<String> = archive
        .file_names()
        .filter_map(|n| Some(n.ok()?.strip_prefix("files/")?.to_string()))
        .filter(|n| {
            ids.iter().any(|id| {
                n.strip_prefix(id.as_str())
                    .is_some_and(|rest| rest.is_empty() || rest.starts_with("__"))
            })
        })
        .collect();
    let mut files = Vec::new();
    for name in names {
        let mut entry = archive
            .by_name(&format!("files/{name}"))
            .map_err(ExportError::Zip)?;
        let too_large = |name: String| ExportFile {
            name,
            data: String::new(),
            too_large: true,
        };
        if entry.size() > MAX_FILE as u64 {
            files.push(too_large(name));
            continue;
        }
        let buffer = Zeroizing::new(Vec::with_capacity(entry.size() as usize));
        let Some(bytes) = bounded(&mut entry, MAX_FILE, buffer).map_err(ExportError::Io)? else {
            files.push(too_large(name));
            continue;
        };
        let need = bytes.len().div_ceil(3) * 4 + escaped_len(&name) + 32;
        if need > room {
            files.push(too_large(name));
            continue;
        }
        room -= need;
        files.push(ExportFile {
            data: data_encoding::BASE64.encode(&bytes),
            name,
            too_large: false,
        });
    }
    Ok(files)
}

/// UTF-8 text without a leading byte order mark.
fn text(mut bytes: Zeroizing<Vec<u8>>) -> Result<Zeroizing<String>, ExportError> {
    if bytes.starts_with(BOM) {
        bytes.drain(..BOM.len());
    }
    if bytes.len() > MAX_TEXT {
        return Err(ExportError::TooLarge);
    }
    if bytes.iter().all(u8::is_ascii_whitespace) {
        return Err(ExportError::Empty);
    }
    let text = match String::from_utf8(std::mem::take(&mut *bytes)) {
        Ok(text) => Zeroizing::new(text),
        Err(error) => {
            drop(Zeroizing::new(error.into_bytes()));
            return Err(ExportError::NotText);
        }
    };
    if escaped_len(&text) > MAX_LINE - ENVELOPE {
        return Err(ExportError::TooLarge);
    }
    Ok(text)
}

/// The length of `text` as a JSON string, without the quotes.
fn escaped_len(text: &str) -> usize {
    text.bytes()
        .map(|b| match b {
            b'"' | b'\\' | b'\n' | b'\r' | b'\t' | 0x08 | 0x0c => 2,
            0..0x20 => 6,
            _ => 1,
        })
        .sum()
}

#[cfg(test)]
mod tests {
    use std::io::Write;

    use zip::write::SimpleFileOptions;
    use zip::{CompressionMethod, ZipWriter};

    use super::*;

    const DATA: &str = r#"{"accounts": [{"vaults": []}]}"#;

    fn zip(entries: &[(&str, &[u8])]) -> Vec<u8> {
        let mut zip = ZipWriter::new(Cursor::new(Vec::new()));
        let options = SimpleFileOptions::default().compression_method(CompressionMethod::Deflated);
        for (name, data) in entries {
            zip.start_file(*name, options).unwrap();
            zip.write_all(data).unwrap();
        }
        zip.finish().unwrap().into_inner()
    }

    fn onepux_bytes() -> Vec<u8> {
        zip(&[
            ("export.attributes", br#"{"version": 3}"#),
            ("export.data", DATA.as_bytes()),
            ("files/abc__photo.jpg", &[0xff; 1024]),
        ])
    }

    #[test]
    fn reads_export_data_from_a_1pux() {
        assert_eq!(decode(onepux_bytes()).unwrap().text.as_str(), DATA);
        assert_eq!(
            read_from(Cursor::new(onepux_bytes()))
                .unwrap()
                .text
                .as_str(),
            DATA
        );
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("export.1pux");
        std::fs::write(&path, onepux_bytes()).unwrap();
        assert_eq!(read(&path).unwrap().text.as_str(), DATA);
    }

    /// Only the files `export.data` names come along: its attachments and
    /// documents, not icons, and none over the size cap.
    #[test]
    fn reads_the_attachments_export_data_names() {
        let data = r#"{"accounts": [{"vaults": [{"attrs": {"avatar": "avatar.png"}, "items": [
            {"details": {"documentAttributes": {"fileName": "scan.pdf", "documentId": "doc1"}}},
            {"details": {"sections": [{"fields": [{"value": {"file": {"fileName": "big.bin", "documentId": "doc2"}}}]}]}},
            {"overview": {"icons": {"detail": {"fileId": "icon1"}}}}
        ]}]}]}"#;
        let big = vec![0; MAX_FILE + 1];
        let bytes = zip(&[
            ("export.data", data.as_bytes()),
            ("files/doc1__scan.pdf", b"%PDF"),
            ("files/doc2__big.bin", &big),
            ("files/doc10__other.txt", b"not named"),
            ("files/icon1", b"icon"),
            ("files/avatar.png", b"avatar"),
        ]);
        let export = decode(bytes).unwrap();
        assert_eq!(export.text.as_str(), data);
        let files: Vec<(&str, &str, bool)> = export
            .files
            .iter()
            .map(|f| (f.name.as_str(), f.data.as_str(), f.too_large))
            .collect();
        assert_eq!(
            files,
            [
                ("doc1__scan.pdf", "JVBERg==", false),
                ("doc2__big.bin", "", true)
            ]
        );
        assert!(!format!("{:?}", export.files).contains("JVBERg"));
        assert_eq!(decode(onepux_bytes()).unwrap().files.len(), 0);
    }

    #[test]
    fn a_zip_without_export_data_is_not_a_1pux() {
        let other = zip(&[("notes.txt", b"secret-in-zip")]);
        let error = decode(other).unwrap_err();
        assert!(matches!(error, ExportError::NotOnePux), "{error:?}");
        let error = decode(b"PK\x03\x04 not really a zip".to_vec()).unwrap_err();
        assert!(matches!(error, ExportError::Zip(_)), "{error:?}");
    }

    #[test]
    fn reads_text_without_a_bom() {
        let csv = "Title,URL,Username,Password,Notes,OTPAuth\n";
        assert_eq!(
            decode([BOM, csv.as_bytes()].concat())
                .unwrap()
                .text
                .as_str(),
            csv
        );
        assert_eq!(read_from(csv.as_bytes()).unwrap().text.as_str(), csv);
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("export.csv");
        std::fs::write(&path, [BOM, csv.as_bytes()].concat()).unwrap();
        assert_eq!(read(&path).unwrap().text.as_str(), csv);
        let short = dir.path().join("short.csv");
        std::fs::write(&short, "a").unwrap();
        assert_eq!(read(&short).unwrap().text.as_str(), "a");
    }

    #[test]
    fn reads_a_pipe_as_a_stream() {
        let dir = tempfile::tempdir().unwrap();
        for (name, bytes) in [
            ("csv", b"Title,Password\nx,y\n".to_vec()),
            ("1pux", onepux_bytes()),
        ] {
            let fifo = dir.path().join(name);
            let status = std::process::Command::new("mkfifo")
                .arg(&fifo)
                .status()
                .unwrap();
            assert!(status.success());
            let writer = {
                let fifo = fifo.clone();
                let bytes = bytes.clone();
                std::thread::spawn(move || std::fs::write(fifo, bytes).unwrap())
            };
            let text = read(&fifo).unwrap();
            writer.join().unwrap();
            let expected = if name == "csv" {
                "Title,Password\nx,y\n"
            } else {
                DATA
            };
            assert_eq!(text.text.as_str(), expected);
        }
    }

    #[test]
    fn rejects_what_is_not_an_export_without_quoting_it() {
        let binary = [b"secret-bytes ".as_slice(), &[0xff, 0xfe, 0x00]].concat();
        let error = decode(binary).unwrap_err();
        assert!(matches!(error, ExportError::NotText), "{error:?}");
        assert!(!error.to_string().contains("secret"));
        assert!(matches!(decode(Vec::new()), Err(ExportError::Empty)));
        assert!(matches!(decode(b" \n".to_vec()), Err(ExportError::Empty)));
        let dir = tempfile::tempdir().unwrap();
        let missing = dir.path().join("missing.json");
        let error = read(&missing).unwrap_err();
        assert!(error.to_string().contains("missing.json"), "{error}");
    }

    #[test]
    fn limits_the_size() {
        let big = vec![b'a'; MAX_TEXT + 1];
        assert!(matches!(decode(big.clone()), Err(ExportError::TooLarge)));
        assert!(matches!(read_from(&big[..]), Err(ExportError::TooLarge)));
        let mut fits = vec![b'a'; MAX_TEXT];
        assert_eq!(decode(fits.clone()).unwrap().text.len(), MAX_TEXT);
        // Every quote doubles when escaped: the request would not fit.
        fits[..MAX_TEXT].fill(b'"');
        assert!(matches!(decode(fits), Err(ExportError::TooLarge)));
        assert_eq!(escaped_len("a\"\n\u{1}é"), 1 + 2 + 2 + 6 + 2);
    }

    #[test]
    fn grows_the_buffer_by_copying() {
        let data = vec![7; 100_000];
        let read = bounded(&data[..], 100_000, Zeroizing::new(Vec::new()))
            .unwrap()
            .unwrap();
        assert_eq!(*read, data);
        assert!(
            bounded(&data[..], 99_999, Zeroizing::new(Vec::new()))
                .unwrap()
                .is_none()
        );
    }
}
