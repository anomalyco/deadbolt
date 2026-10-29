//! Files in item fields, for clients. A file field's value is the file's
//! name, a line break, then its contents in standard base64
//! (`deadbolt_core::item::file_value`); the agent lists one as its name
//! alone unless asked for its contents (`ItemGet` with `files`). Contents
//! read or decoded here are wiped once dropped.

use std::fs::{File, OpenOptions};
use std::io::{self, Read, Write};
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};

use zeroize::Zeroizing;

/// The largest file a field holds (`deadbolt_core::item::MAX_FILE`).
pub const MAX_FILE: usize = 10 * 1024 * 1024;

#[derive(Debug, thiserror::Error)]
pub enum FileError {
    #[error("reading {}", .0.display())]
    Read(PathBuf, #[source] io::Error),
    #[error("writing {}", .0.display())]
    Write(PathBuf, #[source] io::Error),
    #[error("{} isn't a file", .0.display())]
    NotAFile(PathBuf),
    #[error("{} is larger than {} MiB, the most a file field holds", .0.display(), MAX_FILE >> 20)]
    TooLarge(PathBuf),
    #[error("the file's contents aren't here")]
    NoContents,
}

/// A file field's value for the file at `path`: its name and contents.
pub fn read(path: &Path) -> Result<Zeroizing<String>, FileError> {
    let error = |e| FileError::Read(path.into(), e);
    let name = path
        .file_name()
        .and_then(|n| n.to_str())
        .ok_or_else(|| FileError::NotAFile(path.into()))?;
    let file = File::open(path).map_err(error)?;
    let metadata = file.metadata().map_err(error)?;
    if !metadata.is_file() {
        return Err(FileError::NotAFile(path.into()));
    }
    if metadata.len() > MAX_FILE as u64 {
        return Err(FileError::TooLarge(path.into()));
    }
    let mut contents = Zeroizing::new(Vec::with_capacity(metadata.len() as usize));
    file.take(MAX_FILE as u64 + 1)
        .read_to_end(&mut contents)
        .map_err(error)?;
    if contents.len() > MAX_FILE {
        return Err(FileError::TooLarge(path.into()));
    }
    Ok(value(name, &contents))
}

/// A file field's value: `name`, a line break, `contents` in base64.
pub fn value(name: &str, contents: &[u8]) -> Zeroizing<String> {
    let mut value = Zeroizing::new(String::with_capacity(
        name.len() + 1 + contents.len().div_ceil(3) * 4,
    ));
    value.push_str(name);
    value.push('\n');
    value.push_str(&Zeroizing::new(data_encoding::BASE64.encode(contents)));
    value
}

/// A file field's name, from its value or the name alone the agent lists.
pub fn name(value: &str) -> &str {
    value.split_once('\n').map_or(value, |(name, _)| name)
}

/// Whether the value holds the file's contents, not only its name.
pub fn has_contents(value: &str) -> bool {
    value.contains('\n')
}

/// A file field's contents, decoded.
pub fn contents(value: &str) -> Result<Zeroizing<Vec<u8>>, FileError> {
    let (_, data) = value.split_once('\n').ok_or(FileError::NoContents)?;
    data_encoding::BASE64
        .decode(data.as_bytes())
        .map(Zeroizing::new)
        .map_err(|_| FileError::NoContents)
}

/// Writes a file field's contents to `path`, readable only by its owner.
pub fn write(value: &str, path: &Path) -> Result<(), FileError> {
    let contents = contents(value)?;
    let error = |e| FileError::Write(path.into(), e);
    let mut file = OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(path)
        .map_err(error)?;
    file.write_all(&contents).map_err(error)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reads_and_writes_files() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("scan.pdf");
        std::fs::write(&path, b"%PDF-1.7").unwrap();
        let value = read(&path).unwrap();
        assert_eq!(value.as_str(), "scan.pdf\nJVBERi0xLjc=");
        assert_eq!((name(&value), has_contents(&value)), ("scan.pdf", true));
        assert_eq!(name("scan.pdf"), "scan.pdf");
        let out = dir.path().join("out.pdf");
        write(&value, &out).unwrap();
        assert_eq!(std::fs::read(&out).unwrap(), b"%PDF-1.7");
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(&out).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o600);
        assert!(matches!(
            write("scan.pdf", &out),
            Err(FileError::NoContents)
        ));

        let big = dir.path().join("big.bin");
        let f = File::create(&big).unwrap();
        f.set_len(MAX_FILE as u64 + 1).unwrap();
        let error = read(&big).unwrap_err();
        assert!(matches!(error, FileError::TooLarge(_)), "{error:?}");
        assert!(error.to_string().contains("10 MiB"));
        assert!(matches!(read(dir.path()), Err(FileError::NotAFile(_))));
    }
}
