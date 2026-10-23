//! Bundle discovery is deliberately independent of the shell's PATH.
use std::ffi::OsStr;
use std::path::{Path, PathBuf};

/// A bundle must use its own helper, even if it is missing (surface the error,
/// rather than quietly starting a different installation).
pub fn bundled(exe: &Path) -> Option<PathBuf> {
    let macos = exe.parent()?;
    let contents = macos.parent()?;
    let app = contents.parent()?;
    (macos.file_name()? == "MacOS"
        && contents.file_name()? == "Contents"
        && app.extension()? == "app")
        .then(|| contents.join("Helpers/deadbolt"))
}

pub fn discover(
    exe: Option<&Path>,
    override_bin: Option<&OsStr>,
    path: &OsStr,
    home: Option<&Path>,
) -> PathBuf {
    if let Some(binary) = exe.and_then(bundled) {
        return binary;
    }
    if let Some(binary) = override_bin.filter(|s| !s.is_empty()) {
        return binary.into();
    }
    let sibling = exe.and_then(Path::parent).map(|p| p.join("deadbolt"));
    sibling
        .into_iter()
        .chain(
            std::env::split_paths(path)
                .filter(|p| p.is_absolute())
                .map(|p| p.join("deadbolt")),
        )
        .chain(home.map(|p| p.join(".local/bin/deadbolt")))
        .chain(["/opt/homebrew/bin/deadbolt", "/usr/local/bin/deadbolt"].map(PathBuf::from))
        .find(|p| executable(p))
        .unwrap_or_else(|| "deadbolt".into())
}

pub fn executable(path: &Path) -> bool {
    use std::os::unix::fs::PermissionsExt;
    std::fs::metadata(path).is_ok_and(|m| m.is_file() && m.permissions().mode() & 0o111 != 0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    #[test]
    fn bundle_wins_even_when_missing_and_override_is_set() {
        let exe = Path::new("/Applications/Deadbolt.app/Contents/MacOS/Deadbolt");
        assert_eq!(
            discover(
                Some(exe),
                Some(OsStr::new("/other/deadbolt")),
                OsStr::new("/bin"),
                None
            ),
            Path::new("/Applications/Deadbolt.app/Contents/Helpers/deadbolt")
        );
        assert!(bundled(Path::new("/tmp/MacOS/Deadbolt")).is_none());
    }

    #[test]
    fn dev_sibling_then_path_and_explicit_override() {
        let dir = tempfile::tempdir().unwrap();
        let dev = dir.path().join("debug");
        let bin = dir.path().join("bin");
        std::fs::create_dir(&dev).unwrap();
        std::fs::create_dir(&bin).unwrap();
        let write = |p: &Path| {
            std::fs::write(p, "").unwrap();
            std::fs::set_permissions(p, std::fs::Permissions::from_mode(0o755)).unwrap();
        };
        write(&bin.join("deadbolt"));
        let exe = dev.join("deadbolt-app");
        assert_eq!(
            discover(Some(&exe), None, bin.as_os_str(), None),
            bin.join("deadbolt")
        );
        write(&dev.join("deadbolt"));
        assert_eq!(
            discover(Some(&exe), None, bin.as_os_str(), None),
            dev.join("deadbolt")
        );
        assert_eq!(
            discover(
                Some(&exe),
                Some(OsStr::new("/override")),
                bin.as_os_str(),
                None
            ),
            Path::new("/override")
        );
    }
}
