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

/// Whether `path` has the shape of a bundle's helper,
/// `<Something>.app/Contents/Helpers/deadbolt`, whether or not it exists.
pub fn is_helper(path: &Path) -> bool {
    let mut up = path.ancestors().skip(1);
    path.file_name().is_some_and(|n| n == "deadbolt")
        && up
            .next()
            .and_then(Path::file_name)
            .is_some_and(|n| n == "Helpers")
        && up
            .next()
            .and_then(Path::file_name)
            .is_some_and(|n| n == "Contents")
        && up
            .next()
            .and_then(Path::extension)
            .is_some_and(|e| e == "app")
}

/// Where commands live even when the app's PATH doesn't say so: Finder,
/// the Dock and Spotlight start apps with only `/usr/bin:/bin:/usr/sbin:/sbin`.
pub fn well_known_dirs(home: Option<&Path>) -> Vec<PathBuf> {
    let mut dirs = Vec::new();
    if let Some(home) = home {
        dirs.push(home.join(".local/bin"));
    }
    dirs.extend(["/opt/homebrew/bin", "/usr/local/bin"].map(PathBuf::from));
    if let Some(home) = home {
        dirs.push(home.join(".cargo/bin"));
    }
    dirs
}

/// PATH's absolute directories, then the well-known ones it lacks, in order.
pub fn search_dirs(path: &OsStr, home: Option<&Path>) -> Vec<PathBuf> {
    let mut dirs: Vec<PathBuf> = std::env::split_paths(path)
        .filter(|p| p.is_absolute())
        .collect();
    for dir in well_known_dirs(home) {
        if !dirs.contains(&dir) {
            dirs.push(dir);
        }
    }
    dirs
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
            search_dirs(path, home)
                .into_iter()
                .map(|p| p.join("deadbolt")),
        )
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
    fn helpers_are_recognised_by_shape_alone() {
        for helper in [
            "/Applications/Deadbolt.app/Contents/Helpers/deadbolt",
            "/Volumes/Deadbolt/Deadbolt.app/Contents/Helpers/deadbolt",
            "/gone/Deadbolt 2.app/Contents/Helpers/deadbolt",
        ] {
            assert!(is_helper(Path::new(helper)), "{helper}");
        }
        for other in [
            "/opt/homebrew/Cellar/deadbolt/1/bin/deadbolt",
            "/Applications/Deadbolt.app/Contents/MacOS/Deadbolt",
            "/Applications/Deadbolt/Contents/Helpers/deadbolt",
            "Contents/Helpers/deadbolt",
        ] {
            assert!(!is_helper(Path::new(other)), "{other}");
        }
    }

    #[test]
    fn a_finder_launch_still_searches_the_usual_places() {
        let home = Path::new("/Users/dax");
        let dirs = search_dirs(OsStr::new("/usr/bin:/bin:/usr/sbin:/sbin"), Some(home));
        for dir in [
            "/opt/homebrew/bin",
            "/usr/local/bin",
            "/Users/dax/.cargo/bin",
            "/Users/dax/.local/bin",
        ] {
            assert!(dirs.contains(&PathBuf::from(dir)), "{dir}");
        }
        assert_eq!(dirs[0], Path::new("/usr/bin"));
        let once = search_dirs(OsStr::new("/opt/homebrew/bin:relative"), Some(home));
        assert_eq!(
            once.iter()
                .filter(|d| *d == Path::new("/opt/homebrew/bin"))
                .count(),
            1
        );
        assert!(!once.contains(&PathBuf::from("relative")));
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
