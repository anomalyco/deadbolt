//! What `security-framework` doesn't wrap: a code object's signing
//! information and App Group entitlements, a file's code for this process's
//! own architecture, and validity checks with no requirement.

#![expect(
    unsafe_code,
    reason = "Security.framework calls security-framework has no safe wrapper for"
)]

use std::path::{Path, PathBuf};
use std::ptr;

use core_foundation::array::CFArray;
use core_foundation::base::{CFType, TCFType};
use core_foundation::data::CFData;
use core_foundation::dictionary::{CFDictionary, CFDictionaryRef};
use core_foundation::number::CFNumber;
use core_foundation::string::{CFString, CFStringRef};
use core_foundation::url::{CFURL, CFURLRef};
use security_framework::os::macos::code_signing::{Flags, SecCode, SecRequirement, SecStaticCode};
use security_framework_sys::base::errSecSuccess;
use security_framework_sys::code_signing::{
    SecCSFlags, SecCodeCheckValidity, SecStaticCodeCheckValidity, SecStaticCodeRef,
};

/// `kSecCSSigningInformation`.
const SIGNING_INFORMATION: SecCSFlags = 1 << 1;
/// `kSecCSRequirementInformation`, which carries the entitlements.
const REQUIREMENT_INFORMATION: SecCSFlags = 1 << 2;
/// `kSecCSDynamicInformation`.
const DYNAMIC_INFORMATION: SecCSFlags = 1 << 3;
/// `kSecCSNoNetworkAccess`: validity checks never wait on `trustd`'s online
/// revocation (OCSP) lookups, which stall offline, behind a captive portal or
/// in a sandboxed extension.
const NO_NETWORK_ACCESS: SecCSFlags = 1 << 29;

/// The architecture files are read for: this process's own, the one
/// Deadbolt's binaries run as (`CPU_TYPE_ARM64`, `CPU_TYPE_X86_64`).
#[cfg(target_arch = "aarch64")]
const OWN_ARCHITECTURE: i32 = 0x0100_000c;
#[cfg(target_arch = "x86_64")]
const OWN_ARCHITECTURE: i32 = 0x0100_0007;

#[link(name = "Security", kind = "framework")]
unsafe extern "C" {
    fn SecCodeCopySigningInformation(
        code: SecStaticCodeRef,
        flags: SecCSFlags,
        information: *mut CFDictionaryRef,
    ) -> i32;
    fn SecStaticCodeCreateWithPathAndAttributes(
        path: CFURLRef,
        flags: SecCSFlags,
        attributes: CFDictionaryRef,
        code: *mut SecStaticCodeRef,
    ) -> i32;
    safe static kSecCodeInfoIdentifier: CFStringRef;
    safe static kSecCodeInfoMainExecutable: CFStringRef;
    safe static kSecCodeInfoTeamIdentifier: CFStringRef;
    safe static kSecCodeInfoUnique: CFStringRef;
    safe static kSecCodeInfoEntitlementsDict: CFStringRef;
    safe static kSecCodeAttributeArchitecture: CFStringRef;
}

/// One of Security.framework's constant keys.
fn key(constant: CFStringRef) -> CFString {
    // SAFETY: `constant` is one of the framework's immortal CFString
    // constants, declared above, never null once the framework is linked.
    unsafe { CFString::wrap_under_get_rule(constant) }
}

mod sealed {
    pub trait Sealed {}
    impl Sealed for super::SecCode {}
    impl Sealed for super::SecStaticCode {}
}

/// A code object the signing-information call takes: running code
/// (`SecCode`) or code on disk (`SecStaticCode`).
pub trait Code: sealed::Sealed {
    #[doc(hidden)]
    fn static_ref(&self) -> SecStaticCodeRef;
}

impl Code for SecCode {
    /// Security.framework takes a `SecCode` wherever it takes a
    /// `SecStaticCode`, and answers for the running code.
    fn static_ref(&self) -> SecStaticCodeRef {
        self.as_concrete_TypeRef().cast()
    }
}

impl Code for SecStaticCode {
    fn static_ref(&self) -> SecStaticCodeRef {
        self.as_concrete_TypeRef()
    }
}

/// The fields of `SecCodeCopySigningInformation`'s answer Deadbolt reads.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SigningInformation {
    /// `kSecCodeInfoMainExecutable`: the executable, inside the bundle for
    /// an app.
    pub main_executable: Option<PathBuf>,
    /// `kSecCodeInfoIdentifier`.
    pub identifier: Option<String>,
    /// `kSecCodeInfoTeamIdentifier`, as the signature claims it, unverified.
    pub team_identifier: Option<String>,
    /// `kSecCodeInfoUnique`: the code directory hash.
    pub unique: Option<Vec<u8>>,
}

/// `code`'s signing information (`kSecCSSigningInformation`, with
/// `kSecCSDynamicInformation` when `dynamic`), or `None` when
/// Security.framework has none to give.
pub fn signing_information(code: &impl Code, dynamic: bool) -> Option<SigningInformation> {
    let mut flags = SIGNING_INFORMATION;
    if dynamic {
        flags |= DYNAMIC_INFORMATION;
    }
    let info = copy_information(code, flags)?;
    let get = |constant| info.find(key(constant));
    Some(SigningInformation {
        main_executable: get(kSecCodeInfoMainExecutable)
            .and_then(|v| v.downcast::<CFURL>())
            .and_then(|url| url.to_path()),
        identifier: get(kSecCodeInfoIdentifier)
            .and_then(|v| v.downcast::<CFString>())
            .map(|s| s.to_string()),
        team_identifier: get(kSecCodeInfoTeamIdentifier)
            .and_then(|v| v.downcast::<CFString>())
            .map(|s| s.to_string()),
        unique: get(kSecCodeInfoUnique)
            .and_then(|v| v.downcast::<CFData>())
            .map(|d| d.bytes().to_vec()),
    })
}

/// The App Groups `code`'s entitlements name
/// (`com.apple.security.application-groups`), as its signature claims them;
/// empty when it has none. Check the signature before trusting them.
pub fn application_groups(code: &impl Code, dynamic: bool) -> Vec<String> {
    let mut flags = SIGNING_INFORMATION | REQUIREMENT_INFORMATION;
    if dynamic {
        flags |= DYNAMIC_INFORMATION;
    }
    let groups = copy_information(code, flags)
        .and_then(|info| {
            info.find(key(kSecCodeInfoEntitlementsDict))?
                .downcast::<CFDictionary>()
        })
        .and_then(|entitlements| {
            // SAFETY: `entitlements` is a live dictionary (just checked by its
            // type id) of property-list values, every one a CF object; keys
            // are only compared with the CFString passed to `find`.
            let entitlements: CFDictionary<CFString, CFType> =
                unsafe { CFDictionary::wrap_under_get_rule(entitlements.as_concrete_TypeRef()) };
            let name = CFString::from_static_string("com.apple.security.application-groups");
            entitlements.find(name)?.downcast::<CFArray>()
        });
    let Some(groups) = groups else {
        return Vec::new();
    };
    // SAFETY: `groups` is a live array (just checked by its type id) of
    // property-list values, every one a CF object.
    let groups: CFArray<CFType> =
        unsafe { CFArray::wrap_under_get_rule(groups.as_concrete_TypeRef()) };
    groups
        .iter()
        .filter_map(|group| group.downcast::<CFString>())
        .map(|group| group.to_string())
        .collect()
}

/// `SecCodeCopySigningInformation` for `code` with `flags`, or `None`
/// when Security.framework has none to give.
fn copy_information(code: &impl Code, flags: SecCSFlags) -> Option<CFDictionary<CFString, CFType>> {
    let mut info: CFDictionaryRef = ptr::null();
    // SAFETY: `code` is a live code object (`Code` is sealed to the two
    // types the call takes), and `info` is a valid place for its answer.
    let status = unsafe { SecCodeCopySigningInformation(code.static_ref(), flags, &mut info) };
    if status != errSecSuccess || info.is_null() {
        return None;
    }
    // SAFETY: on success the call returns a dictionary it created (the
    // "Copy" rule), which this now owns and releases.
    Some(unsafe { CFDictionary::wrap_under_create_rule(info) })
}

/// The code at `path`, its slice for this process's architecture in a
/// universal binary; `None` when Security.framework can't read it.
pub fn file_code(path: &Path) -> Option<SecStaticCode> {
    let url = CFURL::from_path(path, false)?;
    let attributes = CFDictionary::from_CFType_pairs(&[(
        key(kSecCodeAttributeArchitecture),
        CFNumber::from(OWN_ARCHITECTURE),
    )]);
    let mut code: SecStaticCodeRef = ptr::null_mut();
    // SAFETY: `url` and `attributes` are live CF objects for the call, and
    // `code` is a valid place for its answer.
    let status = unsafe {
        SecStaticCodeCreateWithPathAndAttributes(
            url.as_concrete_TypeRef(),
            0,
            attributes.as_concrete_TypeRef(),
            &mut code,
        )
    };
    if status != errSecSuccess || code.is_null() {
        return None;
    }
    // SAFETY: on success the call returns a static code it created (the
    // "Create" rule), which this now owns and releases.
    Some(unsafe { SecStaticCode::wrap_under_create_rule(code) })
}

/// `SecCodeCheckValidity` on running `code`, without network access: its
/// signature is valid (the kernel's view of its pages and the code
/// directory's signature) and, if given, it satisfies `requirement`.
pub fn running_is_valid(code: &SecCode, requirement: Option<&SecRequirement>) -> bool {
    let requirement = requirement.map_or(ptr::null_mut(), TCFType::as_concrete_TypeRef);
    // SAFETY: `code` is a live code object, and `requirement` is a live
    // requirement or null, which asks for validity alone.
    let status =
        unsafe { SecCodeCheckValidity(code.as_concrete_TypeRef(), NO_NETWORK_ACCESS, requirement) };
    status == errSecSuccess
}

/// `SecStaticCodeCheckValidity` on `code` with `flags`, never with network
/// access, and, if given, `requirement`.
pub fn file_is_valid(
    code: &SecStaticCode,
    flags: Flags,
    requirement: Option<&SecRequirement>,
) -> bool {
    let requirement = requirement.map_or(ptr::null_mut(), TCFType::as_concrete_TypeRef);
    // SAFETY: `code` is a live static code object, and `requirement` is a
    // live requirement or null, which asks for validity alone.
    let status = unsafe {
        SecStaticCodeCheckValidity(
            code.as_concrete_TypeRef(),
            flags.bits() | NO_NETWORK_ACCESS,
            requirement,
        )
    };
    status == errSecSuccess
}

#[cfg(test)]
mod tests {
    use super::*;

    /// An Apple platform binary: signed, valid, with no team, read for this
    /// architecture out of its universal file.
    #[test]
    fn a_system_binary_reads_as_apples() {
        let code = file_code(Path::new("/bin/ls")).unwrap();
        let info = signing_information(&code, false).unwrap();
        assert_eq!(info.identifier.as_deref(), Some("com.apple.ls"));
        assert_eq!(info.team_identifier, None);
        assert_eq!(info.main_executable.as_deref(), Some(Path::new("/bin/ls")));
        assert_eq!(info.unique.map(|u| u.len()), Some(20));
        let flags = Flags::DO_NOT_VALIDATE_EXECUTABLE | Flags::DO_NOT_VALIDATE_RESOURCES;
        assert!(file_is_valid(&code, flags, None));
        let apple: SecRequirement = "anchor apple".parse().unwrap();
        assert!(file_is_valid(&code, flags, Some(&apple)));
        let never: SecRequirement = "never".parse().unwrap();
        assert!(!file_is_valid(&code, flags, Some(&never)));
    }

    /// This test binary, running: its dynamic signing information names its
    /// own file and code directory hash, the same one its file has.
    #[test]
    fn running_code_matches_its_file() {
        let me = std::env::current_exe().unwrap().canonicalize().unwrap();
        let running = SecCode::for_self(Flags::NONE).unwrap();
        let info = signing_information(&running, true).unwrap();
        assert_eq!(info.main_executable.as_deref(), Some(me.as_path()));
        assert!(running_is_valid(&running, None));
        let never: SecRequirement = "never".parse().unwrap();
        assert!(!running_is_valid(&running, Some(&never)));
        let file = signing_information(&file_code(&me).unwrap(), false).unwrap();
        assert!(info.unique.is_some());
        assert_eq!(info.unique, file.unique);
    }

    /// Notes is entitled to its own App Group; `ls` and this ad-hoc test
    /// binary to none.
    #[test]
    fn app_groups_come_from_the_entitlements() {
        let notes = Path::new("/System/Applications/Notes.app");
        if let Some(code) = file_code(notes) {
            let groups = application_groups(&code, false);
            assert!(
                groups.iter().any(|g| g == "group.com.apple.notes"),
                "{groups:?}"
            );
        }
        let ls = file_code(Path::new("/bin/ls")).unwrap();
        assert!(application_groups(&ls, false).is_empty());
        let running = SecCode::for_self(Flags::NONE).unwrap();
        assert!(application_groups(&running, true).is_empty());
    }

    #[test]
    fn a_missing_file_has_no_code() {
        let dir = tempfile::tempdir().unwrap();
        assert!(file_code(&dir.path().join("nothing")).is_none());
    }
}
