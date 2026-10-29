//! A redb backend for an exclusive OPFS sync access handle in a dedicated worker.

#[cfg(target_feature = "atomics")]
compile_error!("the OPFS backend must run in a single-threaded dedicated worker");

use std::io;
use std::ops::Bound;

use redb::{BackendError, StorageBackend};
use wasm_bindgen::prelude::*;

// JS owns the handles so the backend contains only an opaque integer, not a
// JsValue with false Send/Sync promises. All calls stay in the creating worker;
// an id is meaningless in another worker. No wasm threads or shared memory.
#[wasm_bindgen(inline_js = r#"
const handles = new Map();
const owned = new WeakSet();
let nextId = 1;
function get(id) {
    const handle = handles.get(id);
    if (!handle) throw new Error("OPFS backend is closed or belongs to another worker");
    return handle;
}
function position(value) {
    const number = Number(value);
    if (!Number.isSafeInteger(number) || number < 0) throw new Error("OPFS offset out of range");
    return number;
}
export function opfs_take(handle) {
    if (typeof FileSystemSyncAccessHandle === "undefined" ||
        !(handle instanceof FileSystemSyncAccessHandle) || handle.mode !== "readwrite") {
        throw new Error("an exclusive OPFS sync access handle is required in a dedicated worker");
    }
    if (owned.has(handle)) throw new Error("OPFS handle already belongs to a backend");
    handle.getSize(); // Reject a closed handle before taking ownership.
    if (nextId > 0xffffffff) throw new Error("OPFS backend ids exhausted");
    const id = nextId++;
    owned.add(handle);
    handles.set(id, handle);
    return id;
}
export function opfs_len(id) { return BigInt(get(id).getSize()); }
export function opfs_read(id, offset, out) {
    if (get(id).read(out, { at: position(offset) }) !== out.length) {
        throw new Error("short OPFS read");
    }
}
export function opfs_write(id, offset, data) {
    if (get(id).write(data, { at: position(offset) }) !== data.length) {
        throw new Error("short OPFS write");
    }
}
export function opfs_truncate(id, len) { get(id).truncate(position(len)); }
export function opfs_flush(id) { get(id).flush(); }
export function opfs_close(id) {
    const handle = handles.get(id);
    if (handle) {
        handle.close();
        handles.delete(id);
    }
}
"#)]
extern "C" {
    #[wasm_bindgen(catch)]
    fn opfs_take(handle: JsValue) -> Result<u32, JsValue>;
    #[wasm_bindgen(catch)]
    fn opfs_len(id: u32) -> Result<u64, JsValue>;
    #[wasm_bindgen(catch)]
    fn opfs_read(id: u32, offset: u64, out: &mut [u8]) -> Result<(), JsValue>;
    #[wasm_bindgen(catch)]
    fn opfs_write(id: u32, offset: u64, data: &[u8]) -> Result<(), JsValue>;
    #[wasm_bindgen(catch)]
    fn opfs_truncate(id: u32, len: u64) -> Result<(), JsValue>;
    #[wasm_bindgen(catch)]
    fn opfs_flush(id: u32) -> Result<(), JsValue>;
    #[wasm_bindgen(catch)]
    fn opfs_close(id: u32) -> Result<(), JsValue>;
}

/// An exclusive OPFS file owned by redb. Obtain its handle in a dedicated worker:
/// `await file.createSyncAccessHandle()` (the default `readwrite` mode).
/// Pass it to [`Self::new`], then [`crate::init_with_backend`] or
/// [`crate::unlock_with_backend`]. Only ciphertext reaches this adapter.
///
/// Ownership transfers on successful construction: the caller must not use or
/// close the JS handle again. This adapter closes it on drop, including failed
/// initialization and wrong-passphrase errors. Do not transfer an open backend
/// or store between workers. OPFS enforces the exclusive lock across workers
/// and tabs; redb keeps it until the backend is closed.
#[derive(Debug)]
pub struct OpfsBackend {
    id: u32,
}

impl OpfsBackend {
    pub fn new(handle: JsValue) -> io::Result<Self> {
        Ok(Self {
            id: opfs_take(handle).map_err(js_error)?,
        })
    }
}

fn js_error(_error: JsValue) -> io::Error {
    // Browser exception text may contain caller-controlled strings. Keep the
    // storage boundary's error free of values and JS objects.
    io::Error::other("OPFS operation failed")
}

fn whole_file(start: Bound<u64>, end: Bound<u64>) -> bool {
    matches!(start, Bound::Unbounded | Bound::Included(0)) && end == Bound::Unbounded
}

impl StorageBackend for OpfsBackend {
    fn len(&self) -> io::Result<u64> {
        opfs_len(self.id).map_err(js_error)
    }

    fn read(&self, offset: u64, out: &mut [u8]) -> io::Result<()> {
        opfs_read(self.id, offset, out).map_err(js_error)
    }

    fn set_len(&self, len: u64) -> io::Result<()> {
        opfs_truncate(self.id, len).map_err(js_error)
    }

    fn sync_data(&self) -> io::Result<()> {
        opfs_flush(self.id).map_err(js_error)
    }

    fn write(&self, offset: u64, data: &[u8]) -> io::Result<()> {
        opfs_write(self.id, offset, data).map_err(js_error)
    }

    fn close(&self) -> io::Result<()> {
        opfs_close(self.id).map_err(js_error)
    }

    fn try_lock_range(&self, start: Bound<u64>, end: Bound<u64>) -> Result<bool, BackendError> {
        if !whole_file(start, end) {
            return Err(BackendError::Unsupported);
        }
        // createSyncAccessHandle already acquired this exclusive lock.
        self.len()?;
        Ok(true)
    }

    fn unlock_range(&self, start: Bound<u64>, end: Bound<u64>) -> Result<(), BackendError> {
        if whole_file(start, end) {
            // OPFS cannot unlock without closing. Retain the stronger lock
            // until close(), after redb has finished touching the file.
            Ok(())
        } else {
            Err(BackendError::Unsupported)
        }
    }
}

impl Drop for OpfsBackend {
    fn drop(&mut self) {
        #[expect(
            clippy::let_underscore_must_use,
            reason = "best-effort close on drop; redb also calls the fallible close method"
        )]
        let _ = self.close();
    }
}
