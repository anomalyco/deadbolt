//! `unlock-prompt`: the user clicked "Unlock Deadbolt" in the extension's
//! locked menu. Touch ID unlocks it when it's ready; otherwise Deadbolt's
//! own window comes forward, and the passphrase is typed there, never in
//! the browser. The extension's menu follows the `unlocked` push.

use std::os::unix::process::CommandExt;
use std::process::Stdio;

use super::protocol::{Body, Code, Refusal};
use crate::client;
use crate::paths::Paths;
use crate::protocol::{Command, ErrorCode};

/// Brings Deadbolt's window forward. Tests put a fake in its place, so no
/// test opens an app.
pub(super) type OpenApp = fn(&Paths) -> std::io::Result<()>;

/// What `unlock-prompt` does: Touch ID when it's ready, else the app (a
/// Touch ID that failed for any reason but the user cancelling it falls
/// back to the app too). Cancelled is `cancelled`, and nothing opens.
pub(super) async fn prompt(paths: &Paths, open_app: OpenApp) -> Result<Body, Refusal> {
    let status = client::ensure_running(paths).await.map_err(Refusal::from)?;
    if !status.initialized {
        return Err(Refusal {
            code: Code::Locked,
            message: "Set up Deadbolt first: run `deadbolt init`".into(),
        });
    }
    if status.unlocked {
        return Ok(Body::UnlockPrompt { app: false });
    }
    if status.touch_id_ready {
        match client::simple(paths, Command::UnlockBiometric { timeout_secs: None })
            .await
            .map_err(anyhow::Error::from)
        {
            Ok(_) => return Ok(Body::UnlockPrompt { app: false }),
            Err(error) if client::code(&error) == Some(ErrorCode::Cancelled) => {
                return Err(Refusal {
                    code: Code::Cancelled,
                    message: "Touch ID was cancelled".into(),
                });
            }
            // Reset, locked out or no finger read: the passphrase, in the app.
            Err(_) => {}
        }
    }
    open_app(paths).map_err(|error| Refusal {
        code: Code::Failed,
        message: format!("couldn't open Deadbolt: {error}"),
    })?;
    Ok(Body::UnlockPrompt { app: true })
}

/// `deadbolt app` from this binary, detached: it finds the installed app
/// (Deadbolt.app through Launch Services on macOS) and brings a running
/// one forward. Its paths are this host's, from the same environment.
pub(super) fn open_app(_paths: &Paths) -> std::io::Result<()> {
    let exe = crate::app::this_binary().map_err(std::io::Error::other)?;
    let mut child = std::process::Command::new(exe)
        .arg("app")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .process_group(0)
        .spawn()?;
    // Reaped when it exits, which it does once the app is up.
    std::thread::spawn(move || child.wait());
    Ok(())
}
