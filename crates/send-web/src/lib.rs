//! `receive(link, onProgress)` for the receive page (`site/src/receive`).
//! Built with `site/scripts/wasm.sh`; empty on other targets.
#![cfg(all(target_family = "wasm", target_os = "unknown"))]

use deadbolt_send::{Error, Network, Progress, SendTicket, receive as fetch, receiver_endpoint};
use serde::Serialize;
use wasm_bindgen::prelude::*;

#[derive(Serialize)]
struct Failure {
    kind: &'static str,
    message: String,
}

fn failure(error: &Error) -> JsValue {
    let failure = Failure {
        kind: error.kind(),
        message: error.to_string(),
    };
    serde_wasm_bindgen::to_value(&failure).unwrap_or_else(|_| JsValue::from_str(&failure.message))
}

/// Connects to the sender a link (or its fragment) points to, proves the
/// link's secret, downloads and opens the bundle. Calls `on_progress(step,
/// received, total)` with `step` one of `connecting`, `proving`, `downloading`,
/// `decrypting`. Resolves to the bundle; rejects with `{ kind, message }`
/// (see `deadbolt_send::Error::kind`).
#[wasm_bindgen]
pub async fn receive(link: String, on_progress: js_sys::Function) -> Result<JsValue, JsValue> {
    let ticket: SendTicket = link.parse().map_err(|e| failure(&e))?;
    let endpoint = receiver_endpoint(Network::Relays)
        .await
        .map_err(|e| failure(&e))?;
    let report = |progress: Progress| {
        let (step, received, total) = match progress {
            Progress::Connecting => ("connecting", 0, 0),
            Progress::Proving => ("proving", 0, 0),
            Progress::Downloading { received, total } => ("downloading", received, total),
            Progress::Decrypting => ("decrypting", 0, 0),
        };
        #[expect(
            clippy::let_underscore_must_use,
            reason = "progress is advisory; a throwing callback must not stop the download"
        )]
        let _ = on_progress.call3(
            &JsValue::NULL,
            &JsValue::from_str(step),
            &JsValue::from_f64(received as f64),
            &JsValue::from_f64(total as f64),
        );
    };
    let result = fetch(&endpoint, &ticket, report).await;
    endpoint.close().await;
    let bundle = result.map_err(|e| failure(&e))?;
    serde_wasm_bindgen::to_value(&bundle).map_err(|e| JsValue::from_str(&e.to_string()))
}
