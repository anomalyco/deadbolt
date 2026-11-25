//! `deadbolt-ui`, Deadbolt's desktop app: a client of the daemon the
//! headless `deadbolt` runs (docs/app.md). It takes Rune's flags (`--scene`,
//! `--snap`, `--list-scenes`, `--theme`, `--panel`, …). Deadbolt.app's
//! `Contents/MacOS/Deadbolt` is this program; `deadbolt app` and
//! `deadbolt ui` find and start it.

/// Counts the heap in dev builds, so `procwatch`'s lines say how much of
/// the footprint is Rust's own.
#[cfg(debug_assertions)]
#[global_allocator]
static ALLOC: procwatch::alloc::Counting = procwatch::alloc::Counting::system();

fn main() {
    use deadbolt_client::telemetry;
    // Traces to a local OpenTelemetry collector, only when asked for.
    let endpoint = std::env::var_os("OTEL_EXPORTER_OTLP_ENDPOINT");
    telemetry::start(
        "deadbolt-ui",
        env!("CARGO_PKG_VERSION"),
        endpoint
            .as_deref()
            .and_then(|e| e.to_str())
            .and_then(telemetry::endpoint),
    );
    let argv = std::env::args_os()
        .skip(1)
        .map(|a| a.to_string_lossy().into_owned())
        .collect();
    deadbolt_app::run(argv);
    telemetry::flush();
}
