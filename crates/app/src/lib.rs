//! Deadbolt's desktop app: a thin Rune client of the running agent, over
//! the same socket protocol as the CLI. See docs/app.md.

pub mod activity;
pub mod agent;
pub mod agents;
pub mod binary;
pub mod cache;
pub mod edit;
mod enclave;
pub mod health;
pub mod import;
pub mod install;
pub mod keys;
pub mod mirror;
pub mod model;
pub mod onboarding;
pub mod palette;
pub mod panel;
mod scenes;
pub mod settings;
pub mod sheet;
pub mod shortcut;
pub mod trash;
pub mod vault;
pub mod view;
pub(crate) mod worker;

pub use scenes::{LOOPBACK_COST, MANY};
pub(crate) use scenes::{PANEL_SCENES, SCENES};

use deadbolt_client::Paths;
use rune::{AppSpec, KeyEvent, Tx, Waker};

use agent::{Agent, Job};
use model::App;
use onboarding::worker::Worker;

/// The Wayland app id and X11 `WM_CLASS`, which the desktop matches to
/// `deadbolt desktop install`'s entry of the same name.
pub const APP_ID: &str = "pw.deadbolt.Deadbolt";

pub fn spec() -> AppSpec<App> {
    AppSpec {
        title: "Deadbolt",
        size: (820.0, 540.0),
        min_size: Some((640.0, 420.0)),
        init: || App::new(Agent::offline()),
        view: view::app,
        scenes: SCENES,
        fonts: rune_theme_opencode::FONTS,
        families: rune_theme_opencode::FAMILIES,
        setup: Some(setup),
        poll: Some(|s, now, tx| s.poll(now, tx)),
        on_key: Some(|s: &mut App, ev: &KeyEvent, tx: &mut Tx| s.on_key(ev, tx)),
    }
}

/// Runs the app against this user's agent and clipboard, unless `argv` asks
/// for Rune's tooling (`--snap`, `--tree`, `--script`, `--scene`, …): those
/// runs get no agent (and Rune keeps headless runs off the clipboard), so a
/// snapshot or tree dump can never hold real vault data.
///
/// Two windows: the main one (`--window main` for tooling) and the quick
/// panel (`--window panel`), which the global shortcut (⇧⌘Space unless
/// changed in Settings) or "Open Quick Panel" in the app and Dock menus
/// brings up (off macOS, the main window's hint). `--panel` starts with the
/// panel instead of the main window. Headless runs register the default
/// shortcut on the panel virtually, so a script's `{"shortcut": …}` and
/// `{"menu": …}` steps reach it without touching the desktop.
pub fn run() {
    rune::set_app_id(APP_ID);
    let args = rune::tooling::Args::parse();
    let (live, headless) = (is_live(&args), args.headless());
    let extra = rune::extra_args();
    let reduced_motion = extra.iter().any(|a| a == "--reduced-motion");
    let panel_first = extra.iter().any(|a| a == panel::window::FLAG);
    // A headless `--desktop` run drives every window, so they can reach each
    // other as in a live run (the menus' items act on the main window).
    let wired = live || std::env::args().any(|a| a == "--desktop");
    // Started for the panel, Deadbolt runs without a Dock icon so launching
    // doesn't activate it and the app you were in keeps focus; opening the
    // main window brings the icon back (`Windows::open_main`).
    let accessory = live && panel_first;
    let shortcut_file = live.then(|| Paths::get().config.with_file_name("app-shortcut"));
    let chosen = shortcut_file
        .as_deref()
        .map_or_else(|| Some(shortcut::default()), shortcut::load);
    rune::run_windows_with(rune::RunOptions { accessory }, move |_| {
        let mut main = rune::App::new(spec()).chrome(view::CHROME);
        let mut quick = rune::App::new(panel::spec()).windowless();
        // Native menus are macOS's; headless scripts reach them everywhere.
        if cfg!(target_os = "macos") || headless {
            for item in panel::window::menu(chosen.as_ref()) {
                quick = quick.menu_item(item);
            }
        }
        let windows = panel::window::Windows::new(main.handle(), quick.handle());
        let main_windows = windows.clone();
        let quick_handle = quick.handle();
        main = main
            .init(move || {
                let mut app = if live {
                    let paths = Paths::get();
                    let launch = agent::launch();
                    let mut app = App::new(Agent::spawn(
                        paths.clone(),
                        launch.clone(),
                        agent::Window::Main,
                    ));
                    app.onboarding.worker = Worker::new(paths.clone(), launch);
                    app.installer = install::Installer::from_env(&paths);
                    if let Some(file) = shortcut_file {
                        app.hotkey = shortcut::Hotkey::live(quick_handle, file, chosen);
                    }
                    app
                } else {
                    App::new(Agent::offline())
                };
                if wired {
                    app.windows = Some(main_windows);
                }
                app.reduced_motion = reduced_motion;
                app
            })
            .on_focus(|s, focused, tx| s.main_focus(focused, tx))
            .on_close(|s, tx| s.quit(tx));
        // Registers on the panel's App and sets its menu: Rune attaches every
        // window before any queued update runs.
        if live {
            main.handle()
                .update(move |s, _| s.start_shortcut(panel_first));
        }
        let panel_windows = windows.clone();
        let mut quick = quick
            .init(move || {
                let mut app = if live {
                    App::panel(Agent::spawn(
                        Paths::get(),
                        agent::launch(),
                        agent::Window::Panel,
                    ))
                } else {
                    App::panel(Agent::offline())
                };
                if wired {
                    app.windows = Some(panel_windows);
                    if let Some(panel) = &mut app.panel {
                        panel.phase = panel::Phase::Hidden;
                    }
                }
                app.reduced_motion = reduced_motion;
                app
            })
            .on_focus(|s, focused, tx| s.panel_focus(focused, tx))
            .on_close(|s, tx| s.panel_closed(tx));
        if headless {
            quick = quick.global_shortcut(shortcut::DEFAULT, |s, tx| s.toggle_panel(tx));
        }
        // Headless too, so a `--script` with displays and a pointer shows where it's placed.
        if panel_first {
            main = windows.start_with_panel(main);
        }
        vec![
            rune::WindowSpec::from_app("main", main),
            rune::WindowSpec::from_app("panel", quick).configured_options(panel::window::options()),
        ]
    });
}

/// True for a plain windowed run: no headless output, no scene, no script.
pub fn is_live(args: &rune::tooling::Args) -> bool {
    !args.headless() && args.scene.is_none() && args.script.is_none()
}

fn setup(s: &mut App, waker: Waker) {
    s.onboarding.worker.set_waker(waker.clone());
    if let Some(installer) = &s.installer {
        installer.set_waker(waker.clone());
    }
    s.agent.set_waker(waker);
    s.agent.send(Job::Connect);
}

#[cfg(test)]
mod tests {
    use super::is_live;
    use rune::tooling::Args;

    fn live(argv: &[&str]) -> bool {
        is_live(&Args::parse_from(
            argv.iter().map(|a| a.to_string()).collect(),
        ))
    }

    #[test]
    fn tooling_runs_never_reach_the_agent() {
        for argv in [
            &["--snap", "out.png"][..],
            &["--tree", "tree.json"],
            &["--trace", "run.jsonl"],
            &["--frames", "30", "--out", "frames"],
            &["--strip", "strip.png"],
            &["--script", "s.json"],
            &["--list-scenes"],
            &["--list-windows"],
            &["--first-pixels"],
            &["--scene", "vault"],
            &["--theme", "light", "--snap", "out.png"],
        ] {
            assert!(!live(argv), "{argv:?} would connect to the agent");
        }
        assert!(live(&[]));
        assert!(live(&["--reduced-motion"]));
        assert!(live(&["--theme", "light"]));
    }
}
