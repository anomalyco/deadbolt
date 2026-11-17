use super::*;

struct XdgStore<'a> {
    device: &'a Device,
    data: PathBuf,
}

impl<'a> XdgStore<'a> {
    fn new(device: &'a Device, name: &str) -> Self {
        Self {
            device,
            data: device.path(name),
        }
    }

    fn cmd(&self, args: &[&str]) -> Command {
        let mut cmd = self.device.cmd(args);
        cmd.env_remove("DEADBOLT_HOME")
            .env("XDG_DATA_HOME", &self.data);
        cmd
    }

    fn run(&self, args: &[&str]) -> String {
        let output = self.device.output(&mut self.cmd(args));
        assert!(output.status.success(), "deadbolt {args:?} failed");
        String::from_utf8(output.stdout).unwrap()
    }
}

impl Drop for XdgStore<'_> {
    fn drop(&mut self) {
        if let Err(error) = self.cmd(&["debug", "daemon", "stop"]).output() {
            eprintln!("test cleanup could not stop XDG daemon: {error}");
        }
    }
}

#[test]
fn xdg_stores_with_shared_runtime_keep_separate_daemons() {
    let device = Device::new();
    let office = XdgStore::new(&device, "office");
    let personal = XdgStore::new(&device, "personal");
    office.run(&["init"]);
    office.run(&[
        "new",
        "login",
        "--name",
        "Office",
        "username=user-office",
        "password=synthetic-office",
    ]);
    personal.run(&["init"]);
    personal.run(&[
        "new",
        "login",
        "--name",
        "Personal",
        "username=user-personal",
        "password=synthetic-personal",
    ]);

    for (store, expected) in [
        (&office, "Office\tuser-office"),
        (&personal, "Personal\tuser-personal"),
    ] {
        let items = store.run(&["ls"]);
        let labels: Vec<_> = items
            .lines()
            .map(|line| line.split_once('\t').unwrap().1)
            .collect();
        assert_eq!(labels, [expected]);
    }
    let office_status = office.run(&["debug", "daemon", "status"]);
    let personal_status = personal.run(&["debug", "daemon", "status"]);
    assert_ne!(office_status.lines().next(), personal_status.lines().next());
}

#[test]
fn explicit_home_reuses_the_xdg_store_daemon() {
    let device = Device::new();
    let store = XdgStore::new(&device, "office");
    store.run(&["init"]);
    let status = store.run(&["debug", "daemon", "status"]);
    let output = device.output(
        store
            .cmd(&["debug", "daemon", "status"])
            .env("DEADBOLT_HOME", store.data.join("deadbolt")),
    );
    assert!(output.status.success());
    assert_eq!(String::from_utf8(output.stdout).unwrap(), status);
}
