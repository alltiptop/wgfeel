use super::*;
use std::{
    fs,
    os::unix::fs::{PermissionsExt, symlink},
    sync::atomic::{AtomicUsize, Ordering},
};
static NEXT: AtomicUsize = AtomicUsize::new(0);

#[test]
fn unknown_options_are_rejected_by_the_existing_install_parser() {
    for extra in [vec!["--unknown"], vec!["--unknown", "value"]] {
        let args: Vec<_> = extra.into_iter().map(OsString::from).collect();
        assert!(Options::parse(&args, true).is_err());
        assert!(Options::parse(&args, false).is_err());
    }
}
struct Fixture(PathBuf);
impl Fixture {
    fn new() -> Self {
        let root = std::env::temp_dir().join(format!(
            "wgfeel-update-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&root).unwrap();
        fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
        for relative in [
            "opt/wgfeel/instance/bin",
            "etc/systemd/system",
            "usr/local/bin",
            "opt/wgfeel/instance/state",
            "opt/wgfeel/instance/config",
        ] {
            fs::create_dir_all(root.join(relative)).unwrap();
        }
        let home = root.join("opt/wgfeel/instance");
        for path in [&home, &home.join("state"), &home.join("config")] {
            fs::set_permissions(path, fs::Permissions::from_mode(0o700)).unwrap();
        }
        let binary = home.join("bin/wgfeel");
        fs::copy("/bin/true", &binary).unwrap();
        fs::set_permissions(&binary, fs::Permissions::from_mode(0o755)).unwrap();
        symlink(&binary, root.join("usr/local/bin/wgfeel")).unwrap();
        let state = home.join("state");
        let config = home.join("config");
        private(&state.join("state.json"), b"state must not change");
        private(&config.join("admin.json"), b"credential must not change");
        private(&config.join("config.json"), &serde_json::to_vec(&serde_json::json!({"control":"child","listen":"127.0.0.1:51820","endpoint":"127.0.0.1:51820"})).unwrap());
        let unit = root.join("etc/systemd/system/wgfeel.service");
        let contents =
            crate::install::unit(&binary, "child", &state, "127.0.0.1:51820".parse().unwrap());
        private(&unit, contents.as_bytes());
        let receipt = serde_json::json!({"executable":{"directory":home.join("bin"),"alias":root.join("usr/local/bin/wgfeel")},"version":1,"config_dir":config,"state_dir":state,"service":{"scope":"service","unit":{"path":unit,"contents":contents}},"resources":[]});
        private(
            &home.join("install.json"),
            &serde_json::to_vec(&receipt).unwrap(),
        );
        Self(root)
    }
    fn apply(&self, control: &mut Fake, no_start: bool) -> Result<()> {
        let installed = Installed::inspect(&self.0, Path::new("/opt/wgfeel"))?.unwrap();
        apply_from(
            &Options {
                root: self.0.clone(),
                install_dir: "/opt/wgfeel".into(),
                dry: false,
                no_start,
            },
            installed,
            control,
            fs::File::open("/proc/self/exe").unwrap(),
        )
    }
    fn binary(&self) -> Vec<u8> {
        fs::read(self.0.join("opt/wgfeel/instance/bin/wgfeel")).unwrap()
    }
    fn assert_state(&self) {
        assert_eq!(
            fs::read(self.0.join("opt/wgfeel/instance/state/state.json")).unwrap(),
            b"state must not change"
        );
        assert_eq!(
            fs::read(self.0.join("opt/wgfeel/instance/config/admin.json")).unwrap(),
            b"credential must not change"
        );
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}
fn private(path: &Path, contents: &[u8]) {
    fs::write(path, contents).unwrap();
    fs::set_permissions(path, fs::Permissions::from_mode(0o600)).unwrap();
}

#[derive(Default)]
struct Fake {
    calls: Vec<String>,
    inactive: bool,
    fail_stop: bool,
    fail_start: bool,
}
impl UpdateControl for Fake {
    fn active(&mut self, unit: &str, _: &Path) -> Result<bool> {
        self.calls.push(format!("inspect {unit}"));
        Ok(!(self.inactive && unit == "wgfeel.service"))
    }
    fn stop(&mut self, unit: &str, _: &Path) -> Result<()> {
        self.calls.push(format!("stop {unit}"));
        if self.fail_stop && unit == "wgfeel.service" {
            return Err("injected stop failure".into());
        }
        Ok(())
    }
    fn start(&mut self, unit: &str, _: &Path) -> Result<()> {
        self.calls.push(format!("start {unit}"));
        if self.fail_start && unit == "wgfeel.service" {
            return Err("injected start failure".into());
        }
        Ok(())
    }
}

#[test]
fn active_service_are_stopped_and_restarted_after_replacement() {
    let fixture = Fixture::new();
    let mut control = Fake {
        inactive: false,
        ..Fake::default()
    };
    fixture.apply(&mut control, false).unwrap();
    assert_eq!(
        control.calls,
        [
            "inspect wgfeel.service",
            "stop wgfeel.service",
            "start wgfeel.service"
        ]
    );
    assert_eq!(fixture.binary(), fs::read("/proc/self/exe").unwrap());
    fixture.assert_state();
    let mut unchanged = Fake::default();
    fixture.apply(&mut unchanged, false).unwrap();
    assert!(unchanged.calls.is_empty());
}

#[test]
fn inactive_service_is_not_started_during_update() {
    let fixture = Fixture::new();
    let mut control = Fake {
        inactive: true,
        ..Fake::default()
    };
    fixture.apply(&mut control, false).unwrap();
    assert_eq!(control.calls, ["inspect wgfeel.service"]);
    assert_eq!(fixture.binary(), fs::read("/proc/self/exe").unwrap());
    fixture.assert_state();
}

#[test]
fn stop_failure_preserves_binary_and_recovers_the_originally_active_service() {
    let fixture = Fixture::new();
    let mut control = Fake {
        fail_stop: true,
        ..Fake::default()
    };
    assert!(
        fixture
            .apply(&mut control, false)
            .unwrap_err()
            .contains("stop failure")
    );
    assert_eq!(fixture.binary(), fs::read("/bin/true").unwrap());
    assert_eq!(
        control.calls,
        [
            "inspect wgfeel.service",
            "stop wgfeel.service",
            "start wgfeel.service"
        ]
    );
    assert_eq!(
        fs::read_dir(fixture.0.join("opt/wgfeel/instance/bin"))
            .unwrap()
            .count(),
        1
    );
    fixture.assert_state();
}

#[test]
fn failed_restart_is_reported_and_previous_binary_is_retained() {
    let fixture = Fixture::new();
    let mut control = Fake {
        fail_start: true,
        ..Fake::default()
    };
    assert!(
        fixture
            .apply(&mut control, false)
            .unwrap_err()
            .contains("binary updated, but service recovery failed")
    );
    assert_eq!(control.calls.last().unwrap(), "start wgfeel.service");
    assert_eq!(fixture.binary(), fs::read("/proc/self/exe").unwrap());
    let retained = fs::read_dir(fixture.0.join("opt/wgfeel/instance/bin"))
        .unwrap()
        .find(|entry| {
            entry
                .as_ref()
                .unwrap()
                .file_name()
                .to_string_lossy()
                .starts_with("wgfeel.previous-")
        })
        .unwrap()
        .unwrap();
    assert_eq!(
        fs::read(retained.path()).unwrap(),
        fs::read("/bin/true").unwrap()
    );
    fixture.assert_state();
}

#[test]
fn no_start_refuses_a_running_foreground_instance_and_never_controls_services() {
    let fixture = Fixture::new();
    let lock = fs::File::open(fixture.0.join("opt/wgfeel/instance/state")).unwrap();
    rustix::fs::flock(&lock, rustix::fs::FlockOperation::NonBlockingLockExclusive).unwrap();
    let mut control = Fake::default();
    assert!(fixture.apply(&mut control, true).is_err());
    assert!(control.calls.is_empty());
    assert_eq!(fixture.binary(), fs::read("/bin/true").unwrap());
    assert_eq!(
        fs::read_dir(fixture.0.join("opt/wgfeel/instance/bin"))
            .unwrap()
            .count(),
        1
    );
    fixture.assert_state();
}

#[test]
fn changed_service_and_wrong_command_alias_are_refused_before_update() {
    let fixture = Fixture::new();
    let alias = fixture.0.join("usr/local/bin/wgfeel");
    fs::remove_file(&alias).unwrap();
    symlink("/bin/false", &alias).unwrap();
    let mut control = Fake::default();
    assert!(fixture.apply(&mut control, false).is_err());
    assert!(control.calls.is_empty());
    fs::remove_file(&alias).unwrap();
    symlink(fixture.0.join("opt/wgfeel/instance/bin/wgfeel"), &alias).unwrap();
    private(
        &fixture.0.join("etc/systemd/system/wgfeel.service"),
        b"foreign service",
    );
    assert!(fixture.apply(&mut control, false).is_err());
    assert!(control.calls.is_empty());
    assert_eq!(fixture.binary(), fs::read("/bin/true").unwrap());
}

#[test]
fn update_registers_new_owned_command_resources() {
    let fixture = Fixture::new();
    fixture.apply(&mut Fake::default(), true).unwrap();
    let receipt: serde_json::Value = serde_json::from_slice(
        &fs::read(fixture.0.join("opt/wgfeel/instance/install.json")).unwrap(),
    )
    .unwrap();
    assert_eq!(receipt["resources"].as_array().unwrap().len(), 3);
    for relative in [
        "man/man1/wgfeel.1",
        "bash-completion/completions/wgfeel",
        "zsh/site-functions/_wgfeel",
    ] {
        let path = fixture.0.join("usr/local/share").join(relative);
        assert_eq!(
            fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o644
        );
        assert!(!fs::read(&path).unwrap().is_empty());
    }
    fixture.assert_state();
    // Even an unchanged executable must refuse to overwrite a local manual edit.
    let manual = fixture.0.join("usr/local/share/man/man1/wgfeel.1");
    fs::write(&manual, b"local customization").unwrap();
    let mut control = Fake::default();
    assert!(fixture.apply(&mut control, false).is_err());
    assert!(control.calls.is_empty());
    assert_eq!(fs::read(manual).unwrap(), b"local customization");
}

#[test]
fn unowned_completion_file_blocks_update_before_service_or_binary_changes() {
    let fixture = Fixture::new();
    let path = fixture.0.join("usr/local/share/zsh/site-functions/_wgfeel");
    fs::create_dir_all(path.parent().unwrap()).unwrap();
    fs::write(&path, b"foreign completion").unwrap();
    let mut control = Fake::default();
    assert!(fixture.apply(&mut control, false).is_err());
    assert!(control.calls.is_empty());
    assert_eq!(fixture.binary(), fs::read("/bin/true").unwrap());
    assert_eq!(fs::read(path).unwrap(), b"foreign completion");
}

#[test]
fn unchanged_binary_still_refreshes_receipt_owned_old_documentation() {
    let fixture = Fixture::new();
    fixture.apply(&mut Fake::default(), true).unwrap();
    let path = fixture.0.join("usr/local/share/man/man1/wgfeel.1");
    let current = fs::read(&path).unwrap();
    let receipt_path = fixture.0.join("opt/wgfeel/instance/install.json");
    let mut receipt: serde_json::Value =
        serde_json::from_slice(&fs::read(&receipt_path).unwrap()).unwrap();
    receipt["resources"][0]["contents"] = serde_json::json!("previous version manual");
    fs::write(&path, "previous version manual").unwrap();
    fs::write(&receipt_path, serde_json::to_vec(&receipt).unwrap()).unwrap();
    let mut control = Fake::default();
    fixture.apply(&mut control, false).unwrap();
    assert!(control.calls.is_empty());
    assert_eq!(fs::read(path).unwrap(), current);
    fixture.assert_state();
}

#[test]
fn failed_binary_commit_restores_resources_and_original_receipt() {
    let fixture = Fixture::new();
    let receipt_path = fixture.0.join("opt/wgfeel/instance/install.json");
    let before = fs::read(&receipt_path).unwrap();
    let installed = Installed::inspect(&fixture.0, Path::new("/opt/wgfeel"))
        .unwrap()
        .unwrap();
    let resources = installed.resources(&fixture.0).unwrap();
    // Deliberately leave the executable unstaged to fail after resource writes.
    let mut binary = BinaryUpdate::inspect(
        &fixture.0.join("opt/wgfeel/instance/bin"),
        "wgfeel",
        fs::File::open("/proc/self/exe").unwrap(),
    )
    .unwrap();
    assert!(
        replace(
            &installed,
            &mut binary,
            &resources,
            &[],
            &mut Fake::default()
        )
        .unwrap_err()
        .contains("not staged")
    );
    assert_eq!(fixture.binary(), fs::read("/bin/true").unwrap());
    assert_eq!(fs::read(receipt_path).unwrap(), before);
    assert!(!fixture.0.join("usr/local/share/man/man1/wgfeel.1").exists());
    assert!(
        !fixture
            .0
            .join("usr/local/share/bash-completion/completions/wgfeel")
            .exists()
    );
    assert!(
        !fixture
            .0
            .join("usr/local/share/zsh/site-functions/_wgfeel")
            .exists()
    );
    fixture.assert_state();
}
