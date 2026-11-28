use super::*;
use std::{
    fs::{self, OpenOptions},
    os::unix::fs::{OpenOptionsExt, PermissionsExt},
    sync::atomic::{AtomicUsize, Ordering},
};

const CONFIG: &[u8] = b"configuration SECRET_CONFIG_MUST_REMAIN_PRIVATE";
const STATE: &[u8] = b"state SECRET_STATE_MUST_REMAIN_PRIVATE";
const PENDING: &[u8] = b"pending SECRET_PENDING_MUST_REMAIN_PRIVATE";
static NEXT: AtomicUsize = AtomicUsize::new(0);

struct Fixture {
    root: PathBuf,
    install: PathBuf,
}
fn directory(path: &Path) {
    fs::create_dir_all(path).unwrap();
    fs::set_permissions(path, fs::Permissions::from_mode(0o700)).unwrap();
}
fn private_file(path: &Path, bytes: &[u8]) {
    let mut file = OpenOptions::new()
        .create_new(true)
        .write(true)
        .mode(0o600)
        .open(path)
        .unwrap();
    file.write_all(bytes).unwrap();
}
fn executable(path: &Path) {
    fs::copy("/proc/self/exe", path).unwrap();
}
impl Fixture {
    fn new() -> Self {
        let root = std::env::temp_dir().join(format!(
            "wgfeel-uninstall-operation-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        directory(&root);
        let install = root.join("receipts");
        directory(&install.join("instance"));
        directory(&root.join("units"));
        let fixture = Self { root, install };
        directory(&fixture.config());
        directory(&fixture.state());
        private_file(&fixture.config().join("config.json"), CONFIG);
        private_file(&fixture.state().join("state.json"), STATE);
        private_file(&fixture.state().join(".pending"), PENDING);
        let artifacts = fixture.artifacts();
        for (path, contents) in &artifacts {
            private_file(path, contents.as_bytes());
        }
        let receipt = serde_json::json!({"executable": null, "version": 1, "config_dir": fixture.config(), "state_dir": fixture.state(), "service": {"scope": "service", "unit": {"path": artifacts[0].0, "contents": artifacts[0].1}}, "resources": []});
        private_file(&fixture.receipt(), &serde_json::to_vec(&receipt).unwrap());
        executable(&fixture.root.join("wgfeel"));
        fixture
    }
    fn config(&self) -> PathBuf {
        self.install.join("instance/config")
    }
    fn state(&self) -> PathBuf {
        self.install.join("instance/state")
    }
    fn receipt(&self) -> PathBuf {
        self.install.join("instance/install.json")
    }
    fn artifacts(&self) -> [(PathBuf, String); 1] {
        [(self.root.join("units/wgfeel.service"), "[Unit]\nDescription=wgfeel\n[Service]\nExecStart=/owned/wgfeel serve --control child\n[Install]\nWantedBy=multi-user.target\n".into())]
    }
    fn options(&self, purge: bool, dry_run: bool) -> Options {
        Options {
            install_dir: self.install.join("instance"),
            dry_run,
            purge,
            confirmed: purge,
        }
    }
    fn assert_data(&self) {
        assert_eq!(fs::read(self.config().join("config.json")).unwrap(), CONFIG);
        assert_eq!(fs::read(self.state().join("state.json")).unwrap(), STATE);
        assert_eq!(fs::read(self.state().join(".pending")).unwrap(), PENDING);
    }
    fn assert_artifacts(&self, present: bool) {
        for (path, contents) in self.artifacts() {
            if present {
                assert_eq!(fs::read(path).unwrap(), contents.as_bytes());
            } else {
                assert!(!path.exists());
            }
        }
    }
    fn assert_download(&self) {
        assert_eq!(
            fs::read(self.root.join("wgfeel")).unwrap(),
            fs::read("/proc/self/exe").unwrap()
        );
    }
    fn control(&self) -> FakeControl {
        FakeControl {
            unit: self.artifacts()[0].0.clone(),
            calls: vec![],
            fail: None,
            after_stop: None,
        }
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.root);
    }
}

#[test]
fn invalid_uninstall_arguments_are_rejected_before_preparing_a_plan() {
    for flags in [
        vec!["--confirm", "wgfeel"],
        vec!["--purge", "--confirm"],
        vec!["--purge", "--purge", "--confirm", "wgfeel"],
        vec!["--dry-run", "--dry-run"],
        vec!["--install-dir", "/tmp/one", "--install-dir", "/tmp/two"],
        vec!["--install-dir", "relative"],
        vec!["--unknown"],
        vec!["extra"],
        vec!["--purge", "--confirm", "wgfeel", "--confirm", "wgfeel"],
    ] {
        let args: Vec<_> = flags.iter().map(OsString::from).collect();
        assert!(Options::parse(&args).is_err(), "{flags:?}");
    }
}

#[test]
fn uninstall_removes_only_its_owned_manual_and_shell_adapters() {
    let fixture = Fixture::new();
    let mut receipt: serde_json::Value =
        serde_json::from_slice(&fs::read(fixture.receipt()).unwrap()).unwrap();
    let unit = fixture.root.join("etc/systemd/system/wgfeel.service");
    fs::create_dir_all(unit.parent().unwrap()).unwrap();
    fs::rename(&fixture.artifacts()[0].0, &unit).unwrap();
    receipt["service"]["unit"]["path"] = serde_json::json!(unit);
    let mut installed = Vec::new();
    let mut records = Vec::new();
    for (relative, contents) in crate::help::resources() {
        let path = fixture.root.join("usr/local/share").join(relative);
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(&path, &contents).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
        records.push(serde_json::json!({"path":path,"contents":contents}));
        installed.push(path);
    }
    let unrelated = fixture.root.join("usr/local/share/man/man1/other.1");
    fs::write(&unrelated, "unrelated manual").unwrap();
    receipt["resources"] = serde_json::json!(records);
    fs::write(fixture.receipt(), serde_json::to_vec(&receipt).unwrap()).unwrap();
    let mut control = fixture.control();
    control.unit = unit;
    let options = fixture.options(false, false);
    Prepared::new(&options)
        .unwrap()
        .apply(&options, &mut control)
        .unwrap();
    for path in installed {
        assert!(!path.exists());
    }
    assert_eq!(fs::read_to_string(unrelated).unwrap(), "unrelated manual");
    fixture.assert_data();
    let receipt: serde_json::Value =
        serde_json::from_slice(&fs::read(fixture.receipt()).unwrap()).unwrap();
    assert_eq!(receipt["resources"], serde_json::json!([]));
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Call {
    Stop { file_present: bool },
    Reload,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Failure {
    Stop,
    Reload,
}
struct FakeControl {
    unit: PathBuf,
    calls: Vec<Call>,
    fail: Option<Failure>,
    after_stop: Option<Box<dyn FnMut()>>,
}
impl ServiceControl for FakeControl {
    fn stop_service(
        &mut self,
        scope: &str,
        unit: &str,
        path: &Path,
        file_present: bool,
    ) -> Result<()> {
        assert_eq!(scope, "service");
        assert_eq!(unit, "wgfeel.service");
        assert_eq!(path, self.unit);
        assert_eq!(file_present, self.unit.exists());
        self.calls.push(Call::Stop { file_present });
        if self.fail == Some(Failure::Stop) {
            return Err("injected stop or disable failure".into());
        }
        if let Some(hook) = &mut self.after_stop {
            hook();
        }
        Ok(())
    }
    fn reload(&mut self, scope: &str) -> Result<()> {
        assert_eq!(scope, "service");
        self.calls.push(Call::Reload);
        assert!(
            !self.unit.exists(),
            "reload preceded removal of the owned unit"
        );
        if self.fail == Some(Failure::Reload) {
            return Err("injected reload failure".into());
        }
        Ok(())
    }
}
fn execute(_fixture: &Fixture, options: &Options, control: &mut FakeControl) -> Result<()> {
    let mut prepared = Prepared::new(options)?;
    prepared.apply(options, control)
}

#[test]
fn common_installation_removal_preserves_state_until_explicit_purge() {
    let root = std::env::temp_dir().join(format!(
        "wgfeel-common-removal-{}-{}",
        std::process::id(),
        NEXT.fetch_add(1, Ordering::Relaxed)
    ));
    directory(&root);
    let fixture = Fixture {
        install: root.join("opt/wgfeel"),
        root,
    };
    crate::install::run(
        &[
            "--control".into(),
            "child".into(),
            "--root".into(),
            fixture.root.clone().into_os_string(),
            "--no-start".into(),
            "--endpoint".into(),
            "192.0.2.1".into(),
        ],
        |_, _| Err("main provisioning must not run"),
    )
    .unwrap();
    let options = Options::parse(&[
        "--install-dir".into(),
        fixture.install.clone().into_os_string(),
    ])
    .unwrap();
    let state = fixture.state().join("state.json");
    let before = fs::read(&state).unwrap();
    let mut control = FakeControl {
        unit: fixture.root.join("etc/systemd/system/wgfeel.service"),
        calls: vec![],
        fail: None,
        after_stop: None,
    };
    execute(&fixture, &options, &mut control).unwrap();
    assert_eq!(
        control.calls,
        [Call::Stop { file_present: true }, Call::Reload]
    );
    assert_eq!(fs::read(state).unwrap(), before);
    assert!(!fixture.install.join("instance/bin").exists());
    assert!(fs::symlink_metadata(fixture.root.join("usr/local/bin/wgfeel")).is_err());
    for (relative, _) in crate::help::resources() {
        assert!(!fixture.root.join("usr/local/share").join(relative).exists());
    }
    let purge = Options::parse(&[
        "--install-dir".into(),
        fixture.install.clone().into_os_string(),
        "--purge".into(),
        "--confirm".into(),
        "wgfeel".into(),
    ])
    .unwrap();
    control.calls.clear();
    execute(&fixture, &purge, &mut control).unwrap();
    assert!(control.calls.is_empty());
    assert!(!fixture.install.join("instance").exists());
}

#[test]
fn default_removes_only_recorded_artifacts_after_service_shutdown_and_preserves_data() {
    {
        let fixture = Fixture::new();
        let mut control = fixture.control();
        execute(&fixture, &fixture.options(false, false), &mut control).unwrap();
        assert_eq!(
            control.calls,
            [Call::Stop { file_present: true }, Call::Reload]
        );
        fixture.assert_artifacts(false);
        fixture.assert_data();
        fixture.assert_download();
        assert!(fixture.receipt().exists());
    }
}

#[test]
fn dry_run_purge_calls_no_control_and_keeps_data_and_recorded_contents() {
    let fixture = Fixture::new();
    let options = fixture.options(true, true);
    let mut prepared = Prepared::new(&options).unwrap();
    let public = prepared.plan(&options).to_string();
    for secret in [
        "SECRET_CONFIG_MUST_REMAIN_PRIVATE",
        "SECRET_STATE_MUST_REMAIN_PRIVATE",
        "SECRET_PENDING_MUST_REMAIN_PRIVATE",
        "ExecStart=",
    ] {
        assert!(!public.contains(secret));
    }
    let mut control = fixture.control();
    prepared.apply(&options, &mut control).unwrap();
    assert!(control.calls.is_empty());
    fixture.assert_artifacts(true);
    fixture.assert_data();
    fixture.assert_download();
}

#[test]
fn changed_artifact_or_unsafe_data_is_rejected_before_any_service_control() {
    for index in 0..2 {
        let fixture = Fixture::new();
        if index < 1 {
            fs::write(&fixture.artifacts()[index].0, b"locally modified artifact").unwrap();
        } else {
            private_file(&fixture.state().join("unknown-file"), b"unowned data");
        }
        let mut control = fixture.control();
        assert!(execute(&fixture, &fixture.options(true, false), &mut control).is_err());
        assert!(control.calls.is_empty());
        for (at, (path, contents)) in fixture.artifacts().into_iter().enumerate() {
            assert_eq!(
                fs::read(path).unwrap(),
                if at == index {
                    b"locally modified artifact".as_slice()
                } else {
                    contents.as_bytes()
                }
            );
        }
        fixture.assert_data();
        fixture.assert_download();
    }
}

#[test]
fn shutdown_or_reload_error_preserves_data_and_retry_handles_already_removed_artifacts() {
    for failure in [Failure::Stop, Failure::Reload] {
        let fixture = Fixture::new();
        let receipt = fs::read(fixture.receipt()).unwrap();
        let options = fixture.options(true, false);
        let mut control = fixture.control();
        control.fail = Some(failure);
        assert!(execute(&fixture, &options, &mut control).is_err());
        let mut expected = vec![Call::Stop { file_present: true }];
        if failure == Failure::Reload {
            expected.push(Call::Reload);
        }
        assert_eq!(control.calls, expected);
        fixture.assert_data();
        fixture.assert_artifacts(failure != Failure::Reload);
        fixture.assert_download();
        assert_eq!(fs::read(fixture.receipt()).unwrap(), receipt);
        let mut retry = fixture.control();
        execute(&fixture, &options, &mut retry).unwrap();
        assert_eq!(
            retry.calls,
            [
                Call::Stop {
                    file_present: failure != Failure::Reload
                },
                Call::Reload
            ]
        );
        assert!(!fixture.config().exists());
        assert!(!fixture.state().exists());
        fixture.assert_artifacts(false);
        fixture.assert_download();
        assert!(!fixture.receipt().exists());
    }
}

#[test]
fn retained_live_state_lock_stops_purge_before_any_artifact_or_data_write() {
    let fixture = Fixture::new();
    let lock = wgfeel_store::Store::open(&fixture.state()).unwrap();
    let options = fixture.options(true, false);
    let mut control = fixture.control();
    assert!(execute(&fixture, &options, &mut control).is_err());
    assert_eq!(control.calls, [Call::Stop { file_present: true }]);
    fixture.assert_artifacts(true);
    fixture.assert_data();
    fixture.assert_download();
    drop(lock);
    let mut retry = fixture.control();
    execute(&fixture, &options, &mut retry).unwrap();
    assert!(!fixture.config().exists());
    assert!(!fixture.state().exists());
    fixture.assert_download();
}

#[test]
fn artifact_changed_during_shutdown_is_rechecked_before_the_first_removal() {
    let fixture = Fixture::new();
    let changed = fixture.artifacts()[0].0.clone();
    let mut control = fixture.control();
    control.after_stop = Some(Box::new(move || {
        fs::write(&changed, b"changed during service stop").unwrap()
    }));
    assert!(execute(&fixture, &fixture.options(true, false), &mut control).is_err());
    assert_eq!(control.calls, [Call::Stop { file_present: true }]);
    for (index, (path, contents)) in fixture.artifacts().into_iter().enumerate() {
        assert_eq!(
            fs::read(path).unwrap(),
            if index == 0 {
                b"changed during service stop".as_slice()
            } else {
                contents.as_bytes()
            }
        );
    }
    fixture.assert_data();
    fixture.assert_download();
}

#[test]
fn complete_service_purge_removes_instance_and_ownership_receipt() {
    {
        let fixture = Fixture::new();
        let options = fixture.options(true, false);
        {
            let present = true;
            let mut control = fixture.control();
            execute(&fixture, &options, &mut control).unwrap();
            assert_eq!(
                control.calls,
                [
                    Call::Stop {
                        file_present: present
                    },
                    Call::Reload
                ]
            );
            assert!(!fixture.config().exists());
            assert!(!fixture.state().exists());
            fixture.assert_artifacts(false);
            fixture.assert_download();
            assert!(!fixture.receipt().exists());
        }
    }
}

#[test]
fn foreign_unit_alias_is_rejected_before_service_control_or_file_changes() {
    let fixture = Fixture::new();
    let unit = fixture.artifacts()[0].0.clone();
    let mut contents = fs::read_to_string(&unit).unwrap();
    contents.push_str("Alias=other.service\n");
    fs::write(&unit, &contents).unwrap();
    let mut receipt: serde_json::Value =
        serde_json::from_slice(&fs::read(fixture.receipt()).unwrap()).unwrap();
    receipt["service"]["unit"]["contents"] = contents.clone().into();
    let receipt_bytes = serde_json::to_vec(&receipt).unwrap();
    fs::write(fixture.receipt(), &receipt_bytes).unwrap();
    let mut control = fixture.control();
    assert!(execute(&fixture, &fixture.options(true, false), &mut control).is_err());
    assert!(control.calls.is_empty());
    assert_eq!(fs::read(&unit).unwrap(), contents.as_bytes());
    assert_eq!(fs::read(fixture.receipt()).unwrap(), receipt_bytes);
    for (path, recorded) in fixture.artifacts().into_iter().skip(1) {
        assert_eq!(fs::read(path).unwrap(), recorded.as_bytes());
    }
    fixture.assert_data();
    fixture.assert_download();
}

#[test]
fn shutdown_atomic_state_replacement_is_purged_on_the_first_attempt_after_lock() {
    let fixture = Fixture::new();
    let state = fixture.state();
    let mut control = fixture.control();
    control.after_stop = Some(Box::new(move || {
        let replacement = state.join("shutdown-snapshot");
        private_file(&replacement, b"snapshot written during shutdown");
        fs::rename(replacement, state.join("state.json")).unwrap();
    }));
    execute(&fixture, &fixture.options(true, false), &mut control).unwrap();
    assert_eq!(
        control.calls,
        [Call::Stop { file_present: true }, Call::Reload]
    );
    assert!(!fixture.config().exists());
    assert!(!fixture.state().exists());
    fixture.assert_artifacts(false);
    fixture.assert_download();
    assert!(!fixture.receipt().exists());
}

#[test]
fn uninstall_removes_owned_executable_backups_and_alias_but_keeps_download() {
    for purge in [false, true] {
        let fixture = Fixture::new();
        let bin = fixture.install.join("instance").join("bin");
        directory(&bin);
        executable(&bin.join("wgfeel"));
        executable(&bin.join("wgfeel.previous-0123456789abcdef"));
        let alias = fixture.root.join("command/wgfeel");
        directory(alias.parent().unwrap());
        std::os::unix::fs::symlink(bin.join("wgfeel"), &alias).unwrap();
        let mut receipt: serde_json::Value =
            serde_json::from_slice(&fs::read(fixture.receipt()).unwrap()).unwrap();
        receipt["executable"] = serde_json::json!({"directory":bin, "alias":alias});
        fs::write(fixture.receipt(), serde_json::to_vec(&receipt).unwrap()).unwrap();
        execute(
            &fixture,
            &fixture.options(purge, false),
            &mut fixture.control(),
        )
        .unwrap();
        assert!(!bin.exists());
        assert!(fs::symlink_metadata(&alias).is_err());
        fixture.assert_download();
        if purge {
            assert!(!fixture.receipt().exists());
        } else {
            fixture.assert_data();
            let mut control = fixture.control();
            execute(&fixture, &fixture.options(true, false), &mut control).unwrap();
            assert!(control.calls.is_empty());
        }
        assert!(!fixture.install.join("instance").exists());
    }
}

#[test]
fn stale_manager_socket_is_removed_only_after_state_lock_is_available() {
    let fixture = Fixture::new();
    let socket = fixture.state().join("api.sock");
    let listener = std::os::unix::net::UnixListener::bind(&socket).unwrap();
    fs::set_permissions(&socket, fs::Permissions::from_mode(0o600)).unwrap();
    drop(listener);
    execute(
        &fixture,
        &fixture.options(true, false),
        &mut fixture.control(),
    )
    .unwrap();
    assert!(!socket.exists());
    assert!(!fixture.install.join("instance").exists());
    fixture.assert_download();
}

#[test]
fn foreign_alias_or_unknown_executable_blocks_removal_before_service_stop() {
    for foreign_alias in [true, false] {
        let fixture = Fixture::new();
        let bin = fixture.install.join("instance/bin");
        directory(&bin);
        executable(&bin.join("wgfeel"));
        let alias = fixture.root.join("command/wgfeel");
        directory(alias.parent().unwrap());
        std::os::unix::fs::symlink(
            if foreign_alias {
                fixture.root.join("wgfeel")
            } else {
                bin.join("wgfeel")
            },
            &alias,
        )
        .unwrap();
        if !foreign_alias {
            private_file(&bin.join("unrelated"), b"must not remove");
        }
        let mut receipt: serde_json::Value =
            serde_json::from_slice(&fs::read(fixture.receipt()).unwrap()).unwrap();
        receipt["executable"] = serde_json::json!({"directory":bin,"alias":alias});
        fs::write(fixture.receipt(), serde_json::to_vec(&receipt).unwrap()).unwrap();
        let mut control = fixture.control();
        assert!(execute(&fixture, &fixture.options(false, false), &mut control).is_err());
        assert!(control.calls.is_empty());
        assert!(bin.join("wgfeel").exists());
        fixture.assert_data();
        fixture.assert_download();
    }
}
