use std::{
    ffi::OsString,
    fs::{self, OpenOptions},
    io::Write,
    os::unix::fs::{OpenOptionsExt, PermissionsExt, symlink},
    path::{Path, PathBuf},
    sync::atomic::{AtomicUsize, Ordering},
    time::Duration,
};
use wgfeel_store::{ManagementStore, Store};
use wgfeel_test_support::{CapturedOutput, ManagedChild, ProcessLimits, ProcessSpec};

const CONFIG: &[u8] = b"opaque configuration: NEVER_PRINT_CONFIG_SECRET";
const STATE: &[u8] = b"opaque state: NEVER_PRINT_STATE_SECRET";
const PENDING: &[u8] = b"opaque unpublished state: NEVER_PRINT_PENDING_SECRET";
static NEXT: AtomicUsize = AtomicUsize::new(0);

struct Fixture {
    root: PathBuf,
    install: PathBuf,
    config: PathBuf,
    state: PathBuf,
}
fn directory(path: &Path) {
    fs::create_dir(path).unwrap();
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
impl Fixture {
    fn new(control: &'static str) -> Self {
        let root = std::env::temp_dir().join(format!(
            "wgfeel-uninstall-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        directory(&root);
        let install = root.join("install");
        let config = root.join(format!("{control}-config"));
        let state = root.join(format!("{control}-state"));
        for path in [&install, &config, &state] {
            directory(path);
        }
        directory(&install.join("instance"));
        private_file(&config.join("config.json"), CONFIG);
        private_file(&state.join("state.json"), STATE);
        private_file(&state.join(".pending"), PENDING);
        fs::copy(env!("CARGO_BIN_EXE_wgfeel"), root.join("wgfeel")).unwrap();
        let fixture = Self {
            root,
            install,
            config,
            state,
        };
        private_file(
            &fixture.receipt(),
            &serde_json::to_vec(&fixture.receipt_value()).unwrap(),
        );
        fixture
    }
    fn receipt(&self) -> PathBuf {
        self.install.join("instance/install.json")
    }
    fn receipt_value(&self) -> serde_json::Value {
        serde_json::json!({
            "executable": null, "version": 1,
            "config_dir": self.config,
            "state_dir": self.state,
            "service": null, "resources": [],
        })
    }
    fn write_receipt(&self, value: &serde_json::Value) {
        fs::write(self.receipt(), serde_json::to_vec(value).unwrap()).unwrap();
    }
    fn run(&self, extra: &[&str]) -> CapturedOutput {
        let mut args = vec![
            "uninstall".into(),
            "--install-dir".into(),
            self.install.as_os_str().to_owned(),
        ];
        args.extend(extra.iter().map(OsString::from));
        command(args)
    }
    fn assert_data(&self) {
        assert_eq!(fs::read(self.config.join("config.json")).unwrap(), CONFIG);
        assert_eq!(fs::read(self.state.join("state.json")).unwrap(), STATE);
        assert_eq!(fs::read(self.state.join(".pending")).unwrap(), PENDING);
        assert_eq!(
            fs::read(self.root.join("wgfeel")).unwrap(),
            fs::read(env!("CARGO_BIN_EXE_wgfeel")).unwrap()
        );
    }
    fn assert_purged(&self) {
        assert!(!self.config.exists());
        assert!(!self.state.exists());
        assert_eq!(
            fs::read(self.root.join("wgfeel")).unwrap(),
            fs::read(env!("CARGO_BIN_EXE_wgfeel")).unwrap()
        );
        assert!(!self.receipt().exists());
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.root);
    }
}
fn command(args: Vec<OsString>) -> CapturedOutput {
    let output = ManagedChild::spawn(
        ProcessSpec::new(env!("CARGO_BIN_EXE_wgfeel").into(), args, vec![], None),
        ProcessLimits {
            max_stdout_bytes: 16 * 1024,
            max_stderr_bytes: 16 * 1024,
        },
    )
    .unwrap()
    .wait(Duration::from_secs(5))
    .unwrap();
    for bytes in [&output.stdout, &output.stderr] {
        let text = String::from_utf8_lossy(bytes);
        for secret in [
            "NEVER_PRINT_CONFIG_SECRET",
            "NEVER_PRINT_STATE_SECRET",
            "NEVER_PRINT_PENDING_SECRET",
            "NEVER_PRINT_RECEIPT_SECRET",
        ] {
            assert!(!text.contains(secret), "diagnostics disclosed fixture data");
        }
    }
    output
}
fn rejected(output: CapturedOutput) {
    assert!(!output.status.success());
    assert!(
        output.stdout.is_empty(),
        "invalid input emitted an executable plan"
    );
    assert!(!output.stderr.is_empty());
}

#[test]
fn help_and_default_uninstall_preserve_exact_data_and_receipt() {
    let help = command(vec!["uninstall".into(), "--help".into()]);
    assert!(help.status.success());
    assert!(String::from_utf8_lossy(&help.stdout).contains("uninstall"));
    for role in ["main", "child"] {
        let fixture = Fixture::new(role);
        let receipt = fs::read(fixture.receipt()).unwrap();
        assert!(fixture.run(&[]).status.success());
        fixture.assert_data();
        assert_eq!(fs::read(fixture.receipt()).unwrap(), receipt);
        private_file(
            &fixture.config.join("unrelated-config"),
            b"preserve unknown config",
        );
        private_file(
            &fixture.state.join("unrelated-state"),
            b"preserve unknown state",
        );
        assert!(fixture.run(&[]).status.success());
        fixture.assert_data();
        assert_eq!(
            fs::read(fixture.config.join("unrelated-config")).unwrap(),
            b"preserve unknown config"
        );
        assert_eq!(
            fs::read(fixture.state.join("unrelated-state")).unwrap(),
            b"preserve unknown state"
        );
    }
}

#[test]
fn dry_run_purge_needs_no_confirmation_and_reports_public_paths_without_mutation() {
    for role in ["main", "child"] {
        let fixture = Fixture::new(role);
        let receipt = fs::read(fixture.receipt()).unwrap();
        let output = fixture.run(&["--purge", "--dry-run"]);
        assert!(output.status.success());
        let public = String::from_utf8(output.stdout.clone()).unwrap();
        assert!(public.contains(fixture.config.to_str().unwrap()));
        assert!(public.contains(fixture.state.to_str().unwrap()));
        fixture.assert_data();
        assert_eq!(fs::read(fixture.receipt()).unwrap(), receipt);
    }
}

#[test]
fn confirmed_purge_removes_only_known_data_and_repeat_succeeds() {
    let fixture = Fixture::new("child");
    let unrelated = fixture.root.join("unrelated");
    directory(&unrelated);
    private_file(&unrelated.join("state.json"), b"unrelated state");
    for _ in 0..2 {
        assert!(
            fixture
                .run(&["--purge", "--confirm", "wgfeel"])
                .status
                .success()
        );
        fixture.assert_purged();
        assert_eq!(
            fs::read(unrelated.join("state.json")).unwrap(),
            b"unrelated state"
        );
    }
}

#[test]
fn nonterminal_confirmation_and_strict_flags_fail_without_mutation() {
    let fixture = Fixture::new("child");
    for flags in [
        vec!["--purge"],
        vec!["--purge", "--confirm", "other"],
        vec!["--confirm", "wgfeel"],
        vec!["--purge", "--confirm"],
        vec!["--purge", "--purge", "--confirm", "wgfeel"],
        vec!["--dry-run", "--dry-run"],
        vec!["--install-dir", "/tmp"],
        vec!["--unknown"],
        vec!["extra"],
        vec!["--purge", "--confirm", "wgfeel", "--confirm", "wgfeel"],
    ] {
        rejected(fixture.run(&flags));
        fixture.assert_data();
    }
    rejected(command(
        ["uninstall", "--install-dir", "relative"]
            .map(OsString::from)
            .to_vec(),
    ));
}

#[test]
fn missing_or_invalid_receipt_never_assumes_installation_ownership() {
    let mut cases = vec![b"not JSON NEVER_PRINT_RECEIPT_SECRET".to_vec()];
    let fixture = Fixture::new("main");
    let valid = fixture.receipt_value();
    for field in [
        "version",
        "resources",
        "config_dir",
        "state_dir",
        "executable",
        "service",
    ] {
        let mut value = valid.clone();
        value.as_object_mut().unwrap().remove(field);
        cases.push(serde_json::to_vec(&value).unwrap());
    }
    for (field, value) in [
        ("version", serde_json::json!(2)),
        ("version", serde_json::json!(1.0)),
        ("unknown_field", serde_json::json!(true)),
        ("config_dir", serde_json::json!(null)),
        ("state_dir", serde_json::json!("relative")),
        ("service", serde_json::json!(false)),
        ("unknown", serde_json::json!("NEVER_PRINT_RECEIPT_SECRET")),
    ] {
        let mut candidate = valid.clone();
        candidate[field] = value;
        cases.push(serde_json::to_vec(&candidate).unwrap());
    }
    let encoded = valid.to_string();
    cases.push(format!("{{\"version\":1,{}", &encoded[1..]).into_bytes());
    cases.push(vec![0xff, 0xfe]);
    for bytes in cases {
        fs::write(fixture.receipt(), &bytes).unwrap();
        rejected(fixture.run(&["--purge", "--confirm", "wgfeel", "--dry-run"]));
        fixture.assert_data();
        assert_eq!(fs::read(fixture.receipt()).unwrap(), bytes);
    }
    fs::remove_file(fixture.receipt()).unwrap();
    rejected(fixture.run(&["--purge", "--confirm", "wgfeel"]));
    fixture.assert_data();
    assert!(!fixture.receipt().exists());
}

#[test]
fn receipt_byte_limit_accepts_exact_bound_and_rejects_one_extra_byte() {
    let fixture = Fixture::new("child");
    let mut bytes = fixture.receipt_value().to_string().into_bytes();
    bytes.resize(64 * 1024, b' ');
    fs::write(fixture.receipt(), &bytes).unwrap();
    assert!(fixture.run(&["--dry-run"]).status.success());
    fixture.assert_data();
    bytes.push(b' ');
    fs::write(fixture.receipt(), &bytes).unwrap();
    rejected(fixture.run(&["--purge", "--confirm", "wgfeel"]));
    fixture.assert_data();
    assert_eq!(fs::read(fixture.receipt()).unwrap(), bytes);
}

#[test]
fn overlapping_or_non_normalized_paths_fail_before_any_purge_write() {
    for case in ["same", "nested", "install", "parent", "dot", "receipt"] {
        let fixture = Fixture::new("child");
        let mut value = fixture.receipt_value();
        match case {
            "same" => value["config_dir"] = serde_json::to_value(&fixture.state).unwrap(),
            "nested" => {
                value["state_dir"] = serde_json::to_value(fixture.config.join("child")).unwrap()
            }
            "install" => value["config_dir"] = serde_json::to_value(&fixture.install).unwrap(),
            "parent" => {
                value["config_dir"] =
                    serde_json::to_value(fixture.config.join("../gateway-config")).unwrap()
            }
            "dot" => {
                value["config_dir"] =
                    serde_json::to_value(format!("{}/.", fixture.config.display())).unwrap()
            }
            _ => {
                value["config_dir"] = serde_json::to_value(fixture.receipt()).unwrap();
            }
        }
        fixture.write_receipt(&value);
        let before = fs::read(fixture.receipt()).unwrap();
        rejected(fixture.run(&["--purge", "--confirm", "wgfeel"]));
        fixture.assert_data();
        assert_eq!(fs::read(fixture.receipt()).unwrap(), before);
    }
}

#[test]
fn unsafe_receipt_install_directory_or_symlink_ancestor_is_not_trusted() {
    for kind in [
        "receipt-mode",
        "receipt-link",
        "receipt-hardlink",
        "install-mode",
        "install-link",
        "data-link",
    ] {
        let fixture = Fixture::new("child");
        let receipt = fs::read(fixture.receipt()).unwrap();
        let mut install = fixture.install.clone();
        match kind {
            "receipt-mode" => {
                fs::set_permissions(fixture.receipt(), fs::Permissions::from_mode(0o644)).unwrap()
            }
            "receipt-link" => {
                let target = fixture.root.join("receipt-target");
                fs::rename(fixture.receipt(), &target).unwrap();
                symlink(&target, fixture.receipt()).unwrap();
            }
            "receipt-hardlink" => {
                fs::hard_link(fixture.receipt(), fixture.root.join("receipt-alias")).unwrap()
            }
            "install-mode" => {
                fs::set_permissions(&fixture.install, fs::Permissions::from_mode(0o770)).unwrap()
            }
            "install-link" => {
                install = fixture.root.join("install-alias");
                symlink(&fixture.install, &install).unwrap();
            }
            _ => {
                let alias = fixture.root.join("data-alias");
                symlink(&fixture.root, &alias).unwrap();
                let mut value = fixture.receipt_value();
                value["config_dir"] = serde_json::to_value(alias.join("gateway-config")).unwrap();
                fixture.write_receipt(&value);
            }
        }
        rejected(command(vec![
            "uninstall".into(),
            "--install-dir".into(),
            install.into_os_string(),
            "--purge".into(),
            "--confirm".into(),
            "wgfeel".into(),
        ]));
        fixture.assert_data();
        if kind != "data-link" {
            assert_eq!(fs::read(fixture.receipt()).unwrap(), receipt);
        }
    }
}

#[test]
fn unknown_entries_and_unsafe_data_objects_are_rejected_before_deleting_other_files() {
    for area in ["config", "state"] {
        for kind in [
            "unknown",
            "mode",
            "symlink",
            "hardlink",
            "fifo",
            "directory",
            "directory-mode",
        ] {
            let fixture = Fixture::new("child");
            let (base, filename) = if area == "config" {
                (&fixture.config, "config.json")
            } else {
                (&fixture.state, "state.json")
            };
            let path = base.join(filename);
            let original = fs::read(&path).unwrap();
            let outside = fixture.root.join("outside");
            private_file(&outside, &original);
            match kind {
                "unknown" => private_file(&base.join("unowned-data"), b"must not delete"),
                "mode" => fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap(),
                "directory-mode" => {
                    fs::set_permissions(base, fs::Permissions::from_mode(0o750)).unwrap()
                }
                "hardlink" => fs::hard_link(&path, fixture.root.join("data-alias")).unwrap(),
                _ => {
                    fs::remove_file(&path).unwrap();
                    match kind {
                        "symlink" => symlink(&outside, &path).unwrap(),
                        "fifo" => rustix::fs::mkfifoat(
                            rustix::fs::CWD,
                            &path,
                            rustix::fs::Mode::RUSR | rustix::fs::Mode::WUSR,
                        )
                        .unwrap(),
                        _ => directory(&path),
                    }
                }
            }
            let receipt = fs::read(fixture.receipt()).unwrap();
            if kind != "unknown" {
                rejected(fixture.run(&[]));
            }
            rejected(fixture.run(&["--purge", "--confirm", "wgfeel"]));
            assert_eq!(fs::read(&outside).unwrap(), original);
            assert!(fs::symlink_metadata(&path).is_ok());
            assert_eq!(fs::read(fixture.state.join(".pending")).unwrap(), PENDING);
            if area == "config" {
                assert_eq!(fs::read(fixture.state.join("state.json")).unwrap(), STATE);
            } else {
                assert_eq!(
                    fs::read(fixture.config.join("config.json")).unwrap(),
                    CONFIG
                );
            }
            assert_eq!(fs::read(fixture.receipt()).unwrap(), receipt);
            assert_eq!(
                fs::read(fixture.root.join("wgfeel")).unwrap(),
                fs::read(env!("CARGO_BIN_EXE_wgfeel")).unwrap()
            );
        }
    }
}

#[test]
fn live_store_lock_prevents_all_purge_writes_then_release_allows_purge() {
    for role in ["main", "child"] {
        let fixture = Fixture::new(role);
        if role == "main" {
            let lock = ManagementStore::open(&fixture.state).unwrap();
            rejected(fixture.run(&["--purge", "--confirm", "wgfeel"]));
            fixture.assert_data();
            drop(lock);
        } else {
            let lock = Store::open(&fixture.state).unwrap();
            rejected(fixture.run(&["--purge", "--confirm", "wgfeel"]));
            fixture.assert_data();
            drop(lock);
        }
        assert!(fixture.receipt().exists());
        assert!(
            fixture
                .run(&["--purge", "--confirm", "wgfeel"])
                .status
                .success()
        );
        fixture.assert_purged();
    }
}
