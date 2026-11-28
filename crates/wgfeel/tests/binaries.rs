#![cfg(target_os = "linux")]
use std::{os::unix::process::CommandExt, process::Command};

#[test]
fn no_arguments_show_help_and_unknown_commands_point_to_it() {
    let binary = env!("CARGO_BIN_EXE_wgfeel");
    let root = Command::new(binary).output().unwrap();
    let help = Command::new(binary).arg("--help").output().unwrap();
    assert!(root.status.success() && help.status.success());
    assert_eq!(root.stdout, help.stdout);
    let overview = String::from_utf8(root.stdout).unwrap();
    assert!(overview.contains("node") && overview.contains("join"));
    assert!(!overview.contains("wgfeel node add ["), "{overview}");
    let unknown = Command::new(binary)
        .arg("unknown-command")
        .output()
        .unwrap();
    assert!(!unknown.status.success());
    assert!(
        String::from_utf8(unknown.stderr)
            .unwrap()
            .contains("wgfeel --help")
    );
}

#[test]
fn common_executable_exposes_both_capabilities_without_filename_dispatch() {
    for (command, description) in [
        ("init", "--control main|child"),
        ("serve", "--control main|child"),
        ("join", "INVITATION"),
    ] {
        let output = Command::new(env!("CARGO_BIN_EXE_wgfeel"))
            .arg0("arbitrary-download-name")
            .args([command, "--help"])
            .output()
            .unwrap();
        assert!(output.status.success(), "{command} help failed");
        let help = String::from_utf8(output.stdout).unwrap();
        assert!(help.contains(description), "{command} lacks {description}");
    }
    for args in [
        vec!["serve", "--control", "leader"],
        vec!["serve", "--control", "child", "--control", "main"],
        vec!["init", "--control", "child", "--api-port", "8080"],
    ] {
        let output = Command::new(env!("CARGO_BIN_EXE_wgfeel"))
            .args(args)
            .output()
            .unwrap();
        assert!(!output.status.success());
    }
}

#[test]
fn binary_identity_does_not_depend_on_filename_or_argv_zero() {
    let output = Command::new(env!("CARGO_BIN_EXE_wgfeel"))
        .arg0("arbitrary-download-name")
        .arg("--build-info")
        .output()
        .unwrap();
    assert!(output.status.success());
    assert_eq!(
        output.stdout,
        format!("wgfeel {}\n", env!("CARGO_PKG_VERSION")).as_bytes()
    );
}

#[test]
fn package_has_one_executable_target() {
    let output = Command::new(env!("CARGO"))
        .current_dir(env!("CARGO_MANIFEST_DIR"))
        .args([
            "metadata",
            "--offline",
            "--locked",
            "--no-deps",
            "--format-version=1",
        ])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let metadata: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    let package = metadata["packages"]
        .as_array()
        .unwrap()
        .iter()
        .find(|p| p["name"] == env!("CARGO_PKG_NAME"))
        .unwrap();
    let binaries: Vec<_> = package["targets"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|target| {
            target["kind"]
                .as_array()
                .unwrap()
                .iter()
                .any(|kind| kind == "bin")
        })
        .collect();
    let names: Vec<_> = binaries
        .iter()
        .map(|target| target["name"].as_str().unwrap())
        .collect();
    assert_eq!(names, ["wgfeel"]);
    assert!(
        binaries[0]
            .get("required-features")
            .is_none_or(|f| f.as_array().unwrap().is_empty()),
        "wgfeel must be available with the default build"
    );
}
