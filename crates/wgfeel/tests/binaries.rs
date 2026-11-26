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
    let manifest = include_str!("../Cargo.toml");
    assert_eq!(manifest.matches("[[bin]]").count(), 1);
    assert!(manifest.contains(r#"name = "wgfeel""#));
    assert!(!manifest.contains("required-features"));
}
