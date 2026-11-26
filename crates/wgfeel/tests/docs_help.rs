//! Public help must use the command descriptions consumed by cargo docs.
use std::process::Command;

#[test]
fn help_accepts_command_arguments_without_opening_state_or_connections() {
    for (args, usage) in [
        (vec!["api"], "wgfeel api COMMAND"),
        (vec!["api", "--help"], "wgfeel api COMMAND"),
        (
            vec!["init", "--control", "child", "--help"],
            "wgfeel init --control main|child",
        ),
        (
            vec![
                "serve",
                "--control",
                "main",
                "--state-dir",
                "/missing/wgfeel",
                "-h",
            ],
            "wgfeel serve --control main|child",
        ),
        (
            vec![
                "user",
                "--profile",
                "/missing/admin.json",
                "show",
                "user1",
                "--help",
            ],
            "wgfeel user show [ID]",
        ),
        (
            vec![
                "join",
                "not-an-invitation",
                "--endpoint",
                "192.0.2.2:51820",
                "--help",
            ],
            "wgfeel join INVITATION",
        ),
        (vec!["uninstall", "--purge", "--help"], "wgfeel uninstall"),
    ] {
        let output = Command::new(env!("CARGO_BIN_EXE_wgfeel"))
            .args(&args)
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{args:?}: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(output.stderr.is_empty());
        assert!(
            String::from_utf8(output.stdout)
                .unwrap()
                .starts_with(&format!("Usage: {usage}"))
        );
    }
    for args in [
        vec!["node", "unknown", "--help"],
        vec!["user", "unknown", "--help"],
    ] {
        let output = Command::new(env!("CARGO_BIN_EXE_wgfeel"))
            .args(args)
            .output()
            .unwrap();
        assert!(!output.status.success());
    }
}

#[test]
fn enrollment_help_exposes_only_the_invitation_workflow() {
    let binary = env!("CARGO_BIN_EXE_wgfeel");
    let missing = Command::new(binary)
        .args(["init", "--control", "child"])
        .output()
        .unwrap();
    assert!(!missing.status.success());
    let error = String::from_utf8(missing.stderr).unwrap();
    assert!(error.contains("wgfeel init --control child"), "{error}");
    let result = Command::new(binary)
        .args(["node", "add", "--help"])
        .output()
        .unwrap();
    assert!(result.status.success());
    let help = String::from_utf8(result.stdout).unwrap();
    let flags: Vec<_> = help
        .lines()
        .filter_map(|line| line.strip_prefix("  --"))
        .map(|arg| arg.split_whitespace().next().unwrap())
        .collect();
    assert_eq!(
        flags,
        [
            "traffic",
            "revision",
            "profile",
            "socket",
            "credential-file"
        ]
    );
}

#[test]
fn detailed_help_is_available_without_state_or_services() {
    for (binary, args, expected) in [
        (
            env!("CARGO_BIN_EXE_wgfeel"),
            vec!["user", "add", "--help"],
            vec!["wgfeel user add [NAME]", "--profile", "first device"],
        ),
        (
            env!("CARGO_BIN_EXE_wgfeel"),
            vec!["node", "add", "--help"],
            vec!["--traffic", "--revision", "one-time invitation"],
        ),
        (
            env!("CARGO_BIN_EXE_wgfeel"),
            vec!["init", "--help"],
            vec!["--listen", "--endpoint", "administrator profile"],
        ),
        (
            env!("CARGO_BIN_EXE_wgfeel"),
            vec!["join", "--help"],
            vec!["INVITATION", "--endpoint", "--install-dir"],
        ),
        (
            env!("CARGO_BIN_EXE_wgfeel"),
            vec!["init", "--help"],
            vec!["--control main|child", "wgfeel join"],
        ),
    ] {
        let output = Command::new(binary).args(args).output().unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(output.stderr.is_empty());
        let help = String::from_utf8(output.stdout).unwrap();
        for text in expected {
            assert!(help.contains(text), "missing help: {text}");
        }
    }
}
