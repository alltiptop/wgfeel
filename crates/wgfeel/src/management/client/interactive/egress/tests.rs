use super::profile_input::read_profile;
use super::*;
use base64::{Engine, engine::general_purpose::STANDARD};
use serde_json::{Value, json};
use std::fs::File;
use std::{cell::RefCell, ffi::OsString, io::Cursor};
use wgfeel_core::MAX_PROFILE_BYTES;

fn profile() -> String {
    format!(
        "[Interface]\nPrivateKey = {}\nAddress = 172.16.0.2/32\n[Peer]\nPublicKey = {}\nAllowedIPs = 0.0.0.0/0, ::/0\nEndpoint = VPN.Example.net.:51820\n",
        STANDARD.encode([41; 32]),
        STANDARD.encode([42; 32])
    )
}
fn response(value: Value, revision: u64) -> Response {
    Response {
        status: 200,
        generation: Some(revision),
        is_config: false,
        body: serde_json::to_vec(&value).unwrap(),
    }
}
fn cli(args: &[&str], input: &[u8], terminal: bool, api: &Api<'_>) -> (Result<()>, String) {
    let options =
        Options::parse(&args[1..].iter().map(OsString::from).collect::<Vec<_>>()).unwrap();
    let mut out = Vec::new();
    let result = super::super::run(
        args[0],
        options,
        api,
        &mut Cursor::new(input),
        &mut out,
        terminal,
    );
    (result, String::from_utf8(out).unwrap())
}
#[test]
fn stdin_import_is_atomic_and_uses_only_supported_default_routes() {
    let raw = profile();
    let calls = RefCell::new(Vec::new());
    let (result, out) = cli(
        &[
            "egress",
            "--users",
            "alice,bob",
            "add",
            "--internet",
            "--config-stdin",
            "--node",
            "edge",
        ],
        raw.as_bytes(),
        true,
        &|method, path, rev, data| {
            calls
                .borrow_mut()
                .push((method.to_owned(), path.to_owned(), rev));
            if method == "GET" {
                return Ok(response(json!({"egresses":[]}), 7));
            }
            let body: Value = serde_json::from_slice(data).unwrap();
            assert_eq!(
                body,
                json!({"name":"vpn.example.net","node":"edge","config":raw,"users":[
                {"user":"alice","routes":["0.0.0.0/0"],"dns":{"mode":"none"}},
                {"user":"bob","routes":["0.0.0.0/0"],"dns":{"mode":"none"}}]})
            );
            Ok(response(json!({"id":"eg_corp","generation":8}), 8))
        },
    );
    result.unwrap();
    assert_eq!(
        *calls.borrow(),
        [
            ("GET".into(), ROOT.into(), None),
            ("POST".into(), ROOT.into(), Some(7))
        ]
    );
    assert!(out.contains(REEXPORT));
    assert!(
        !out.contains("PrivateKey")
            && !out.contains(&STANDARD.encode([41; 32]))
            && !out.contains("Select")
    );
}
#[test]
fn placement_conflict_reports_partial_success_without_rollback_or_retry() {
    let calls = RefCell::new(Vec::new());
    let (result, out) = cli(
        &[
            "user",
            "egress",
            "set",
            "--node",
            "edge",
            "alice",
            "--internet",
            "eg_corp",
        ],
        b"",
        false,
        &|method, path, rev, body| {
            calls
                .borrow_mut()
                .push((method.to_owned(), path.to_owned(), rev));
            Ok(match (method, path) {
                ("GET", "/api/v1/egresses/eg_corp") => response(
                    json!({"id":"eg_corp","name":"Office","placement_state":"unassigned","addresses":["172.16.0.2"],"allowed_ips":["0.0.0.0/0"]}),
                    4,
                ),
                ("GET", "/api/v1/users/alice") => response(json!({"id":"alice"}), 4),
                ("PUT", "/api/v1/egresses/eg_corp/node") => {
                    assert_eq!(
                        serde_json::from_slice::<Value>(body).unwrap(),
                        json!({"node":"edge"})
                    );
                    response(json!({"node":"edge","placement_state":"placed"}), 5)
                }
                ("PUT", "/api/v1/users/alice/egresses/eg_corp") => {
                    assert_eq!(
                        serde_json::from_slice::<Value>(body).unwrap(),
                        json!({"routes":["0.0.0.0/0"],"dns":{"mode":"none"}})
                    );
                    Response::error(412, "revision_conflict")
                }
                _ => panic!("unexpected call"),
            })
        },
    );
    assert!(result.is_err());
    assert_eq!(
        calls
            .borrow()
            .iter()
            .map(|(_, _, r)| *r)
            .collect::<Vec<_>>(),
        [None, None, Some(4), Some(5)]
    );
    assert!(out.contains("Egress attached to edge. User assignment was not saved."));
    assert!(!out.contains(REEXPORT));
}
#[test]
fn prompt_cancellation_distinguishes_eof_from_enter_and_skips_users_when_unplaced() {
    let path =
        std::env::temp_dir().join(format!("wgfeel-egress-cli-profile-{}", std::process::id()));
    let mut file = File::create_new(&path).unwrap();
    file.write_all(profile().as_bytes()).unwrap();
    drop(file);
    let path_arg = path.to_str().unwrap();
    for (input, expected_writes) in [
        ("", 0),
        ("\n", 0),
        ("\n0\n", 1),
        ("\n\n", 1),
        ("\n1\n", 0),
        ("\n1\n1\ninternet\n", 0),
        ("\n1\n1\ninternet\n\n", 1),
    ] {
        let writes = RefCell::new(0);
        let (result, out) = cli(
            &["egress", "add", path_arg],
            input.as_bytes(),
            true,
            &|method, path, rev, body| {
                Ok(match (method, path) {
                    ("GET", "/api/v1/egresses") => response(json!({"egresses":[]}), 4),
                    ("GET", "/api/v1/gateways") => response(
                        json!({"gateways":[{"recipient":"edge","traffic":"entry","endpoint":"192.0.2.2:51820"},{"recipient":"relay","traffic":"relay","endpoint":"192.0.2.3:51820"}]}),
                        4,
                    ),
                    ("GET", "/api/v1/users") => response(
                        json!({"users":[{"id":"alice","name":"Alice","suspended":false,"devices":[]}]}),
                        4,
                    ),
                    ("POST", "/api/v1/egresses") => {
                        assert_eq!(rev, Some(4));
                        let b: Value = serde_json::from_slice(body).unwrap();
                        assert_eq!(b["name"], "vpn.example.net");
                        if input.contains("internet") {
                            assert_eq!(b["users"][0]["user"], "alice");
                            assert_eq!(b["node"], "edge")
                        } else {
                            assert_eq!(b["users"], json!([]));
                            assert!(b["node"].is_null())
                        }
                        *writes.borrow_mut() += 1;
                        response(json!({"id":"eg_corp"}), 5)
                    }
                    _ => panic!("unexpected call"),
                })
            },
        );
        result.unwrap();
        assert_eq!(*writes.borrow(), expected_writes);
        assert!(!out.contains("relay"));
        if input == "\n0\n" {
            assert!(!out.contains("Select users"))
        }
    }
    std::fs::remove_file(path).unwrap();
}
#[test]
fn scripts_never_confirm_deletions_or_open_menus() {
    for args in [
        &["egress", "delete", "eg_office"][..],
        &["user", "egress", "remove", "alice", "eg_office"],
        &["egress"],
        &["egress", "add", "--non-interactive"],
        &["egress", "add", "--config-stdin", "--users", "alice"],
        &["egress", "add", "--config-stdin", "file"],
        &[
            "egress",
            "add",
            "--internet",
            "--routes",
            "10.0.0.0/8",
            "file",
        ],
    ] {
        let (result, out) = cli(args, b"y\n", false, &|_, _, _, _| {
            panic!("unexpected API call")
        });
        assert!(result.is_err(), "{args:?}");
        assert!(out.is_empty());
    }
    let (result, out) = cli(&["egress"], b"0\n", true, &|_, _, _, _| {
        panic!("unexpected API call")
    });
    result.unwrap();
    assert!(out.contains("1. add egress") && out.contains("2. list egresses"));
    assert!(read_profile(&vec![b'x'; MAX_PROFILE_BYTES + 1][..]).is_err());
}

#[test]
fn unassign_only_commits_after_explicit_terminal_confirmation() {
    let (result, _) = cli(
        &[
            "egress",
            "node",
            "eg_office",
            "--unassign",
            "--non-interactive",
        ],
        b"y\n",
        true,
        &|_, _, _, _| panic!("unattended detach must fail before connecting"),
    );
    assert_eq!(result, Err(NEED_TERMINAL));
    for (terminal, input, expected) in [
        (true, &b""[..], 0),
        (true, &b"\n"[..], 0),
        (true, &b"y\n"[..], 1),
        (false, &b"y\n"[..], 0),
    ] {
        let writes = std::cell::Cell::new(0);
        let (result, output) = cli(
            &["egress", "node", "eg_office", "--unassign"],
            input,
            terminal,
            &|method, path, rev, body| match (method, path) {
                ("GET", "/api/v1/egresses/eg_office") => Ok(response(
                    json!({"id":"eg_office","name":"Office","node":"entry","placement_state":"placed","addresses":["172.16.0.2"],"allowed_ips":["0.0.0.0/0"]}),
                    4,
                )),
                ("PUT", "/api/v1/egresses/eg_office/node") => {
                    assert_eq!(rev, Some(4));
                    assert_eq!(
                        serde_json::from_slice::<Value>(body).unwrap(),
                        json!({"node":null})
                    );
                    writes.set(writes.get() + 1);
                    Ok(response(json!({"placement_state":"detaching"}), 5))
                }
                _ => panic!("unexpected call"),
            },
        );
        if terminal {
            result.unwrap()
        } else {
            assert_eq!(result, Err(NEED_TERMINAL))
        };
        assert_eq!(writes.get(), expected);
        assert_eq!(output.contains("(y/n) [n]"), terminal);
    }
}
