use super::*;

fn interfaces(addresses: &[(&str, &str)]) -> Result<Vec<(String, IpAddr)>> {
    Ok(addresses
        .iter()
        .map(|(name, ip)| (name.to_string(), ip.parse().unwrap()))
        .collect())
}

#[test]
fn unknown_options_are_rejected_before_prompts_or_discovery() {
    for extra in [vec!["--unknown"], vec!["--unknown", "value"]] {
        let mut args = vec!["--control", "main", "--endpoint", "192.0.2.7:51820"];
        args.extend(extra);
        let args: Vec<_> = args.into_iter().map(std::ffi::OsString::from).collect();
        assert!(
            crate::install::Options::read(
                &args,
                |_, _| panic!("unknown options must be rejected before prompting"),
                || panic!("unknown options must be rejected before discovery"),
            )
            .is_err()
        );
    }
}

#[test]
fn proposes_a_single_interface_address_and_selected_port_for_both_families() {
    for (ip, expected) in [
        ("93.184.215.14", "93.184.215.14:53100"),
        ("2a01:4f8:1::7", "[2a01:4f8:1::7]:53100"),
    ] {
        let answer = ask(
            interfaces(&[("eth0", ip)]),
            None,
            Some(53100),
            &mut |label, default| {
                assert!(label.contains("eth0"));
                assert_eq!(default, expected);
                Ok(default.into())
            },
        )
        .unwrap();
        assert_eq!(answer[0].to_string(), expected);
    }
}

#[test]
fn dual_stack_or_multiple_addresses_require_selection_and_allow_manual_nat_endpoint() {
    let available = || interfaces(&[("ens3", "93.184.215.14"), ("ens3", "2a01:4f8:1::7")]);
    let answer = ask(available(), None, Some(51821), &mut |label, default| {
        assert!(default.is_empty());
        assert!(label.contains("93.184.215.14:51821"));
        assert!(label.contains("[2a01:4f8:1::7]:51821"));
        Ok("2".into())
    })
    .unwrap();
    assert_eq!(answer[0].to_string(), "[2a01:4f8:1::7]:51821");
    assert!(
        ask(available(), None, Some(51821), &mut |_, default| Ok(
            default.into()
        ))
        .is_err()
    );
    for number in ["0", "3"] {
        assert!(
            ask(
                available(),
                None,
                Some(51821),
                &mut |_, _| Ok(number.into())
            )
            .is_err()
        );
    }
    let manual = "[2001:db8::2]:63000";
    assert_eq!(
        ask(
            available(),
            None,
            Some(51821),
            &mut |_, _| Ok(manual.into())
        )
        .unwrap(),
        [manual.parse::<SocketAddr>().unwrap()]
    );
}

#[test]
fn private_and_tunnel_addresses_remain_selectable_without_range_filters() {
    for (name, ip) in [
        ("ens4", "10.0.0.7"),
        ("ens4", "172.16.1.7"),
        ("ens4", "192.168.1.7"),
        ("wg0", "100.64.1.7"),
        ("wg0", "fd00::7"),
        ("wg0", "2606:4700:110::2"),
        ("tun0", "192.0.2.7"),
    ] {
        let expected = SocketAddr::new(ip.parse().unwrap(), 51820).to_string();
        let answer = ask(
            interfaces(&[(name, ip)]),
            None,
            Some(51820),
            &mut |label, default| {
                assert!(label.contains(name));
                assert_eq!(default, expected);
                Ok("1".into())
            },
        )
        .unwrap();
        assert_eq!(answer[0].to_string(), expected);
    }
}

#[test]
fn unavailable_discovery_still_accepts_an_explicit_endpoint() {
    ask(
        Err("discovery unavailable".into()),
        None,
        Some(51820),
        &mut |label, default| {
            assert!(label.contains("Could not read"));
            assert!(default.is_empty());
            Ok("93.184.215.14:51820".into())
        },
    )
    .unwrap();
}

#[test]
fn explicit_bind_filters_candidates_and_duplicate_addresses_are_not_ambiguous() {
    let addresses = interfaces(&[
        ("eth0", "93.184.215.14"),
        ("eth1", "93.184.215.14"),
        ("eth0", "2a01:4f8:1::7"),
    ]);
    let answer = ask(
        addresses,
        Some("0.0.0.0".parse().unwrap()),
        Some(51820),
        &mut |_, default| {
            assert_eq!(default, "93.184.215.14:51820");
            Ok(default.into())
        },
    )
    .unwrap();
    assert_eq!(answer[0].to_string(), "93.184.215.14:51820");
}

#[test]
fn interactive_ipv6_selection_reaches_each_roles_settings() {
    for (role, port) in [("main", "53100"), ("child", "0")] {
        let options = crate::install::Options::read(
            &[],
            |label, default| match label {
                _ if label.starts_with("Control capability") => {
                    Ok(if role == "main" { "1" } else { "2" }.into())
                }
                _ if role == "child"
                    && (label.contains(" port") || label.starts_with("Traffic capability")) =>
                {
                    panic!("child must not choose a port or traffic mode")
                }
                "WireGuard / mesh UDP port" => Ok(port.into()),
                _ => Ok(default.into()),
            },
            || interfaces(&[("ens3", "2a01:4f8:1::7")]),
        )
        .unwrap();
        assert_eq!(options.control, role);
        assert_eq!(
            options.endpoints[0],
            format!("[2a01:4f8:1::7]:{port}").parse().unwrap()
        );
        assert_eq!(options.listen, format!("[::]:{port}").parse().unwrap());
    }
}

#[test]
fn explicit_endpoints_skip_discovery_and_keep_independent_service_families() {
    for (role, endpoint, listen) in [
        ("main", "192.0.2.7:51820", "0.0.0.0:51820"),
        ("child", "2001:db8::7", "[::]:0"),
    ] {
        let args = ["--control", role, "--endpoint", endpoint].map(std::ffi::OsString::from);
        let options = crate::install::Options::read(
            &args,
            |_, _| panic!("explicit settings must not prompt"),
            || panic!("explicit endpoints must not trigger discovery"),
        )
        .unwrap();
        assert_eq!(
            options.endpoints[0],
            parse(endpoint, (role == "main").then_some(51820)).unwrap()
        );
        assert_eq!(options.listen, listen.parse().unwrap());
    }
}

#[test]
fn interactive_management_setup_never_offers_node_installation() {
    let options = crate::install::Options::read(
        &[],
        |label, default| match label {
            _ if label.starts_with("Control capability") => Ok("main".into()),
            "WireGuard / mesh UDP port" => Ok("51129".into()),
            _ if label.starts_with("Traffic capability") => Ok("2".into()),
            "External REST HTTP port" => Ok("8087".into()),
            "Node name (unique in this mesh)" => Ok("main".into()),
            _ if label.contains("Advertised endpoints") => Ok(default.into()),
            _ => panic!("unexpected installation question: {label}"),
        },
        || interfaces(&[("eth0", "2a01:4f8:1::7")]),
    )
    .unwrap();
    assert_eq!(options.control, "main");
    assert_eq!(options.listen.port(), 51129);
    assert_eq!(options.api_port, Some(8087));
    assert_eq!(options.traffic.as_deref(), Some("relay"));
}

#[test]
fn interactive_choices_keep_only_selected_addresses_in_order() {
    let main = crate::install::Options::read(
        &[],
        |label, default| {
            if label.starts_with("Control capability") || label.starts_with("Traffic capability") {
                assert_eq!(default, "1");
            }
            if label.starts_with("Detected interface addresses") {
                for hidden in ["127.23.4.5", "[::1]", "192.0.2.8", "fe80::1"] {
                    assert!(!label.contains(hidden));
                }
                return Ok("2, 1".into());
            }
            Ok(default.into())
        },
        || {
            interfaces(&[
                ("eth1", "127.23.4.5"),
                ("lo", "192.0.2.8"),
                ("lo", "::1"),
                ("wg0", "10.4.0.1"),
                ("eth2", "2001:db8::3"),
                ("eth2", "fe80::1"),
            ])
        },
    )
    .unwrap();
    assert_eq!(main.control, "main");
    assert_eq!(main.id.as_str(), "main");
    assert_eq!(main.traffic.as_deref(), Some("entry"));
    assert_eq!(main.api_port, Some(9280));
    assert_eq!(
        main.endpoints,
        ["[2001:db8::3]:51820", "10.4.0.1:51820"].map(|s| s.parse::<SocketAddr>().unwrap())
    );
}
