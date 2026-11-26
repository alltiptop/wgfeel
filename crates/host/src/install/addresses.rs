use super::Result;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

// Discovery only reads local interfaces; it neither probes remote hosts nor
// guesses an external NAT mapping. The operator confirms the advertised address.
pub(crate) fn discover() -> Result<Vec<(String, IpAddr)>> {
    #[cfg(all(
        target_os = "linux",
        target_arch = "x86_64",
        target_pointer_width = "64"
    ))]
    {
        use nix::ifaddrs::getifaddrs;
        Ok(getifaddrs()
            .map_err(|_| "cannot read network interface addresses")?
            .filter_map(|interface| {
                if interface
                    .flags
                    .contains(nix::net::if_::InterfaceFlags::IFF_LOOPBACK)
                {
                    return None;
                }
                let address = interface.address?;
                let ip = address
                    .as_sockaddr_in()
                    .map(|address| IpAddr::V4(address.ip()))
                    .or_else(|| {
                        address
                            .as_sockaddr_in6()
                            .map(|address| IpAddr::V6(address.ip()))
                    })?;
                Some((interface.interface_name, ip))
            })
            .collect())
    }
    #[cfg(not(all(
        target_os = "linux",
        target_arch = "x86_64",
        target_pointer_width = "64"
    )))]
    Err("interface address discovery is unsupported on this platform".into())
}

pub(super) fn ask(
    discovered: Result<Vec<(String, IpAddr)>>,
    bind: Option<IpAddr>,
    port: Option<u16>,
    prompt: &mut impl FnMut(&str, &str) -> Result<String>,
) -> Result<Vec<SocketAddr>> {
    let (mut candidates, mut label) = match discovered {
        Ok(addresses) => (addresses, String::new()),
        Err(_) => (
            vec![],
            "Could not read network interface addresses.\n".into(),
        ),
    };
    candidates.retain(|(name, ip)| {
        if name == "lo"
            || ip.is_loopback()
            || wgfeel_core::validate_node_endpoints(&[SocketAddr::new(*ip, 1)]).is_err()
        {
            return false;
        }
        bind.is_none_or(|bind| {
            bind.is_ipv4() == ip.is_ipv4() && (bind.is_unspecified() || bind == *ip)
        })
    });
    candidates.sort_by_key(|(name, ip)| (*ip, name.clone()));
    candidates.dedup_by_key(|(_, ip)| *ip);
    let display = |ip: IpAddr| match port {
        Some(port) => SocketAddr::new(ip, port).to_string(),
        None => ip.to_string(),
    };
    let mut default = String::new();
    if candidates.is_empty() {
        label.push_str("No interface address selected; enter the reachable address manually.\n");
    } else {
        label.push_str("Detected interface addresses:\n");
        for (index, (name, ip)) in candidates.iter().enumerate() {
            label.push_str(&format!("  {}. {} ({name:?})\n", index + 1, display(*ip)));
        }
        if candidates.len() == 1 {
            default = display(candidates[0].1);
        }
    }
    label.push_str(match port {
        Some(_) => {
            "Advertised endpoints (numbers or IP:port, IPv6 [address]:port, comma-separated)"
        }
        None => "Advertised child addresses (numbers or IPs, comma-separated)",
    });
    let answer = prompt(&label, &default)?;
    answer
        .split(',')
        .map(|part| {
            let part = part.trim();
            if let Ok(number) = part.parse::<usize>() {
                let index = number.checked_sub(1).ok_or("invalid address selection")?;
                let (_, ip) = candidates.get(index).ok_or("invalid address selection")?;
                return Ok(SocketAddr::new(*ip, port.unwrap_or(0)));
            }
            parse(part, port)
        })
        .collect()
}

pub(super) fn parse(value: &str, port: Option<u16>) -> Result<SocketAddr> {
    if port.is_none() {
        let ip = value
            .parse()
            .map_err(|_| "enter a child IP without a port (main assigns the UDP port)")?;
        Ok(SocketAddr::new(ip, 0))
    } else {
        value
            .parse()
            .map_err(|_| "enter an IPv4 address and port or [IPv6]:port".into())
    }
}

pub(super) fn listen_ip(explicit: Option<IpAddr>, endpoint: SocketAddr) -> Result<IpAddr> {
    match explicit {
        Some(ip) if ip.is_ipv4() != endpoint.is_ipv4() => {
            Err("listen IP and advertised endpoint must use the same IP version".into())
        }
        Some(ip) => Ok(ip),
        None if endpoint.is_ipv4() => Ok(Ipv4Addr::UNSPECIFIED.into()),
        None => Ok(Ipv6Addr::UNSPECIFIED.into()),
    }
}

#[cfg(test)]
mod tests;
