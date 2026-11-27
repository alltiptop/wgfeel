use super::*;
use wgfeel_core::{DnsZone, EgressDnsSelection};
#[derive(Clone, Deserialize, Serialize)]
pub(super) struct Policy {
    routes: Vec<IpPrefix>,
    dns: EgressDnsSelection,
}
impl Policy {
    pub(super) fn description(&self) -> String {
        let dns = match &self.dns {
            EgressDnsSelection::None {} => "none".to_owned(),
            EgressDnsSelection::Default {} => "default".to_owned(),
            EgressDnsSelection::Zones { zones } => zones
                .iter()
                .map(DnsZone::as_str)
                .collect::<Vec<_>>()
                .join(", "),
        };
        format!(
            "routes {} | DNS {}",
            self.routes
                .iter()
                .map(ToString::to_string)
                .collect::<Vec<_>>()
                .join(", "),
            dns
        )
    }
}

#[derive(Default)]
pub(super) struct Intent {
    internet: bool,
    routes: Option<String>,
    dns_default: bool,
    zones: Option<String>,
}
impl Intent {
    pub(super) fn parse(opts: &mut Options) -> Result<Self> {
        let value = Self {
            internet: opts.take("--internet").is_some(),
            routes: opts.take("--routes"),
            dns_default: opts.take("--dns-default").is_some(),
            zones: opts.take("--dns-zones"),
        };
        if value.internet && value.routes.is_some() {
            return Err("choose --internet or --routes");
        }
        if value.dns_default && value.zones.is_some() {
            return Err("choose --dns-default or --dns-zones");
        }
        Ok(value)
    }
    pub(super) fn supplied(&self) -> bool {
        self.internet || self.routes.is_some() || self.dns_default || self.zones.is_some()
    }
    pub(super) fn policy(
        mut self,
        ui: &mut Ui<'_>,
        addresses: &[IpAddr],
        allowed: &[IpPrefix],
    ) -> Result<Option<Policy>> {
        if !self.internet && self.routes.is_none() {
            if !ui.terminal {
                return Err("specify --internet or --routes for user assignments");
            }
            let Some(route) = line(
                ui.input,
                ui.out,
                "Routes (internet or comma-separated CIDRs): ",
            )?
            else {
                return Ok(None);
            };
            if matches!(route.as_str(), "internet" | "--internet") {
                self.internet = true
            } else {
                self.routes = Some(route)
            }
        }
        let routes = if self.internet {
            let prefixes: Vec<_> = allowed
                .iter()
                .copied()
                .filter(|p| {
                    p.length() == 0
                        && addresses
                            .iter()
                            .any(|ip| ip.is_ipv4() == p.network().is_ipv4())
                })
                .collect();
            if prefixes.is_empty() {
                return Err("profile has no matching default route and interface address");
            }
            prefixes
        } else {
            split_list(self.routes.as_deref().unwrap_or(""))?
                .into_iter()
                .map(|value| value.parse::<IpPrefix>().map_err(|_| "invalid route CIDR"))
                .collect::<Result<Vec<_>>>()?
        };
        unique(&routes)?;
        if routes.len() > wgfeel_core::MAX_ROUTES_PER_ASSIGNMENT
            || routes.iter().any(|route| {
                route.internal()
                    || !addresses
                        .iter()
                        .any(|ip| ip.is_ipv4() == route.network().is_ipv4())
                    || !allowed.iter().any(|p| p.covers(*route))
            })
        {
            return Err("routes must be supported by this egress profile");
        }
        if ui.terminal && !self.dns_default && self.zones.is_none() {
            let Some(dns) = line(
                ui.input,
                ui.out,
                "DNS (none / default / comma-separated zones) [none]: ",
            )?
            else {
                return Ok(None);
            };
            match dns.as_str() {
                "" | "none" => (),
                "default" => self.dns_default = true,
                _ => self.zones = Some(dns),
            }
        }
        let dns = if self.dns_default {
            EgressDnsSelection::Default {}
        } else if let Some(text) = self.zones {
            let zones: Vec<DnsZone> = split_list(&text)?
                .into_iter()
                .map(|zone| serde_json::from_value(zone.into()).map_err(|_| "invalid DNS zone"))
                .collect::<Result<_>>()?;
            if zones.len() > wgfeel_core::MAX_DNS_ZONES_PER_ASSIGNMENT {
                return Err("too many DNS zones");
            }
            unique(&zones.iter().map(DnsZone::as_str).collect::<Vec<_>>())?;
            EgressDnsSelection::Zones { zones }
        } else {
            EgressDnsSelection::None {}
        };
        Ok(Some(Policy { routes, dns }))
    }
}
