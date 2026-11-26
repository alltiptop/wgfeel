//! Host installation is explicit. Preview and custom-root tests have no service effects.
use serde_json::json;
use std::{
    collections::{BTreeMap, BTreeSet},
    ffi::OsString,
    io::{self, IsTerminal, Write},
    net::{IpAddr, SocketAddr},
    path::{Path, PathBuf},
};
use wgfeel_core::NodeId;
pub(crate) mod addresses;
pub(crate) mod paths;
pub mod update;
pub use crate::uninstall::installed::{ChildSettings, child_settings};
use paths::Directory;

pub type ManagerSetup = fn(&[OsString], &[SocketAddr]) -> std::result::Result<(), &'static str>;
type Result<T> = std::result::Result<T, String>;
const HELP: &str = "wgfeel install --control main|child [--traffic entry|relay|off] [--port PORT] --endpoint ADDRESS ...\n  Installs one executable and wgfeel.service. Main selects each child's traffic mode when issuing its invitation.\n  Main HTTP REST: --api-port PORT (default 9280), --api-listen-ip IP (default 127.0.0.1).\n  --listen-ip IP, --no-start, --dry-run, --install-dir PATH (default /opt/wgfeel).\n  Repeat --endpoint with IP:port on main or a bare IP on child. Main assigns the child port at join.\n  --root ABS --no-start stages an isolated installation tree. Existing state is never overwritten.\n";

struct Options {
    control: String,
    root: PathBuf,
    install_dir: PathBuf,
    listen: SocketAddr,
    endpoints: Vec<SocketAddr>,
    id: NodeId,
    api_port: Option<u16>,
    api_listen_ip: Option<IpAddr>,
    traffic: Option<String>,
    no_start: bool,
    dry: bool,
}
fn prompt(label: &str, default: &str) -> Result<String> {
    if !io::stdin().is_terminal() {
        return Err(format!("{label} must be specified in noninteractive mode"));
    }
    if default.is_empty() {
        print!("{label}: ");
    } else {
        print!("{label} [{default}]: ");
    }
    io::stdout()
        .flush()
        .map_err(|_| "cannot write installation prompt")?;
    let mut value = String::new();
    if io::stdin()
        .read_line(&mut value)
        .map_err(|_| "cannot read installation answer")?
        == 0
    {
        return Err("installation cancelled".into());
    }
    let value = value.trim();
    Ok(if value.is_empty() {
        default.into()
    } else {
        value.into()
    })
}
fn port(value: &str) -> Result<u16> {
    value
        .parse::<u16>()
        .ok()
        .filter(|port| *port != 0)
        .ok_or_else(|| "port must be 1..65535".into())
}
fn choose(
    label: &str,
    choices: &[(&str, &str)],
    prompt: &mut impl FnMut(&str, &str) -> Result<String>,
) -> Result<String> {
    use std::fmt::Write;
    let mut menu = format!("{label}\n");
    for (i, (name, description)) in choices.iter().enumerate() {
        writeln!(menu, "{}. {name:<6} {description}", i + 1).unwrap();
    }
    write!(menu, "Select {}", label.to_ascii_lowercase()).unwrap();
    let answer = prompt(&menu, "1")?;
    choices
        .iter()
        .enumerate()
        .find(|(i, (name, _))| answer == (i + 1).to_string() || answer == *name)
        .map(|(_, (name, _))| name.to_string())
        .ok_or_else(|| {
            format!(
                "choose a listed {} number or name",
                label.to_ascii_lowercase()
            )
        })
}

fn child_name() -> Result<String> {
    if let Ok(host) = std::fs::read_to_string("/proc/sys/kernel/hostname")
        && let Some(name) = host.trim().split('.').next()
        && NodeId::new(name).is_ok()
    {
        return Ok(name.into());
    }
    Ok(crate::node::generated_id()?.as_str().into())
}
impl Options {
    fn parse(args: &[OsString]) -> Result<Self> {
        Self::read(args, prompt, addresses::discover)
    }
    fn read(
        args: &[OsString],
        mut prompt: impl FnMut(&str, &str) -> Result<String>,
        discover: impl FnOnce() -> Result<Vec<(String, IpAddr)>>,
    ) -> Result<Self> {
        let mut values = BTreeMap::new();
        let mut explicit_endpoints = Vec::new();
        let mut flags = BTreeSet::new();
        let mut arguments = args.iter();
        while let Some(argument) = arguments.next() {
            let name = argument.to_str().ok_or(HELP)?;
            if ["--no-start", "--dry-run"].contains(&name) {
                if !flags.insert(name) {
                    return Err(HELP.into());
                }
            } else if name == "--endpoint" {
                explicit_endpoints.push(arguments.next().and_then(|v| v.to_str()).ok_or(HELP)?);
            } else if [
                "--control",
                "--root",
                "--install-dir",
                "--port",
                "--listen-ip",
                "--id",
                "--api-port",
                "--api-listen-ip",
                "--traffic",
            ]
            .contains(&name)
            {
                if values
                    .insert(
                        name,
                        arguments
                            .next()
                            .and_then(|value| value.to_str())
                            .ok_or(HELP)?
                            .to_owned(),
                    )
                    .is_some()
                {
                    return Err(HELP.into());
                }
            } else {
                return Err(HELP.into());
            }
        }
        let interactive = args.is_empty();
        let control = match values.get("--control") {
            Some(value) => value.clone(),
            None if interactive => choose(
                "Control capability",
                &[
                    ("main", "Manage this mesh and distribute its configuration."),
                    (
                        "child",
                        "Join an existing mesh and apply its main node’s configuration.",
                    ),
                ],
                &mut prompt,
            )?,
            None => return Err("specify --control main or --control child".into()),
        };
        if !matches!(control.as_str(), "main" | "child") {
            return Err("control capability must be main or child".into());
        }
        if control == "child"
            && (values.contains_key("--api-port") || values.contains_key("--api-listen-ip"))
        {
            return Err("the external HTTP API is available only on main".into());
        }
        if control == "child" && values.contains_key("--traffic") {
            return Err("child traffic policy is assigned by main during enrollment".into());
        }
        let traffic = if control == "main" {
            let mode = match values.get("--traffic") {
                Some(mode) => mode.clone(),
                None if interactive => choose(
                    "Traffic capability",
                    &[
                        (
                            "entry",
                            "Accept WireGuard clients and forward their traffic.",
                        ),
                        (
                            "relay",
                            "Forward encrypted traffic between nodes. Clients connect through an entry.",
                        ),
                        ("off", "Carry service WireGuard traffic only."),
                    ],
                    &mut prompt,
                )?,
                None => "entry".into(),
            };
            if !matches!(mode.as_str(), "entry" | "relay" | "off") {
                return Err("traffic capability must be entry, relay or off".into());
            }
            Some(mode)
        } else {
            None
        };
        let api_port = if control == "main" {
            Some(match values.get("--api-port") {
                Some(value) => port(value)?,
                None if interactive => port(&prompt("External REST HTTP port", "9280")?)?,
                None => 9280,
            })
        } else {
            None
        };
        let api_listen_ip = if control == "main" {
            let ip = values
                .get("--api-listen-ip")
                .map(String::as_str)
                .unwrap_or("127.0.0.1")
                .parse()
                .map_err(|_| "invalid HTTP API listen IP")?;
            wgfeel_store::RestApi::new(SocketAddr::new(ip, api_port.expect("main HTTP port")))
                .map_err(|_| "invalid HTTP API listen address")?;
            Some(ip)
        } else {
            None
        };
        if control == "child" && values.contains_key("--port") {
            return Err("main assigns the child's WireGuard port during join".into());
        }
        let selected_port = if control == "child" {
            None
        } else {
            Some(match values.get("--port") {
                Some(value) => port(value)?,
                None if interactive => port(&prompt("WireGuard / mesh UDP port", "51820")?)?,
                None => 51820,
            })
        };
        let bind_ip: Option<IpAddr> = values
            .get("--listen-ip")
            .map(|value| value.parse())
            .transpose()
            .map_err(|_| "invalid listen IP")?;
        if bind_ip.is_some_and(|ip| ip.is_multicast()) {
            return Err("invalid listen IP".into());
        }
        let endpoints = if explicit_endpoints.is_empty() {
            addresses::ask(discover(), bind_ip, selected_port, &mut prompt)?
        } else {
            explicit_endpoints
                .into_iter()
                .map(|value| addresses::parse(value, selected_port))
                .collect::<Result<Vec<_>>>()?
        };
        let validation: Vec<_> = endpoints
            .iter()
            .map(|a| {
                if selected_port.is_none() {
                    SocketAddr::new(a.ip(), 1)
                } else {
                    *a
                }
            })
            .collect();
        wgfeel_core::validate_node_endpoints(&validation)
            .map_err(|_| "invalid, duplicate or too many advertised addresses")?;
        let first = endpoints
            .first()
            .ok_or("select at least one advertised address")?;
        let ip = addresses::listen_ip(bind_ip, *first)?;
        if !ip.is_unspecified() && endpoints.iter().any(|addr| addr.is_ipv4() != ip.is_ipv4()) {
            return Err("mixed address families require a wildcard listen address".into());
        }
        let id = match values.get("--id") {
            Some(value) => value.clone(),
            None => {
                let default = if control == "main" {
                    "main".into()
                } else {
                    child_name()?
                };
                if interactive {
                    prompt("Node name (unique in this mesh)", &default)?
                } else {
                    default
                }
            }
        };
        let id = NodeId::new(&id)
            .map_err(|_| "node name must be 1–64 ASCII letters, digits, underscores or hyphens")?;
        let root = PathBuf::from(values.get("--root").map(String::as_str).unwrap_or("/"));
        let root_text = root.to_str().ok_or("invalid root")?;
        if !root.is_absolute()
            || root.components().collect::<PathBuf>() != root
            || root_text.split('/').any(|part| part == ".." || part == ".")
            || !root_text
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || b"/._-".contains(&byte))
        {
            return Err(
                "root must be an absolute normalized path using ASCII letters, digits, / . _ -"
                    .into(),
            );
        }
        let dry = flags.contains("--dry-run");
        let no_start = flags.contains("--no-start");
        if root != Path::new("/") && !no_start && !dry {
            return Err("--root requires --no-start or --dry-run".into());
        }
        let install_dir = values
            .get("--install-dir")
            .map(PathBuf::from)
            .unwrap_or_else(|| {
                if root == Path::new("/") {
                    crate::default_install_dir()
                } else {
                    "/opt/wgfeel".into()
                }
            });
        crate::installation_path(&root, &install_dir)?;
        Ok(Self {
            install_dir,
            control,
            root,
            listen: SocketAddr::new(ip, selected_port.unwrap_or(0)),
            endpoints,
            id,
            api_port,
            api_listen_ip,
            traffic,
            no_start,
            dry,
        })
    }
    fn home(&self, suffix: &str) -> PathBuf {
        crate::installation_path(&self.root, &self.install_dir)
            .expect("validated installation directory")
            .join(suffix)
    }
    fn path(&self, suffix: &str) -> PathBuf {
        self.root.join(suffix)
    }
}
fn unit(binary: &Path, control: &str, state: &Path, listen: SocketAddr) -> String {
    let listen = if control == "child" {
        if listen.port() == 0 {
            format!(" --listen-ip {}", listen.ip())
        } else {
            format!(" --listen {listen}")
        }
    } else {
        String::new()
    };
    format!(
        "[Unit]\nDescription=wgfeel {control}\nAfter=network-online.target\nWants=network-online.target\n\n[Service]\nType=exec\nExecStart={} serve --control {control} --state-dir {}{listen}\nRestart=on-failure\nRestartSec=2\nTimeoutStopSec=15\nKillMode=control-group\nUMask=0077\nNoNewPrivileges=true\nLimitCORE=0\n\n[Install]\nWantedBy=multi-user.target\n",
        binary.display(),
        state.display()
    )
}
pub fn run(args: &[OsString], manager: ManagerSetup) -> Result<()> {
    if args == [OsString::from("--help")] {
        print!("{HELP}");
        return Ok(());
    }
    if update::existing_install(args)? {
        return Ok(());
    }
    let options = Options::parse(args)?;
    let home = options.home("instance");
    let binary = home.join("bin/wgfeel");
    let state = home.join("state");
    let config = home.join("config");
    let profile = config.join("admin.json");
    let unit_path = options.path("etc/systemd/system/wgfeel.service");
    let contents = unit(&binary, &options.control, &state, options.listen);
    let resources = crate::help::resources();
    if options.dry {
        if let (Some(ip), Some(port)) = (options.api_listen_ip, options.api_port) {
            println!("# External REST HTTP: http://{}", SocketAddr::new(ip, port));
        }
        println!(
            "# {}: state={}, config={}\n# {}\n{contents}",
            options.control,
            state.display(),
            config.display(),
            unit_path.display()
        );
        for (relative, _) in resources {
            println!(
                "# Install command resource: {}",
                options.path("usr/local/share").join(relative).display()
            );
        }
        return Ok(());
    }
    let mut source = crate::executable::source()?;
    let base = Directory::create(&options.home(""), false)?;
    let _base_lock = base.lock()?;
    let receipts = Directory::create(&home, true)?;
    let _receipt_lock = receipts.lock()?;
    receipts.absent(crate::uninstall::RECEIPT)?;
    let units = Directory::create(&options.path("etc/systemd/system"), false)?;
    units.absent("wgfeel.service")?;
    Directory::create(&state, true)?.absent("state.json")?;
    let configuration = Directory::create(&config, true)?;
    configuration.absent("config.json")?;
    configuration.absent("admin.json")?;
    let commands = Directory::create(&options.path("usr/local/bin"), false)?;
    for (relative, _) in &resources {
        let path = options.path("usr/local/share").join(relative);
        Directory::create(path.parent().ok_or("invalid resource path")?, false)?.absent(
            path.file_name()
                .and_then(|name| name.to_str())
                .ok_or("invalid resource name")?,
        )?;
    }
    Directory::create(&home.join("bin"), false)?.binary("wgfeel", &mut source)?;
    commands.alias("wgfeel", &binary)?;
    let resource_receipts: Vec<_> = resources.iter().map(|(relative, contents)| json!({"path":options.path("usr/local/share").join(relative),"contents":contents})).collect();
    let receipt = json!({"version":1,"config_dir":config,"state_dir":state,"executable":{"directory":home.join("bin"),"alias":options.path("usr/local/bin/wgfeel")},"service":{"scope":"service","unit":{"path":unit_path,"contents":contents}},"resources":resource_receipts});
    receipts.write(
        crate::uninstall::RECEIPT,
        &serde_json::to_vec(&receipt).map_err(|_| "cannot encode installation receipt")?,
        false,
    )?;
    for (relative, contents) in &resources {
        let path = options.path("usr/local/share").join(relative);
        Directory::create(path.parent().ok_or("invalid resource path")?, false)?.write_public(
            path.file_name()
                .and_then(|name| name.to_str())
                .ok_or("invalid resource name")?,
            contents.as_bytes(),
        )?;
    }
    if options.control == "main" {
        let args = vec![
            "--state-dir".into(),
            state.as_os_str().to_owned(),
            "--profile".into(),
            profile.as_os_str().to_owned(),
            "--listen".into(),
            options.listen.to_string().into(),
            "--endpoint".into(),
            options.endpoints[0].to_string().into(),
            "--id".into(),
            options.id.as_str().into(),
            "--api-port".into(),
            options.api_port.expect("main HTTP port").to_string().into(),
            "--api-listen-ip".into(),
            options
                .api_listen_ip
                .expect("main HTTP bind IP")
                .to_string()
                .into(),
            "--traffic".into(),
            options.traffic.as_ref().expect("main traffic mode").into(),
        ];
        manager(&args, &options.endpoints)?;
    } else {
        crate::node::initialize_unbound(&state, options.id)?;
    }
    configuration.write(
        "config.json",
        &serde_json::to_vec(&if options.control == "child" {
            json!({"control":"child","listen_ip":options.listen.ip(),"addresses":options.endpoints.iter().map(SocketAddr::ip).collect::<Vec<_>>(),"start_after_join":!options.no_start})
        } else {json!({"control":"main","listen":options.listen,"endpoints":options.endpoints})})
        .map_err(|_| "cannot encode service settings")?,
        false,
    )?;
    units.write("wgfeel.service", contents.as_bytes(), false)?;
    if !options.no_start && options.control == "main" {
        crate::uninstall::services::install_unit("wgfeel.service", &unit_path)?;
    }
    println!(
        "Installed {}. State: {}. {}",
        options.control,
        state.display(),
        if options.control == "child" {
            "Service is stopped. Run the join command issued by main."
        } else if options.no_start {
            "Service was not started; unit file is ready."
        } else {
            "Service enabled and started."
        }
    );
    if options.control == "main" {
        println!("Administrator profile: {}", profile.display());
    }
    Ok(())
}

pub fn activate_child(state: &Path) -> std::result::Result<(), &'static str> {
    let base = state
        .parent()
        .and_then(Path::parent)
        .ok_or("invalid installation path")?;
    let installed = crate::uninstall::installed::Installed::inspect(Path::new("/"), base)
        .map_err(|_| "cannot verify installed child service")?
        .ok_or("missing installed child service")?;
    crate::uninstall::services::install_unit("wgfeel.service", &installed.unit)
        .map_err(|_| "configuration saved, but service activation failed; inspect wgfeel.service and run systemctl enable --now wgfeel.service")
}
