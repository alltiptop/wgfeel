use super::{
    paths,
    profile::{Profile, validate_endpoint},
};
use rustix::fs::{self, AtFlags};
use std::{
    collections::BTreeMap,
    ffi::OsString,
    io,
    net::SocketAddr,
    path::{Path, PathBuf},
};
use wgfeel_core::{
    AdminCredential, Config, GatewayAssignment, ManagementConfig, ManagementDocument, NodeId,
    Policy, TrafficMode,
};
use wgfeel_store::{ManagementApi, ManagementStore, RestApi};
use zeroize::Zeroizing;

const USAGE: &str = "usage: wgfeel init --control main --state-dir ABS --profile ABS --listen ADDRESS:PORT --endpoint ADDRESS:PORT [--id ID] [--api-port PORT] [--api-listen-ip IP]";

pub(crate) fn run(args: &[OsString]) -> Result<(), &'static str> {
    initialize(args, None)
}

pub(crate) fn initialize(
    args: &[OsString],
    selected: Option<&[SocketAddr]>,
) -> Result<(), &'static str> {
    let options = Options::parse(args)?;
    // Validate destinations and prepare each independent identity before any
    // durable writes. The selected provider supplies all randomness and X25519.
    let (node_private, node_public, gateway_public) = wgfeel_host::generate_node_keys()?;
    let (admin_private, admin_public) = generate_key()?;
    if node_public == admin_public || gateway_public == admin_public {
        return Err("generated Management identities must be distinct");
    }
    let mut bearer = Zeroizing::new([0u8; 32]);
    aws_lc_rs::rand::fill(bearer.as_mut_slice())
        .map_err(|_| "cannot generate Management credential")?;
    let credential =
        AdminCredential::new(*bearer).map_err(|_| "invalid generated Management credential")?;
    let mut endpoints = selected
        .unwrap_or(std::slice::from_ref(&options.endpoint))
        .to_vec();
    if selected.is_none() && options.listen.ip().is_unspecified() {
        for endpoint in wgfeel_host::discover_endpoints(options.listen.port()) {
            if endpoints.len() < wgfeel_core::MAX_NODE_ENDPOINTS && !endpoints.contains(&endpoint) {
                endpoints.push(endpoint);
            }
        }
    }
    let api = ManagementApi::new(options.listen, admin_public)
        .and_then(|api| api.with_endpoints(endpoints.clone()))
        .map_err(|_| "invalid Management listen address")?;
    let assignments = vec![
        GatewayAssignment::new(
            options.id.clone(),
            node_public.clone(),
            gateway_public,
            vec![],
            vec![],
        )
        .and_then(|node| node.with_traffic(options.traffic))
        .and_then(|node| node.with_endpoints(endpoints))
        .map(|node| node.with_auto_networks(true))
        .map_err(|_| "invalid main forwarding configuration")?,
    ];
    let document = ManagementDocument::new(
        ManagementConfig::new(
            options.id.clone(),
            Config::new(1, vec![], Policy::new(vec![], vec![], vec![]))
                .map_err(|_| "cannot create Management configuration")?,
            assignments,
        )
        .map_err(|_| "cannot create Management configuration")?,
        vec![],
    )
    .map_err(|_| "cannot create Management document")?;
    let profile = Profile::new(
        options.id,
        options.endpoint,
        node_public,
        admin_private,
        credential,
    )?;
    // Inspect profile ancestry before creating a missing state leaf. Exclusive
    // profile creation below repeats this check and closes an existence race.
    let (profile_parent, profile_name) = paths::parent(&options.profile)?;
    match fs::statat(&profile_parent, &profile_name, AtFlags::SYMLINK_NOFOLLOW) {
        Err(rustix::io::Errno::NOENT) => (),
        _ => return Err("private Management profile already exists or cannot be inspected"),
    }
    match std::fs::symlink_metadata(&options.state) {
        Ok(_) => {
            paths::parent(&options.state.join("state.json"))?;
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            paths::parent(&options.state)?;
        }
        Err(_) => return Err("cannot inspect Management state directory"),
    }
    let mut store = ManagementStore::initialize(&options.state)
        .map_err(|_| "cannot initialize protected Management state")?;
    if store
        .load()
        .map_err(|_| "cannot inspect existing Management state")?
        .is_some()
    {
        return Err("Management state already exists");
    }
    reject_reserved_profile(&options.state, &options.profile)?;
    profile.create_transport(&options.profile)?;
    store.initialize_with_apis(&document, &node_private, profile.credential()?, &api, options.rest.as_ref())
        .map_err(|_| "Management state commit failed or is uncertain; preserve the private profile and inspect state before retry")?;
    Ok(())
}

use wgfeel_host::generate_service_key as generate_key;

fn reject_reserved_profile(state: &Path, profile: &Path) -> Result<(), &'static str> {
    let (profile_parent, name) = paths::parent(profile)?;
    if name != "state.json" && name != ".pending" && name != "api.sock" {
        return Ok(());
    }
    let (state_directory, _) = paths::parent(&state.join("state.json"))?;
    let first = fs::fstat(&profile_parent).map_err(|_| "cannot inspect profile directory")?;
    let second = fs::fstat(&state_directory).map_err(|_| "cannot inspect state directory")?;
    if first.st_dev == second.st_dev && first.st_ino == second.st_ino {
        return Err("profile path conflicts with reserved Management state files");
    }
    Ok(())
}

struct Options {
    state: PathBuf,
    profile: PathBuf,
    listen: SocketAddr,
    endpoint: SocketAddr,
    id: NodeId,
    rest: Option<RestApi>,
    traffic: TrafficMode,
}
impl Options {
    fn parse(args: &[OsString]) -> Result<Self, &'static str> {
        if !args.len().is_multiple_of(2) {
            return Err(USAGE);
        }
        let mut values = BTreeMap::new();
        for pair in args.as_chunks::<2>().0 {
            let name = pair[0].to_str().ok_or(USAGE)?;
            if ![
                "--state-dir",
                "--profile",
                "--listen",
                "--endpoint",
                "--id",
                "--api-port",
                "--api-listen-ip",
                "--traffic",
            ]
            .contains(&name)
                || values.insert(name, &pair[1]).is_some()
            {
                return Err(USAGE);
            }
        }
        let state = PathBuf::from(*values.get("--state-dir").ok_or(USAGE)?);
        let profile = PathBuf::from(*values.get("--profile").ok_or(USAGE)?);
        if !state.is_absolute() || !profile.is_absolute() {
            return Err("Management initialization paths must be absolute");
        }
        let listen: SocketAddr = values
            .get("--listen")
            .and_then(|value| value.to_str())
            .ok_or(USAGE)?
            .parse()
            .map_err(|_| "invalid Management listen address")?;
        let endpoint = values
            .get("--endpoint")
            .and_then(|value| value.to_str())
            .ok_or(USAGE)?
            .parse()
            .map_err(|_| "invalid profile endpoint")?;
        validate_endpoint(endpoint)?;
        let traffic = values
            .get("--traffic")
            .map(|value| match value.to_str() {
                Some("entry") => Ok(TrafficMode::Entry),
                Some("relay") => Ok(TrafficMode::Relay),
                Some("off") => Ok(TrafficMode::Off),
                _ => Err("traffic mode must be entry, relay or off"),
            })
            .transpose()?
            .unwrap_or_default();
        let rest = if let Some(port) = values.get("--api-port") {
            let port: u16 = port
                .to_str()
                .ok_or(USAGE)?
                .parse()
                .map_err(|_| "HTTP API port must be 1..65535")?;
            let ip = values
                .get("--api-listen-ip")
                .map(|value| value.to_str().ok_or(USAGE))
                .transpose()?
                .unwrap_or("127.0.0.1")
                .parse()
                .map_err(|_| "invalid HTTP API listen IP")?;
            Some(
                RestApi::new(SocketAddr::new(ip, port))
                    .map_err(|_| "invalid HTTP API listen address")?,
            )
        } else {
            if values.contains_key("--api-listen-ip") {
                return Err("--api-listen-ip requires --api-port");
            }
            None
        };
        let id = if let Some(id) = values.get("--id") {
            NodeId::new(id.to_str().ok_or(USAGE)?).map_err(|_| "invalid Management identity")?
        } else {
            let mut bytes = [0u8; 16];
            aws_lc_rs::rand::fill(&mut bytes).map_err(|_| "cannot generate Management identity")?;
            let hex: String = bytes.iter().map(|byte| format!("{byte:02x}")).collect();
            NodeId::new(&format!("management-{hex}"))
                .map_err(|_| "invalid generated Management identity")?
        };
        Ok(Self {
            state,
            profile,
            listen,
            endpoint,
            id,
            rest,
            traffic,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::management::profile::Profile;
    use gotatun::x25519::{PublicKey, StaticSecret};
    use std::{
        fs::{self, OpenOptions},
        io::Write,
        os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt},
        path::PathBuf,
        sync::atomic::{AtomicUsize, Ordering},
    };
    use wgfeel_core::{
        AdminCredential, Config, ManagementConfig, ManagementDocument, NodeId, Policy,
        ServicePrivateKey,
    };
    use wgfeel_store::ManagementStore;
    static NEXT: AtomicUsize = AtomicUsize::new(0);
    struct Directory(PathBuf);
    impl Directory {
        fn new() -> Self {
            let path = std::env::temp_dir().join(format!(
                "wgfeel-bootstrap-{}-{}",
                std::process::id(),
                NEXT.fetch_add(1, Ordering::Relaxed)
            ));
            fs::create_dir(&path).unwrap();
            fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).unwrap();
            Self(path)
        }
        fn state(&self) -> PathBuf {
            self.0.join("state")
        }
        fn profile(&self) -> PathBuf {
            self.0.join("admin.profile")
        }
        fn args(&self) -> Vec<OsString> {
            vec![
                "--state-dir".into(),
                self.state().into_os_string(),
                "--profile".into(),
                self.profile().into_os_string(),
                "--listen".into(),
                "0.0.0.0:51820".into(),
                "--endpoint".into(),
                "203.0.113.7:51820".into(),
                "--id".into(),
                "management".into(),
            ]
        }
    }
    impl Drop for Directory {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }
    fn document() -> ManagementDocument {
        ManagementDocument::new(
            ManagementConfig::new(
                NodeId::new("existing").unwrap(),
                Config::new(7, vec![], Policy::new(vec![], vec![], vec![])).unwrap(),
                vec![],
            )
            .unwrap(),
            vec![],
        )
        .unwrap()
    }
    fn public(key: &ServicePrivateKey) -> [u8; 32] {
        PublicKey::from(&StaticSecret::from(*key.expose_bytes())).to_bytes()
    }
    #[test]
    fn init_persists_main_entry_assignment_and_corresponding_private_profile() {
        let directory = Directory::new();
        run(&directory.args()).expect("valid Management initialization rejected");
        let profile = Profile::load(&directory.profile()).unwrap();
        let store = ManagementStore::open(&directory.state()).unwrap();
        let state = store.load().unwrap().unwrap();
        assert_eq!(state.document().routing().generation(), 1);
        assert_eq!(
            state.document().routing().management_id(),
            profile.management_id()
        );
        assert_eq!(profile.management_id().as_str(), "management");
        assert!(state.document().clients().is_empty());
        assert!(state.document().routing().config().networks().is_empty());
        let assignments = state.document().routing().assignments();
        assert_eq!(assignments.len(), 1);
        assert_eq!(assignments[0].recipient(), profile.management_id());
        assert_eq!(assignments[0].traffic(), TrafficMode::Entry);
        assert_eq!(
            assignments[0].service_public_key(),
            profile.server_public_key()
        );
        assert_eq!(
            public(state.service_private_key()),
            *profile.server_public_key().as_bytes()
        );
        assert_eq!(
            public(profile.admin_private_key()),
            *state.api().unwrap().admin_public_key().as_bytes()
        );
        assert!(profile.credential().is_err());
        assert!(
            state.service_private_key().expose_bytes()
                != profile.admin_private_key().expose_bytes()
        );
        assert!(
            !state
                .admin_verifier()
                .verify(state.service_private_key().expose_bytes())
        );
        assert!(
            !state
                .admin_verifier()
                .verify(profile.admin_private_key().expose_bytes())
        );
        assert_eq!(profile.endpoint(), "203.0.113.7:51820".parse().unwrap());
        assert_eq!(
            state.api().unwrap().listen(),
            "0.0.0.0:51820".parse().unwrap()
        );
        for path in [directory.profile(), directory.state().join("state.json")] {
            let meta = fs::symlink_metadata(path).unwrap();
            assert_eq!(meta.permissions().mode() & 0o7777, 0o600);
            assert_eq!(meta.nlink(), 1);
        }
        let json = fs::read_to_string(directory.state().join("state.json")).unwrap();
        assert!(json.contains("\"management_storage_version\":7"));
        assert!(!json.contains("\"admin_credential\""));
        assert!(
            !fs::read_to_string(directory.profile())
                .unwrap()
                .contains("\"credential\"")
        );
        drop(store);
        let reopened = ManagementStore::open(&directory.state())
            .unwrap()
            .load()
            .unwrap()
            .unwrap();
        assert_eq!(reopened.document(), state.document());
        assert!(
            reopened.service_private_key().expose_bytes()
                == state.service_private_key().expose_bytes()
        );
        assert!(reopened.admin_verifier() == state.admin_verifier());
    }
    #[test]
    fn init_generates_fresh_independent_id_and_secrets_for_each_installation() {
        let first = Directory::new();
        let second = Directory::new();
        for directory in [&first, &second] {
            let mut args = directory.args();
            args.truncate(8);
            run(&args).unwrap();
        }
        let first = Profile::load(&first.profile()).unwrap();
        let second = Profile::load(&second.profile()).unwrap();
        assert_ne!(first.management_id(), second.management_id());
        assert_ne!(first.server_public_key(), second.server_public_key());
        assert!(
            first.admin_private_key().expose_bytes() != second.admin_private_key().expose_bytes()
        );
        assert!(first.credential().is_err());
        assert!(second.credential().is_err());
    }
    #[test]
    fn init_never_overwrites_existing_profile_or_existing_state() {
        let directory = Directory::new();
        OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(directory.profile())
            .unwrap()
            .write_all(b"keep existing profile")
            .unwrap();
        assert!(run(&directory.args()).is_err());
        assert_eq!(
            fs::read(directory.profile()).unwrap(),
            b"keep existing profile"
        );
        assert!(!directory.state().join("state.json").exists());
        let directory = Directory::new();
        ManagementStore::initialize(&directory.state())
            .unwrap()
            .commit(
                &document(),
                &wgfeel_test_support::fixture_node_keys([53; 32]),
                &AdminCredential::new([59; 32]).unwrap(),
                None,
            )
            .unwrap();
        let before = fs::read(directory.state().join("state.json")).unwrap();
        assert!(run(&directory.args()).is_err());
        assert!(fs::read(directory.state().join("state.json")).unwrap() == before);
        assert!(!directory.profile().exists());
    }
    #[test]
    fn profile_cannot_use_store_reserved_state_or_staging_names() {
        for name in ["state.json", ".pending", "api.sock"] {
            let directory = Directory::new();
            drop(ManagementStore::initialize(&directory.state()).unwrap());
            let mut args = directory.args();
            args[3] = directory.state().join(name).into_os_string();
            assert!(run(&args).is_err());
            assert!(!directory.state().join("state.json").exists());
            assert!(!directory.state().join(".pending").exists());
            assert!(!directory.state().join("api.sock").exists());
        }
    }
    #[test]
    fn malformed_options_do_not_create_profile_or_state() {
        for (position, value) in [
            (1, "relative"),
            (3, "relative.profile"),
            (5, "0.0.0.0:0"),
            (7, "0.0.0.0:51820"),
            (7, "224.0.0.1:51820"),
            (9, "invalid/id"),
        ] {
            let directory = Directory::new();
            let mut args = directory.args();
            args[position] = value.into();
            assert!(run(&args).is_err());
            assert!(!directory.profile().exists());
            assert!(!directory.state().exists());
        }
        let directory = Directory::new();
        let mut args = directory.args();
        args.extend(["--id".into(), "duplicate".into()]);
        assert!(run(&args).is_err());
        assert!(!directory.profile().exists());
        assert!(!directory.state().exists());
    }
}
