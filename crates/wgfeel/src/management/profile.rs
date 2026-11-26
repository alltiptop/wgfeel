use super::paths;
use rustix::{
    fs::{self, FileType, Mode, OFlags},
    process::geteuid,
};
use serde::{Deserialize, Serialize};
use std::{
    fmt,
    fs::File,
    io::{self, Read, Write},
    net::{IpAddr, SocketAddr},
    path::Path,
};
use wgfeel_core::{AdminCredential, DevicePublicKey, NodeId, ServicePrivateKey};
use zeroize::Zeroizing;

pub(super) const MAX_PROFILE_BYTES: usize = 4096;

/// Private local client material. This value deliberately has no Debug or
/// general-purpose serialization implementation.
pub(super) struct Profile {
    management_id: NodeId,
    endpoint: SocketAddr,
    server_public_key: DevicePublicKey,
    admin_private_key: ServicePrivateKey,
    credential: Option<AdminCredential>,
}
impl Profile {
    pub(super) fn new(
        management_id: NodeId,
        endpoint: SocketAddr,
        server_public_key: DevicePublicKey,
        admin_private_key: ServicePrivateKey,
        credential: AdminCredential,
    ) -> Result<Self, &'static str> {
        validate_endpoint(endpoint)?;
        Ok(Self {
            management_id,
            endpoint,
            server_public_key,
            admin_private_key,
            credential: Some(credential),
        })
    }

    pub(super) fn load(path: &Path) -> Result<Self, &'static str> {
        let (parent, name) = paths::parent(path)?;
        let fd = fs::openat(
            &parent,
            name,
            OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .map_err(|_| "cannot open private Management profile")?;
        let mut file = File::from(fd);
        check_file(&file)?;
        let mut buffer = Zeroizing::new([0u8; MAX_PROFILE_BYTES + 1]);
        let mut length = 0;
        while length < buffer.len() {
            match file.read(&mut buffer[length..]) {
                Ok(0) => break,
                Ok(count) => length += count,
                Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
                Err(_) => return Err("cannot read private Management profile"),
            }
        }
        if length > MAX_PROFILE_BYTES {
            return Err("private Management profile is too large");
        }
        let raw: ReadProfile = serde_json::from_slice(&buffer[..length])
            .map_err(|_| "invalid private Management profile")?;
        if raw.profile_version != 1 {
            return Err("unsupported private Management profile version");
        }
        let credential = raw
            .credential
            .map(|secret| AdminCredential::new(*secret.0).map_err(|_| "invalid profile credential"))
            .transpose()?;
        Ok(Self {
            management_id: NodeId::new(&raw.management_id)
                .map_err(|_| "invalid profile Management identity")?,
            endpoint: {
                validate_endpoint(raw.endpoint)?;
                raw.endpoint
            },
            server_public_key: DevicePublicKey::new(raw.server_public_key)
                .map_err(|_| "invalid profile server public key")?,
            admin_private_key: ServicePrivateKey::new(*raw.admin_private_key.0)
                .map_err(|_| "invalid profile admin private key")?,
            credential,
        })
    }

    /// Exclusive creation precedes authoritative state publication. On failure
    /// the new file is retained; callers must never erase a possibly durable
    /// profile or replace an existing client identity automatically.
    pub(super) fn create_transport(&self, path: &Path) -> Result<(), &'static str> {
        let raw = WriteProfile {
            profile_version: 1,
            management_id: self.management_id.as_str(),
            endpoint: self.endpoint,
            server_public_key: self.server_public_key.as_bytes(),
            admin_private_key: self.admin_private_key.expose_bytes(),
            credential: None,
        };
        let mut buffer = Zeroizing::new([0u8; MAX_PROFILE_BYTES]);
        let length = {
            let mut writer = io::Cursor::new(buffer.as_mut_slice());
            serde_json::to_writer(&mut writer, &raw)
                .map_err(|_| "cannot encode private Management profile")?;
            writer.position() as usize
        };
        let (parent, name) = paths::parent(path)?;
        let fd = fs::openat(
            &parent,
            name,
            OFlags::WRONLY
                | OFlags::CREATE
                | OFlags::EXCL
                | OFlags::NOFOLLOW
                | OFlags::NONBLOCK
                | OFlags::CLOEXEC,
            Mode::RUSR | Mode::WUSR,
        )
        .map_err(|_| "cannot exclusively create private Management profile")?;
        let mut file = File::from(fd);
        check_file(&file)?;
        file.write_all(&buffer[..length])
            .map_err(|_| "cannot write private Management profile")?;
        file.sync_all()
            .map_err(|_| "cannot sync private Management profile")?;
        fs::fsync(&parent).map_err(|_| "cannot sync private Management profile directory")?;
        Ok(())
    }
    pub(super) fn management_id(&self) -> &NodeId {
        &self.management_id
    }
    pub(super) fn endpoint(&self) -> SocketAddr {
        self.endpoint
    }
    pub(super) fn server_public_key(&self) -> &DevicePublicKey {
        &self.server_public_key
    }
    pub(super) fn admin_private_key(&self) -> &ServicePrivateKey {
        &self.admin_private_key
    }
    pub(super) fn credential(&self) -> Result<&AdminCredential, &'static str> {
        self.credential.as_ref().ok_or(
            "remote profile has no API token; issue a token with wgfeel token rotate on Management",
        )
    }
}

pub(super) fn validate_endpoint(endpoint: SocketAddr) -> Result<(), &'static str> {
    if endpoint.port() == 0
        || endpoint.ip().is_unspecified()
        || endpoint.ip().is_multicast()
        || match endpoint.ip() {
            IpAddr::V4(address) => address.is_broadcast(),
            IpAddr::V6(address) => address.to_ipv4_mapped().is_some(),
        }
    {
        return Err("profile endpoint must be a concrete unicast address with a port");
    }
    Ok(())
}

fn check_file(file: &File) -> Result<(), &'static str> {
    let stat = fs::fstat(file).map_err(|_| "cannot inspect private Management profile")?;
    if FileType::from_raw_mode(stat.st_mode) != FileType::RegularFile
        || stat.st_uid != geteuid().as_raw()
        || stat.st_mode & 0o7777 != 0o600
        || stat.st_nlink != 1
        || stat.st_size < 0
        || stat.st_size > MAX_PROFILE_BYTES as i64
    {
        return Err(
            "private Management profile requires one owned regular file with mode 0600 within its size bound",
        );
    }
    Ok(())
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ReadProfile {
    profile_version: u64,
    management_id: String,
    endpoint: SocketAddr,
    server_public_key: [u8; 32],
    admin_private_key: SecretBytes,
    #[serde(default, deserialize_with = "read_credential")]
    credential: Option<SecretBytes>,
}
fn read_credential<'de, D: serde::Deserializer<'de>>(
    deserializer: D,
) -> Result<Option<SecretBytes>, D::Error> {
    SecretBytes::deserialize(deserializer).map(Some)
}

#[derive(Serialize)]
struct WriteProfile<'a> {
    profile_version: u8,
    management_id: &'a str,
    endpoint: SocketAddr,
    server_public_key: &'a [u8; 32],
    admin_private_key: &'a [u8; 32],
    #[serde(skip_serializing_if = "Option::is_none")]
    credential: Option<&'a [u8; 32]>,
}

struct SecretBytes(Zeroizing<[u8; 32]>);
impl<'de> Deserialize<'de> for SecretBytes {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct SecretVisitor;
        impl<'de> serde::de::Visitor<'de> for SecretVisitor {
            type Value = SecretBytes;
            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str("32 secret bytes")
            }
            fn visit_seq<A: serde::de::SeqAccess<'de>>(
                self,
                mut sequence: A,
            ) -> Result<Self::Value, A::Error> {
                let mut bytes = Zeroizing::new([0u8; 32]);
                for byte in bytes.iter_mut() {
                    *byte = sequence
                        .next_element()?
                        .ok_or_else(|| serde::de::Error::custom("invalid secret length"))?;
                }
                if sequence.next_element::<serde::de::IgnoredAny>()?.is_some() {
                    return Err(serde::de::Error::custom("invalid secret length"));
                }
                Ok(SecretBytes(bytes))
            }
        }
        deserializer.deserialize_seq(SecretVisitor)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        fs::{self, OpenOptions},
        io::Write,
        os::unix::fs::{OpenOptionsExt, PermissionsExt, symlink},
        path::PathBuf,
        sync::atomic::{AtomicUsize, Ordering},
    };

    static NEXT: AtomicUsize = AtomicUsize::new(0);
    struct Directory(PathBuf);
    impl Directory {
        fn new() -> Self {
            let path = std::env::temp_dir().join(format!(
                "wgfeel-profile-{}-{}",
                std::process::id(),
                NEXT.fetch_add(1, Ordering::Relaxed)
            ));
            fs::create_dir(&path).unwrap();
            fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).unwrap();
            Self(path)
        }
        fn file(&self) -> PathBuf {
            self.0.join("admin.profile")
        }
        fn write(&self, text: &str) {
            OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(self.file())
                .unwrap()
                .write_all(text.as_bytes())
                .unwrap();
        }
    }
    impl Drop for Directory {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }
    fn bytes(value: u8, count: usize) -> String {
        format!(
            "[{}]",
            std::iter::repeat_n(value.to_string(), count)
                .collect::<Vec<_>>()
                .join(",")
        )
    }
    fn valid() -> String {
        format!(
            r#"{{"profile_version":1,"management_id":"management","endpoint":"203.0.113.7:51820","server_public_key":{},"admin_private_key":{},"credential":{}}}"#,
            bytes(11, 32),
            bytes(31, 32),
            bytes(47, 32)
        )
    }
    #[test]
    fn hand_authored_private_profile_loads_exact_identity_endpoint_and_credentials() {
        let directory = Directory::new();
        directory.write(&valid());
        let profile = Profile::load(&directory.file()).expect("valid private profile rejected");
        assert_eq!(profile.management_id().as_str(), "management");
        assert_eq!(profile.endpoint(), "203.0.113.7:51820".parse().unwrap());
        assert_eq!(profile.server_public_key().as_bytes(), &[11; 32]);
        assert!(profile.admin_private_key().expose_bytes() == &[31; 32]);
        assert!(profile.credential().unwrap().expose_bytes() == &[47; 32]);
    }
    #[test]
    fn decoder_rejects_unknown_duplicate_fields_wrong_versions_and_secret_shapes() {
        let original = valid();
        let mut inputs = vec![
            original.replacen("{", "{\"extra\":1,", 1),
            original.replacen("{", "{\"profile_version\":1,", 1),
            original.replace("\"profile_version\":1", "\"profile_version\":2"),
            original.replace("\"management\"", "\"not/valid\""),
            original.replace("\"management_id\":\"management\",", ""),
            format!("{original}{{}}"),
        ];
        for name in ["admin_private_key", "credential", "server_public_key"] {
            let byte = match name {
                "admin_private_key" => 31,
                "credential" => 47,
                _ => 11,
            };
            let field = format!("\"{name}\":{}", bytes(byte, 32));
            for value in [
                "null".to_owned(),
                "\"secret\"".to_owned(),
                bytes(byte, 31),
                bytes(byte, 33),
                bytes(0, 32),
                bytes(byte, 32).replacen(&byte.to_string(), "256", 1),
                bytes(byte, 32).replacen(&byte.to_string(), "-1", 1),
            ] {
                inputs.push(original.replace(&field, &format!("\"{name}\":{value}")));
            }
            inputs.push(original.replacen("{", &format!("{{{field},"), 1));
        }
        for input in inputs {
            let directory = Directory::new();
            directory.write(&input);
            assert!(
                Profile::load(&directory.file()).is_err(),
                "invalid private profile accepted"
            );
        }
    }
    #[test]
    fn endpoint_must_be_concrete_unicast_with_a_port() {
        for address in [
            "0.0.0.0:51820",
            "[::]:51820",
            "203.0.113.7:0",
            "224.0.0.1:51820",
            "255.255.255.255:51820",
            "[ff02::1]:51820",
            "[::ffff:192.0.2.1]:51820",
        ] {
            let directory = Directory::new();
            directory.write(&valid().replace("203.0.113.7:51820", address));
            assert!(Profile::load(&directory.file()).is_err());
        }
    }
    #[test]
    fn exact_byte_bound_accepts_whitespace_but_one_extra_byte_is_rejected() {
        let mut text = valid();
        text.extend(std::iter::repeat_n(' ', MAX_PROFILE_BYTES - text.len()));
        let directory = Directory::new();
        directory.write(&text);
        assert!(Profile::load(&directory.file()).is_ok());
        let other = Directory::new();
        text.push(' ');
        other.write(&text);
        assert!(Profile::load(&other.file()).is_err());
    }
    #[test]
    fn unsafe_file_modes_links_and_ancestors_are_rejected_without_changes() {
        let directory = Directory::new();
        directory.write(&valid());
        let original = fs::read(directory.file()).unwrap();
        fs::set_permissions(directory.file(), fs::Permissions::from_mode(0o644)).unwrap();
        assert!(Profile::load(&directory.file()).is_err());
        fs::set_permissions(directory.file(), fs::Permissions::from_mode(0o600)).unwrap();
        let alias = directory.0.join("alias");
        symlink(directory.file(), &alias).unwrap();
        assert!(Profile::load(&alias).is_err());
        let hard = directory.0.join("hard");
        fs::hard_link(directory.file(), &hard).unwrap();
        assert!(Profile::load(&hard).is_err());
        fs::remove_file(hard).unwrap();
        let nested = directory.0.join("private");
        fs::create_dir(&nested).unwrap();
        fs::set_permissions(&nested, fs::Permissions::from_mode(0o700)).unwrap();
        fs::rename(directory.file(), nested.join("admin.profile")).unwrap();
        fs::set_permissions(&directory.0, fs::Permissions::from_mode(0o770)).unwrap();
        assert!(Profile::load(&nested.join("admin.profile")).is_err());
        assert!(fs::read(nested.join("admin.profile")).unwrap() == original);
    }
    #[test]
    fn nonregular_profile_is_rejected_without_blocking_or_removal() {
        let directory = Directory::new();
        rustix::fs::mkfifoat(
            rustix::fs::CWD,
            directory.file(),
            rustix::fs::Mode::RUSR | rustix::fs::Mode::WUSR,
        )
        .unwrap();
        assert!(Profile::load(&directory.file()).is_err());
        assert!(fs::symlink_metadata(directory.file()).is_ok());
    }
}
