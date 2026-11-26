//! Bounded in-process engine measurements for `small` and `stress` cases.
//! Excludes confined worker fleets, service load and mesh forwarding.
use std::fs::File;
use std::io::Read;
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::{Duration, Instant};

use gotatun::noise::{Tunn, TunnResult, index_table::IndexTable, rate_limiter::RateLimiter};
use gotatun::packet::Packet;
use gotatun::x25519::{PublicKey, StaticSecret};
use wgfeel_core::{
    DeviceId, DevicePublicKey, NetworkId, NodeId, ServicePrivateKey, TenantPrivateKey,
};
use wgfeel_wireguard::{
    ContextConfig, ContextId, DatagramEvent, Gateway, Limits, PeerConfig, PeerId, WireGuardError,
};

type Result<T> = std::result::Result<T, &'static str>;
const FORGED_BATCH: usize = 1024;
const ROUNDS: usize = 20;
const BURST: usize = 8;
const LIMIT: u32 = 1000;
const MAX_SECONDS: u64 = 45;
const DEVICES_PER_TENANT: usize = 5;

fn require(condition: bool, message: &'static str) -> Result<()> {
    if condition { Ok(()) } else { Err(message) }
}

#[derive(Clone, Copy)]
struct Case {
    name: &'static str,
    tenants: usize,
    service_peers: usize,
}

impl Case {
    fn parse(value: &str) -> Result<Self> {
        match value {
            "small" => Ok(Self {
                name: "small",
                tenants: 1,
                service_peers: 1,
            }),
            "stress" => Ok(Self {
                name: "stress",
                tenants: 150,
                service_peers: 150,
            }),
            _ => Err("expected exactly one case argument: small or stress"),
        }
    }

    fn device_peers(self) -> usize {
        self.tenants * DEVICES_PER_TENANT
    }
    fn total_peers(self) -> usize {
        self.device_peers() + self.service_peers
    }
}

struct Deadline(Instant);
impl Deadline {
    fn check(&self) -> Result<()> {
        require(
            self.0.elapsed() < Duration::from_secs(MAX_SECONDS),
            "profile deadline exceeded",
        )
    }
}

#[derive(Clone, Copy)]
struct FixtureKey {
    role: u8,
    index: u16,
}
impl FixtureKey {
    fn bytes(self) -> [u8; 32] {
        // Public deterministic test fixtures, never operational key generation.
        let mut bytes = [43; 32];
        bytes[8] = self.role;
        bytes[9..11].copy_from_slice(&self.index.to_be_bytes());
        bytes
    }
    fn public(self) -> [u8; 32] {
        PublicKey::from(&StaticSecret::from(self.bytes())).to_bytes()
    }
}

fn address(host: u8, port: u16) -> SocketAddr {
    SocketAddr::from((Ipv4Addr::new(198, 51, 100, host), port))
}

struct PeerSpec {
    context: ContextId,
    peer: PeerId,
    key: FixtureKey,
    gateway_key: FixtureKey,
    source: SocketAddr,
}

fn peer_spec(case: Case, index: usize) -> Result<PeerSpec> {
    require(index < case.total_peers(), "fixture index outside case")?;
    let source = address(2, 30000 + index as u16);
    if index < case.device_peers() {
        let tenant = index / DEVICES_PER_TENANT;
        Ok(PeerSpec {
            context: ContextId::Tenant(
                NetworkId::new(&format!("tenant-{tenant}"))
                    .map_err(|_| "fixture tenant ID rejected")?,
            ),
            peer: PeerId::Device(
                DeviceId::new(&format!("device-{}", index % DEVICES_PER_TENANT))
                    .map_err(|_| "fixture device ID rejected")?,
            ),
            key: FixtureKey {
                role: 3,
                index: index as u16,
            },
            gateway_key: FixtureKey {
                role: 1,
                index: tenant as u16,
            },
            source,
        })
    } else {
        let node = index - case.device_peers();
        Ok(PeerSpec {
            context: ContextId::Service,
            peer: PeerId::Node(
                NodeId::new(&format!("node-{node}")).map_err(|_| "fixture node ID rejected")?,
            ),
            key: FixtureKey {
                role: 4,
                index: node as u16,
            },
            gateway_key: FixtureKey { role: 2, index: 0 },
            source,
        })
    }
}

fn configuration(case: Case, deadline: &Deadline) -> Result<Vec<ContextConfig>> {
    let mut contexts = Vec::with_capacity(case.tenants + 1);
    for tenant in 0..case.tenants {
        deadline.check()?;
        let mut peers = Vec::with_capacity(DEVICES_PER_TENANT);
        for device in 0..DEVICES_PER_TENANT {
            let spec = peer_spec(case, tenant * DEVICES_PER_TENANT + device)?;
            peers.push(PeerConfig {
                id: spec.peer,
                public_key: DevicePublicKey::new(spec.key.public())
                    .map_err(|_| "fixture public key rejected")?,
            });
        }
        contexts.push(ContextConfig::tenant(
            NetworkId::new(&format!("tenant-{tenant}"))
                .map_err(|_| "fixture tenant ID rejected")?,
            TenantPrivateKey::new(
                FixtureKey {
                    role: 1,
                    index: tenant as u16,
                }
                .bytes(),
            )
            .map_err(|_| "fixture tenant key rejected")?,
            peers,
        ));
    }
    let mut peers = Vec::with_capacity(case.service_peers);
    for node in 0..case.service_peers {
        deadline.check()?;
        let spec = peer_spec(case, case.device_peers() + node)?;
        peers.push(PeerConfig {
            id: spec.peer,
            public_key: DevicePublicKey::new(spec.key.public())
                .map_err(|_| "fixture public key rejected")?,
        });
    }
    contexts.push(ContextConfig::service(
        ServicePrivateKey::new(FixtureKey { role: 2, index: 0 }.bytes())
            .map_err(|_| "fixture service key rejected")?,
        peers,
    ));
    Ok(contexts)
}

struct RawPeer {
    spec: PeerSpec,
    engine: Tunn,
    limiter: Arc<RateLimiter>,
}
enum RawOutput {
    Network(Vec<u8>),
    Plaintext(Vec<u8>),
    None,
}
impl RawPeer {
    fn new(spec: PeerSpec) -> Self {
        let private = StaticSecret::from(spec.key.bytes());
        let limiter = Arc::new(RateLimiter::new(
            &PublicKey::from(&private),
            u64::from(LIMIT),
        ));
        let engine = Tunn::new(
            private,
            PublicKey::from(spec.gateway_key.public()),
            None,
            None,
            IndexTable::from_os_rng(),
            Arc::clone(&limiter),
        );
        Self {
            spec,
            engine,
            limiter,
        }
    }
    fn initiate(&mut self) -> Result<Vec<u8>> {
        Ok(self
            .engine
            .format_handshake_initiation(false)
            .ok_or("fixture initiation unavailable")?
            .into_bytes()
            .as_ref()
            .to_vec())
    }
    fn receive(&mut self, bytes: &[u8]) -> Result<RawOutput> {
        self.limiter.try_reset_count();
        let result = match self
            .limiter
            .verify_packet(address(1, 51820), Packet::copy_from(bytes))
        {
            Ok(packet) => self.engine.handle_incoming_packet(packet),
            Err(result) => result,
        };
        match result {
            TunnResult::Done => Ok(RawOutput::None),
            TunnResult::WriteToNetwork(packet) => {
                let packet: Packet = packet.into();
                Ok(RawOutput::Network(packet.as_ref().to_vec()))
            }
            TunnResult::WriteToTunnel(packet) => Ok(RawOutput::Plaintext(packet.as_ref().to_vec())),
            TunnResult::Err(_) => Err("fixture rejected a packet"),
        }
    }
    fn encrypt(&mut self, bytes: &[u8]) -> Result<Vec<u8>> {
        Ok(self
            .engine
            .encapsulate_with_session(Packet::copy_from(bytes))
            .map_err(|_| "fixture session unavailable")?
            .into_bytes()
            .as_ref()
            .to_vec())
    }
}

#[derive(Default)]
struct Counts {
    baseline_handshakes: usize,
    repeat_handshakes: usize,
    forged_rejections: usize,
    targeted_rejections: usize,
    gateway_receives: usize,
    gateway_sends: usize,
    handshake_responses: usize,
    confirmations: usize,
    inbound_plaintexts: usize,
    outbound_plaintexts: usize,
}

fn header(bytes: &[u8], kind: u8, length: usize) -> Result<()> {
    require(
        bytes.len() == length && bytes.get(..4) == Some(&[kind, 0, 0, 0]),
        "unexpected fixture wire type or size",
    )
}

fn network(event: DatagramEvent, spec: &PeerSpec) -> Result<Vec<u8>> {
    match event {
        DatagramEvent::Network {
            destination,
            context,
            peer,
            packet,
        } if destination == spec.source
            && context == spec.context
            && peer.as_ref() == Some(&spec.peer) =>
        {
            Ok(packet.as_bytes().to_vec())
        }
        _ => Err("wrong network event context, peer or endpoint"),
    }
}

fn receive(
    gateway: &mut Gateway,
    spec: &PeerSpec,
    bytes: &[u8],
    counts: &mut Counts,
    deadline: &Deadline,
) -> Result<Option<DatagramEvent>> {
    deadline.check()?;
    counts.gateway_receives += 1;
    gateway
        .receive_datagram(spec.source, bytes)
        .map_err(|_| "gateway rejected expected fixture packet")
}

fn handshake(
    gateway: &mut Gateway,
    peer: &mut RawPeer,
    counts: &mut Counts,
    deadline: &Deadline,
) -> Result<Duration> {
    deadline.check()?;
    let started = Instant::now();
    let initiation = peer.initiate()?;
    header(&initiation, 1, 148)?;
    let response = network(
        receive(gateway, &peer.spec, &initiation, counts, deadline)?
            .ok_or("gateway handshake response absent")?,
        &peer.spec,
    )?;
    header(&response, 2, 92)?;
    counts.handshake_responses += 1;
    let confirmation = match peer.receive(&response)? {
        RawOutput::Network(packet) => packet,
        _ => return Err("fixture handshake confirmation absent"),
    };
    header(&confirmation, 4, 32)?;
    require(
        receive(gateway, &peer.spec, &confirmation, counts, deadline)?.is_none(),
        "confirmation returned unexpected event",
    )?;
    let elapsed = started.elapsed();
    counts.confirmations += 1;
    require(
        gateway
            .endpoint(&peer.spec.context, &peer.spec.peer)
            .map_err(|_| "endpoint lookup failed")?
            == Some(peer.spec.source),
        "authenticated endpoint differs",
    )?;
    Ok(elapsed)
}

fn ip_packet(sequence: u32, reverse: bool) -> [u8; 32] {
    // Complete IPv4 packet with experimental protocol 253 and 12 payload bytes.
    // Sixteen-byte alignment avoids unrelated WireGuard padding in this profile.
    let mut packet = [0; 32];
    packet[0] = 0x45;
    packet[2..4].copy_from_slice(&32_u16.to_be_bytes());
    packet[8] = 64;
    packet[9] = 253;
    let (source, destination) = if reverse { (1, 2) } else { (2, 1) };
    packet[12..16].copy_from_slice(&[10, 222, 0, source]);
    packet[16..20].copy_from_slice(&[10, 222, 0, destination]);
    packet[20..24].copy_from_slice(&sequence.to_be_bytes());
    packet[24..32].copy_from_slice(b"PROFILE!");
    let mut sum: u32 = packet[..20]
        .as_chunks::<2>()
        .0
        .iter()
        .map(|pair| u32::from(u16::from_be_bytes([pair[0], pair[1]])))
        .sum();
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    packet[10..12].copy_from_slice(&(!(sum as u16)).to_be_bytes());
    packet
}

fn probe_data(
    gateway: &mut Gateway,
    peer: &mut RawPeer,
    sequence: u32,
    counts: &mut Counts,
    deadline: &Deadline,
) -> Result<()> {
    let input = ip_packet(sequence, false);
    let encrypted = peer.encrypt(&input)?;
    header(&encrypted, 4, 64)?;
    match receive(gateway, &peer.spec, &encrypted, counts, deadline)?
        .ok_or("inbound plaintext absent")?
    {
        DatagramEvent::Plaintext {
            context,
            peer: identity,
            packet,
        } if context == peer.spec.context
            && identity == peer.spec.peer
            && packet.as_bytes() == input => {}
        _ => return Err("inbound authenticated identity or plaintext differs"),
    }
    counts.inbound_plaintexts += 1;
    deadline.check()?;
    let output = ip_packet(sequence, true);
    counts.gateway_sends += 1;
    let encrypted = network(
        gateway
            .send_datagram(&peer.spec.context, &peer.spec.peer, &output)
            .map_err(|_| "gateway data send failed")?,
        &peer.spec,
    )?;
    header(&encrypted, 4, 64)?;
    match peer.receive(&encrypted)? {
        RawOutput::Plaintext(packet) if packet == output => (),
        _ => return Err("outbound authenticated plaintext differs"),
    }
    counts.outbound_plaintexts += 1;
    Ok(())
}

fn reject(
    gateway: &mut Gateway,
    packet: &[u8],
    expected: WireGuardError,
    counts: &mut Counts,
    deadline: &Deadline,
) -> Result<()> {
    deadline.check()?;
    counts.gateway_receives += 1;
    match gateway.receive_datagram(address(3, 40000), packet) {
        Err(error) if error == expected => Ok(()),
        _ => Err("interference packet did not produce expected rejection"),
    }
}

#[derive(Clone, Copy)]
struct Memory {
    rss: u64,
    anonymous: u64,
    peak: u64,
    virtual_size: u64,
    rollup: Option<[u64; 3]>,
}

fn read_bounded(file: File) -> Result<String> {
    let mut content = String::new();
    file.take(65537)
        .read_to_string(&mut content)
        .map_err(|_| "process memory read failed")?;
    require(
        content.len() <= 65536,
        "process memory record exceeds bound",
    )?;
    Ok(content)
}

fn kib_field(content: &str, name: &str) -> Result<u64> {
    let mut found = None;
    for line in content.lines() {
        if let Some((field, value)) = line.split_once(':')
            && field == name
        {
            require(found.is_none(), "duplicate process memory field")?;
            let mut words = value.split_whitespace();
            let value = words
                .next()
                .ok_or("missing process memory value")?
                .parse()
                .map_err(|_| "invalid process memory value")?;
            require(
                words.next() == Some("kB") && words.next().is_none(),
                "unexpected process memory unit",
            )?;
            found = Some(value);
        }
    }
    found.ok_or("required process memory field absent")
}

impl Memory {
    fn snapshot() -> Result<Self> {
        let status = read_bounded(
            File::open("/proc/self/status").map_err(|_| "process status unavailable")?,
        )?;
        let rollup = match File::open("/proc/self/smaps_rollup") {
            Ok(file) => {
                let rollup = read_bounded(file)?;
                Some([
                    kib_field(&rollup, "Pss")?,
                    kib_field(&rollup, "Private_Clean")?,
                    kib_field(&rollup, "Private_Dirty")?,
                ])
            }
            Err(_) => None,
        };
        Ok(Self {
            rss: kib_field(&status, "VmRSS")?,
            anonymous: kib_field(&status, "RssAnon")?,
            peak: kib_field(&status, "VmHWM")?,
            virtual_size: kib_field(&status, "VmSize")?,
            rollup,
        })
    }
    fn print(self, prefix: &str) {
        println!("{prefix}_rss_kib={}", self.rss);
        println!("{prefix}_anonymous_kib={}", self.anonymous);
        println!("{prefix}_peak_rss_kib={}", self.peak);
        println!("{prefix}_virtual_kib={}", self.virtual_size);
        println!(
            "{prefix}_smaps_available={}",
            usize::from(self.rollup.is_some())
        );
        if let Some([pss, clean, dirty]) = self.rollup {
            println!("{prefix}_pss_kib={pss}");
            println!("{prefix}_private_clean_kib={clean}");
            println!("{prefix}_private_dirty_kib={dirty}");
        }
    }
}

fn percentile(sorted: &[Duration], percent: usize) -> Duration {
    sorted[(percent * sorted.len()).div_ceil(100) - 1]
}

fn print_timings(name: &str, samples: &mut [Duration]) {
    samples.sort_unstable();
    println!("{name}_samples={}", samples.len());
    println!("{name}_min_ns={}", samples[0].as_nanos());
    println!("{name}_p50_ns={}", percentile(samples, 50).as_nanos());
    println!("{name}_p95_ns={}", percentile(samples, 95).as_nanos());
    println!("{name}_max_ns={}", samples[samples.len() - 1].as_nanos());
}

fn run(case: Case) -> Result<()> {
    let deadline = Deadline(Instant::now());
    let initial = Memory::snapshot()?;
    let started = Instant::now();
    let configs = configuration(case, &deadline)?;
    let fixture_configuration_time = started.elapsed();
    let started = Instant::now();
    let mut gateway = Gateway::new(
        configs,
        Limits {
            handshake_limit_per_ip: LIMIT,
        },
    )
    .map_err(|_| "gateway construction failed")?;
    let construction_time = started.elapsed();
    let constructed = Memory::snapshot()?;
    let mut counts = Counts::default();
    let mut baseline = Vec::with_capacity(case.total_peers());
    for index in 0..case.total_peers() {
        deadline.check()?;
        let spec = peer_spec(case, index)?;
        require(
            gateway
                .public_key(&spec.context)
                .map(DevicePublicKey::as_bytes)
                == Some(&spec.gateway_key.public()),
            "gateway public context key differs",
        )?;
        let mut peer = RawPeer::new(spec);
        baseline.push(handshake(&mut gateway, &mut peer, &mut counts, &deadline)?);
        probe_data(
            &mut gateway,
            &mut peer,
            index as u32,
            &mut counts,
            &deadline,
        )?;
        counts.baseline_handshakes += 1;
        // The sole fixture engine is dropped here; gateway sessions stay live.
    }
    let established = Memory::snapshot()?;

    let mut unknown = peer_spec(case, case.device_peers() - 1)?;
    unknown.key = FixtureKey { role: 5, index: 0 };
    let mut unknown = RawPeer::new(unknown);
    let targeted = unknown.initiate()?;
    header(&targeted, 1, 148)?;
    drop(unknown);
    let mut forged = targeted.clone();
    // Standard initiation MAC1 occupies bytes 116..132. No cryptography is implemented here.
    forged[116] ^= 1;

    let started = Instant::now();
    for _ in 0..FORGED_BATCH {
        reject(
            &mut gateway,
            &forged,
            WireGuardError::Protocol,
            &mut counts,
            &deadline,
        )?;
        counts.forged_rejections += 1;
    }
    let forged_time = started.elapsed();
    let mut healthy = RawPeer::new(peer_spec(case, case.device_peers())?);
    let mut completion = Vec::with_capacity(ROUNDS);
    let mut service = Vec::with_capacity(ROUNDS);
    let mut preceding = Vec::with_capacity(ROUNDS);
    for round in 0..ROUNDS {
        deadline.check()?;
        let started = Instant::now();
        for _ in 0..BURST {
            reject(
                &mut gateway,
                &forged,
                WireGuardError::Protocol,
                &mut counts,
                &deadline,
            )?;
            counts.forged_rejections += 1;
        }
        for _ in 0..BURST {
            reject(
                &mut gateway,
                &targeted,
                WireGuardError::UnknownPeer,
                &mut counts,
                &deadline,
            )?;
            counts.targeted_rejections += 1;
        }
        let latency = handshake(&mut gateway, &mut healthy, &mut counts, &deadline)?;
        let total = started.elapsed();
        service.push(latency);
        completion.push(total);
        preceding.push(
            total
                .checked_sub(latency)
                .ok_or("timing boundaries reversed")?,
        );
        probe_data(
            &mut gateway,
            &mut healthy,
            (case.total_peers() + round) as u32,
            &mut counts,
            &deadline,
        )?;
        counts.repeat_handshakes += 1;
    }
    drop(healthy);
    let handshakes = case.total_peers() + ROUNDS;
    require(
        counts.baseline_handshakes == case.total_peers()
            && counts.repeat_handshakes == ROUNDS
            && counts.forged_rejections == FORGED_BATCH + ROUNDS * BURST
            && counts.targeted_rejections == ROUNDS * BURST
            && counts.gateway_receives == handshakes * 3 + FORGED_BATCH + ROUNDS * BURST * 2
            && counts.gateway_sends == handshakes
            && counts.handshake_responses == handshakes
            && counts.confirmations == handshakes
            && counts.inbound_plaintexts == handshakes
            && counts.outbound_plaintexts == handshakes,
        "scenario operation counts differ",
    )?;
    deadline.check()?;
    let elapsed = deadline.0.elapsed();
    println!("profile_version=1");
    println!("case={}", case.name);
    println!("architecture={}", std::env::consts::ARCH);
    println!(
        "available_parallelism={}",
        std::thread::available_parallelism()
            .map_err(|_| "parallelism metadata unavailable")?
            .get()
    );
    println!("debug_assertions={}", usize::from(cfg!(debug_assertions)));
    println!("selected_rust_toolchain=1.99.0\ngotatun_version=0.10.3\naws_lc_rs_version=1.19.0");
    println!("memory_source=proc_self_status_and_optional_smaps_rollup");
    println!("memory_scope=whole_process_allocator_retention_included");
    println!(
        "tenant_contexts={}\ndevice_peers={}\nservice_peers={}\ntotal_contexts={}\ntotal_peers={}",
        case.tenants,
        case.device_peers(),
        case.service_peers,
        case.tenants + 1,
        case.total_peers()
    );
    println!(
        "handshake_limit_per_ip={LIMIT}\nsource_derived_forged_scan_candidates={}",
        case.tenants + 1
    );
    println!(
        "baseline_handshakes={}\nrepeat_handshakes={}\nforged_rejections={}\ntargeted_rejections={}",
        counts.baseline_handshakes,
        counts.repeat_handshakes,
        counts.forged_rejections,
        counts.targeted_rejections
    );
    println!(
        "gateway_receives={}\ngateway_sends={}\nhandshake_responses={}\nconfirmations={}\ninbound_plaintexts={}\noutbound_plaintexts={}",
        counts.gateway_receives,
        counts.gateway_sends,
        counts.handshake_responses,
        counts.confirmations,
        counts.inbound_plaintexts,
        counts.outbound_plaintexts
    );
    initial.print("initial");
    constructed.print("constructed");
    established.print("established");
    println!(
        "fixture_configuration_ns={}\ngateway_construction_ns={}",
        fixture_configuration_time.as_nanos(),
        construction_time.as_nanos()
    );
    println!(
        "forged_batch_count={FORGED_BATCH}\nforged_batch_ns={}\nforged_mean_ns={}",
        forged_time.as_nanos(),
        forged_time.as_nanos() / FORGED_BATCH as u128
    );
    print_timings("baseline_handshake", &mut baseline);
    print_timings("system_service", &mut service);
    print_timings("service_batch_completion", &mut completion);
    print_timings("service_preceding_delay", &mut preceding);
    println!("profile_elapsed_ns={}\nvalidated=1", elapsed.as_nanos());
    // Make the live gateway lifetime extend through all measurements and reporting.
    drop(gateway);
    Ok(())
}

fn main() {
    let mut arguments = std::env::args().skip(1);
    let result = arguments
        .next()
        .ok_or("expected exactly one case argument: small or stress")
        .and_then(|value| {
            require(
                arguments.next().is_none(),
                "expected exactly one case argument: small or stress",
            )?;
            run(Case::parse(&value)?)
        });
    if let Err(error) = result {
        eprintln!("packet profile failed: {error}");
        std::process::exit(1);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn proc_memory_fields_require_exact_name_unit_and_single_value() {
        let fixture = "Name:\tfixture\nVmRSS:\t 1234 kB\nVmSize:\t 9876 kB\n";
        assert_eq!(kib_field(fixture, "VmRSS"), Ok(1234));
        assert!(kib_field(fixture, "RssAnon").is_err());
        assert!(kib_field("VmRSS: 12 MB\n", "VmRSS").is_err());
        assert!(kib_field("VmRSS: 12 kB\nVmRSS: 13 kB\n", "VmRSS").is_err());
        assert!(kib_field("VmRSS: 12 kB extra\n", "VmRSS").is_err());
    }

    #[test]
    fn nearest_rank_percentiles_have_explicit_even_and_small_sample_behavior() {
        let values: Vec<_> = [10, 20, 30, 40, 50, 60].map(Duration::from_nanos).into();
        assert_eq!(percentile(&values, 50), Duration::from_nanos(30));
        assert_eq!(percentile(&values, 95), Duration::from_nanos(60));
        assert_eq!(
            percentile(&[Duration::from_nanos(7)], 95),
            Duration::from_nanos(7)
        );
    }
}
