//! Packet validation and same-family rewriting. Quotes in ICMP errors can end
//! after eight transport bytes; those carry the tuple even when the original
//! transport checksum cannot be recomputed.
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub(super) enum Protocol {
    Tcp,
    Udp,
    Echo,
}

#[derive(Clone, Copy)]
pub(super) struct Flow {
    pub protocol: Protocol,
    ports: [u16; 2],
    pub flags: u8,
    echo_request: bool,
}
pub(super) const FIN: u8 = 1;
pub(super) const SYN: u8 = 2;
pub(super) const RST: u8 = 4;
pub(super) const ACK: u8 = 16;

impl Flow {
    /// The echo identifier is the translated field in both directions.
    pub fn tuple(self, outbound: bool) -> Option<(u16, u16)> {
        match self.protocol {
            Protocol::Echo if self.echo_request == outbound => Some((self.ports[0], 0)),
            Protocol::Echo => None,
            _ if outbound => Some((self.ports[0], self.ports[1])),
            _ => Some((self.ports[1], self.ports[0])),
        }
    }
}

fn word(bytes: &[u8], i: usize) -> u16 {
    u16::from_be_bytes([bytes[i], bytes[i + 1]])
}
fn set_word(bytes: &mut [u8], i: usize, value: u16) {
    bytes[i..i + 2].copy_from_slice(&value.to_be_bytes());
}

#[derive(Clone, Copy)]
pub(super) struct Header {
    pub src: IpAddr,
    pub dst: IpAddr,
    pub len: usize,
    pub offset: usize,
    proto: u8,
    df: bool,
}

fn eligible(ip: IpAddr) -> bool {
    !ip.is_unspecified()
        && !ip.is_loopback()
        && !ip.is_multicast()
        && match ip {
            IpAddr::V4(ip) => !ip.is_broadcast() && !ip.is_link_local(),
            IpAddr::V6(ip) => ip.to_ipv4_mapped().is_none() && !ip.is_unicast_link_local(),
        }
}

impl Header {
    fn parse(bytes: &[u8], quote: bool) -> Option<Self> {
        let header = match bytes.first()? >> 4 {
            4 => {
                let ip = bytes.get(..20)?;
                if ip[0] != 0x45 || word(ip, 6) & !0x4000 != 0 || finish(sum(ip)) != 0 {
                    return None;
                }
                Self {
                    src: IpAddr::V4(Ipv4Addr::from(<[u8; 4]>::try_from(&ip[12..16]).ok()?)),
                    dst: IpAddr::V4(Ipv4Addr::from(<[u8; 4]>::try_from(&ip[16..20]).ok()?)),
                    len: usize::from(word(ip, 2)),
                    offset: 20,
                    proto: ip[9],
                    df: word(ip, 6) == 0x4000,
                }
            }
            6 => {
                let ip = bytes.get(..40)?;
                Self {
                    src: IpAddr::V6(Ipv6Addr::from(<[u8; 16]>::try_from(&ip[8..24]).ok()?)),
                    dst: IpAddr::V6(Ipv6Addr::from(<[u8; 16]>::try_from(&ip[24..40]).ok()?)),
                    len: usize::from(word(ip, 4)) + 40,
                    offset: 40,
                    proto: ip[6],
                    df: true,
                }
            }
            _ => return None,
        };
        if header.len < header.offset + 8
            || !eligible(header.src)
            || !eligible(header.dst)
            || (!quote && (bytes.len() != header.len || bytes[header.hop_offset()] == 0))
        {
            return None;
        }
        Some(header)
    }
    fn hop_offset(self) -> usize {
        if self.src.is_ipv4() { 8 } else { 7 }
    }
    fn pseudo(self, payload_len: usize) -> u32 {
        if self.proto == 1 {
            return 0;
        }
        let addresses = match (self.src, self.dst) {
            (IpAddr::V4(s), IpAddr::V4(d)) => sum(&s.octets()) + sum(&d.octets()),
            (IpAddr::V6(s), IpAddr::V6(d)) => sum(&s.octets()) + sum(&d.octets()),
            _ => unreachable!("a parsed IP header has one family"),
        };
        addresses + u32::from(self.proto) + payload_len as u32
    }
    fn checksum_offset(self) -> usize {
        match self.proto {
            6 => 16,
            17 => 6,
            _ => 2,
        }
    }
    fn repaired(self, bytes: &mut [u8], absent_udp: bool) {
        if self.src.is_ipv4() {
            set_word(bytes, 10, 0);
            let c = finish(sum(&bytes[..20]));
            set_word(bytes, 10, c);
        }
        let off = self.checksum_offset();
        let payload = &mut bytes[self.offset..];
        set_word(payload, off, 0);
        if !absent_udp {
            let mut c = finish(self.pseudo(payload.len()) + sum(payload));
            if self.proto == 17 && c == 0 {
                c = u16::MAX;
            }
            set_word(payload, off, c);
        }
    }
    fn replace_address(&mut self, bytes: &mut [u8], source: bool, new: IpAddr) {
        match new {
            IpAddr::V4(ip) => {
                let i = if source { 12 } else { 16 };
                bytes[i..i + 4].copy_from_slice(&ip.octets());
            }
            IpAddr::V6(ip) => {
                let i = if source { 8 } else { 24 };
                bytes[i..i + 16].copy_from_slice(&ip.octets());
            }
        }
        if source {
            self.src = new;
        } else {
            self.dst = new;
        }
    }
}
use crate::framing::{finish, sum};

// Validate option lengths before allowing a segment to affect connection state.
// A validated MSS value may occur at an odd byte offset.
fn mss_option(tcp: &[u8], header_len: usize) -> Option<Option<usize>> {
    let mut i = 20;
    let mut mss = None;
    while i < header_len {
        match tcp[i] {
            0 => break,
            1 => i += 1,
            kind => {
                let len = usize::from(*tcp.get(i + 1)?);
                if len < 2 || i + len > header_len {
                    return None;
                }
                if kind == 2 && (len != 4 || mss.replace(i + 2).is_some()) {
                    return None;
                }
                i += len;
            }
        }
    }
    Some(mss)
}

#[derive(Clone, Copy)]
pub(super) enum Body {
    Flow(Flow),
    Related,
}
#[derive(Clone, Copy)]
pub(super) struct Packet {
    pub ip: Header,
    pub body: Body,
    mss: Option<usize>,
}

impl Packet {
    pub fn parse(bytes: &[u8]) -> Option<Self> {
        let pkt = Self::read(bytes, false)?;
        (bytes[pkt.ip.hop_offset()] > 1).then_some(pkt)
    }
    pub fn delivery_remote(bytes: &[u8]) -> Option<IpAddr> {
        let packet = Self::read(bytes, false)?;
        match packet.body {
            Body::Flow(flow) => {
                flow.tuple(false)?;
                Some(packet.ip.src)
            }
            Body::Related => {
                let quote = Self::quoted(&bytes[packet.ip.offset + 8..])?;
                let Body::Flow(flow) = quote.body else {
                    return None;
                };
                flow.tuple(true)?;
                (quote.ip.src == packet.ip.dst).then_some(quote.ip.dst)
            }
        }
    }
    pub fn quoted(bytes: &[u8]) -> Option<Self> {
        Self::read(bytes, true)
    }
    fn read(bytes: &[u8], quote: bool) -> Option<Self> {
        let ip = Header::parse(bytes, quote)?;
        let payload = bytes.get(ip.offset..ip.len.min(bytes.len()))?;
        let length = ip.len - ip.offset;
        if payload.len() < 8 {
            return None;
        }
        let complete = payload.len() == length;
        let mut mss = None;
        let body = match ip.proto {
            6 | 17 => {
                let (source, target) = (word(payload, 0), word(payload, 2));
                if target == 0 || (ip.proto == 6 && source == 0) {
                    return None;
                }
                let mut flags = 0;
                let proto = if ip.proto == 17 {
                    if usize::from(word(payload, 4)) != length
                        || (ip.src.is_ipv6() && word(payload, 6) == 0)
                    {
                        return None;
                    }
                    Protocol::Udp
                } else {
                    if length < 20 {
                        return None;
                    }
                    if let Some(off) = payload.get(12) {
                        let header_len = usize::from(off >> 4) * 4;
                        if !(20..=length).contains(&header_len) {
                            return None;
                        }
                        if header_len <= payload.len() {
                            mss = mss_option(payload, header_len)?;
                        }
                    }
                    if let Some(&f) = payload.get(13) {
                        flags = f;
                        if flags & SYN != 0 && flags & (RST | FIN) != 0
                            || flags & (FIN | RST) == (FIN | RST)
                        {
                            return None;
                        }
                    }
                    // A single byte of a quoted checksum cannot be adjusted.
                    if payload.len() == 17 {
                        return None;
                    }
                    Protocol::Tcp
                };
                Body::Flow(Flow {
                    protocol: proto,
                    ports: [source, target],
                    flags,
                    echo_request: false,
                })
            }
            1 if ip.src.is_ipv4() => match (payload[0], payload[1]) {
                (ty @ (0 | 8), 0) => Body::Flow(Flow {
                    protocol: Protocol::Echo,
                    ports: [word(payload, 4), 0],
                    flags: 0,
                    echo_request: ty == 8,
                }),
                (3, 0..=15) | (11, 0..=1) if !quote => Body::Related,
                _ => return None,
            },
            58 if ip.src.is_ipv6() => match (payload[0], payload[1]) {
                (ty @ (128 | 129), 0) => Body::Flow(Flow {
                    protocol: Protocol::Echo,
                    ports: [word(payload, 4), 0],
                    flags: 0,
                    echo_request: ty == 128,
                }),
                (1, 0..=7) | (2, 0) | (3, 0..=1) if !quote => Body::Related,
                _ => return None,
            },
            _ => return None,
        };
        if complete
            && !(ip.proto == 17 && ip.src.is_ipv4() && word(payload, 6) == 0)
            && finish(ip.pseudo(length) + sum(payload)) != 0
        {
            return None;
        }
        Some(Self { ip, body, mss })
    }
    fn port_offset(self, source: bool) -> usize {
        self.ip.offset
            + match self.ip.proto {
                1 | 58 => 4,
                _ if source => 0,
                _ => 2,
            }
    }
    pub fn translate(
        self,
        bytes: &[u8],
        source: bool,
        new_addr: IpAddr,
        port: u16,
        mtu: u16,
    ) -> Vec<u8> {
        let mut out = bytes.to_vec();
        let mut ip = self.ip;
        ip.replace_address(&mut out, source, new_addr);
        set_word(&mut out, self.port_offset(source), port);
        if let (Body::Flow(flow), Some(pos)) = (self.body, self.mss)
            && flow.flags & SYN != 0
        {
            let pos = ip.offset + pos;
            let mss =
                word(&out, pos).min(mtu.saturating_sub(if ip.src.is_ipv4() { 40 } else { 60 }));
            set_word(&mut out, pos, mss);
        }
        out[ip.hop_offset()] -= 1;
        let absent = ip.proto == 17 && ip.src.is_ipv4() && word(&out, ip.offset + 6) == 0;
        ip.repaired(&mut out, absent);
        out
    }
    /// Repair both the quoted tuple and the enclosing packet. If the quote is
    /// short, the transport checksum (when present) covers unavailable bytes,
    /// so replace just the changed checksum words using one's complement math.
    pub fn translate_error(
        self,
        bytes: &[u8],
        quoted: Self,
        outbound: bool,
        addr: IpAddr,
        port: u16,
    ) -> Vec<u8> {
        let mut out = bytes.to_vec();
        let inner = &mut out[self.ip.offset + 8..];
        let mut ip = quoted.ip;
        let adr_offset = if ip.src.is_ipv4() {
            if outbound { 16 } else { 12 }
        } else if outbound {
            24
        } else {
            8
        };
        let adr_len = if ip.src.is_ipv4() { 4 } else { 16 };
        let port_offset = quoted.port_offset(!outbound);
        let checksum = ip.offset + ip.checksum_offset();
        let mut delta = u32::from(!word(inner, port_offset)) + u32::from(port);
        if ip.proto != 1 {
            for old in inner[adr_offset..adr_offset + adr_len].as_chunks::<2>().0 {
                delta += u32::from(!u16::from_be_bytes(*old));
            }
        }
        ip.replace_address(inner, !outbound, addr);
        if ip.proto != 1 {
            delta += sum(&inner[adr_offset..adr_offset + adr_len]);
        }
        set_word(inner, port_offset, port);
        if checksum + 2 <= inner.len() {
            let old = word(inner, checksum);
            if !(ip.proto == 17 && old == 0) {
                let mut c = finish(u32::from(!old) + delta);
                if ip.proto == 17 && c == 0 {
                    c = u16::MAX;
                }
                set_word(inner, checksum, c);
            }
        }
        if ip.src.is_ipv4() {
            set_word(inner, 10, 0);
            let check = finish(sum(&inner[..20]));
            set_word(inner, 10, check);
        }
        let mut outer = self.ip;
        outer.replace_address(&mut out, outbound, addr);
        out[outer.hop_offset()] -= 1;
        outer.repaired(&mut out, false);
        out
    }

    pub fn pmtu_error(self, original: &[u8], router: IpAddr, mtu: u16) -> Option<Vec<u8>> {
        if !self.ip.df || matches!(self.body, Body::Related) {
            return None;
        }
        let v4 = self.ip.src.is_ipv4();
        // IPv4 errors fit the classic 576-byte datagram, IPv6 errors fit the
        // minimum IPv6 MTU. Keep as much of the offending packet as can fit.
        let offset = self.ip.offset;
        let cap = usize::from(mtu).min(if v4 { 576 } else { 1280 });
        let quote_len = original.len().min(cap.checked_sub(offset + 8)?);
        if quote_len < offset + 8 {
            return None;
        }
        let len = offset + 8 + quote_len;
        let mut out = vec![0u8; len];
        let proto = if v4 { 1 } else { 58 };
        if v4 {
            out[0] = 0x45;
            set_word(&mut out, 2, len as u16);
            out[8] = 64;
            out[9] = proto;
            out[offset] = 3;
            out[offset + 1] = 4;
            set_word(&mut out, offset + 6, mtu);
        } else {
            out[0] = 0x60;
            set_word(&mut out, 4, (len - 40) as u16);
            out[6] = proto;
            out[7] = 64;
            out[offset] = 2;
            out[offset + 4..offset + 8].copy_from_slice(&u32::from(mtu).to_be_bytes());
        }
        out[offset + 8..].copy_from_slice(&original[..quote_len]);
        let mut ip = Header {
            src: router,
            dst: self.ip.src,
            len,
            offset,
            proto,
            df: false,
        };
        ip.replace_address(&mut out, true, router);
        ip.replace_address(&mut out, false, self.ip.src);
        ip.repaired(&mut out, false);
        Some(out)
    }
}
