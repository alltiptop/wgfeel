use std::{
    net::{Ipv4Addr, Ipv6Addr, SocketAddr, UdpSocket},
    thread,
    time::{Duration, Instant},
};
use wgfeel_wireguard::UdpListener;

#[test]
fn wildcard_listener_exchanges_both_families_on_one_port_without_mapped_addresses() {
    for wildcard in ["0.0.0.0:0", "[::]:0"] {
        let server = UdpListener::bind(wildcard.parse().unwrap()).unwrap();
        let port = server.local_addr().unwrap().port();
        let v4 = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let v6 = UdpSocket::bind((Ipv6Addr::LOCALHOST, 0)).unwrap();
        for client in [&v4, &v6] {
            client
                .set_read_timeout(Some(Duration::from_secs(2)))
                .unwrap();
            let destination = match client.local_addr().unwrap() {
                SocketAddr::V4(_) => SocketAddr::from((Ipv4Addr::LOCALHOST, port)),
                SocketAddr::V6(_) => SocketAddr::from((Ipv6Addr::LOCALHOST, port)),
            };
            assert!(server.supports_endpoint(destination));
            client.send_to(b"probe", destination).unwrap();
            let deadline = Instant::now() + Duration::from_secs(2);
            let mut bytes = [0; 64];
            let (length, source) = loop {
                match server.recv_from(&mut bytes) {
                    Ok(received) => break received,
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                        assert!(
                            Instant::now() < deadline,
                            "listener did not receive datagram"
                        );
                        thread::sleep(Duration::from_millis(1));
                    }
                    Err(error) => panic!("{error}"),
                }
            };
            assert_eq!(&bytes[..length], b"probe");
            assert_eq!(source, client.local_addr().unwrap());
            server.send_to(b"reply", source).unwrap();
            let (length, source) = client.recv_from(&mut bytes).unwrap();
            assert_eq!(&bytes[..length], b"reply");
            assert_eq!(source, destination);
        }
    }
}

#[test]
fn explicit_listener_keeps_its_address_scope() {
    for address in ["127.0.0.1:0", "[::1]:0"] {
        let address: SocketAddr = address.parse().unwrap();
        let socket = UdpListener::bind(address).unwrap();
        assert_eq!(socket.local_addr().unwrap().ip(), address.ip());
        assert_eq!(
            socket.supports_endpoint("127.0.0.1:51820".parse().unwrap()),
            address.is_ipv4()
        );
        assert_eq!(
            socket.supports_endpoint("[::1]:51820".parse().unwrap()),
            address.is_ipv6()
        );
    }
}
