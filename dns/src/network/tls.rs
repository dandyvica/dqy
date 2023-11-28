// Specific TLS handling
use std::{
    io::{BufReader, Read, Write},
    net::{IpAddr, Ipv4Addr, TcpStream, UdpSocket},
    str::FromStr,
    sync::Arc,
    time::Duration,
};

use log::debug;
use rustls::{ClientConfig, ClientConnection, Connection, RootCertStore, Stream};

pub struct TlsConnexion {
    pub(super) sock: TcpStream,
    pub(super) conn: ClientConnection,
    // tls_stream: Option<rustls::Stream<'a, ClientConnection, TcpStream>>,
}

impl TlsConnexion {
    pub fn new(server: &str) -> Self {
        // First we load some root certificates. These are used to authenticate the server.
        // The recommended way is to depend on the webpki_roots crate which contains the Mozilla set of root certificates.
        let mut root_store = rustls::RootCertStore::empty();
        root_store.add_trust_anchors(webpki_roots::TLS_SERVER_ROOTS.iter().map(|ta| {
            rustls::OwnedTrustAnchor::from_subject_spki_name_constraints(
                ta.subject,
                ta.spki,
                ta.name_constraints,
            )
        }));

        // Next, we make a ClientConfig. You’re likely to make one of these per process, and use it for all connections made by that process.
        let config = rustls::ClientConfig::builder()
            .with_safe_defaults()
            .with_root_certificates(root_store)
            .with_no_client_auth();

        let server_name = server.try_into().unwrap();
        let destination = format!("{}:853", server);

        let sock = TcpStream::connect(destination).unwrap();
        let conn = ClientConnection::new(Arc::new(config), server_name).unwrap();

        Self { sock, conn }
    }
}

// pub fn init_tls(server: &str) -> (TcpStream, ClientConnection) {
//     // First we load some root certificates. These are used to authenticate the server.
//     // The recommended way is to depend on the webpki_roots crate which contains the Mozilla set of root certificates.
//     let mut root_store = rustls::RootCertStore::empty();
//     root_store.add_trust_anchors(webpki_roots::TLS_SERVER_ROOTS.iter().map(|ta| {
//         rustls::OwnedTrustAnchor::from_subject_spki_name_constraints(
//             ta.subject,
//             ta.spki,
//             ta.name_constraints,
//         )
//     }));

//     // Next, we make a ClientConfig. You’re likely to make one of these per process, and use it for all connections made by that process.
//     let config = rustls::ClientConfig::builder()
//         .with_safe_defaults()
//         .with_root_certificates(root_store)
//         .with_no_client_auth();

//     let server_name = server.try_into().unwrap();

//     let sock = TcpStream::connect("dns.google:853").unwrap();
//     let conn = ClientConnection::new(Arc::new(config), server_name).unwrap();

//     (sock, conn)
// }
