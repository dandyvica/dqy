// Common functions for TLS related processes (TLS, QUIC)

use rustls::{ClientConfig, RootCertStore};
use rustls_pki_types::CertificateDer;

use crate::error::{Error, Result};

// build a new client config for TLS connexions
pub fn tls_config(root_store: RootCertStore) -> ClientConfig {
    ClientConfig::builder()
        .with_root_certificates(root_store)
        .with_no_client_auth()
}

// manage CAs
pub fn root_store(cert: &Option<Vec<u8>>) -> Result<RootCertStore> {
    let mut root_store = rustls::RootCertStore::empty();

    // we've got a certificate here
    if let Some(buf) = cert {
        let cert = CertificateDer::from_slice(buf);
        root_store.add(cert).map_err(Error::Tls)?;
    }
    // use root CAs
    else {
        root_store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    }

    Ok(root_store)
}
