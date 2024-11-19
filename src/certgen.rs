// used to create cert and private key for testing sqelf-sigend

use rcgen::{generate_simple_self_signed, CertifiedKey};
use std::io::Write;
use std::{error::Error, fs::File};

fn main() -> Result<(), Box<dyn Error>> {
    // Generate a certificate
    let subject_alt_names = vec!["127.0.0.1".to_string(), "localhost".to_string()];
    let CertifiedKey { cert, key_pair } = generate_simple_self_signed(subject_alt_names).unwrap();

    // save cert
    let mut cert_file = File::create("cert.pem")?;
    cert_file.write_all(cert.pem().as_bytes())?;
    cert_file.sync_all()?;

    // write private key
    let mut key_file = File::create("key.pem")?;
    key_file.write_all(key_pair.serialize_pem().as_bytes())?;
    key_file.sync_all()?;

    Ok(())
}
