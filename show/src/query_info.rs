use serde::Serialize;
use std::{fmt, net::SocketAddr};

//───────────────────────────────────────────────────────────────────────────────────
// Gather some information which might be useful for the user
//───────────────────────────────────────────────────────────────────────────────────
#[derive(Debug, Default, Serialize)]
pub struct QueryInfo {
    //resolver reached
    pub server: Option<SocketAddr>,

    // elapsed time in ms
    pub elapsed: u128,

    // transport used (ex: Udp)
    pub mode: String,

    // bytes sent and received during network operations
    pub bytes_sent: usize,
    pub bytes_received: usize,
}

impl fmt::Display for QueryInfo {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if let Some(peer) = self.server {
            write!(f, "\nendpoint: {} ({})\n", peer, self.mode)?;
        }
        writeln!(f, "elapsed: {} ms", self.elapsed)?;
        write!(
            f,
            "sent:{}, received:{} bytes",
            self.bytes_sent, self.bytes_received
        )
    }
}
