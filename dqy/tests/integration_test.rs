use std::process::{Command, ExitStatus};

const DQY: &str = "/data/projects/rust/dqy/target/debug/dqy";

fn to_args(s: &str) -> Vec<&str> {
    s.split_whitespace().collect()
}

fn call_dqy(args: &[&str]) -> std::io::Result<ExitStatus> {
    Command::new(DQY).args(args).status()
}

#[test]
fn rr_a() {
    //───────────────────────────────────────────────────────────────────────────────────
    // host resolvers
    //───────────────────────────────────────────────────────────────────────────────────
    // UDP
    let args = to_args("A www.google.fr");
    let status = call_dqy(&args).unwrap();
    assert_eq!(status.code().unwrap(), 0);

    // UDP6
    let args = to_args("A www.google.fr -6");
    let status = call_dqy(&args).unwrap();
    assert_eq!(status.code().unwrap(), 0);

    // TCP
    let args = to_args("A www.google.fr --tcp");
    let status = call_dqy(&args).unwrap();
    assert_eq!(status.code().unwrap(), 0);

    // TCP6
    let args = to_args("A www.google.fr --tcp -6");
    let status = call_dqy(&args).unwrap();
    assert_eq!(status.code().unwrap(), 0);

    // TLS
    let args = to_args("A www.google.fr @1.1.1.1 --tls");
    let status = call_dqy(&args).unwrap();
    assert_eq!(status.code().unwrap(), 0);

    // TLS6
    let args = to_args("A www.google.fr @2606:4700:4700::1001 --tls -6");
    let status = call_dqy(&args).unwrap();
    assert_eq!(status.code().unwrap(), 0);

    //───────────────────────────────────────────────────────────────────────────────────
    // Cloudflare
    //───────────────────────────────────────────────────────────────────────────────────
    // UDP
    let args = to_args("A www.google.fr @1.1.1.1");
    let status = call_dqy(&args).unwrap();
    assert_eq!(status.code().unwrap(), 0);

    // TCP
    let args = to_args("A www.google.fr @1.1.1.1 --tcp");
    let status = call_dqy(&args).unwrap();
    assert_eq!(status.code().unwrap(), 0);

    // TLS
    let args = to_args("A www.google.fr @1.1.1.1 --tls");
    let status = call_dqy(&args).unwrap();
    assert_eq!(status.code().unwrap(), 0);

    // TLS6
    let args = to_args("A www.google.fr @2606:4700:4700::1001 --tls -6");
    let status = call_dqy(&args).unwrap();
    assert_eq!(status.code().unwrap(), 0);

    // HTTPS
    let args = to_args("A www.google.fr @https://mozilla.cloudflare-dns.com/dns-query --https");
    let status = call_dqy(&args).unwrap();
    assert_eq!(status.code().unwrap(), 0);

    // HTTPS6
    let args = to_args("A www.google.fr @https://mozilla.cloudflare-dns.com/dns-query --https -6");
    let status = call_dqy(&args).unwrap();
    assert_eq!(status.code().unwrap(), 0);
}
