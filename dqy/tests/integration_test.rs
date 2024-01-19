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
    let args = to_args("A www.google.fr --short");
    let status = call_dqy(&args).unwrap();
    assert_eq!(status.code().unwrap(), 0);

    let args = to_args("A www.google.fr @1.1.1.1 --tls");
    let status = call_dqy(&args).unwrap();
    assert_eq!(status.code().unwrap(), 0);

    let args = to_args("A www.google.fr @one.one.one.one --tls");
    let status = call_dqy(&args).unwrap();
    assert_eq!(status.code().unwrap(), 0);

    let args = to_args("A www.google.fr @https://mozilla.cloudflare-dns.com/dns-query --https");
    let status = call_dqy(&args).unwrap();
    assert_eq!(status.code().unwrap(), 0);
}
