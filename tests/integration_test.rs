use std::process::{Command, ExitStatus, Stdio};

#[cfg(target_family = "unix")]
const DQY: &str = "./target/debug/dqy";

#[cfg(target_family = "windows")]
const DQY: &str = ".\\target\\debug\\dqy.exe";

fn to_args(s: &str) -> Vec<&str> {
    s.split_whitespace().collect()
}

fn call_dqy(args: &[&str]) -> std::io::Result<ExitStatus> {
    Command::new(DQY).args(args).stdout(Stdio::null()).status()
}

fn test_dqy_call(args: &str) {
    let args = to_args(args);
    let status = call_dqy(&args).expect("error calling dqy exe");
    assert!(status.code().is_some());
    assert_eq!(status.code().unwrap(), 0);
}

macro_rules! test_dqy {
    ($fn_name:ident, $args:literal, $is_ipv6:literal) => {
        #[test]
        fn $fn_name() {
            // don't use IPV6 on github action runners because it's not yet supported
            if $is_ipv6 || std::env::var("GITHUB_REPOSITORY").is_err() {
                test_dqy_call($args);
            }
        }
    };
}

// test transports
test_dqy!(udp, "A www.google.com", false);
test_dqy!(udp6, "A www.google.com -6", true);
test_dqy!(tcp, "A www.google.com --tcp", false);
test_dqy!(tcp6, "A www.google.com --tcp -6", true);
test_dqy!(tls, "A www.google.com @1.1.1.1 --tls", false);
test_dqy!(tls6, "A www.google.com @2606:4700:4700::1001 --tls", true);
test_dqy!(
    doh,
    "A www.google.fr @https://mozilla.cloudflare-dns.com/dns-query --https",
    false
);
test_dqy!(
    doh6,
    "A www.google.fr @https://mozilla.cloudflare-dns.com/dns-query --https -6",
    true
);
test_dqy!(doq, "A www.google.com @quic://dns.adguard.com", false);
test_dqy!(doq6, "A www.google.com @quic://dns.adguard.com -6", true);

// endpoints
test_dqy!(one, "A www.google.com @one.one.one.one", false);
test_dqy!(one6, "A www.google.com @one.one.one.one -6", true);
test_dqy!(one_tcp, "A www.google.com @one.one.one.one --tcp", false);
test_dqy!(one_tcp6, "A www.google.com @one.one.one.one --tcp -6", true);
test_dqy!(one_port, "A www.google.com @one.one.one.one:53", false);
test_dqy!(one_port6, "A www.google.com @one.one.one.one:53 -6", true);

// IDNA
test_dqy!(german, "A münchen.de", false);
test_dqy!(cyrillic, "A россия.рф", false);
test_dqy!(greek, "AAAA ουτοπία.δπθ.gr", false);
test_dqy!(korean, "A 스타벅스코리아.com", false);
test_dqy!(nordic, "A www.øl.com", false);
test_dqy!(chinese, "A 香港.中國", false);

// Misc
test_dqy!(dropbox, "TXT dropbox.com", false);
test_dqy!(
    zoneversion,
    "@ns1-dyn.bortzmeyer.fr dyn.bortzmeyer.fr SOA --zoneversion",
    false
);
test_dqy!(wallet, "bortzmeyer.fr WALLET", false);
test_dqy!(type262, "bortzmeyer.fr type262", false);
test_dqy!(axfr, "axfr @nsztm1.digi.ninja zonetransfer.me", false);
test_dqy!(any, "@a.gtld-servers.net ANY com.", false);
test_dqy!(https, "HTTPS arts.fr", false);
test_dqy!(caa, "CAA duckduckgo.com", false);
test_dqy!(ptr, "-x 3.209.40.246", false);
test_dqy!(mx, "mx yahoo.com", false);
