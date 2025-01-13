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
    ($fn_name:ident, $args:literal, $gha:literal) => {
        #[test]
        fn $fn_name() {
            // don't use IPV6 on github action runners because it's not yet supported
            if $gha || std::env::var("GITHUB_REPOSITORY").is_err() {
                test_dqy_call($args);
            }
        }
    };
}

// test transports
test_dqy!(udp, "A www.google.com", true);
test_dqy!(udp6, "A www.google.com -6", false);
test_dqy!(tcp, "A www.google.com --tcp", true);
test_dqy!(tcp6, "A www.google.com --tcp -6", false);
test_dqy!(tls, "A www.google.com @1.1.1.1 --tls", true);
test_dqy!(tls6, "A www.google.com @2606:4700:4700::1001 --tls", false);
test_dqy!(
    doh,
    "A www.google.fr @https://mozilla.cloudflare-dns.com/dns-query --https",
    true
);
test_dqy!(
    doh6,
    "A www.google.fr @https://mozilla.cloudflare-dns.com/dns-query --https -6",
    false
);
test_dqy!(doq, "A www.google.com @quic://dns.adguard.com", true);
test_dqy!(doq6, "A www.google.com @quic://dns.adguard.com -6", false);

// endpoints
test_dqy!(one, "A www.google.com @one.one.one.one", true);
test_dqy!(one6, "A www.google.com @one.one.one.one -6", false);
test_dqy!(one_tcp, "A www.google.com @one.one.one.one --tcp", true);
test_dqy!(one_tcp6, "A www.google.com @one.one.one.one --tcp -6", false);
test_dqy!(one_port, "A www.google.com @one.one.one.one:53", true);
test_dqy!(one_port6, "A www.google.com @one.one.one.one:53 -6", false);

// IDNA
test_dqy!(german, "A münchen.de", true);
test_dqy!(cyrillic, "A россия.рф", true);
test_dqy!(greek, "AAAA ουτοπία.δπθ.gr", true);
test_dqy!(korean, "A 스타벅스코리아.com", true);
test_dqy!(nordic, "A www.øl.com", true);
test_dqy!(chinese, "A 香港.中國", true);

// Misc
test_dqy!(dropbox, "TXT dropbox.com", true);
test_dqy!(
    zoneversion,
    "@ns1-dyn.bortzmeyer.fr dyn.bortzmeyer.fr SOA --zoneversion",
    true
);
test_dqy!(wallet, "bortzmeyer.fr WALLET", true);
test_dqy!(type262, "bortzmeyer.fr type262", true);
test_dqy!(axfr, "axfr @nsztm1.digi.ninja zonetransfer.me", true);
test_dqy!(any, "@a.gtld-servers.net ANY com.", true);
test_dqy!(https, "HTTPS arts.fr", true);
test_dqy!(caa, "CAA duckduckgo.com", true);
test_dqy!(ptr, "-x 3.209.40.246", true);
test_dqy!(mx, "mx yahoo.com", true);
