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
    ($fn_name:ident, $args:literal) => {
        #[test]
        fn $fn_name() {
            // don't use IPV6 on github action runners because it's not yet supported
            if std::env::var("GITHUB_REPOSITORY").is_err() {
                test_dqy_call($args);
            } else if !$args.contains("-6") {
                test_dqy_call($args);
            }
        }
    };
}

// test transports
test_dqy!(udp, "A www.google.com");
test_dqy!(udp6, "A www.google.com -6");
test_dqy!(tcp, "A www.google.com --tcp");
test_dqy!(tcp6, "A www.google.com --tcp -6");
test_dqy!(tls, "A www.google.com @1.1.1.1 --tls");
test_dqy!(tls6, "A www.google.com @2606:4700:4700::1001 --tls");
test_dqy!(
    doh,
    "A www.google.fr @https://mozilla.cloudflare-dns.com/dns-query --https"
);
test_dqy!(
    doh6,
    "A www.google.fr @https://mozilla.cloudflare-dns.com/dns-query --https -6"
);
test_dqy!(doq, "A www.google.com @quic://dns.adguard.com");
test_dqy!(doq6, "A www.google.com @quic://dns.adguard.com -6");

// endpoints
test_dqy!(one, "A www.google.com @one.one.one.one");
test_dqy!(one6, "A www.google.com @one.one.one.one -6");
test_dqy!(one_tcp, "A www.google.com @one.one.one.one --tcp");
test_dqy!(one_tcp6, "A www.google.com @one.one.one.one --tcp -6");
test_dqy!(one_port, "A www.google.com @one.one.one.one:53");
test_dqy!(one_port6, "A www.google.com @one.one.one.one:53 -6");

// IDNA
test_dqy!(german, "A münchen.de");
test_dqy!(cyrillic, "A россия.рф");
test_dqy!(greek, "AAAA ουτοπία.δπθ.gr");
test_dqy!(korean, "A 스타벅스코리아.com");
test_dqy!(nordic, "A www.øl.com");
test_dqy!(chinese, "A 香港.中國");

// Misc
test_dqy!(dropbox, "TXT dropbox.com");
test_dqy!(
    zoneversion,
    "@ns1-dyn.bortzmeyer.fr dyn.bortzmeyer.fr SOA --zoneversion"
);
test_dqy!(wallet, "bortzmeyer.fr WALLET");
test_dqy!(type262, "bortzmeyer.fr type262");
test_dqy!(axfr, "axfr @nsztm1.digi.ninja zonetransfer.me");
test_dqy!(any, "@a.gtld-servers.net ANY com.");
test_dqy!(https, "HTTPS arts.fr");
test_dqy!(caa, "CAA duckduckgo.com");
test_dqy!(ptr, "-x 3.209.40.246");
test_dqy!(mx, "mx yahoo.com");
