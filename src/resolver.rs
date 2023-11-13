use std::net::IpAddr;

#[cfg(target_family = "unix")]
use std::str::FromStr;

#[cfg(target_family = "windows")]
use windows::Win32::{
    Foundation::{ERROR_BUFFER_OVERFLOW, ERROR_INVALID_PARAMETER, ERROR_SUCCESS},
    NetworkManagement::IpHelper::{
        GetAdaptersAddresses, GAA_FLAG_INCLUDE_PREFIX, IP_ADAPTER_ADDRESSES_LH,
    },
    Networking::WinSock::{AF_INET, AF_INET6, AF_UNSPEC, SOCKADDR, SOCKADDR_IN, SOCKADDR_IN6},
};

pub struct Resolver;
use dnslib::error::DNSResult;

impl Resolver {
    #[cfg(target_family = "unix")]
    pub fn servers(resolv: Option<&str>) -> DNSResult<Vec<IpAddr>> {
        const RESOLV_CONF_FILE: &'static str = "/etc/resolv.conf";

        // resolv file is usually at "/etc/resolv.conf" but some distros (Ubuntu) moved it elsewhere
        let resolv_file = resolv.unwrap_or(RESOLV_CONF_FILE);

        // read whole file, get rid of comments and extract DNS stubs
        let resolv_conf = std::fs::read_to_string(resolv_file)?;

        let stubs: Vec<IpAddr> = resolv_conf
            .lines()
            .filter(|line| line.trim().starts_with("nameserver"))
            .filter_map(|addr| addr.split_ascii_whitespace().nth(1))
            .map(|ip| IpAddr::from_str(ip))
            .collect::<Result<Vec<_>, _>>()
            // .map_err(|e| {
            //     let msg = format!("unable to convert {}", e);
            //     std::io::Error::new(std::io::ErrorKind::Other, msg.to_owned())
            // })?;
            ?;

        Ok(stubs)
    }

    #[cfg(target_family = "windows")]
    pub fn _servers(_resolv: Option<&str>) -> Result<Vec<IpAddr>, Error> {
        let mut v = Vec::new();

        // first call
        let family = AF_UNSPEC.0 as u32;
        let mut buflen = 0u32;
        let mut rc = unsafe {
            GetAdaptersAddresses(family, GAA_FLAG_INCLUDE_PREFIX, None, None, &mut buflen)
        };

        // second with the actual buffer size large enough to hold data
        if rc == ERROR_BUFFER_OVERFLOW.0 {
            let mut addr = vec![0u8; buflen as usize];
            let ptr = addr.as_mut_ptr() as *mut IP_ADAPTER_ADDRESSES_LH;

            rc = unsafe {
                GetAdaptersAddresses(
                    family,
                    GAA_FLAG_INCLUDE_PREFIX,
                    None,
                    Some(ptr),
                    &mut buflen,
                )
            };

            // second with the actual buffer size large enough to hold data
            if rc == ERROR_SUCCESS.0 {
                // loop through adapters and grab DNS addresses
                let mut p = ptr;

                while !p.is_null() {
                    unsafe {
                        let mut p_dns = (*p).FirstDnsServerAddress;

                        // loop through DNS addresses for this adapter
                        while !p_dns.is_null() {
                            let sockaddr = (*p_dns).Address.lpSockaddr;
                            let dns_addr = Resolver::from_sockaddr(sockaddr)?;
                            v.push(dns_addr);

                            p_dns = (*p_dns).Next;
                        }

                        p = (*p).Next;
                    }
                }
                Ok(v)
            } else {
                Err(Error::Windows(rc))
            }
        } else {
            Err(Error::Windows(rc))
        }
    }

    // utility function which is used to build an IpAddr from an array used in Windows OS
    #[cfg(target_family = "windows")]
    fn from_sockaddr(sockaddr: *const SOCKADDR) -> Result<IpAddr, Error> {
        use std::net::{Ipv4Addr, Ipv6Addr};

        // this is only valid for INET4 or 6 family
        unsafe {
            match (*sockaddr).sa_family {
                AF_INET => {
                    // ip v4 addresses reported by GetAdaptersAddresses() API are like: [0, 0, 8, 8, 8, 8, 0, 0, 0, 0, 0, 0, 0, 0] (for 8.8.8.8)
                    let sockaddr_in = sockaddr as *const SOCKADDR_IN;
                    let bytes = (*sockaddr_in).sin_addr.S_un.S_un_b;
                    let ip = IpAddr::V4(Ipv4Addr::new(
                        bytes.s_b1, bytes.s_b2, bytes.s_b3, bytes.s_b4,
                    ));
                    Ok(ip)
                }
                AF_INET6 => {
                    // ip v6 addresses reported by GetAdaptersAddresses() API are like: [0, 0, 0, 0, 0, 0, 254, 192, 0, 0, 0, 0, 255, 255] (for 8.8.8.8)
                    let sockaddr_in = sockaddr as *const SOCKADDR_IN6;
                    let bytes = (*sockaddr_in).sin6_addr.u.Byte;
                    let ip = IpAddr::V6(Ipv6Addr::from(bytes));
                    Ok(ip)
                }
                _ => Err(Error::Windows(ERROR_INVALID_PARAMETER.0)),
            }
        }
    }
}
