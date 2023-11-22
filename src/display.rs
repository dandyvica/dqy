//! Display method: as we can't impl the Display trait outside the module where it's defined, and
//! to not put these methods in the lib, use a wrapper
use std::fmt;

use dns::rfc1035::{
    domain::DomainName,
    flags::Flags,
    header::Header,
    message::Message,
    packet_type::PacketType,
    qtype::QType,
    question::Question,
    //RData, A, AAAA, HINFO, MX, NS, SOA, TXT,
    resource_record::*,
};

// a helper macro for displaying RR data when it's easy
macro_rules! rr_display {
    ($fmt:expr, $rd_data:expr, $rd_arm:path, $tag:literal) => {
        match $rd_data {
            Some($rd_arm(x)) => write!($fmt, "{}: {}\n", $tag, DisplayWrapper(x)),
            _ => panic!("unexpected error when displaying RR {}", $tag),
        }
    };
}

// helper macro to print out boolean flags if true
macro_rules! flag_display {
    ($fmt:expr, $bit:expr, $label:literal) => {
        if $bit {
            write!($fmt, "{} ", $label)?
        }
    };
}

// we need this because of error E0117: "impl doesn't use only types from inside the current crate"
pub struct DisplayWrapper<'a, T>(pub &'a T);

// Now we can implement the Display trait for DisplayWrapper for all structure we want to display
impl<'a> fmt::Display for DisplayWrapper<'_, DomainName<'a>> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl<'a> fmt::Display for DisplayWrapper<'_, Ttl> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.0 {
            Ttl::Ttl(t) => write!(f, "{}", t),
            Ttl::Ext(e) => write!(
                f,
                "extented_rcode: {}, version: {}, doz: {}",
                e.extented_rcode, e.version, e.doz
            ),
        }
    }
}

impl<'a> fmt::Display for DisplayWrapper<'_, Class> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.0 {
            Class::Qc(c) => write!(f, "{}", c),
            Class::Payload(p) => write!(f, "payload: {}", p),
        }
    }
}

impl<'a> fmt::Display for DisplayWrapper<'_, SOA<'a>> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "mname:{} rname:{} serial:{} refresh:{} retry:{} expire:{} minimum:{}",
            self.0.mname,
            self.0.rname,
            self.0.serial,
            self.0.refresh,
            self.0.retry,
            self.0.expire,
            self.0.minimum
        )
    }
}

// impl<'a> fmt::Display for DisplayWrapper<'_, MX<'a>> {
//     fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
//         write!(
//             f,
//             "preference:{} exchange:{}",
//             self.0.preference, self.0.exchange,
//         )
//     }
// }

// impl<'a> fmt::Display for DisplayWrapper<'_, HINFO<'a>> {
//     fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
//         write!(f, "cpu:{} os:{}", self.0.cpu, self.0.os,)
//     }
// }

// impl<'a> fmt::Display for DisplayWrapper<'_, TXT<'a>> {
//     fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
//         write!(f, "{}", self.0)
//     }
// }

impl fmt::Display for DisplayWrapper<'_, Header> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // output depends on whether it's a query or a response
        // because some fields are unnecessary when Query or Response
        write!(f, "id:0x{:X}({}) ", self.0.id, self.0.id)?;
        write!(f, "flags:<{}>  ", DisplayWrapper(&self.0.flags))?;

        if self.0.flags.qr == PacketType::Query {
            write!(f, "QUERY:{}", self.0.qd_count)
        } else {
            write!(
                f,
                "QUERY:{}, ANSWER:{} AUTHORITY:{} ADDITIONAL:{}",
                self.0.qd_count, self.0.an_count, self.0.ns_count, self.0.ar_count
            )
        }
    }
}

impl fmt::Display for DisplayWrapper<'_, Flags> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // output depends on whether it's a query or a response
        // because some fields are unnecessary when Query or Response
        write!(f, "qr:{:?} ", self.0.qr)?;

        if self.0.qr == PacketType::Query {
            write!(
                f,
                "opcode:{:?} rd:{}",
                self.0.op_code, self.0.recursion_desired
            )
        } else {
            write!(f, "response code:{} ", self.0.response_code)?;
            Ok({
                flag_display!(f, self.0.authorative_answer, "aa");
                flag_display!(f, self.0.truncated, "tc");
                flag_display!(f, self.0.recursion_desired, "rd");
                flag_display!(f, self.0.recursion_available, "ra");
                flag_display!(f, self.0.authentic_data, "ad");
                flag_display!(f, self.0.checking_disabled, "cd");
            })
        }
    }
}

impl<'a> fmt::Display for DisplayWrapper<'_, Question<'a>> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "domain:{} qtype:{:?} qclass:{:?}",
            self.0.qname, self.0.qtype, self.0.qclass
        )
    }
}

// impl<'a> fmt::Display for DisplayWrapper<'_, Message<'a>> {
//     fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
//         // header first
//         write!(f, "{}\n", DisplayWrapper(&self.0.header))?;

//         // query or response ?
//         match self.0.header.flags.qr {
//             PacketType::Query => write!(f, "\nQUESTION: {}", DisplayWrapper(&self.0.question)),
//             PacketType::Response => Ok({
//                 write!(f, "\nANSWER:\n")?;

//                 // print out anwser, authority, additional if any
//                 if let Some(answer) = &self.0.answer {
//                     for ans in answer {
//                         write!(f, "{}", DisplayWrapper(ans))?;
//                     }
//                 }

//                 if let Some(auth) = &self.0.authority {
//                     for a in auth {
//                         write!(f, "{}", DisplayWrapper(a))?;
//                     }
//                 }

//                 if let Some(add) = &self.0.additional {
//                     for a in add {
//                         write!(f, "{}", DisplayWrapper(a))?;
//                     }
//                 }
//             }),
//         }
//     }
// }

// impl<'a> fmt::Display for DisplayWrapper<'_, ResourceRecord<'a>> {
//     fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
//         //println!("===========> rtype={:?}", self.0.r#type);

//         write!(
//             f,
//             "{:<20} {:<10?} {:<10} {:<10} {:<10}",
//             self.0.name.to_string(),
//             self.0.r#type,
//             DisplayWrapper(&self.0.class),
//             DisplayWrapper(&self.0.ttl),
//             self.0.rd_length
//         )?;

//         match self.0.r#type {
//             QType::A => match &self.0.r_data {
//                 Some(RData::A(ipv4)) => write!(f, "{}\n", std::net::Ipv4Addr::from(*ipv4)),
//                 _ => panic!("unexpected error when displaying RR A"),
//             },
//             QType::AAAA => match &self.0.r_data {
//                 Some(RData::AAAA(ipv6)) => write!(f, "{}\n", std::net::Ipv6Addr::from(*ipv6)),
//                 _ => panic!("unexpected error when displaying RR AAAA"),
//             },
//             QType::CNAME => rr_display!(f, &self.0.r_data, RData::CName, "CNAME"),
//             QType::HINFO => rr_display!(f, &self.0.r_data, RData::HInfo, "HINFO"),
//             QType::NS => rr_display!(f, &self.0.r_data, RData::Ns, "NS"),
//             QType::TXT => rr_display!(f, &self.0.r_data, RData::Txt, "TXT"),
//             QType::SOA => rr_display!(f, &self.0.r_data, RData::Soa, "SOA"),
//             QType::MX => rr_display!(f, &self.0.r_data, RData::Mx, "MX"),
//             _ => unimplemented!(),
//         }
//     }
// }
