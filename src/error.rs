//! A dedicated error for all possible errors in DNS queries: I/O, DNS packet unconsistencies, etc
use std::net::AddrParseError;
use std::path::PathBuf;
use std::process::ExitCode;
use std::time::Duration;
use std::{fmt, io};

use thiserror::Error;

/// A specific custom `Result` for all functions
pub type Result<T> = std::result::Result<T, self::Error>;

#[derive(Debug)]
pub enum Network {
    Bind,
    Connect,
    LocalAddr,
    PeerAddr,
    Read,
    Receive,
    Send,
    SetTimeout,
    SocketAddr,
}

#[derive(Debug)]
pub enum Dns {
    //domain name is over 255 bytes
    DomainNameTooLong,

    // a label of a domain name is over 63 bytes
    DomainLabelTooLong,

    // trying to create a domain from an empty string
    EmptyDomainName,

    // can't convert to an OpCode
    UnknowOpCode,

    // can't convert to a packet type
    UnknowPacketType,

    // when fetching the domain name from bytes, an index error
    CantCreateDomainName, //UnreachableResolvers,

    // when fetching the NSEC3 type bits, can't extract values
    CantCreateNSEC3Types,

    // no resolver is reachable
    UnreachableResolvers,

    // can't convert the server name or ip address to a socket address
    CantCreateSocketAddress,

    // error when tracing
    ImpossibleToTrace,

    // error during deserialization
    CantDeserialize,

    // error during Serialization
    CantSerialize,

    // SNI bad name
    InvalidSNI,
}

#[derive(Error, Debug)]
pub enum Error {
    // I/O errors
    #[error("cannot open file '{1}' ({0})")]
    OpenFile(#[source] io::Error, PathBuf),

    #[error("write buffer error {0}")]
    Buffer(#[source] io::Error),

    #[error("network {1:?} error ({0})")]
    Network(#[source] io::Error, Network),

    // #[error("unable to build a socket address '{1}' ({0})")]
    // SocketAddr(#[source] io::Error, String),
    #[error("unable to set network operations timeout to {1:?}ms ({0})")]
    Timeout(#[source] io::Error, Duration),

    // TLS errors
    #[error("TLS error ({0})")]
    Tls(#[source] rustls::Error),

    // Reqwest errors
    #[error("https error ({0})")]
    Reqwest(#[source] reqwest::Error),

    // Reqwest errors
    #[error("DNS error: {0}")]
    Dns(Dns),

    // IP address parsing errors
    #[error("unable to parse IP '{0}'")]
    IPParse(#[source] AddrParseError, String),

    // Logger info
    #[error("logger error '{0}'")]
    Logger(#[source] log::SetLoggerError),

    // Resolver errors
    #[error("resolver error ({0:?})")]
    Resolver(#[source] resolving::Error),

    #[cfg(feature = "mlua")]
    Lua(#[source] mlua::Error),
}

impl From<Error> for ExitCode {
    // Required method
    fn from(e: Error) -> Self {
        match e {
            Error::OpenFile(_, _) => ExitCode::from(1),
            Error::Buffer(_) => ExitCode::from(2),
            Error::Network(_, _) => ExitCode::from(3),
            Error::Timeout(_, _) => ExitCode::from(4),
            Error::Tls(_) => ExitCode::from(5),
            Error::Reqwest(_) => ExitCode::from(6),
            Error::Dns(_) => ExitCode::from(7),
            Error::IPParse(_, _) => ExitCode::from(8),
            Error::Logger(_) => ExitCode::from(9),
            Error::Resolver(_) => ExitCode::from(10),
            #[cfg(feature = "mlua")]
            Error::Lua(_) => ExitCode::from(10),
        }
    }
}

impl fmt::Display for Dns {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Dns::DomainNameTooLong => f.write_str("domain name is longer than 255 bytes"),
            Dns::DomainLabelTooLong => f.write_str("domain label is longer than 63 bytes"),
            Dns::EmptyDomainName => f.write_str("trying to create a domain from an empty string"),
            Dns::UnknowOpCode => f.write_str("opcode found in message was not recognized"),
            Dns::UnknowPacketType => f.write_str("patcket type found in message was not recognized"),
            Dns::CantSerialize => f.write_str("can't map DNS record to buffer"),
            Dns::CantDeserialize => f.write_str("can't recognize DNS message"),
            Dns::CantCreateDomainName => f.write_str("domain name can't be created from RR"),
            Dns::CantCreateNSEC3Types => f.write_str("can't extract types from NSEC or NSEC3 RR"),
            Dns::UnreachableResolvers => f.write_str("can't contact any resolver"),
            Dns::CantCreateSocketAddress => f.write_str("can't create a socket address from input"),
            Dns::ImpossibleToTrace => f.write_str("during tracing, an unexpected error occured"),
            Dns::InvalidSNI => f.write_str("SNI DNS name is invalid"),
            //Dns::ResponseError(rcode) => write!(f, "{rcode}"),
        }
    }
}

// impl Error {
//     pub fn new_internal(e: Dns) -> Self {
//         Error::Internal(e)
//     }
// }

// // All conversion for internal errors for Error
// macro_rules! ErrFrom {
//     ($err:path, $arm:path) => {
//         impl From<$err> for Error {
//             fn from(err: $err) -> Self {
//                 $arm(err)
//             }
//         }
//     };
// }

// ErrFrom!(io::Error, Error::Io);
// ErrFrom!(str::Utf8Error, Error::Utf8);
// ErrFrom!(AddrParseError, Error::IPParse);
// ErrFrom!(reqwest::Error, Error::Reqwest);
// ErrFrom!(rustls::Error, Error::Tls);
// ErrFrom!(resolving::error::Error, Error::Resolv);
// ErrFrom!(Dns, Error::Internal);
// ErrFrom!(log::SetLoggerError, Error::Logger);
// ErrFrom!(ParseIntError, Error::IntegerParse);

// #[cfg(feature = "mlua")]
// ErrFrom!(mlua::Error, Error::Lua);
