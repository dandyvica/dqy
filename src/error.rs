//! A dedicated error for all possible errors in DNS queries: I/O, DNS packet unconsistencies, etc
use std::fmt::Display;
use std::net::{AddrParseError, SocketAddr};
use std::num::ParseIntError;
use std::process::ExitCode;
use std::str;
use std::{fmt, io};

use crate::dns::rfc::response_code::ResponseCode;

/// A specific custom `Result` for all functions
pub type Result<T> = std::result::Result<T, self::Error>;

// helper macro to ease returning the internal DNS errors
#[macro_export]
macro_rules! err_internal {
    ($err:ident) => {
        Error::Internal(ProtocolError::$err)
    };
}

#[derive(Debug)]
pub enum Error {
    // a network error
    Io(io::Error),

    // a conversion to str caused an error
    Utf8(str::Utf8Error),

    // conversion from a string to int error
    IntegerParse(ParseIntError),

    // an str to IP conversion error
    IPParse(AddrParseError),

    // DNS protocol error (malformed data)
    Internal(ProtocolError),

    // reqwest error when using DoH
    Reqwest(reqwest::Error),

    // TLS error when using DoT
    Tls(rustls::Error),

    // Error when fetching resolvers
    Resolv(resolver::error::Error),

    // No connexion to any TCP address succeeds
    NoValidTCPConnection(Vec<SocketAddr>),

    // Error when creating log file
    Logger(log::SetLoggerError),

    // Error during Lua calls
    #[cfg(feature = "mlua")]
    Lua(mlua::Error),
}

impl Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Io(e) => write!(f, "I/O error: {}", e),
            Error::Utf8(e) => write!(f, "UTF8 conversion {}", e),
            Error::IPParse(e) => write!(f, "IP address parsing error: {}", e),
            Error::IntegerParse(e) => write!(f, "Can't convert port number: {}", e),
            Error::Internal(e) => write!(f, "DNS error: {}", e),
            Error::Reqwest(e) => write!(f, "DoH error: {}", e),
            Error::Tls(e) => write!(f, "TLS error: {}", e),
            Error::Resolv(e) => write!(f, "error {:?} fetching resolvers", e),
            Error::Logger(e) => write!(f, "error {:?} setting logger", e),
            Error::NoValidTCPConnection(e) => write!(f, "error {:?} for TCP connections", e),
            #[cfg(feature = "mlua")]
            Error::Lua(e) => write!(f, "Lua error: {:?}", e),
        }
    }
}

impl From<Error> for ExitCode {
    // Required method
    fn from(e: Error) -> Self {
        match e {
            Error::Io(_) => ExitCode::from(1),
            Error::Utf8(_) => ExitCode::from(2),
            Error::IPParse(_) => ExitCode::from(3),
            Error::Internal(_) => ExitCode::from(4),
            Error::Reqwest(_) => ExitCode::from(5),
            Error::Tls(_) => ExitCode::from(6),
            Error::Resolv(_) => ExitCode::from(7),
            Error::NoValidTCPConnection(_) => ExitCode::from(8),
            Error::Logger(_) => ExitCode::from(10),
            Error::IntegerParse(_) => ExitCode::from(11),
            #[cfg(feature = "mlua")]
            Error::Lua(_) => ExitCode::from(9),
        }
    }
}

#[derive(Debug)]
pub enum ProtocolError {
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
    ErrorDuringTracing,

    // resolver response error
    ResponseError(ResponseCode),
}

impl fmt::Display for ProtocolError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ProtocolError::DomainNameTooLong => f.write_str("domain name is longer than 255 bytes"),
            ProtocolError::DomainLabelTooLong => {
                f.write_str("domain label is longer than 63 bytes")
            }
            ProtocolError::EmptyDomainName => {
                f.write_str("trying to create a domain from an empty string")
            }
            ProtocolError::UnknowOpCode => {
                f.write_str("opcode found in message was not recognized")
            }
            ProtocolError::UnknowPacketType => {
                f.write_str("patcket type found in message was not recognized")
            }
            ProtocolError::CantCreateDomainName => {
                f.write_str("domain name can't be created from RR")
            }
            ProtocolError::CantCreateNSEC3Types => {
                f.write_str("can't extract types from NSEC or NSEC3 RR")
            }
            ProtocolError::UnreachableResolvers => f.write_str("can't contact any resolver"),
            ProtocolError::CantCreateSocketAddress => {
                f.write_str("can't create a socket address from input")
            }
            ProtocolError::ErrorDuringTracing => {
                f.write_str("during tracing, an unexpected error occured")
            }
            ProtocolError::ResponseError(rcode) => write!(f, "{rcode}"),
        }
    }
}

impl Error {
    pub fn new_internal(e: ProtocolError) -> Self {
        Error::Internal(e)
    }
}

// All conversion for internal errors for Error
macro_rules! ErrFrom {
    ($err:path, $arm:path) => {
        impl From<$err> for Error {
            fn from(err: $err) -> Self {
                $arm(err)
            }
        }
    };
}

ErrFrom!(io::Error, Error::Io);
ErrFrom!(str::Utf8Error, Error::Utf8);
ErrFrom!(AddrParseError, Error::IPParse);
ErrFrom!(reqwest::Error, Error::Reqwest);
ErrFrom!(rustls::Error, Error::Tls);
ErrFrom!(resolver::error::Error, Error::Resolv);
ErrFrom!(ProtocolError, Error::Internal);
ErrFrom!(log::SetLoggerError, Error::Logger);
ErrFrom!(ParseIntError, Error::IntegerParse);

#[cfg(feature = "mlua")]
ErrFrom!(mlua::Error, Error::Lua);
