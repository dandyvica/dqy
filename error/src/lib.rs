//! A dedicated error for all possible errors in DNS queries: I/O, DNS packet unconsistencies, etc
use std::net::{AddrParseError, SocketAddr};
use std::str;
use std::{fmt, io};

/// A specific custom `Result` for all functions
pub type Result<T> = std::result::Result<T, self::Error>;

// helper macro to ease returning the internal DNS errors
#[macro_export]
macro_rules! err_internal {
    ($err:ident) => {
        Error::InternalError(ProtocolError::$err)
    };
}

//#[derive(Debug)]
pub enum Error {
    // a network error
    Io(io::Error),

    // a conversion to str caused an error
    Utf8(str::Utf8Error),

    // an str to IP conversion error
    AddrParseError(AddrParseError),

    // DNS protocol error (malformed data)
    InternalError(ProtocolError),

    // reqwest error when using DoH
    Reqwest(reqwest::Error),

    // TLS error when using DoT
    Tls(rustls::Error),

    // Error when fetching resolvers
    Resolv(resolver::error::Error),

    // No connexion to any TCP address succeeds
    NoValidTCPConnection(Vec<SocketAddr>),

    // Error during Lua calls
    #[cfg(feature = "mlua")]
    Lua(mlua::Error),
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
}

impl fmt::Display for ProtocolError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ProtocolError::DomainNameTooLong => {
                f.write_str("trying to use a domain name longer than 255 bytes")
            }
            ProtocolError::DomainLabelTooLong => {
                f.write_str("trying to use a domain label longer than 63 bytes")
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
        }
    }
}

impl Error {
    pub fn new_internal(e: ProtocolError) -> Self {
        Error::InternalError(e)
    }
}

impl fmt::Debug for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Io(e) => write!(f, "I/O {}", e),
            //Error::FromUtf8(e) => write!(f, "UTF8 conversion {}", e),
            Error::Utf8(e) => write!(f, "UTF8 conversion {}", e),
            Error::AddrParseError(e) => write!(f, "IP address {}", e),
            Error::InternalError(e) => write!(f, "internal DNS error {:?}", e),
            Error::Reqwest(e) => write!(f, "DoH error {:?}", e),
            Error::Tls(e) => write!(f, "TLS error {:?}", e),
            Error::Resolv(e) => write!(f, "error {:?} fetching resolvers", e),
            Error::NoValidTCPConnection(e) => write!(f, "error {:?} for TCP connections", e),
            #[cfg(feature = "mlua")]
            Error::Lua(e) => write!(f, "Lua error: {:?}", e),
        }
    }
}

// All convertion for internal errors for Error
impl From<io::Error> for Error {
    fn from(err: io::Error) -> Self {
        Error::Io(err)
    }
}

impl From<str::Utf8Error> for Error {
    fn from(err: str::Utf8Error) -> Self {
        Error::Utf8(err)
    }
}

impl From<AddrParseError> for Error {
    fn from(err: AddrParseError) -> Self {
        Error::AddrParseError(err)
    }
}

impl From<reqwest::Error> for Error {
    fn from(err: reqwest::Error) -> Self {
        Error::Reqwest(err)
    }
}

impl From<rustls::Error> for Error {
    fn from(err: rustls::Error) -> Self {
        Error::Tls(err)
    }
}

impl From<resolver::error::Error> for Error {
    fn from(err: resolver::error::Error) -> Self {
        Error::Resolv(err)
    }
}

#[cfg(feature = "mlua")]
impl From<mlua::Error> for Error {
    fn from(err: mlua::Error) -> Self {
        Error::Lua(err)
    }
}
