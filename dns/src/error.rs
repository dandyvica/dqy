//! A dedicated error for all possible errors in DNS queries: I/O, DNS packet unconsistencies, etc
use std::net::AddrParseError;
use std::str;
use std::{fmt, io};

//#[derive(Debug)]
pub enum DNSError {
    Io(io::Error),
    FromUtf8(std::string::FromUtf8Error),
    Utf8(str::Utf8Error),
    AddrParseError(AddrParseError),
    //DNS(String),
    DNSInternalError(InternalError),
    //Conversion(String),
}

#[derive(Debug)]
pub enum InternalError {
    DnsDomainNameTooLong,
    EmptyDomainName,
    UnknowOpCode,
    UnknowPacketType,
    UnknowQClass,
    UnreachableResolvers,
}

impl DNSError {
    // Helper function to create a new DNS error from a string
    // pub fn new(s: &str) -> Self {
    //     DNSError::DNS(String::from(s))
    // }

    pub fn new_internal(e: InternalError) -> Self {
        DNSError::DNSInternalError(e)
    }
}

impl fmt::Debug for DNSError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            DNSError::Io(e) => write!(f, "I/O {}", e),
            DNSError::FromUtf8(e) => write!(f, "UTF8 conversion {}", e),
            DNSError::Utf8(e) => write!(f, "UTF8 conversion {}", e),
            DNSError::AddrParseError(e) => write!(f, "IP address {}", e),
            //DNSError::DNS(String) => {}
            DNSError::DNSInternalError(e) => write!(f, "internal DNS error {:?}", e),
            //DNSError::Conversion(String) => {}
        }
    }
}

/// A specific custom `Result` for all functions
pub type DNSResult<T> = Result<T, DNSError>;

// All convertion for internal errors for DNSError
impl From<io::Error> for DNSError {
    fn from(err: io::Error) -> Self {
        DNSError::Io(err)
    }
}

// impl From<String> for DNSError {
//     fn from(err: String) -> Self {
//         DNSError::DNS(err)
//     }
// }

impl From<std::string::FromUtf8Error> for DNSError {
    fn from(err: std::string::FromUtf8Error) -> Self {
        DNSError::FromUtf8(err)
    }
}

impl From<str::Utf8Error> for DNSError {
    fn from(err: str::Utf8Error) -> Self {
        DNSError::Utf8(err)
    }
}

// impl From<log::SetLoggerError> for DNSError {
//     fn from(err: log::SetLoggerError) -> Self {
//         DNSError::LoggerError(err)
//     }
// }

impl From<AddrParseError> for DNSError {
    fn from(err: AddrParseError) -> Self {
        DNSError::AddrParseError(err)
    }
}

// impl<'a> From<&'a str> for DNSError {
//     fn from(err: &str) -> Self {
//         DNSError::Conversion(String::from(err))
//     }
// }
