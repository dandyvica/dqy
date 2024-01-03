use std::fmt;

use type2network::ToNetworkOrder;
use type2network_derive::ToNetwork;

use crate::databuf::Buffer;

// NSID: https://www.rfc-editor.org/rfc/rfc5001.html
#[derive(Debug, Default, ToNetwork)]
pub struct PADDING(Option<Buffer>);

impl From<Buffer> for PADDING {
    fn from(buf: Buffer) -> Self {
        Self(Some(buf))
    }
}

impl fmt::Display for PADDING {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.0.is_some() {
            let buf = self.0.as_ref().unwrap();
            for c in buf.iter() {
                write!(f, "{:0X?} ", c)?;
            }
            for c in buf.iter() {
                write!(f, "{}", *c as char)?;
            }
        }

        Ok(())
    }
}
