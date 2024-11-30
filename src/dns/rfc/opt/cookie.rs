use type2network::ToNetworkOrder;
use type2network_derive::ToNetwork;

use serde::Serialize;

// Cookie: https://www.rfc-editor.org/rfc/rfc7873
#[derive(Debug, Default, ToNetwork, Serialize)]
pub struct COOKIE {
    client_cookie: Vec<u8>,
    server_cookie: Option<Vec<u8>>,
}
