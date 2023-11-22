


#[derive(Debug, Default, ToNetwork, FromNetwork)]
pub struct ExtendedRcode {
    pub extented_rcode: u8,
    pub version: u8,
    pub doz: u16,
}