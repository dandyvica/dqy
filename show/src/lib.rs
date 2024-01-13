#[derive(Debug, Default, PartialEq)]
pub enum ShowType {
    Json,

    #[default]
    Regular,
    Color,
}

pub trait Show {
    fn show(&self, stype: ShowType);
}
