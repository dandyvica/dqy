// Module to print out DNS response results
use dnslib::rfc1035::resource_record::*;

#[derive(Debug, Copy, Clone)]
enum Color {
    Black = 30,
    Red = 31,
    Green = 32,
    Yellow = 33,
    Blue = 34,
    Magenta = 35,
    Cyan = 36,
    White = 37,
    Default = 39,
    Reset = 0,
}

enum DisplayType {
    Color(Color),
    JSON,
    Text,
}

pub struct DisplayWrapper<'a, T> {
    dtype: DisplayType,
    data: &'a T,
}
