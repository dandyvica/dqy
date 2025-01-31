// titles when displaying headers: build a map giving for each title its colored version
use colored::*;
use std::collections::HashMap;
use std::sync::LazyLock;

type ColoredTitles = HashMap<String, ColoredString>;

pub static TITLES: LazyLock<ColoredTitles> = LazyLock::new(|| {
    const COLOR: Color = Color::BrightCyan;

    // local helper
    fn insert_title(h: &mut ColoredTitles, title: &str, color: Color) {
        h.insert(title.to_string(), title.color(color));
    }

    // init new hmap
    let mut h = HashMap::new();

    // add all titles
    insert_title(&mut h, "qname", COLOR);
    insert_title(&mut h, "qtype", COLOR);
    insert_title(&mut h, "qclass", COLOR);
    insert_title(&mut h, "name", COLOR);
    insert_title(&mut h, "type", COLOR);
    insert_title(&mut h, "payload", COLOR);
    insert_title(&mut h, "rcode", COLOR);
    insert_title(&mut h, "version", COLOR);
    insert_title(&mut h, "flags", COLOR);

    h
});

pub fn header_section(text: &str, length: Option<usize>) -> ColoredString {
    let s = if let Some(l) = length {
        format!("{:<l$}", text)
    } else {
        text.to_string()
    };
    s.black().on_bright_cyan()
}