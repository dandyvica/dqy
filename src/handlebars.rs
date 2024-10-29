// Manage handlebars display
use handlebars::Handlebars;
use serde::Serialize;

use crate::dns::message::MessageList;
use crate::QueryInfo;

#[derive(Serialize)]
struct HBData<'a> {
    messages: &'a MessageList,
    info: &'a QueryInfo,
}

pub fn render(messages: &MessageList, info: &QueryInfo, tpl: &str) {
    let mut handlebars = Handlebars::new();
    let data = HBData { messages, info };

    let rendered = handlebars.render_template(tpl, &data).unwrap();

    println!("{}", rendered);
}
