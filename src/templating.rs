use serde::Serialize;
use tera::*;

use crate::dns::message::MessageList;
use crate::QueryInfo;

#[derive(Serialize)]
struct HBData<'a> {
    messages: &'a MessageList,
    info: &'a QueryInfo,
}

pub fn render(messages: &MessageList, info: &QueryInfo, tpl: &str) {
    let mut context = Context::new();

    context.insert("messages", messages);
    context.insert("info", info);
    let rendered = Tera::one_off(tpl, &context, true);

    println!("{}", rendered.unwrap());
}
