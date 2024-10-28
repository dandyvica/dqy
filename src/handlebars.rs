// Manage handlebars display
use handlebars::Handlebars;

use crate::dns::message::MessageList;

pub fn render(messages: &MessageList, tpl: &str) {
    let mut handlebars = Handlebars::new();
    let rendered = handlebars.render_template(tpl, messages).unwrap();

    println!("{}", rendered);
}
