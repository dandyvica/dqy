// Manage handlebars display
use handlebars::*;
use serde::Serialize;

use crate::dns::message::MessageList;
use crate::QueryInfo;

// custom helper
handlebars_helper!(ljust: |length: usize, x: String| format!("{:<length$}", x));

#[derive(Debug, Serialize)]
struct HBData<'a> {
    messages: &'a MessageList,
    info: &'a QueryInfo,
}

impl HelperDef for HBData<'_> {
    fn call<'reg: 'rc, 'rc>(
        &self,
        h: &Helper,
        _: &Handlebars,
        _: &Context,
        _rc: &mut RenderContext,
        out: &mut dyn Output,
    ) -> HelperResult {
        let param1 = h.param(0).unwrap();
        let param2 = h.param(1).unwrap();

        let length = param1.value().as_u64().unwrap() as usize;

        out.write(&format!("{:<length$}", param2.value().render()))?;
        Ok(())
    }
}

pub fn render(messages: &MessageList, info: &QueryInfo, tpl: &str) {
    let handlebars = Handlebars::new();

    //handlebars.register_helper("ljust", Box::new(ljust));
    //handlebars.register_helper("ljust", Box::new(data));

    let data = HBData { messages, info };
    let rendered = handlebars.render_template(tpl, &data).unwrap();

    println!("{}", rendered);
}
