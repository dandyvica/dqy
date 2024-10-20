#[cfg(feature = "lua")]
use mlua::{Lua, LuaSerdeExt, Result};
use serde::Serialize;

pub struct LuaDisplay;

impl LuaDisplay {
    pub fn call_lua<T: Serialize, U: Serialize>(
        messages: T,
        info: U,
        lua_code: &str,
    ) -> Result<()> {
        // get lua context
        let lua = Lua::new();

        // convert data to value
        let lua_messages = lua.to_value(&messages)?;
        let lua_info = lua.to_value(&info)?;

        // we'll set a global name for all the DNS messages and info as well
        let globals = lua.globals();
        globals.set("dns", lua_messages)?;
        globals.set("info", lua_info)?;

        // execute code
        lua.load(lua_code).exec()?;

        Ok(())
    }
}
