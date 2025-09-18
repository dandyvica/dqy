#[cfg(feature = "mlua")]
use mlua::{Lua, LuaSerdeExt};
use serde::Serialize;

use dnslib::error::Error;

pub struct LuaDisplay;

impl LuaDisplay {
    pub fn call_lua<T: Serialize, U: Serialize>(messages: T, info: U, lua_code: &str) -> dnslib::error::Result<()> {
        // get lua context
        let lua = Lua::new();

        // convert data to value
        let lua_messages = lua.to_value(&messages).map_err(|e| Error::Lua(e))?;
        let lua_info = lua.to_value(&info).map_err(|e| Error::Lua(e))?;

        // we'll set a global name for all the DNS messages and info as well
        let globals = lua.globals();
        globals.set("dns", lua_messages).map_err(|e| Error::Lua(e))?;
        globals.set("info", lua_info).map_err(|e| Error::Lua(e))?;

        // execute code
        lua.load(lua_code).exec().map_err(|e| Error::Lua(e))?;

        Ok(())
    }
}
