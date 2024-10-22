# Compiling `dqy`
If you want to compile `dqy` on your own, following are the instructions.

## With Lua scripting

* on Linux: make sure pkg-config is installed ```sudo apt-get install pkg-config``` and Lua dev libs too: ```sudo apt install liblua5.4-dev```
* OS/X: ```brew install pkg-config``` and ```brew install lua@5.4```
* on Windows (using ```PowerShell```)
    * download ```pkg-config```: https://download.gnome.org/binaries/win32/dependencies/
    * download ```Lua5.4 libs```: https://luabinaries.sourceforge.net/
    * set environment variables:    
        * ```Set-Item -Path env:LUA_LIB_NAME -Value "lua54"```
        * ```Set-Item -Path env:LUA_LIB -Value "mypath_where_lua54_lib_are"```
* then: ```cargo build --release --features mlua```

## Without Lua scripting
```cargo build --release```
