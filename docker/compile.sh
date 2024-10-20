cd dqy
. ~/.cargo/env

# get target triple used to rename exe
triple=$(rustc -vV | sed -n 's|host: ||p')

# build without Lua and rename exe
cargo build --release
strip /dqy/target/release/dqy
cp /dqy/target/release/dqy /dqy/target/release/dqy-$triple

# build with Lua and rename exe
cargo build --release --features mlua
strip /dqy/target/release/dqy
cp /dqy/target/release/dqy /dqy/target/release/dqy_lua-$triple