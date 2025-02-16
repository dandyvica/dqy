# download MUSL target and compile
# only for Linux
if [ $(uname) = "Linux" ]; then
    platform=$(uname -i)
    target="$platform-unknown-linux-musl"

    # install musl gcc
    sudo apt install musl-tools

    # add target
    rustup target add $target

    # compile
    cargo build --release --target=$target
fi
