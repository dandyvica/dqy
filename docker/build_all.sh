#!/bin/bash
# build all possible images of dqy using docker

function build_dqy() {
    docker build -t $target -f $dockerfile .
    container_id=$(docker run -d $target)
    docker cp $container_id:/dqy/target/release/dqy-* ./images
    sha256sum ./images/$target >> ./images/sha256sum.txt    
    # docker start $container_id
    # docker rm $container_id
}

# platforms to build dqy for
declare -A platforms
platforms[dockerfile.alpine]="x86_64-unknown-linux-musl"
# platforms[dockerfile.arm64v8-alpine]="dqy-aarch64-linux-musl"
# platforms[dockerfile.arm64v8-ubuntu]="dqy-aarch64-linux-libc"
# platforms[dockerfile.ubuntu]="dqy-amd64-linux-libc"

for dockerfile in "${!platforms[@]}"
do
    target=${platforms[$dockerfile]}

    # build docker file depending on platform
    echo "build $target for platform $dockerfile"
    build_dqy
done



