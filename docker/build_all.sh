#!/bin/bash
# build all possible images of dqy using docker

function build_dqy() {
    # $1 is the name of the image and the container (e.g.: x86_64-unknown-linux-musl)
    # $2 is the name of the platform (e.g: linux/amd64)
    # $3 is the name of the docker hub base image (e.g.: alpine)
    # $4 is the name of the dockerfile

    target=$1
    platform=$2
    base_image=$3
    dockerfile=$4 

    docker build -t $target --no-cache --platform $platform --build-arg BASE_IMAGE=$base_image -f $dockerfile .
    docker run --name $target $target
    docker cp $target:/dqy/target/release/dqy ./images/dqy-$target
    sha256sum ./images/dqy-$target >> ./images/sha256sum.txt    
    docker rm $target
}

# platforms to build dqy for
set -o xtrace

# this is where images will be located
mkdir -p ./images

# build_dqy "x86_64-unknown-linux-musl" "linux/amd64" "alpine" "dockerfile.alpine"
build_dqy "linux-arm" "linux/arm64" "alpine" "dockerfile.alpine"

# build dqy for all platforms
# for image in "${!platforms[@]}"
# do
#     target=${platforms[$image]}

#     # build docker file depending on platform
#     echo "build $target for platform $image"
#     build_dqy
# done



