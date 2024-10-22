# used to compile Linux x64 musl
# build image with: docker build -t dqy-alpine -f dockerfile.alpine .
# run a container from image: docker run -d -it --name dqy-alpine-ctr dqy-alpine /bin/sh
# compile dqy: 

# build dqy inside container

ARG IMAGE
FROM $IMAGE

RUN <<EOF
apk update
apk add git
apk add curl
apk add gcc
apk add musl-dev
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --profile minimal
git clone https://github.com/dandyvica/dqy
echo "cd dqy" >compile.sh
echo "git pull" >> compile.sh
echo "source ~/.cargo/env" >> compile.sh
echo "cargo build --release" >> compile.sh
chmod +x compile.sh
EOF

CMD /compile.sh
    