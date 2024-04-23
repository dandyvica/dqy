"""
Build dqy executable depending on the platform
"""
import subprocess


def exec_docker(docker_file: str, target: str):
    try:
        # build dqy
        args = ["docker", "-t", target, "-f", docker_file, "."]
        print(args)
        rc = subprocess.run(args, capture_output=True, text=True)
        container_id = rc.stdout
        print(container_id)

        # copy exec from docker image
        args = ["docker", "cp",
                f"{container_id}:/dqy/target/release/dqy", f"images/{target}"]
    except subprocess.CalledProcessError as e:
        print(e.output)


# dockerfile is build depending on the platform
DOCKERFILE = """
FROM {}

RUN <<EOF
sudo apt-get install git
sudo apt-get install curl
sudo apt-get install gcc
sudo apt-get install pkg-config
sudo apt-get install lua
sudo apt-get install lua5.4-dev
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
source "$HOME/.cargo/env"
git clone https://github.com/dandyvica/dqy
cd dqy
cargo build --release
EOF
"""

# list of all possible platforms
platforms = {
    "alpine": "dqy-amd64-linux-musl",
    "arm64v8/alpine": "dqy-aarch64-linux-musl",
    "ubuntu": "dqy-amd64-linux-libc",
    "arm64v8/ubuntu": "dqy-amd64-linux-musl"
}

for pf, target in platforms.items():
    docker_ext = pf.replace('/', '-')
    docker_file = f"dockerfile.{docker_ext}"

    # build docker file and build dqy
    with open(docker_file, "w") as f:
        f.write(DOCKERFILE.format(pf))

        # exec_docker(docker_file, target)
