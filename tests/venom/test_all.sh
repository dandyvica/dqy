# should start in the directory where venom yml files are located

# test IDNA
venom run idna.yml --output-dir=./log

# test different ways of using an endpoint
venom run endpoint-ipv4.yml --output-dir=./log
venom run endpoint-ipv6.yml --output-dir=./log