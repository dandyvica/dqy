# dqy tests using venom and bind9 bespoke configuration

# test internet resources
venom run venom/internet.yml

# test BIND9 server on Docker
echo "testing on udp"
venom run venom/bind9.yml --var="target='@localhost'" --var="opts='-p 10053'" 

echo "testing on tcp"
venom run venom/bind9.yml --var="target='@localhost'" --var="opts='-p 10053 --tcp'"

echo "testing on DoT"
venom run venom/bind9.yml --var="target='@localhost'" --var="opts='-p 10853 --dot --cert bind9/cert/cert.der'"

echo "testing on DoH"
venom run venom/bind9.yml --var="target='@https://localhost:10443/dns-query'" --var="opts='--doh --cert bind9/cert/cert.pem'"