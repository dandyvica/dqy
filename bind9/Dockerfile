# used to test dqy

FROM ubuntu/bind9

COPY db.dqy-test.dns /etc/bind
COPY named.conf.local /etc/bind
COPY named.conf.options /etc/bind
COPY cert/cert.pem /etc/bind
COPY cert/key.pem /etc/bind

RUN <<EOF
apt update
apt-get install dnsutils -y
apt-get install net-tools -y
EOF

# CMD sudo service bind9 start 