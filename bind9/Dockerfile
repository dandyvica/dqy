# used to test dqy

FROM ubuntu/bind9

COPY db.medical.equipment /etc/bind
COPY named.conf.local /etc/bind
COPY named.conf.options /etc/bind
COPY ./config/*.* /etc/bind/

CMD service bind9 start 