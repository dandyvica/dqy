#/usr/bin/bash

# runs dig commands and tcpdump to capture data for tests
set -x
tcpdump -i enp5s0 -c 2 -n -w $1.pcap host 45.90.28.55 &
sleep 1 
dig $1 $1.dns.netmeister.org. +short
sleep 1
/data/projects/rust/dqy/target/debug/dqy $1 $1.dns.netmeister.org.