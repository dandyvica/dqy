#/usr/bin/bash

# runs dig commands and tcpdump to capture data for tests
set -x

# start tcpdump to capture packets
tcpdump -i enp5s0 -c 100 -n -w $1.pcap host 45.90.28.55 &
tcpdump_pid=$!
echo "process ID=$tcpdump_pid"
sleep 1 

# start dig to send/receive DNS packets
dig $2 $1 $1.dns.netmeister.org. +short
sleep 2

# gracedully kill tcpdump
kill -INT $tcpdump_pid

# compare with dqy
/data/projects/rust/dqy/target/debug/dqy $1 $1.dns.netmeister.org.