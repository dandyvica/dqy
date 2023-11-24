#/usr/bin/bash

# runs dig commands and tcpdump to capture data for tests

# cap1: plain DNS query to google.com without OPT
tcpdump -c 2 -n -w cap1.pcap host 1.1.1.1 2>/dev/null &
sleep 1 
dig @1.1.1.1 A www.google.com +noedns 1>/dev/null

# cap2: NS to hk. domain
tcpdump -c 2 -n -w cap2.pcap host 1.1.1.1 2>/dev/null &
sleep 1 
dig @1.1.1.1 NS hk. 1>/dev/null

# cap3: DNSKEY to hk. domain
tcpdump -c 2 -n -w cap3.pcap host 1.1.1.1 2>/dev/null &
sleep 1 
dig @1.1.1.1 DNSKEY hk. 1>/dev/null
