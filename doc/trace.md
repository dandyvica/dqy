https://superuser.com/questions/715632/how-does-dig-trace-actually-work

dig +trace www.google.co.uk

* choose a random root server => 192.5.5.241
* send a non-recursive request to 192.5.5.241 for www.google.co.uk
* in the authority section, choose a random NS server for uk. domain => 195.66.240.130
* send a non-recursive request to 195.66.240.130 for www.google.co.uk
* in the authority section, choose a random NS server for google.co.uk. domain => 

Samples:

1) Send to the h-root server

dqy A www.google.co.uk @198.97.190.53 --no-recurse

uk.                          NS         IN         172800     10        nsa.nic.uk.
uk.                          NS         IN         172800     6         nsb.nic.uk.
uk.                          NS         IN         172800     6         nsc.nic.uk.
uk.                          NS         IN         172800     6         nsd.nic.uk.
uk.                          NS         IN         172800     7         dns1.nic.uk.
uk.                          NS         IN         172800     7         dns2.nic.uk.
uk.                          NS         IN         172800     7         dns3.nic.uk.
uk.                          NS         IN         172800     7         dns4.nic.uk.
nsa.nic.uk.                  A          IN         172800     4         156.154.100.3
nsb.nic.uk.                  A          IN         172800     4         156.154.101.3
nsc.nic.uk.                  A          IN         172800     4         156.154.102.3
nsd.nic.uk.                  A          IN         172800     4         156.154.103.3
dns1.nic.uk.                 A          IN         172800     4         213.248.216.1
dns2.nic.uk.                 A          IN         172800     4         103.49.80.1
dns3.nic.uk.                 A          IN         172800     4         213.248.220.1
dns4.nic.uk.                 A          IN         172800     4         43.230.48.1
nsa.nic.uk.                  AAAA       IN         172800     16        2001:502:ad09::3
nsb.nic.uk.                  AAAA       IN         172800     16        2001:502:2eda::3
nsc.nic.uk.                  AAAA       IN         172800     16        2610:a1:1009::3
nsd.nic.uk.                  AAAA       IN         172800     16        2610:a1:1010::3
dns1.nic.uk.                 AAAA       IN         172800     16        2a01:618:400::1
dns2.nic.uk.                 AAAA       IN         172800     16        2401:fd80:400::1
dns3.nic.uk.                 AAAA       IN         172800     16        2a01:618:404::1
dns4.nic.uk.                 AAAA       IN         172800     16        2401:fd80:404::1

2) choose a referral ip address and send request to ip

dqy A www.google.co.uk @156.154.100.3 --no-recurse

google.co.uk.                NS         IN         172800     16        ns2.google.com.
google.co.uk.                NS         IN         172800     6         ns3.google.com.
google.co.uk.                NS         IN         172800     6         ns4.google.com.
google.co.uk.                NS         IN         172800     6         ns1.google.com.

3) no glue records, so need to get the ip address of ns2.google.com. (for example)
so need to restart from any root (e.g.: g-root)

dqy A @192.112.36.4 ns2.google.com. --no-recurse

com.                         NS         IN         172800     20        j.gtld-servers.net.
com.                         NS         IN         172800     4         f.gtld-servers.net.
com.                         NS         IN         172800     4         a.gtld-servers.net.
com.                         NS         IN         172800     4         d.gtld-servers.net.
com.                         NS         IN         172800     4         b.gtld-servers.net.
com.                         NS         IN         172800     4         c.gtld-servers.net.
com.                         NS         IN         172800     4         m.gtld-servers.net.
com.                         NS         IN         172800     4         l.gtld-servers.net.
com.                         NS         IN         172800     4         i.gtld-servers.net.
com.                         NS         IN         172800     4         e.gtld-servers.net.
com.                         NS         IN         172800     4         h.gtld-servers.net.
com.                         NS         IN         172800     4         k.gtld-servers.net.
com.                         NS         IN         172800     4         g.gtld-servers.net.
m.gtld-servers.net.          A          IN         172800     4         192.55.83.30
l.gtld-servers.net.          A          IN         172800     4         192.41.162.30
k.gtld-servers.net.          A          IN         172800     4         192.52.178.30
j.gtld-servers.net.          A          IN         172800     4         192.48.79.30
i.gtld-servers.net.          A          IN         172800     4         192.43.172.30
h.gtld-servers.net.          A          IN         172800     4         192.54.112.30
g.gtld-servers.net.          A          IN         172800     4         192.42.93.30
f.gtld-servers.net.          A          IN         172800     4         192.35.51.30
e.gtld-servers.net.          A          IN         172800     4         192.12.94.30
d.gtld-servers.net.          A          IN         172800     4         192.31.80.30
c.gtld-servers.net.          A          IN         172800     4         192.26.92.30
b.gtld-servers.net.          A          IN         172800     4         192.33.14.30
a.gtld-servers.net.          A          IN         172800     4         192.5.6.30
m.gtld-servers.net.          AAAA       IN         172800     16        2001:501:b1f9::30
l.gtld-servers.net.          AAAA       IN         172800     16        2001:500:d937::30
k.gtld-servers.net.          AAAA       IN         172800     16        2001:503:d2d::30
j.gtld-servers.net.          AAAA       IN         172800     16        2001:502:7094::30
i.gtld-servers.net.          AAAA       IN         172800     16        2001:503:39c1::30
h.gtld-servers.net.          AAAA       IN         172800     16        2001:502:8cc::30
g.gtld-servers.net.          AAAA       IN         172800     16        2001:503:eea3::30
f.gtld-servers.net.          AAAA       IN         172800     16        2001:503:d414::30
e.gtld-servers.net.          AAAA       IN         172800     16        2001:502:1ca1::30
d.gtld-servers.net.          AAAA       IN         172800     16        2001:500:856e::30
c.gtld-servers.net.          AAAA       IN         172800     16        2001:503:83eb::30
b.gtld-servers.net.          AAAA       IN         172800     16        2001:503:231d::2:30
a.gtld-servers.net.          AAAA       IN         172800     16        2001:503:a83e::2:30

4) find NS records of .com and send request to let say 192.55.83.30 (m.gtld-servers.net.)

dqy A @192.55.83.30 ns2.google.com. --no-recurse

google.com.                  NS         IN         172800     2         ns2.google.com.
google.com.                  NS         IN         172800     6         ns1.google.com.
google.com.                  NS         IN         172800     6         ns3.google.com.
google.com.                  NS         IN         172800     6         ns4.google.com.
ns2.google.com.              AAAA       IN         172800     16        2001:4860:4802:34::a
ns2.google.com.              A          IN         172800     4         216.239.34.10
ns1.google.com.              AAAA       IN         172800     16        2001:4860:4802:32::a
ns1.google.com.              A          IN         172800     4         216.239.32.10
ns3.google.com.              AAAA       IN         172800     16        2001:4860:4802:36::a
ns3.google.com.              A          IN         172800     4         216.239.36.10
ns4.google.com.              AAAA       IN         172800     16        2001:4860:4802:38::a
ns4.google.com.              A          IN         172800     4         216.239.38.10

5) now we have the ip address of ns2.google.com. => 216.239.34.10, we can send final request:

dqy A @216.239.34.10 www.google.co.uk. --no-recurse

www.google.co.uk.            A          IN         300        4         172.217.20.195

Finished, the ww.google.co.uk ip 4 address is: 172.217.20.195




