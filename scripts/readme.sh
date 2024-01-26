# name servers for root
dqy NS .

# same with no OPT record sent
dqy NS . --no-opt

# query AAAA records using OS configured DNS resolvers
dqy AAAA www.google.com

# setting payload in OPT
dqy AAAA www.google.com --bufsize=4096

# same but to Cloudfare server
dqy AAAA www.google.com @1.1.1.1

# using TCP
dqy AAAA www.google.com @1.1.1.1 --tcp

# using DoT
dqy AAAA www.google.com @dns.quad9.net --tls
dqy AAAA www.google.com @1.1.1.1 --dot

# using DoH
dqy TXT www.google.com @https://cloudflare-dns.com/dns-query --doh