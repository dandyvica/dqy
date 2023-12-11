# dqy
A DNS query tool

## List of RFCs

* [NSEC3 & NSEC3PARAM](https://datatracker.ietf.org/doc/html/rfc5155)
* [Handling of Unknown DNS Resource Record (RR) Types](https://datatracker.ietf.org/doc/html/rfc3597)
* [OPT Padding](https://datatracker.ietf.org/doc/html/rfc7830)

## Tests
* dig +dnssec NSEC3 gggg.icann.org.
* dqy @1.1.1.1 NSEC gggg.icann.org. --dnssec --tls => Padding option
dig +dnssec @ns6.cloudflare.com NSEC ocsp.cloudflare.com => A HINFO MX TXT AAAA LOC SRV NAPTR CERT SSHFP RRSIG NSEC TLSA SMIMEA HIP OPENPGPKEY TYPE64 TYPE65 URI CAA


