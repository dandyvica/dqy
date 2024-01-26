[![Actions](https://github.com/dandyvica/siphash_c_d/actions/workflows/rust.yml/badge.svg)](https://github.com/dandyvica/siphash_c_d/actions/workflows/rust.yml)

Note: this is currently under development in my free time. Version is not even yet 0.1.0 
but hope to release executables in a couple of weeks.

# dqy
A DNS query tool inspired by _dig_, _drill_ and _dog_.

## Features
This tool is written in pure Rust with the following features:

* depends only on _rustls_ (no _openssl_)
* support upd, tcp, DoT and DoH protocols (DoQ to come)
* available on: Linux (x64, ARM64, musl), Window, MacOs
* possible outputs:
    * plain vanilla ascii
    * Json
    * ability to call a Lua script to fine tune the output

## Supported resource records
The following list of RRs is supported:

* A
* AAAA
* AFSDB
* APL
* CAA
* CDNSKEY
* CDS
* CERT
* CNAME
* CSYNC
* DHCID
* DLV
* DNAME
* DNSKEY
* DS
* EUI48
* EUI64
* HINFO
* HIP (*)
* HTTPS (*)
* IPSECKEY
* KX
* LOC
* MX
* NAPTR
* NS
* NSEC
* NSEC3
* NSEC3PARAM
* OPENPGPKEY
* OPT
* PTR
* RP
* RRSIG
* SMIMEA
* SOA
* SRV
* SSHFP
* SVCB (*)
* TLSA
* TXT
* UNKNOWN
* URI
* ZONEMD

Those with (*) are not yet fully tested.

## JSON support
The _--json_ and _--json-pretty_ options allows to display output data in JSON format with key:

* messages: list of messages
* info: meta-info like elpased time, endpoint address etc

## Lua scripting support
Using _-l <Lua source file>_, all DNS data are sent as global variables to the Lua interpreter which makes it possible to format the output in a very flexible manner.

## Roadmap
Following is a tentative roadmap:

* v0.2: ipv6 support
* v0.3: trace option
* v0.4: DNS over Quic
* v0.5: OPT options full support
* ...

## Usage
Just type:

```
$ dqy --help
```

## Examples




