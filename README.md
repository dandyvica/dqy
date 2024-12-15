[![Actions](https://github.com/dandyvica/dqy/actions/workflows/rust.yml/badge.svg)](https://github.com/dandyvica/dqy/actions/workflows/rust.yml)

Note: this is currently under development in my free time.

# dqy
A DNS query tool inspired by _dig_, _drill_ and _dog_.

## Features
This tool is written in pure Rust with the following features:

* depends only on _rustls_ (no _openssl_ dependency)
* support upd, tcp, DoT, DoH and DoQ protocols
* available on: Linux (x64, ARM64, musl), Window, MacOs
* IDNA support
* possible outputs:
    * plain vanilla ascii
    * Json (useful with ```jq```)
    * ability to call a Lua script to fine tune the output (when `mlua` feature is enabled)

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
* URI
* ZONEMD

Those with (*) are not yet fully tested. This will probably the case for v0.5

## JSON support
The _--json_ and _--json-pretty_ options allows to display output data in JSON format with key:

* messages: list of messages
* info: meta-info like elpased time, endpoint address etc

## Lua scripting support
Using `-l <Lua source file>`, all DNS data are sent as global variables to the Lua interpreter which makes it possible to format the output in a very flexible manner.

As Lua tables can't keep the order of fields when created, a special Lua module is provided in the repository: ```rdata.lua``` which contains RRs list of fields in an ordered way, and a helper function to display ```RData```.

To use that module, you need to set the ```LUA_PATH``` module:

* ```export LUA_PATH=/home/johndoe/lua/rdata.lua``` on UNIX platforms
* ```Set-Item -Path env:LUA_PATH -Value "C:\Users\johndoe\projects\dqy\lua\rdata.lua"``` on Windows PowerShell

Two Lua examples are also provided:

* ```dig.lua``` which mimics ```dig``` output
* ```dog.lua``` which mimics ```dog``` output (to some extent without colors)

Lua uses 2 global variables which are created by ```dqy```:

* ```dns``` which contains the list of queries and responses for each type requested
* ```info``` for some meta information like elpased time, bytes count sent and received etc

If you want to dump the whole Lua table, just use this Lua code posted here:
https://stackoverflow.com/questions/9168058/how-to-dump-a-table-to-console


## Bugs
Beware it's a humble utility and probably buggy. Feel free to test it and report issues.
Specially in the display options, not all are implemented or even specially useful because of the Lua scripting or JSON output.

## Roadmap
Following is a tentative roadmap:

* v0.2: ipv6 support (done)
* v0.3: trace option (done)
* v0.4: OPT options full support
* v0.5: DNS over Quic
* ...

## Usage
Just type:

```
$ dqy --help
```

If no resolver is given, OS-configured resolvers are fetched from:
* ```resolv.conf``` file form UNIX platforms
* using the ```GetAdaptersAddresses``` Windows API for Windows platforms
using the resolver crate: https://github.com/dandyvica/resolver

## Compiling
Compiled and tested with Rust version 1.81.

Compilation instructions: [compiling dqy](./compile.md)

## Exit codes
* 0: no error
* 1: I/O error (probably a networking error)
* 2: UTF-8 conversion error
* 3: IP address parsing error from a string
* 4: internal DNS protocol error
* 5: DoH error
* 6: DoT error
* 7: error fetching OS resolvers
* 8: network timeout error
* 9: Lua script error
* 10: logger error




