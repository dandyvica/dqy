[![Actions](https://github.com/dandyvica/dqy/actions/workflows/rust.yml/badge.svg)](https://github.com/dandyvica/dqy/actions/workflows/rust.yml)

Note: this is currently under development in my free time.

# Dns QuerY (dqy)
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
* OPT coverage: NSID, COOKIE, Padding, Extended, ReportChannel, ZONEVERSION

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
* HTTPS
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
* SVCB
* TLSA
* TXT
* URI
* ZONEMD
* WALLET

Those with (*) are not yet fully tested. 

You can also use a `TYPEn` where `n` is an integer <=255 for the query type.

## General usage
Usage is similar to __dig__, without support for options starting with `+`.
Example:
```console
$ dqy A www.google.com
```

The only thing to remeber is that other options (those starting with `--` or `-` must be placed after qtype, domain and optional resolver):
```console
$ dqy A www.google.com @1.1.1.1 --stats
```

## Addressing queries to a specific resolver
You can specify a resolver by prepending the ip address or host name by the character `@`:
```console
$ dqy A www.google.com @1.1.1.1
$ dqy @a.gtld-servers.net ANY com.
```
Qtype, domain name and resolver can be specified in any order provided they are set before any dash option.

## Transport options
### Timeout
For all network operations (apart from DoQ), a timeout can be set with `--timeout=n` (n is the value is miliseconds).

### UDP
By default, dqy uses UDP on port 53. If response is truncated, query is resend on TCP port 53 as stated in RFC1035.

```console
# uses UDP:53
$ dqy A www.google.com
```

### TCP
You can force to use TCP with the `--tcp` option: 
```console
# uses TCP:53
$ dqy A www.google.com --tcp
```

### DoT (DNS over TLS)
You can force to use DNS over TLS on port 853 with the `--dot` option: 
```console
$ dqy A www.google.com @1.1.1.1 --dot
```

You can set the ALPN protocol to DoT with `--alpn`. The SNI can be added using `--sni=name`. A PEM self-signed certificated can be added using `--cert=file`.

### DoH (DNS over HTTPS)
You can force to use DNS over HTTPS on port 443 with `--https` option, or by prepending resolver address with `@https://`
```console
$ dqy A www.google.com @1.1.1.1 --dot
$ dqy A www.google.com @https://doh.dns4all.eu/dns-query
```

### DoQ (DNS over QUIC)
You can force to use DNS over HTTPS on port 853 with `--doq` option, or by prepending resolver address with `@quic://`
```console
$ dqy A www.google.com @dns.adguard.com --doq
$ dqy A www.google.com @quic://dns.adguard.com
```

### Setting a specific port number
You can use a specific port number with the `--port` option:
```console
$ dqy A www.google.com @127.0.0.1 --port 8053
```

## Statistics on query
Adding --stats, you can get some figures about the query:
```console
$ dqy A www.google.com @8.8.8.8 --stats
...
endpoint: 8.8.8.8:53 (Udp)
elapsed: 5 ms
sent:43, received:59 bytes
```

## IDNA support
International Domain Name are fully support too:
```console
$ dqy A 스타벅스코리아.com  
$ dqy AAAA ουτοπία.δπθ.gr 
```

Using `--puny` gives the punycode string instead of the UTF-8 domain name.

## Output options
### JSON support
The `--json` and `--json-pretty` options allows to display output data in JSON format with key:

* messages: list of messages
* info: meta-info like elpased time, endpoint address etc

### Debugging mode
You can ask for a info to trace mode using `-v` (info) to `-vvvvv` (trace). In addition the `--log` option allows to save debug output into a file.

### Colors
By default, output is colored. To dismiss colored output, just add `--no-colors`.

### IPV4 and IPV6 transport
You can force to use IPV4 using `-4`, and IPV6 `-6`. You can then verify usage with `--stats`:
```console
$ dqy A www.google.com @one.one.one.one -6 --stats
```

### Save query and response into a file
You can save raw query or response bytes using `--wq` or `--wr` respectively.
```console
$ dqy TXT dropbox.com --wr response.bin --wq query.bin
```

### DQY_FLAGS environment variable
You can set the `DQY_FLAGS` environment variable to all the options you always want
to use. You just need to respect the order of options, by having the dash options
after all other ones.

If this environment variable is set, `dqy` will use the options found in the variable.

Example:
```console
$ export DQY_FLAG='@1.1.1.1 --no-colors --stats'
$ dqy A www.google.com
```


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
Beware it's an utility developed during some of my free time and probably buggy. Feel free to test it and report issues.
Specially in the display options, not all are implemented or even specially useful because of the Lua scripting or JSON output.

## Roadmap
Following is a tentative roadmap:

* v0.2: ipv6 support (done)
* v0.3: trace option (done)
* v0.4: OPT options full support (done) and DoQ (done)
* v0.5: fine-tuning displaying options
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
* 1: I/O error (probably a networking or file access error)
* 2: UTF-8 conversion error
* 3: IP address parsing error from a string
* 4: timeout during network operations
* 5: TLS error
* 6: DoH error
* 7: Dns procotol error
* 8: error during IP address parsing
* 9: logger error
* 10: resolver error
* 11: QUIC error
* 12: integer parsing error
* 13: network resolving error
* 14: tokio runtime error
* 15: IDNA conversion error



