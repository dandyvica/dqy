set -x

dqy +nocmd +nocomments +noquestion +nostats +multiline soa dns.netmeister.org.
dqy +short a a.dns.netmeister.org.
dqy +short aaaa aaaa.dns.netmeister.org.
dqy +short a6 a6.dns.netmeister.org.
dqy +short afsdb afsdb.dns.netmeister.org.
dqy +short amtrelay amtrelay.dns.netmeister.org.
dqy +nocmd +nocomments +noquestion +nostats +multiline any any.dns.netmeister.org.
dqy +short txt $$.dns.netmeister.org.
dqy +short apl apl.dns.netmeister.org.
dqy +short atma atma.dns.netmeister.org.
dqy +short avc avc.dns.netmeister.org.
dqy +short caa caa.dns.netmeister.org.
dqy +short cdnskey cdnskey.dns.netmeister.org.
dqy +short cds cds.dns.netmeister.org.
dqy +nocmd +nocomments +noquestion +nostats +multiline cert cert.dns.netmeister.org. 
dqy +short cname cname.dns.netmeister.org.
dqy +short csync csync.dns.netmeister.org.
dqy +short dhcid dhcid.dns.netmeister.org.
dqy +short dlv dlv.dns.netmeister.org.
dqy +short dname dname.dns.netmeister.org.
dqy +short txt a.dname.dns.netmeister.org.
dqy +short dnskey dnskey.dns.netmeister.org.
dqy +short doa doa.dns.netmeister.org.
dqy +short ds ds.dns.netmeister.org.
dqy +short eid eid.dns.netmeister.org. 
dqy +short eui48 eui48.dns.netmeister.org.
dqy +short eui64 eui64.dns.netmeister.org.
dqy +short gpos gpos.dns.netmeister.org.
dqy +short hinfo hinfo.dns.netmeister.org.
dqy +short @ns3.cloudflare.com  any cloudflare.com
dqy +nocmd +nocomments +noquestion +nostats +multiline hip hip.dns.netmeister.org. 
dqy +short ipseckey ipseckey.dns.netmeister.org. 
dqy +short isdn isdn.dns.netmeister.org. 
dqy +short key key.dns.netmeister.org. 
dqy +short kx kx.dns.netmeister.org. 
dqy +short l32 l32.dns.netmeister.org. 
dqy +short l64 l64.dns.netmeister.org. 
dqy +short loc loc.dns.netmeister.org. 
dqy +short lp lp.dns.netmeister.org. 
dqy +short mb mb.dns.netmeister.org. 
dqy +short mg mg.dns.netmeister.org. 
dqy +short minfo minfo.dns.netmeister.org. 
dqy +short mr mr.dns.netmeister.org. 
dqy +short mx mx.dns.netmeister.org. 
dqy +short naptr naptr.dns.netmeister.org. 
dqy +short nid nid.dns.netmeister.org. 
dqy +short nimloc nimloc.dns.netmeister.org. 
dqy +short ninfo ninfo.dns.netmeister.org. 
dqy +short ns ns.dns.netmeister.org. 
dqy +short nsap nsap.dns.netmeister.org. 
dqy +short nsap-ptr nsap-ptr.dns.netmeister.org. 
dqy +short nsec nsec.dns.netmeister.org. 
dqy +dnssec +nocmd +nocomments +noquestion +nostats +multiline nsec3 nsec3.dns.netmeister.org.
dqy +short nsec3param nsec3param.dns.netmeister.org. 
dqy +dnssec +nocmd +nocomments +noquestion +nostats nsec3 nsec3.dns.netmeister.org. | \
dqy +short nxt nxt.dns.netmeister.org. 
dqy +multiline +nocmd +nocomments +noquestion +nostats openpgpkey openpgpkey.dns.netmeister.org.
dqy +multiline +nocmd +nocomments +noquestion +nostats openpgpkey                           \
dqy +short ptr ptr.dns.netmeister.org.
dqy +short px px.dns.netmeister.org.
dqy +short rp rp.dns.netmeister.org.
dqy +multiline +nocmd +nocomments +noquestion +nostats rrsig rrsig.dns.netmeister.org.
dqy +short rt rt.dns.netmeister.org 
dqy +short sink sink.dns.netmeister.org 
dqy +short smimea smimea.dns.netmeister.org 
dqy +multiline +nocmd +nocomments +noquestion +nostats soa soa.dns.netmeister.org.
dqy +short spf spf.dns.netmeister.org 
dqy +short srv srv.dns.netmeister.org 
dqy +short sshfp sshfp.dns.netmeister.org 
dqy +multiline +nocmd +nocomments +noquestion +nostats TYPE64 svcb.dns.netmeister.org.
dqy +short ta ta.dns.netmeister.org. 
dqy +short talink talink.dns.netmeister.org. 
dqy +short tlsa tlsa.dns.netmeister.org. 
dqy +short txt txt.dns.netmeister.org.
dqy +short uri uri.dns.netmeister.org.
dqy +short wks wks.dns.netmeister.org.
dqy +short x25 x25.dns.netmeister.org.
dqy +short zonemd zonemd.dns.netmeister.org.
dqy +short @f.root-servers.net hostname.bind chaos txt

# added ANY, AXFR
dqy @a.gtld-servers.net ANY com. --bufsize=512
dqy @192.5.6.30 ANY com. --stats --bufsize=400 -vvvvv --no-opt
dqy axfr @nsztm1.digi.ninja zonetransfer.me

