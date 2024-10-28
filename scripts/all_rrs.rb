#!/usr/bin/ruby
# call all RRs from the list and test for execution
tests = <<~HEREDOC
  dqy @192.5.6.30 ANY com. --stats --bufsize=400 --no-opt
  dqy @a.gtld-servers.net ANY com. --bufsize=512
  dqy @f.root-servers.net hostname.bind chaos txt
  dqy @ns3.cloudflare.com  any cloudflare.com
  dqy TYPE64 svcb.dns.netmeister.org.
  dqy a a.dns.netmeister.org.
  dqy a6 a6.dns.netmeister.org.
  dqy aaaa aaaa.dns.netmeister.org.
  dqy afsdb afsdb.dns.netmeister.org.
  dqy amtrelay amtrelay.dns.netmeister.org.
  dqy any any.dns.netmeister.org.
  dqy apl apl.dns.netmeister.org.
  dqy atma atma.dns.netmeister.org.
  dqy avc avc.dns.netmeister.org.
  dqy axfr @nsztm1.digi.ninja zonetransfer.me
  dqy caa caa.dns.netmeister.org.
  dqy cdnskey cdnskey.dns.netmeister.org.
  dqy cds cds.dns.netmeister.org.
  dqy cert cert.dns.netmeister.org. 
  dqy cname cname.dns.netmeister.org.
  dqy csync csync.dns.netmeister.org.
  dqy dhcid dhcid.dns.netmeister.org.
  dqy dlv dlv.dns.netmeister.org.
  dqy dname dname.dns.netmeister.org.
  dqy dnskey dnskey.dns.netmeister.org.
  dqy doa doa.dns.netmeister.org.
  dqy ds ds.dns.netmeister.org.
  dqy eid eid.dns.netmeister.org. 
  dqy eui48 eui48.dns.netmeister.org.
  dqy eui64 eui64.dns.netmeister.org.
  dqy gpos gpos.dns.netmeister.org.
  dqy hinfo hinfo.dns.netmeister.org.
  dqy hip hip.dns.netmeister.org. 
  dqy ipseckey ipseckey.dns.netmeister.org. 
  dqy isdn isdn.dns.netmeister.org. 
  dqy key key.dns.netmeister.org. 
  dqy kx kx.dns.netmeister.org. 
  dqy l32 l32.dns.netmeister.org. 
  dqy l64 l64.dns.netmeister.org. 
  dqy loc loc.dns.netmeister.org. 
  dqy lp lp.dns.netmeister.org. 
  dqy mb mb.dns.netmeister.org. 
  dqy mg mg.dns.netmeister.org. 
  dqy minfo minfo.dns.netmeister.org. 
  dqy mr mr.dns.netmeister.org. 
  dqy mx mx.dns.netmeister.org. 
  dqy naptr naptr.dns.netmeister.org. 
  dqy nid nid.dns.netmeister.org. 
  dqy nimloc nimloc.dns.netmeister.org. 
  dqy ninfo ninfo.dns.netmeister.org. 
  dqy ns ns.dns.netmeister.org. 
  dqy nsap nsap.dns.netmeister.org. 
  dqy nsap-ptr nsap-ptr.dns.netmeister.org. 
  dqy nsec nsec.dns.netmeister.org. 
  dqy nsec3 nsec3.dns.netmeister.org.
  dqy nsec3 nsec3.dns.netmeister.org.
  dqy nsec3param nsec3param.dns.netmeister.org. 
  dqy nxt nxt.dns.netmeister.org. 
  dqy openpgpkey openpgpkey.dns.netmeister.org.
  dqy ptr ptr.dns.netmeister.org.
  dqy px px.dns.netmeister.org.
  dqy rp rp.dns.netmeister.org.
  dqy rrsig rrsig.dns.netmeister.org.
  dqy rt rt.dns.netmeister.org 
  dqy sink sink.dns.netmeister.org 
  dqy smimea smimea.dns.netmeister.org 
  dqy soa dns.netmeister.org.
  dqy soa soa.dns.netmeister.org.
  dqy spf spf.dns.netmeister.org 
  dqy srv srv.dns.netmeister.org 
  dqy sshfp sshfp.dns.netmeister.org 
  dqy ta ta.dns.netmeister.org. 
  dqy talink talink.dns.netmeister.org. 
  dqy tlsa tlsa.dns.netmeister.org. 
  dqy txt a.dname.dns.netmeister.org.
  dqy txt txt.dns.netmeister.org.
  dqy txt txt.dns.netmeister.org.
  dqy uri uri.dns.netmeister.org.
  dqy wks wks.dns.netmeister.org.
  dqy x25 x25.dns.netmeister.org.
  dqy zonemd zonemd.dns.netmeister.org.
HEREDOC


tests.split("\n").each do |x|
  # execute dqy
  cmd = x.strip
  puts "starting:#{cmd}"
  %x( #{cmd} )

  puts $?.exitstatus
end
