-- definition of all fields for RRs
RData = {}
RData['AFSDB'] = { "subtype", "hostname" }
RData['APL'] = { "address_family", "prefix", "afdlength", "afdpart", "apl" }
RData['CAA'] = { "flags", "tag_length", "tag_key", "tag_value" }
RData['CERT'] = { "certificate_type", "key_tag", "algorithm", "certificate" }
RData['CHAR_STRING'] = {}
RData['CSYNC'] = { "soa_serial", "flags", "types" }
RData['DHCID'] = { "data" }
RData['DNSKEY'] = { "flags", "protocol", "algorithm", "key" }
RData['DOMAIN_ORIG'] = {}
RData['DOMAIN'] = {}
RData['DS'] = { "key_tag", "algorithm", "digest_type", "digest" }
RData['FLAGS'] = {}
RData['HEADER'] = {}
RData['HINFO'] = { "cpu", "os" }
RData['HIP'] = { "hit_length", "pk_algorithm", "pk_length", "hit", "public_key", "rendezvous_servers" }
RData['IPSECKEY'] = { "precedence", "gateway_type", "algorithm", "gateway", "public_key" }
RData['KX'] = { "preference", "exchanger" }
RData['LOC'] = { "version", "size", "horiz_pre", "vert_pre", "latitude1", "latitude2", "longitude1", "longitude2", "altitude1", "altitude2" }
RData['MESSAGE'] = {}
RData['MOD'] = {}
RData['MX'] = { "preference", "exchange" }
RData['NAPTR'] = { "order", "preference", "flags", "services", "regex", "replacement" }
RData['NSEC3PARAM'] = { "algorithm", "flags", "iterations", "salt_length", "salt" }
RData['NSEC3'] = { "params", "hash_length", "owner_name", "types" }
RData['NSEC'] = { "domain", "types" }
RData['OPCODE'] = {}
RData['OPENPGPKEY'] = { "key" }
RData['PACKET_TYPE'] = {}
RData['RP'] = { "mbox", "hostname" }
RData['RRSIG'] = { "type_covered", "algorithm", "labels", "ttl", "sign_expiration", "sign_inception", "key_tag", "name", "signature" }
RData['SOA'] = { "mname", "rname", "serial", "refresh", "retry", "expire", "minimum" }
RData['SRV'] = { "priority", "weight", "port", "target" }
RData['SSHFP'] = { "algorithm", "fp_type", "fingerprint" }
RData['SVCB'] = { "svc_priority", "target_name", "svc_params" }
RData['TKEY'] = { "algorithm", "inception", "expiration", "mode", "error", "key_size", "key_data", "other_size", "other_data" }
RData['TLSA'] = { "cert_usage", "selector", "matching_type", "data" }
RData['URI'] = { "priority", "weight", "target" }
RData['ZONEMD'] = { "serial", "scheme", "hash_algorithm", "digest" }

-- get Rdata fields
function RData.format(rr_name, rdata)
    if type(rdata) == "string" then
        return rdata
    else
        local s = ""
        for i, f in ipairs(RData[rr_name]) do
            s = s .. string.format("%s ", rdata[f])
        end
        return s
    end
end

return RData
