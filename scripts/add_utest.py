#!/usr/bin/python3
import sys

ut = """#[cfg(test)]
mod tests {{
    use crate::{{
        error::DNSResult,
        rfc::{{rdata::RData, response::Response}},
        test_rdata,
        tests::{{get_pcap_buffer, read_pcap_sample}},
    }};

    use type2network::FromNetworkOrder;

    use super::{0};

    test_rdata!(
        "./tests/{1}.pcap",
        RData::{2},
        (|x: &{3}, _| {{
            assert_eq!(&x.to_string(), "");
        }})
    );
}}
"""

rr = sys.argv[1]
type = rr.upper()

print(ut.format(type, rr, type, type))
