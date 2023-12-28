#!/usr/bin/python3
# create enum from text taken from RFCs
import sys

name = sys.argv[1]

text = """
             0            Reserved
             1  PKIX      X.509 as per PKIX
             2  SPKI      SPKI certificate
             3  PGP       OpenPGP packet
             4  IPKIX     The URL of an X.509 data object
             5  ISPKI     The URL of an SPKI certificate
             6  IPGP      The fingerprint and URL of an OpenPGP packet
             7  ACPKIX    Attribute Certificate
             8  IACPKIX   The URL of an Attribute Certificate
         9-252            Available for IANA assignment
           253  URI       URI private
           254  OID       OID private
           255            Reserved
     256-65279            Available for IANA assignment
   65280-65534            Experimental
         65535            Reserved
"""

print("""
#[derive(
    Debug,
    Default,
    Copy,
    Clone,
    PartialEq,
    EnumFromStr,
    EnumTryFrom,
    EnumDisplay,
    ToNetwork,
    FromNetwork,
)]
#[repr(u16)]
pub enum {} {{
      """.format(name))

for line in text.split("\n"):
    tab = line.strip().split()

    if len(tab) >= 3:
        print(f"{tab[1]} = {tab[0]}, //{' '.join(tab[2:])}")

print("}")
