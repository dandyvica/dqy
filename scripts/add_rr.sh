#!/bin/zsh
# add a new RR in all source files
if [ $# -eq 0 ]; then
    >&2 echo "No arguments provided"
    exit 1
fi

base=/data/projects/rust/dqy
module=${1:l}

# copy from another RR
cp $base/dns/src/rfc/dnskey.rs $base/dns/src/rfc/$module.rs

# add ref to this new RR in the RData defition
sed -i "/RData definition/a $1($1)," $base/dns/src/rfc/rdata.rs

# add ref to this new RR in the RData Display trait
line="RData::$1(a) => write!(f, \"{}\", a),"
sed -i "/RData Display/a $line" $base/dns/src/rfc/rdata.rs

# add ref to this new RR in the RData enum in resource record
line="QType::$1 => self.r_data = get_rr!(buffer, $1, RData::$1),"
sed -i "/RData enum/a $line" $base/dns/src/rfc/resource_record.rs

# add module in mod.rs
sed -i "/all RRs/a pub mod $module;" $base/dns/src/rfc/mod.rs

# clean up
cd $base/dns
cargo fmt

