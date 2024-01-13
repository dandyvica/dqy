#!/usr/bin/python3

"""
Simple extraction of all received RRs
"""

import sys
import json

# read JSON fro stdin
json_str = sys.stdin.buffer.read()

# convert to dict
dns_data = json.loads(json_str)

print(dns_data['response']['answer'][0]['type'])

