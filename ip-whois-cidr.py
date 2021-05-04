#!/bin/python3
# https://www.DIVD.nl
# Usage: cat ips.txt | ./ip-whois-cidr.py
# ips.txt 1 ip per line

from ipwhois import IPWhois
from pprint import pprint
import sys

for line in sys.stdin:
    try:
        ip = line.strip('\n')
        obj = IPWhois(ip)
        rdap = obj.lookup_rdap()
        # whois =obj.lookup_whois()
        result = "{};{};{};{};{}".format(rdap['asn_description'], rdap['network']['name'] , rdap['network']['cidr'] , rdap['network']['start_address'] , rdap['network']['end_address'])
        print (result)
    except:
        pass