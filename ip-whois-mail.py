#!/bin/python3
# https://www.DIVD.nl
# Developer by Hidde Smit & Wietse Boonstra
# Usage: cat ips.txt | python3 ip-whois-mail.py
# ips.txt 1 ip per line
# Debugging: sys.stdin = ['1.1.1.1', '8.8.8.8']

from ipwhois import IPWhois
import sys

for line in sys.stdin:
    try:
        ip = line.strip('\n')
        obj = IPWhois(ip)
        rdap = obj.lookup_rdap(depth=2)
        result = rdap['objects']
        abusemails = []
        for key, value in result.items():
            if 'abuse' in value['roles']:
                for abusemail in value['contact']['email']:
                    abusemails.append(abusemail['value'])
        print (ip,str(abusemails)[1:-1].replace(' ', ''),sep=',')
    except Exception as e:
        print ("Failed with ip: {}; error {}".format(ip, e))
        pass
