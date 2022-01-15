#!/bin/python3
# https://www.DIVD.nl
# Developed by Hidde Smit & Wietse Boonstra
# Usage: cat ips.txt | python3 ip-whois-mail.py
# ips.txt 1 ip per line
# Debugging: sys.stdin = ['1.1.1.1', '8.8.8.8']

from ipwhois import IPWhois
import sys

for line in sys.stdin:
    try:
        ip = line.strip('\n')
        # Some results produce an error, even when emails are found. When an error occurs the script falls into an Exception
        # This boolean causes the script to succesfully move to the next IP after retrieving abuse mails.
        foundEmail = False
        obj = IPWhois(ip)
        rdap = obj.lookup_rdap(depth=2)
        result = rdap['objects']
        abusemails = []

        for key, value in result.items():
            if foundEmail: # Break this loop, move to the next when mails were found
                break

            if value['roles'] and 'abuse' in value['roles']:
                for abusemail in value['contact']['email']:
                    abusemails.append(abusemail['value'])
                    foundEmail = True

        abusemails = list(dict.fromkeys(abusemails))
        result = f"{ip},{str(abusemails)[1:-1].replace(' ', '')}"

        with open("result.txt", "a") as file:
            file.write(result + "\n")
            file.close()

        print (result)
    except Exception as e:
        print ("Failed with ip: {}; error {}".format(ip, e))
        pass
