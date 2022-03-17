#!/bin/python3
# https://www.DIVD.nl
# Usage: ./to_validated_reverse_dns.py "127.0.0.1" or
# Usage: ./to_validated_reverse_dns.py < list-of-ips
# Output: Combination of ip and validate reverse dns if it is consistent, inconsistent record will not be output-ed

import socket
import sys


def find_host_name(ip):
    result = lookup_reverse_dns(ip)
    if result is not None and lookup_forward_dns(result) == ip:
        print(ip + "," + result)


def lookup_reverse_dns(host):
    try:
        return socket.gethostbyaddr(host)[0]
    except socket.herror:
        return None


def lookup_forward_dns(host):
    try:
        return socket.gethostbyname(host)
    except socket.gaierror:
        return None


if __name__ == "__main__":
    if len(sys.argv) == 2:
        find_host_name(sys.argv[1])
    else:
        data = sys.stdin.read()

        lines = data.strip().split('\n')
        for line in lines:
            ip_from_line = line.strip()
            if not ip_from_line:
                continue

            find_host_name(ip_from_line)
