#!/usr/bin/env python3

import sqlite3
import argparse
import sys
import re
from netaddr import *


def enrich(ip, cur, conn) :
    if valid_ipv4(ip) :
        m = re.match("(.*)\\.\\d+$",ip)
        ipstr = "{}.0".format(m.group(1))
        res = cur.execute("""
            SELECT ips.country, ips.asn, ips.asn_name, ips.asn_domain, asns.abuse, asns.source, asns.status, timestamp
            FROM ips
            LEFT JOIN asns
                ON ips.asn = asns.asn
            WHERE
                ip = ?
        """, [ ipstr ])
        data = res.fetchall()
        if len(data) > 0 :
            return data[0]
        else:
            return []
    else:
        if verbose > 1:
            print("Not ipv4: '{}'".format(ip), file=sys.stderr)
        return []


if __name__ == '__main__':
    parser = argparse.ArgumentParser(
        description='Enrich ips addresses from a sqlite database',
        epilog='If no file and no IP addresses are given, the IP addresses are read from stdin',
        allow_abbrev=False
    )
    parser.add_argument("--sqlite", "-s", type=str, metavar="abuse.sqlite3", required=False, default="abuse.sqlite3", help="Path of the sqlite database")
    parser.add_argument("--infile", "-i", type=str, metavar="ips.txt", required=False, default="", help="Path of a file of ip addresses to enricht one per line")
    parser.add_argument('--verbose', '-v', action="count", default=1, help="Be (more) verbose" )
    parser.add_argument('--quiet', '-q', action="store_true", help="Be quiet" )
    parser.add_argument('ips', metavar='IP', type=str, nargs='*', help='IP addresses to enrich')


    args = parser.parse_args()

    verbose = args.verbose
    if args.quiet :
        verbose = 0

    # Open and check database
    try:
        conn = sqlite3.connect(args.sqlite)
    except Exception as e :
        print("\nUnable to open database '{}', error is {}".format(args.sqlite,str(e)), file=sys.stderr)
        exit(1)
    cur = conn.cursor()

    try :
        cur.execute("select count(*) from ips left join asns on ips.asn = asns.asn")
    except Exception as e:
        print("\nDatabase '{}', does nto contain the right tables. Error is '{}'".format(args.sqlite,str(e)), file=sys.stderr)
        exit(1)


    if verbose :
        print('"ip","country","asn","asn_name","asn_domain","abuse","abuse_source","abuse_status","abuse_timestamp"')

    infile = None
    if len(args.ips) == 0 and not args.infile:
        infile = sys.stdin
    elif args.infile :
        infile = open(infile,"r")

    if infile:
        for ip in infile:
            ip = ip.strip()
            res = enrich(ip, cur, conn)
            if res and len(res) > 0 :
                fields = []
                for field in res:
                    fields.append(str(field))
                print('"{}","{}"'.format(ip,'","'.join(fields)))
        if infile is not sys.stdin:
            infile.close()

    for ip in args.ips :
        res = enrich(ip, cur, con)
        if res and len(res) > 0 :
            fields = []
            for field in res:
                fields.append(str(field))
            print('"{}","{}"'.format(ip,'","'.join(fields)))


