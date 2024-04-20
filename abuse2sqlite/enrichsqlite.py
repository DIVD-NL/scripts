#!/usr/bin/env python3

import sqlite3
import argparse
import sys
import re
import csv
import json
import jq
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
    elif valid_ipv6(ip) :
        v6 = IPAddress(ip, 6)
        v6str = str(hex(int(int(v6)/0x10000000000000000)))
        res = cur.execute("""
            SELECT ipv6.country, ipv6.asn, ipv6.asn_name, ipv6.asn_domain, asns.abuse, asns.source, asns.status, timestamp
            FROM ipv6
            LEFT JOIN asns
                ON ipv6.asn = asns.asn
            WHERE
                start <= ? AND end >= ?
        """, [ v6str, v6str ])
        data = res.fetchall()
        if len(data) > 0 :
            return data[0]
        else:
            return []
    else:
        if verbose > 1:
            print("Not ipv4 or ipv6: '{}'".format(ip), file=sys.stderr)
        return []


if __name__ == '__main__':
    parser = argparse.ArgumentParser(
        description='Enrich ips addresses from a sqlite database',
        epilog='If no file and no IP addresses are given, the IP addresses are read from stdin',
        allow_abbrev=False
    )
    parser.add_argument("--sqlite", "-s", type=str, metavar="abuse.sqlite3", required=False, default="/opt/enrich/abuse.sqlite3", help="Path of the sqlite database")
    parser.add_argument("--infile", "-i", type=str, metavar="ips.txt", required=False, default="", help="Path of a file of ip addresses to enricht one per line")
    parser.add_argument('--verbose', '-v', action="count", default=1, help="Be (more) verbose" )
    parser.add_argument('--csv', type=str, metavar='ip', required=False, default="ip", help="CSV field containing the IP address (if --infile arugment ends in .csv)")
    parser.add_argument('--jq', type=str, metavar='.ip', required=False, default=".ip", help="jq query to find IP address in json record (if --infile argument ends in .json)")
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


    infile = None
    if len(args.ips) == 0 and not args.infile:
        infile = sys.stdin
    elif args.infile :
        infile = open(args.infile,"r")


    if infile:
        if args.infile.endswith(".csv") :
            csvreader = csv.DictReader(infile)
            fieldnames = []
            csvwriter = None
            for row in csvreader:
                if not args.csv in row :
                    print(row)
                    print("\nCSV file '{}', does not contain field '{}'".format(args.infile,args.csv), file=sys.stderr)
                    exit(1)
                if len(fieldnames) == 0 :
                    fieldnames = list(row.keys())
                    fieldnames = fieldnames + ["country","asn","asn_name","asn_domain","abuse","abuse_source","abuse_status","abuse_timestamp"]
                    csvwriter = csv.DictWriter(sys.stdout,fieldnames=fieldnames)
                    if verbose:
                        csvwriter.writeheader()
                if(row[args.csv]) :
                    res= enrich(row[args.csv], cur, conn)
                    if len(res) == 8:
                        row["country"] = res[0]
                        row["asn"] = res[1]
                        row["asn_name"] = res[2]
                        row["asn_domain"] = res[3]
                        row["abuse"] = res[4]
                        row["abuse_source"] = res[5]
                        row["abuse_status"] = res[6]
                        row["abuse_timestamp"] = res[7]
                        csvwriter.writerow(row)
                    elif len(res) == 0 :
                        csvwriter.writerow(row)
                    else:
                        print("Incorrect result '{}' from row '{}".format(res,row), file=sys.stderr)
                        exit(1)
        elif args.infile.endswith(".json") :
            # Compile jq string
            jqc = jq.compile(args.jq)
            for row in infile:
                record = json.loads(row)
                ip =  jq.compile(".ip").input_value(record).first()
                if ip:
                    res=enrich(ip, cur, conn)
                    record["enriched"] = {}
                    record["enriched"]["ip"] = ip
                    if len(res) == 8:
                        record["enriched"]["country"] = res[0]
                        record["enriched"]["asn"] = res[1]
                        record["enriched"]["asn_name"] = res[2]
                        record["enriched"]["asn_domain"] = res[3]
                        record["enriched"]["abuse"] = res[4]
                        record["enriched"]["abuse_source"] = res[5]
                        record["enriched"]["abuse_status"] = res[6]
                        record["enriched"]["abuse_timestamp"] = res[7]
                    elif len(res) == 0:
                        pass
                    else:
                        print("Incorrect result '{}' from ip '{}".format(res,ip), file=sys.stderr)
                    print(json.dumps(record))
        else:
            if verbose :
                print('"ip","country","asn","asn_name","asn_domain","abuse","abuse_source","abuse_status","abuse_timestamp"')
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


