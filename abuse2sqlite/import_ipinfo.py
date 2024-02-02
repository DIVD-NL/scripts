#!/usr/bin/env python3

import argparse
import json
import sys
import sqlite3
import progressbar
#import re
from netaddr import *

#from enrich_functions import abuse_from_asn

# Global variables

# Main
if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Import ipinfo data into a sqllite database', allow_abbrev=False)
    parser.add_argument("--sqlite", "-s", type=str, metavar="abuse.sqlite3", required=False, default="abuse.sqlite3", help="Path of the sqlite database")
    parser.add_argument("--json", "-j", type=str, metavar="country_asn.json", required=False, default="country_asn.json", help="Country and ASN JSOn file from ipinfo.io")
    parser.add_argument('--verbose', '-v', action="count", default=1, help="Be (more) verbose" )
    parser.add_argument('--quiet', '-q', action="store_true", help="Be quiet" )

    args = parser.parse_args()

    if args.quiet :
        verbose = 0
    else :
        verbose = args.verbose

    # Open databases
    try:
        lines=0
        json_file = open(args.json)
        for lines, line in enumerate(json_file) :
            pass
        lines=lines+1
        json_file.close()
        json_file = open(args.json)
    except Exception as e:
        print("\nUnable to open json file '{}', error is {}".format(args.json, str(e)),file=sys.stderr)
        exit(1)

    if sqlite3.threadsafety == 3:
        check_same_thread = False
    else:
        check_same_thread = True

    try:
        conn = sqlite3.connect(args.sqlite, check_same_thread=check_same_thread)
    except Exception as e :
        print("\nUnable to open database '{}', error is {}".format(args.sqlite,str(e)), file=sys.stderr)
        exit(1)
    cur = conn.cursor()

    try :
        cur.execute("delete from ips")
    except :
        # Need to create IPS table
        cur.execute("""
            CREATE TABLE ips (
                ip varchar(15),
                country varchar(2),
                asn varchar(10),
                asn_name varchar(100),
                asn_domain varchar(100),
                FOREIGN KEY (asn) REFERENCES asns(asn)
             );
        """)
        cur.execute("CREATE INDEX ips_ip on ips ( ip );")

    try :
        cur.execute("delete from ipv6")
    except :
        # Need to create IPv6 table
        cur.execute("""
            CREATE TABLE ipv6 (
                start varchar(18),
                end varchar(18),
                country varchar(2),
                asn varchar(10),
                asn_name varchar(100),
                asn_domain varchar(100),
                FOREIGN KEY (asn) REFERENCES asns(asn)
             );
        """)
        cur.execute("CREATE INDEX ipv6_start on ipv6 ( start );")
        cur.execute("CREATE INDEX ipv6_end on ipv6 ( end );")



    try :
        cur.execute("select count(*) from asns")
    except :
        # Need to create asns table
        cur.execute("""
            CREATE TABLE asns (
                asn varchar(10),
                abuse varchar(250),
                status varchar(15),
                source varchar(15),
                error varchar(250),
                timestamp datatime
             );
        """)
        cur.execute("CREATE INDEX asns_asn on asns ( asn );")


    # Setup progress bar
    if verbose == 1:
        widgets = [
            progressbar.Percentage(),
            progressbar.Bar(),
            progressbar.ETA()
        ]
        bar = progressbar.ProgressBar(widgets=widgets, max_value=lines)
        bar.start()
        bar.update(0)

    # Put ipinfo into database
    lineno = 0
    for line in json_file:
        ip_dict = json.loads(line)
        if ip_dict["asn"] :
            if valid_ipv4(ip_dict["start_ip"]) :
                if verbose > 2: print("Range {}-{}".format(ip_dict["start_ip"],ip_dict["end_ip"]))
                iprange = list(iter_iprange(ip_dict["start_ip"], ip_dict["end_ip"]))
                nets = cidr_merge(iprange)
                for net in nets :
                    if verbose > 2: print("CIDR {}".format(str(net)))
                    for slash24 in net.subnet(24) :
                        if verbose > 2: print("Subnet {}".format(str(slash24)))
                        cur.execute(
                            "INSERT INTO ips (ip, country, asn, asn_name, asn_domain) values (?, ?, ?, ?, ?)",
                            (
                                str(slash24).replace("/24",""),
                                ip_dict["country"],
                                ip_dict["asn"],
                                ip_dict["as_name"],
                                ip_dict["as_domain"]
                            )
                        )
            elif valid_ipv6(ip_dict["start_ip"]) :
                if verbose > 2: print("Range {}-{}".format(ip_dict["start_ip"],ip_dict["end_ip"]))
                start = IPAddress(ip_dict["start_ip"], 6)
                end = IPAddress(ip_dict["end_ip"], 6)
                s = int(start)/0x10000000000000000
                e = int(end)/0x10000000000000000
                cur.execute(
                    "INSERT INTO ipv6 (start, end, country, asn, asn_name, asn_domain) values (?, ?, ?, ?, ?, ?)"   ,
                    (
                        hex(int(s)),
                        hex(int(e)),
                        ip_dict["country"],
                        ip_dict["asn"],
                        ip_dict["as_name"],
                        ip_dict["as_domain"]
                    )
                )
        lineno=lineno+1
        if verbose == 1:
            bar.update(lineno)
    conn.commit()
    if verbose == 1:
        bar.update(lines)
        print()

