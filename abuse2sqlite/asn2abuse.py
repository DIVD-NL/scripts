#!/usr/bin/env python3

import argparse
import json
import sys
import sqlite3
import progressbar
import queue
import threading
import re
from netaddr import *

#import os
#import maxminddb

from enrich_functions import abuse_from_asn

# Global variables
sourceapp = "AS50559-DIVD_NL"
running = True

def process_task(task,out_queue,task_queue,threads) :
    global verbose
    if verbose > 2:
        print("Processing task '{}'".format(task))
    if threads == 1 :
        result = abuse_from_asn(task["asn"],verbose)
        out_queue.put(result)
    else:
        try:
            result = abuse_from_asn(task["asn"], verbose)
        except Exception as e:
            if task["retry"] > 0 :
                task["retry"] = task["retry"] - 1
                task_queue.put(task)
            else:
                result = {
                    "asn" : task["asn"],
                    "abuse" : "error",
                    "error" : str(e)
                }
                out_queue.put(result)
        else:
            out_queue.put(result)

def worker(task_queue, out_queue, threads) :
    global running
    while running :
        task = task_queue.get(True)
        try :
            process_task(task, out_queue, task_queue, threads)
        except Exception as e:
            if task["retry"] > 0 :
                task["retry"] = task["retry"] - 1
                task_queue.put(task)
            else:
                result = {
                    "ip" : task["ip"],
                    "abuse" : "error",
                    "error" :  str(e)
                }
                out_queue.put(result)

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Update ASN abuse data in sqlite database', allow_abbrev=False)
    parser.add_argument("--sqlite", "-s", type=str, metavar="abuse.sqlite3", required=False, default="abuse.sqlite3", help="Path of the sqlite database")
    parser.add_argument("--threads", "-t", type=int, metavar="N", default=8, help="Number of request threads [default: 8]")
    parser.add_argument("--retry", "-r", type=int, metavar="N", default=0, help="Number of retries for failed queries [default: 0]")
    parser.add_argument('--verbose', '-v', action="count", default=1, help="Be (more) verbose" )
    parser.add_argument('--quiet', '-q', action="store_true", help="Be quiet" )

    args = parser.parse_args()

    if args.quiet :
        verbose = 0
    else :
        verbose = args.verbose

    # Open databases
    try:
        conn = sqlite3.connect(args.sqlite)
    except Exception as e :
        print("\nUnable to open database '{}', error is {}".format(args.sqlite,str(e)), file=sys.stderr)
        exit(1)
    cur = conn.cursor()

    try :
        cur.execute("select count(*) from ips")
    except :
        print("There is no ips table in database '{}'".format(args.sqlite),file=sys.stderr)
        exit(1)

    try :
        cur.execute("select count(*) from ipv6")
    except :
        print("There is no ipv6 table in database '{}'".format(args.sqlite),file=sys.stderr)
        exit(1)

    try :
        cur.execute("select count(*) from asns")
    except :
        print("There is no asns table in database '{}'".format(args.sqlite),file=sys.stderr)
        exit(1)

    # Set up queues
    task_queue = queue.Queue()
    out_queue  = queue.Queue()

    # Fill task_queue
    if verbose > 1:
        print("Getting tasks...")
    res = cur.execute("""
        SELECT DISTINCT * FROM (
            SELECT DISTINCT asn
            FROM ips
            UNION ALL
            SELECT DISTINCT asn
            FROM ipv6
        )
        WHERE asn NOT IN (
            SELECT asn
            FROM ASNS
            WHERE timestamp > date('now','-30 days')
        ) OR asn IN (
            SELECT asn
            FROM ASNS
            WHERE status = 'error' and timestamp <> date('now')
        )
        ORDER BY random();
    """)
    task_count = 0
    for record in res.fetchall() :
        task_queue.put({ "asn" : record[0], "retry" : args.retry })
        task_count = task_count+1

    if verbose > 0 :
        print("Enrichment of {} asns started.".format(task_count))

    # Spawn worker threads
    threads=[]
    if args.threads > 1:
        for i in range(args.threads):
            threads.append(threading.Thread(target=worker, args=(task_queue, out_queue, args.threads), daemon=True).start())

    # Setup progress bar
    if verbose == 1:
        widgets = [
            progressbar.Percentage(),
            progressbar.Bar(),
            progressbar.ETA()
        ]
        bar = progressbar.ProgressBar(widgets=widgets, max_value=task_count)
        bar.start()
        bar.update(0)


    running = True
    done = 0
    bar_update = 0
    while running:
        if args.threads == 1:
            task = task_queue.get()
            process_task(task, out_queue, task_queue, args.threads)

        count = 0
        while (not out_queue.empty()) and count < 100:
            try:
                result = out_queue.get(False,0)
                if verbose > 2:
                    print("Got result: {}".format(result))
            except queue.Timeout:
                break
            if result["abuse"] == "error" :
                res = cur.execute("SELECT count(*) FROM asns WHERE asn = ?",[ result["asn"] ] )
                if res.fetchall()[0][0] == 0 :
                    cur.execute("INSERT INTO asns (asn, status, error, timestamp) VALUES ( ?, 'error', ?, date('now'));",[ result["asn"], result["error"] ])
                else:
                    cur.execute("UPDATE asns set status='error', error=?, timestamp=date('now') WHERE asn=?;", [ result["error"], result["asn"] ] )
            elif result["abuse"] == "Not found" or not result["abuse"] :
                res = cur.execute("SELECT count(*) FROM asns WHERE asn = ?",[ result["asn"] ] )
                if res.fetchall()[0][0] == 0 :
                    cur.execute("INSERT INTO asns (asn, status, error, timestamp) VALUES ( ?, 'not found', null, date('now'));",[result["asn"]])
                else:
                    cur.execute("UPDATE asns set status='not found', error=null, timestamp=date('now') WHERE asn=?;",[result["asn"]])
            else :
                res = cur.execute("SELECT count(*) FROM asns WHERE asn = ?", [ result["asn"] ] )
                if res.fetchall()[0][0] == 0 :
                    cur.execute("""
                        INSERT INTO asns (asn, abuse, source, status, error, timestamp)
                        VALUES ( ?, ?, ?, 'ok', null, date('now'));
                        """,
                        [
                            result["asn"],
                            result["abuse"],
                            result["abuse_source"]
                        ]
                    )
                else:
                    cur.execute("UPDATE asns set abuse=?, status='ok', timestamp=date('now') WHERE asn=?;",[ result["abuse"], result["asn"]])
            done = done + 1
            count = count + 1
        if count > 0 :
            conn.commit()
            if verbose == 1:
                if bar_update < 5 and args.threads != 1 :
                    bar_update=bar_update+1
                else:
                    bar_update=0
                    bar.update(done)
        if task_queue.empty() and out_queue.empty() and done == task_count :
            running = False

