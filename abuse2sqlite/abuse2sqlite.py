#!/usr/bin/env python3

import argparse
import os
import sys
import progressbar
import maxminddb
import sqlite3
import queue
import threading

from enrich_functions import get_info

# Global variables
sourceapp = "AS50559-DIVD_NL"
running = True



def process_task(task,out_queue,task_queue, mmdb, threads) :
    if threads == 1 :
        result = get_info(task["ip"], mmdb)
        out_queue.put(result)
    else:
        try:
            result = get_info(task["ip"], mmdb)
        except :
            if task["retry"] > 0 :
                task["retry"] = task["retry"] - 1
                task_queue.put(task)
            else:
                result = {
                    "ip" : task["ip"],
                    "abuse" : "error"
                }
                out_queue.put(result)
        else:
            out_queue.put(result)

def worker(task_queue, out_queue, mmdb) :
    global running
    while running :
        task = task_queue.get(True)
        try :
            process_task(task, out_queue, task_queue, mmdb,2)
        except Exception as e:
            if task["retry"] > 0 :
                task["retry"] = task["retry"] - 1
                task_queue.put(task)
            else:
                result = {
                    "ip" : task["ip"],
                    "abuse" : "error"
                }
                out_queue.put(result)

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Update abuse and location information in a sqllite database', allow_abbrev=False)
    parser.add_argument("--sqlite", "-s", type=str, metavar="FILE.sqlite3", required=False, default="abuse.sqlite3", help="Path of the sqlite database")
    parser.add_argument("--maxminddb", "-m", type=str, metavar="GeoLite2-City.mmdb", required=False, default="GeoLite2-City.mmdb", help="Path of the maxmind database")
    parser.add_argument("--threads", "-t", type=int, metavar="N", default=8, help="Number of request threads [default: 8]")
    parser.add_argument("--retry", "-r", type=int, metavar="N", default=3, help="Number of retries for failed queries [default: 3]")
    parser.add_argument('--verbose', '-v', action="count", default=1, help="Be (more) verbose" )
    parser.add_argument('--quiet', '-q', action="store_true", help="Be quiet" )

    args = parser.parse_args()

    if args.quiet :
        verbose = 0
    else :
        verbose = args.verbose

    # Open databases
    try:
        mmdb = maxminddb.open_database(args.maxminddb)
    except Exception as e:
        print("\nUnable to open MaxMindDB '{}', error is {}".format(args.maxminddb, str(e)),file=sys.stderr)
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

    # Setup progress bar
    if verbose == 1:
        count_result = cur.execute("select count(*) from slash24")
        max_value = count_result.fetchall()[0][0]
        done_result = cur.execute("select count(*) from slash24 where last >= date('now', '-7 days')")
        done = done_result.fetchall()[0][0]
        widgets = [
            progressbar.Percentage(),
            progressbar.Bar(),
            progressbar.AdaptiveETA()
        ]
        bar = progressbar.ProgressBar(widgets=widgets, max_value=max_value)
        bar.start()
        bar.update(done)

    # Set up queues
    task_queue = queue.Queue()
    out_queue  = queue.Queue()

    # Spawn worker threads
    threads=[]
    if args.threads > 1:
        for i in range(args.threads):
            threads.append(threading.Thread(target=worker, args=(task_queue, out_queue, mmdb), daemon=True).start())

    running = True
    bar_update = 0
    while running:
        if task_queue.empty() :
            for row in cur.execute("select ip from slash24 where last < date('now', '-7 days') order by last, random() limit 1000").fetchall() :
                if verbose > 2 :
                    print("Adding {}".format(row[0]))
                task = {
                    "ip" : row[0],
                    "retry" : args.retry
                }
                task_queue.put(task)

        if args.threads == 1:
            task = task_queue.get()
            process_task(task, out_queue, task_queue, mmdb, args.threads)

        count = 0
        while (not out_queue.empty()) and count < 100:
            try:
                result = out_queue.get(False,0)
            except queue.Timeout:
                break
            if verbose > 2:
                print(result)
            if result["abuse"] == "error" :
                cur.execute("UPDATE slash24 SET last=date('now'), status='error' WHERE ip=?", [result["ip"]])
            elif result["abuse"] == "Not found" or not result["abuse"] :
                cur.execute(
                    "UPDATE slash24 SET prefix=?, asn=?, country=?, reg_country=?, city=?, abuse_source=?, rir=?, last=date('now'), status='not found' WHERE ip=?",
                    [
                        result["prefix"], result["asn"], result["country"], result["reg_country"], result["city"], result["abuse_source"], result["rir"], result["ip"]
                    ])
            else:
                cur.execute(
                    "UPDATE slash24 SET abuse=?, prefix=?, asn=?, country=?, reg_country=?, city=?, abuse_source=?, rir=?, last=date('now'), timestamp=datetime('now'), status='ok' WHERE ip=?",
                    [
                        result["abuse"], result["prefix"], result["asn"], result["country"], result["reg_country"], result["city"], result["abuse_source"], result["rir"], result["ip"]
                    ])
            count = count + 1
        if count > 0 :
            conn.commit()
            if verbose == 1:
                if bar_update < 15 or args.threads == 1:
                    bar_update = bar_update+1
                else :
                    bar_update=0
                    done_result = cur.execute("select count(*) from slash24 where last >= date('now', '-7 days')")
                    done = done_result.fetchall()[0][0]
                    bar.update(done)

