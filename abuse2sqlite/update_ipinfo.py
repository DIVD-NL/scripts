#!/usr/bin/env python3

import argparse
import sys
import yaml
import progressbar
import requests
import os


if __name__ == '__main__':
    parser = argparse.ArgumentParser(
        description='Downlaod updated ASN and country infor from ipinfo.io',
        allow_abbrev=False
    )
    parser.add_argument("--config", "-c", type=str, metavar="ipinfo.yml", required=False, default="ipinfo.yml", help="Path of the config file")
    parser.add_argument('--verbose', '-v', action="count", default=1, help="Be (more) verbose" )
    parser.add_argument('--quiet', '-q', action="store_true", help="Be quiet" )
    parser.add_argument('ips', metavar='IP', type=str, nargs='*', help='IP addresses to enrich')


    args = parser.parse_args()

    verbose = args.verbose
    if args.quiet :
        verbose = 0

    try:
        with open(args.config, 'r') as file :
            config = yaml.safe_load(file)
    except Exception as e:
        print("Unable to open config file '{}', error is: '{}'".format(args.config, str(e)),file=sys.stderr)
        exit(1)

    with open("country_asn.json.gz", "wb") as f:
        response = requests.get("{}?token={}".format(config["ipinfo"]["url"], config["ipinfo"]["token"]), stream=True)
        total_length = response.headers.get('content-length')

        if total_length is None or not verbose: # no content length header
            f.write(response.content)
        else:
            print("Downloading...")
            # Setup progress bar
            dl = 0
            total_length = int(total_length)
            widgets = [
                progressbar.Percentage(),
                progressbar.Bar(),
                progressbar.ETA()
            ]
            bar = progressbar.ProgressBar(widgets=widgets, max_value=total_length)
            bar.start()
            bar.update(dl)
            for data in response.iter_content(chunk_size=4096):
                dl += len(data)
                f.write(data)
                bar.update(dl)

    if verbose :
        print("\nDecompressing...")
        if os.path.isfile("country_asn.json"):
            os.system("rm country_asn.json")
        os.system("gunzip country_asn.json.gz")

