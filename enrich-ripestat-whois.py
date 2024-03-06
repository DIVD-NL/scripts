#!/usr/bin/env python3

import argparse
import requests
import os
from ipwhois import IPWhois
import sys
from multiprocessing import Process, Queue
import random

sourceapp = "AS50559-DIVD_NL"

def rest_get(call,resource,session,retries=3):
	url = "https://stat.ripe.net/data/{}/data.json?resource={}&sourceapp={}".format(call,resource,sourceapp)
	try:
		response = session.get(url, timeout = 1)
	except KeyboardInterrupt:
		sys.exit()
	except:
		if retries > 0:
			return rest_get(call,resource,session,retries-1)
		else:
			return "Timeout"
	reply = response.json()
	return reply['data']


def abuse_from_whois(ip):
	try:
		obj = IPWhois(ip)
		rdap = obj.lookup_rdap(depth=2)
		result = rdap['objects']
		abusemails = []
		othermails = []
		if result:
			for key in result.keys():
				data = result[key]
				if 'roles' in data and data['roles'] and 'abuse' in data['roles']:
					if data['contact'] and data['contact']['email']:
						for email in data['contact']['email']:
							abusemails.append(email['value'])
				else :
					if 'contact' in data and data['contact'] and data['contact']['email']:
						for email in data['contact']['email']:
							if 'abuse' in email['value']:
								abusemails.append(email['value'])
							else :
								othermails.append(email['value'])

		else :
			whois = obj.lookup_whois()
			if whois['nets']:
				for net in whois['nets']:
					if net['emails']:
						for email in net['emails']:
							if 'abuse' in email:
								abusemails.append(email)
							else :
								othermails.append(email)

		mails = list(set(abusemails))
		abuse = str(mails)[1:-1].replace(' ', '').replace("'", "")
		if abuse:
			# Return a abuse contact
			return abuse
		else :
			# Just pick an email from whois
			mails = list(set(othermails))
			return random.choice(mails)

	except KeyboardInterrupt:
		sys.exit()
	except Exception as e:
		sys.stderr.write(e)
		return None

def worker(in_q, out_q):
	task = in_q.get()
	while task != 'STOP':
		line = task["line"]
		try: 
			result = get_info(line)
			out_q.put(result)

		except:
			# Retry:
			if task["retry"] > 0:
				task["retry"] = task["retry"] - 1
				out_q.put('"{}","Error while resolving, {} retries left"'.format(task["line"],task["retry"]))
			else:
				task = in_q.get()
		else:
			task = in_q.get()
	out_q.put("DONE")


def get_info(line):
	session = requests.Session()

	# Get abuse info
	# https://stat.ripe.net/data/abuse-contact-finder/data.<format>?<parameters>

	abuse_reply = rest_get("abuse-contact-finder",line,session)
	contacts = []
	rir = ""
	if "authoritative_rir" in abuse_reply:
		rir = abuse_reply["authoritative_rir"]
	if 'abuse_contacts' in abuse_reply:
		contacts = abuse_reply['abuse_contacts']
	if len(contacts) > 0 :
		abuse_email = contacts[0]
		abuse_source = "ripeSTAT"
	else:
		whoisabuse = abuse_from_whois(line)
		if whoisabuse:
			abuse_email = whoisabuse
			abuse_source = "whois"
		else: 
			abuse_email = "Not found"
			abuse_source = ""

	# Get ASN
	# https://stat.ripe.net/data/network-info/data.json?resource=194.5.73.5

	asn_reply = rest_get("network-info",line,session)
	asn = "unknown"
	prefix = "unknown"
	if 'asns' in asn_reply:
        if len(asn_reply['asns']) > 0 :
            asn = asn_reply['asns'][0]
		prefix = asn_reply['prefix']

		# Get ASN info
		if asn in asns:
			asn_data = asns[asn]
		else:
			asn_data = rest_get("as-overview",asn,session)
			asns[asn] = asn_data

		holder = asn_data['holder']
	else: 
		holder = "unknown"

	# Get geolocation
	if prefix != "unknown":
		if prefix in locations:
			location_data = locations[prefix]
		else:
			location_data = rest_get("maxmind-geo-lite",prefix,session)

		city=location_data['located_resources'][0]['locations'][0]['city']
		country=location_data['located_resources'][0]['locations'][0]['country']
	else:
		city = "unknown"
		country = "unknown"

	return'"{}","{}","{}","{}","{}","{}","{}","{}","{}"'.format(line,abuse_email,prefix,asn,holder,country,city,abuse_source,rir)


# Process level global variables
asns = {}
locations = {}

if __name__ == '__main__':
	parser = argparse.ArgumentParser(description='Get abuse and location information for IPs', allow_abbrev=False)
	parser.add_argument('input', type=str, metavar="INPUT.txt", nargs="*", default="/dev/stdin", help="Either a list files with one IP address per line or a IP address [default: stdin]")
	parser.add_argument('--output', "-o", type=str, metavar="OUTPUT.csv", help="output csv file")
	parser.add_argument('--threads', "-t", type=int, metavar="N", default=8, help="Number of request threads [default: 8]")
	parser.add_argument('--retry', "-r", type=int, metavar="N", default=3, help="Number of retries for failed queries [default: 3]")

	args = parser.parse_args()

	# Set up queues
	task_queue = Queue()
	out_queue  = Queue()


	# Spawn worker threads
	for i in range(args.threads):
		Process(target=worker, args=(task_queue, out_queue), daemon=True).start()

	# Read input and submit to queue
	if isinstance(args.input,str):
		files = [args.input]
	else :
		files = args.input

	for f in files:
		if os.path.isfile(f) or f == "/dev/stdin":
			file = open(f,"r")
			for line in file.readlines():
				line = line.strip()
				task = {
					"line" : line,
					"retry" : args.retry
				}
				task_queue.put(task)
			file.close()
		else:
			task = {
				"line" : f,
				"retry" : args.retry
			}
			task_queue.put(task)

	# Tell workers to stop when done.
	for i in range(args.threads):
		task_queue.put("STOP")

	# Write
	if args.output :
		outfile = open(args.output,"w")
		outfile.write('ip,abuse,prefix,asn,holder,country,city,abuse_source,rir\n')
		outfile.flush()

	workers = args.threads
	print('ip,abuse,prefix,asn,holder,country,city,abuse_source')
	sys.stdout.flush()
	while workers > 0:
		line = out_queue.get()
		if line == "DONE":
			workers = workers - 1
		else:
			if args.output:
				outfile.write("{}\n".format(line))
				outfile.flush()
			print(line)
			sys.stdout.flush()

	if args.output :
		outfile.close()
