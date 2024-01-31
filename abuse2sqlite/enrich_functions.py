import requests
import random
import sys
import time
import whoisit
import re

from ipwhois import IPWhois


sourceapp = "AS50559-DIVD_NL"
verbose=0
sleep_unit=0.5

def rest_get(call,resource,session,retries=3, backoff=1):
    url = "https://stat.ripe.net/data/{}/data.json?resource={}&sourceapp={}".format(call,resource,sourceapp)
    error = ""
    try:
        response = session.get(url, timeout = 5)
    except KeyboardInterrupt:
        sys.exit()
    except Exception as e:
        if retries > 0:
            time.sleep(sleep_unit*backoff)
            return rest_get(call,resource,session,retries-1,backoff*2)
        else:
            raise Exception("RIPEstat returned an error on API call '{}', error '{}".format(url,e))
    reply = response.json()
    if response.status_code != 200 or reply['status_code'] != 200 :
        if retries > 0:
            time.sleep(sleep_unit*backoff)
            return rest_get(call,resource,session,retries-1,backoff*2)
        else:
            raise Exception("RIPEstat API call '{}', return status '{}' and replied status '{}'".format(url, response.status_code, reply['status_code'] ))
    return reply['data']

def abuse_from_whois(ip):
    global verbose
    obj = IPWhois(ip)
    try:
        rdap = obj.lookup_rdap(depth=2,retry_count=0)
    except Exception as e:
        if verbose:
            print("\nError http whois resolving {}, error is: {}".format(ip, str(e)),file=sys.stderr)
        result=None
    else:
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
        try:
            whois = obj.lookup_whois(retry_count=1)
        except Exception as e:
            if verbose :
                print("\nError native whois resolving {}, error is: {}".format(ip, str(e)),file=sys.stderr)
            return None
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
        # return all emails found
        mails = list(set(othermails))
        if len(mails) > 0 :
            return ",".join(mails)
        else:
            return None

def get_info(ip, maxminddb=None, verbosity=0, session=None):
    verbose = verbosity

    if not session :
        session = requests.Session()

    # Get abuse info
    # https://stat.ripe.net/data/abuse-contact-finder/data.<format>?<parameters>

    abuse_reply = rest_get("abuse-contact-finder",ip,session)
    contacts = []
    rir = ""
    if "authoritative_rir" in abuse_reply:
        rir = abuse_reply["authoritative_rir"]
    if 'abuse_contacts' in abuse_reply:
        contacts = abuse_reply['abuse_contacts']
    if len(contacts) > 0 :
        abuse_email = ",".join(contacts)
        abuse_source = "RIPEstat"
    else:
        whoisabuse = abuse_from_whois(ip)
        if whoisabuse :
            abuse_email = whoisabuse
            abuse_source = "whois"
        else:
            abuse_email = "Not found"
            abuse_source = ""

    # Get ASN
    # https://stat.ripe.net/data/network-info/data.json?resource=194.5.73.5

    asn_reply = rest_get("network-info",ip,session)
    asn = ""
    prefix = ""
    if 'asns' in asn_reply:
        if len(asn_reply['asns']) > 0 :
            asn = asn_reply['asns'][0]
        prefix = asn_reply['prefix']

    # Get geolocation
    if maxminddb :
        mmresult = maxminddb.get(ip)
        city = ""
        country = ""
        reg_country = ""
        if isinstance(mmresult, dict) :
            if "city" in mmresult :
                city = mmresult["city"]["names"]["en"]
            if "country" in mmresult:
                country = mmresult["country"]["iso_code"]
            if "registered_country" in mmresult:
                reg_country = mmresult["registered_country"]["iso_code"]
        else:
            print("\nNo geodata for {}".format(ip),file=sys.stderr)

    result = {
        "ip" : ip,
        "abuse" : abuse_email,
        "asn" : asn,
        "prefix" : prefix,
        "country" : country,
        "reg_country" : reg_country,
        "city" : city,
        "abuse_source" : abuse_source,
        "rir" : rir
    }
    return result


def abuse_from_asn(asn, verbosity=0, session=None):
    verbose = verbosity

    if not session :
        session = requests.Session()

    # Get abuse info
    # https://stat.ripe.net/data/abuse-contact-finder/data.<format>?<parameters>

    try:
        abuse_reply = rest_get("abuse-contact-finder",asn,session, retries=0)
    except:
        try:
            abuse_reply = abuse_from_asn_scraped(asn)
        except Exception as e:
            raise Exception("Scraping for info of '{}' failed. Error: '{}'".format(asn, str(e) ))
    contacts = []
    rir = ""
    abuse_email = ""
    abuse_source = ""
    if "authoritative_rir" in abuse_reply:
        rir = abuse_reply["authoritative_rir"]
    if 'abuse_contacts' in abuse_reply:
        contacts = abuse_reply['abuse_contacts']
    if len(contacts) > 0 :
        abuse_email = ",".join(contacts)
        abuse_source = "RIPEstat"
    else:
        result={
            "abuse_contacts" : None,
        }
        try:
            result = abuse_from_asn_scraped(asn)
        except Exception as e:
            #raise Exception("Scraping for info of '{}' failed. Error: '{}'".format(asn, str(e) ))
            result["abuse_contacts"] = []
            pass
        if len(result["abuse_contacts"]) > 0 :
            abuse_email = ",".join(result["abuse_contacts"])
            abuse_source = "scraped"

    result = {
        "asn" : asn,
        "abuse" : abuse_email,
        "abuse_source" : abuse_source,
        "rir" : rir
    }
    return result

def abuse_from_asn_scraped(asnnr, verbosity=0) :
    emails = {}
    abuse_emails = {}
    whoisit.bootstrap()
    asn = whoisit.asn(asnnr)
    entities = {}
    for role in asn["entities"] :
        for entity in asn["entities"][role] :
            if "email" in entity :
                if role == "abuse" :
                    abuse_emails[entity["email"]] = 1
                else:
                    emails[entity["email"]] = 1
            entities[entity["handle"]] = 1
    if len(abuse_emails) == 0 and len(emails) == 0 :
        # Resolve entities and go scraping, hope for an email somewhere in text
        for entity in entities :
            try :
                e = whoisit.entity(entity, rir=asn["rir"])
            except Exception as e :
                pass
            else:
                for field in e :
                    for line in str(e[field]).split("\n") :
                        for match in re.findall("\\b[A-Za-z0-9\\._%+-]+@[A-Za-z0-9\\.-]+\\.[A-Z|a-z]{2,7}\\b", line) :
                            if re.search("(abuse|security)[^\\@]*\\@", match) :
                                abuse_emails[match] = 1
                            else:
                                emails[match] = 1
    if len(abuse_emails) > 0 :
        abuse_contacts = list(abuse_emails.keys())
    else :
        abuse_contacts = list(emails.keys())

    result = {
        "abuse_contacts" : abuse_contacts,
        "authoritative_rir" : asn["rir"]
    }
    return result
