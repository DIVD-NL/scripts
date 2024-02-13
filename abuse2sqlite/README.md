abuse2sqlite
============

Took to get asn and country data from ipinfo.io, add them to a sqlite database, add abuse addresses to the asns and enrich bloody fast based on this database.

General usage
-------------

```sh
./update_ipinfo.py                       # To download the data from ipinfo.io
./import_ipfino.py                       # To import the data in abuse.sqlite3
./asn2abuse.py                           # To get abuse data from the ASNs into the DB
cat ips.tx | ./enrichsqlite.py | tee enriched.csv
                                         # To enricht ip information from a file to a csv
```

update_ipinfo.py
----------------

```
usage: update_ipinfo.py [-h] [--config ipinfo.yml] [--verbose] [--quiet] [IP ...]

Downlaod updated ASN and country infor from ipinfo.io

positional arguments:
  IP                    IP addresses to enrich

options:
  -h, --help            show this help message and exit
  --config ipinfo.yml, -c ipinfo.yml
                        Path of the config file
  --verbose, -v         Be (more) verbose
  --quiet, -q           Be quiet
```

Script needs a config file (`ipinfo.yml` by default)with the following format:
```yml
ipinfo:
  url: https://ipinfo.io/data/free/country_asn.json.gz
  token : 1234abc1234abc
```

Usually finishes within a minute

import_ipinfo.py
----------------

```
usage: import_ipinfo.py [-h] [--sqlite abuse.sqlite3] [--json country_asn.json]
                        [--verbose] [--quiet]

Import ipinfo data into a sqllite database

options:
  -h, --help            show this help message and exit
  --sqlite abuse2.sqlite3, -s abuse2.sqlite3
                        Path of the sqlite database
  --json country_asn.json, -j country_asn.json
                        Country and ASN JSOn file from ipinfo.io
  --verbose, -v         Be (more) verbose
  --quiet, -q           Be quiet
```

WARNING: this script will start by nuking the ips and ipv6 table !!!

Gets the information from country_asn.json and populates the tables ips and ipv6 with the information in them, so enrichment can be fast. While this script runs the database is locked. 

asn2abuse.py
------------

```
usage: asn2abuse.py [-h] [--sqlite abuse.sqlite3] [--threads N] [--retry N] [--verbose]
                    [--quiet]

Update ASN abuse data in sqlite database

options:
  -h, --help            show this help message and exit
  --sqlite abuse.sqlite3, -s abuse.sqlite3
                        Path of the sqlite database
  --threads N, -t N     Number of request threads [default: 8]
  --retry N, -r N       Number of retries for failed queries [default: 0]
  --verbose, -v         Be (more) verbose
  --quiet, -q           Be quiet
```

This looks at the ips and ipv6 table and the asns table to determine if the abuse addreses of asns need to be resolved. asns are resolved if they are:
* Not in the database,
* Have not been resolved in the last 30 days
* Had an error when they were last resolved

The primary data source for abuse addreses is [RIPEstat](https://stat.ripe.net/), if RIPEstat does not have data, we fall back to rdap via the shoisit python library. If we fall back to rdap we look for the abuse role, if that doesn't exist, we scrape any email we can find, prefering addresses with security or abuse before the @ sign.

enrichsqlite.py
---------------

```
usage: enrichsqlite.py [-h] [--sqlite abuse.sqlite3] [--infile ips.txt] [--verbose]
                       [--quiet]
                       [IP ...]

Enrich ips addresses from a sqlite database

positional arguments:
  IP                    IP addresses to enrich

options:
  -h, --help            show this help message and exit
  --sqlite abuse.sqlite3, -s abuse.sqlite3
                        Path of the sqlite database
  --infile ips.txt, -i ips.txt
                        Path of a file of ip addresses to enricht one per line
  --verbose, -v         Be (more) verbose
  --quiet, -q           Be quiet

If no file and no IP addresses are given, the IP addresses are read from stdin
```

enriches ip addresses by using the abuse.sqlite3 database. IP addreses can be read from file, standard in or given as command line arguments. -q also suppresses the standard csv header.
