#!/bin/python3
# https://www.DIVD.nl
# Usage: python3 ./favicon_shodan_calc.py https://www.DIVD.nl:443/
# Original script: https://gist.github.com/yehgdotnet/b9dfc618108d2f05845c4d8e28c5fc6a

import mmh3
import requests
import codecs
import sys

url = sys.argv[1]
# url = 'http://localhost:6080/'
faviconurl = "{}/favicon.ico".format(url)
response = requests.get(faviconurl, verify=False)
favicon = codecs.encode(response.content,"base64")
hash = mmh3.hash(favicon)

shodan_url = "https://www.shodan.io/search?query=http.favicon.hash:{}&language=en"
print(shodan_url.format(hash))