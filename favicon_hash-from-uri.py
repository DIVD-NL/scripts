import sys
import mmh3
import requests
import codecs
import warnings

if len(sys.argv) < 2:
    print("Usage: {} <uri>".format(sys.argv[0]))
    sys.exit(1)

warnings.filterwarnings("ignore") 

# specify absolute path to favicon
host = sys.argv[1]

response = requests.get(host, verify=False)
favicon = codecs.encode(response.content,"base64")
hash = mmh3.hash(favicon)

print(hash)

