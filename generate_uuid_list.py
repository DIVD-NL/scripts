#!/bin/python3
# https://www.DIVD.nl
# Usage: ./generate_uuid_list.py 100 | pbcopy
# Output: list of requests number of random UUID's

import sys
import uuid


count = int(sys.argv[1])
for line in range(count):
    sys.stdout.write(str(uuid.uuid4()) + '\n')
