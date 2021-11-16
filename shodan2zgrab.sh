#!/bin/bash

# https://www.DIVD.nl
# Based on Frank Breedijk's scan script
# Developed by Wietse Boonstra
# Usage:
#   Change the multiple_$PORT.ini variables to the desired endpoints.
#   ./shodan2zgrab.sh shodan_export.json.gz
# TODO:
#   Make the zgrab2 multiple_$PORT.ini as variable?
#
# This script will take the Shodan export and fetch IP and port  
# then all IP's/port are fetched and put in targets_$PORT.txt
# then a multiple_$PORT.ini is created for that PORT. 
# then zgrab goes to work.
# output will be placed in zgrab_output folder.


function locate {
        command -v $1 >/dev/null
        if [[ $? -gt 0 ]]; then
                echo "Unable to locate $1! Make sure it is installed!";
                exit 0
	else
		echo "Found $1!";
        fi      
        
}

locate zgrab2
locate jq

if [[ ! -f "$1" ]]; then
	echo "Unable to locate Shodan export file $1";
	echo "run as $0 shodan_export.json.gz";
	exit 1
fi

ZGRABOUTPUT="zgrab_output"
if [[ ! -d $ZGRABOUTPUT ]]; then
        mkdir $ZGRABOUTPUT
fi

ZGRABSLOG="$ZGRABOUTPUT/grabs.log"
echo -n "" > $ZGRABSLOG

MULTIPLEDIR="multiples"
if [[ ! -d $MULTIPLEDIR ]]; then
        mkdir $MULTIPLEDIR
fi


if [[ "${1: -3}" == '.gz' ]]; then
        zcat "$1" | jq -r ". | .ip_str +\",\"+(.port|tostring)" |sort -u > ip-port.txt
else
        cat "$1" | jq -r ". | .ip_str +\",\"+(.port|tostring)" |sort -u > ip-port.txt
fi

for PORT in $(cat ip-port.txt |awk -F"," '{print $2}' |sort -u ); do
        grep ",$PORT$" ip-port.txt | sed 's/\"//g' | awk -F"," '{print $1}' | sort -u | tee "targets_$PORT.txt" > /dev/null  
        HOSTCOUNT=$(cat targets_$PORT.txt|wc -l)
        echo "===== $PORT =====" >> $ZGRABSLOG
        echo "Scanning $HOSTCOUNT ips on port $PORT..."
echo "[http]
name=\"get_env\"
port=$PORT
endpoint=\"/About/info\"
[http]
name=\"get_login\"
port=$PORT
endpoint=\"/login.php\"
[http]
name=\"get_info\"
port=$PORT
endpoint=\"/info/server/file\"
" > $MULTIPLEDIR/multiple_$PORT.ini
        zgrab2 multiple -c $MULTIPLEDIR/multiple_$PORT.ini -f targets_$PORT.txt -o $ZGRABOUTPUT/results_$PORT.json -l $ZGRABOUTPUT/zgrab.log |tee -a $ZGRABSLOG
        cat $ZGRABOUTPUT/zgrab.log >> $ZGRABSLOG
        echo "Done"
done
