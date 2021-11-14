Steps below explain how to convert shodan dump to a file which is useable in zgrab2.
After that the instructions will show two methods to parse the html response body using jq and regex.

### Convert shodan json for usage in zgrab
```cat shodan_dump.json|jq -r "[.ip_str ] | .[]" > example```

```cat shodan_dump.json|jq -r ". | .ip_str +\":\"+ (.port|tostring)" > example```

### Run zgrab2 outputting to json
```zgrab2 http -f example --endpoint=/login --max-redirects=1 -o results.json```

### Using jq and regex to parse response body
Capture method:

```jq '.ip as $newip | .data.http.result.response.body | capture("(?<version>Version................)") | [$newip,.version] | @csv' results.json```

Match method:

```jq -r '.ip as $newip | .data.http.result.response.body | [$newip,match("(Version:\\s\"([0-9]+.[0-9]+.[0-9]+.[0-9]+)\",)").captures[1].string] | @csv' results.json```

The two commands listed above will result in just the version being parsed from the response body.
