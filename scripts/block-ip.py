import time
import sys
import json
from json.decoder import JSONDecodeError

# Arguments to the script can be passed as JSON (in config PassParmAsJson: true) or separated by Comma
# The below logic shows the handling of both methods
#
# The sammple assumes that a Response Action has been defined, which sends the ip address as "ipaddr"
#
json_error = False
ip = ""
try:
    args = json.loads(sys.argv[1])
    
    print("Parameters are in JSON Format")

    # Now you can access the parameters as sent by NetWitness Respond Action Server
    # e.g. accessing ipaddr
    ip = args["ipaddr"]
    print("IP address: ", ip )
except JSONDecodeError:
    print("Parameters are in CSV Format")
    json_error = True

if json_error:
    pos = 0
    args = sys.argv[1].split(sep=",")
    for arg in args:
        if arg == "ipaddr":
            ip = args[pos+1]
            print("IP address : ", args[pos+1])
            break
        pos = pos + 1

# Insert your logic here to do whatever is needed with the ip address

# Simulate longer execution time of script
time.sleep(5)
exit(0)