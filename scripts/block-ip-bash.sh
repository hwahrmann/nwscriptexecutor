#!/bin/bash

ip=$(echo "$1" | jq '.ipaddr')  # Extract the value of "ipaddr"
echo "IP Address: $ip"

# Do whatever is needed with the ip address

exit