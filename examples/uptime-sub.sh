#!/bin/bash
#
# Scan all of the physical devices on the portal to check for errors.
#

# Exit on ^C.
function sig_caught {
    exit 1
}
trap sig_caught SIGINT

OSTYPE=$(uname)
if [[ "$OSTYPE" == "Linux" ]] ; then
    HN=$(hostname -s)
else
    HN=$(hostname)
fi

printf "  %-12s %-5s " $HN $OSTYPE
uptime
