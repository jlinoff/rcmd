#!/bin/bash
#
# Scan all of the physical devices on the portal to check for errors.
#

# Exit on ^C.
function sig_caught {
    exit 1
}
trap sig_caught SIGINT

PROG=/usr/sbin/smartctl
DEVS=($($PROG --scan | awk '{print $1;}'))
OSTYPE=$(uname)
  if [[ "$OSTYPE" == "Linux" ]] ; then
    HN=$(hostname -s)
  elif [[ "$OSTYPE" == "SunOS" ]] ; then
    HN=$(hostname)
  else
    HN='unknown'
  fi

for DEV in ${DEVS[@]} ; do
    CAP=$($PROG -i $DEV | grep "User Capacity" | cut -c 19- | \
	sed -e 's/^.*\[//' -e 's/\]//')
    MODEL=$($PROG -i $DEV | grep "Device Model" | cut -c 19-)
    DATA=$($PROG -H $DEV | grep ^SMART | grep overall-health | \
	awk -F: '{print $2;}' | sed -e 's/^ *//')
    if [[ "$DATA" != "" ]] ; then
        printf "  %-8s %-5s %-20s %-8s %-24s %s\n" $HN $OSTYPE $DEV "$CAP" "$MODEL" "$DATA"
    fi
done
