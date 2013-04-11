#!/bin/bash
#
# Check for clock drift on all of the hosts.
#

# Exit on ^C.
function sig_caught {
    rm -f $$.rcmd
    exit 1
}
trap sig_caught SIGINT

# Include the utilities.
MEDIR=$(dirname -- $(readlink -f $0))
. $MEDIR/conf.sh

# Get all of the hosts.
PORTAL_HOSTS=($($RCMDL --list-hosts))

# Each host must be processed individually because of the time lag.
for PORTAL_HOST in ${PORTAL_HOSTS[@]} ; do
    REFDATE=$(date +%s)
    $RCMDL -H $PORTAL_HOST \
	-c 'echo "DELTA '$PORTAL_HOST' $(( $(date +%s) - '$REFDATE' ))"' | \
	awk '{printf("DRIFT:  %-24s  %4d\n",$2,$3);}'
done

