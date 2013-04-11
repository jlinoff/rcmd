#!/bin/bash
#
# Scan all of the physical devices on the portal to check for errors.
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
SUB=$MEDIR/disk-check-sub.sh

if [ ! -f $SUB ] ; then
    echo "ERROR: file does not exist: $SUB"
    exit 1
fi

# Check all of the physical disk devices on the portal.
cat <<EOF

DISK HEALTH REPORT `date`

  Hostname O/S   Device               Capacity Type                     Health
  ======== ===== ==================== ======== ======================== ======
EOF
$RCMDL -H '^vs-.*' -H '^webfs.*' -b $SUB
echo
