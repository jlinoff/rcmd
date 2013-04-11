#!/bin/bash
#
# Check user activity.
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

SUB=$MEDIR/uptime-sub.sh

if [ ! -f $SUB ] ; then
    echo "ERROR: file does not exist: $SUB"
    exit 1
fi

cat <<EOF

UPTIME REPORT `date`

  Hostname     O/S   Uptime
  ============ ===== ========================================
EOF
$RCMDL -b $SUB
echo
