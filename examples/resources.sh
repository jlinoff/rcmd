#!/bin/bash
#
# Scan all hypervisors to determine the state of the system.
#
# This assumes that all of the hypervisors and their guests
# are in the login configuration file.
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
SUB=$MEDIR/resources-sub.sh

if [ ! -f $SUB ] ; then
    echo "ERROR: file does not exist: $SUB"
    exit 1
fi

LOGFILE=/tmp/res-$$.tmp
$RCMDL -H '^vs-.*' -b $SUB >$LOGFILE

echo
echo 'HYPERVISOR REPORT'
echo
echo '         Num     Total  Free    Total Free   Total  Free'
echo '  Server Guests  RAM    RAM     CPUs  CPUs   Disk   Disk    IP Address       Uptime        Kernel'
echo '  ====== ======  ====== ======  ===== =====  ====== ======  ===============  ============  =========================='
grep ^VS: $LOGFILE | sed -e 's/^VS: /  /' | sort -fu

echo
echo
echo 'GUEST REPORT'
echo '                                          Img'
echo '   #   Guest         Server  RAM    CPUs  Size    IP               Uptime        Kernel'
echo '  ===  ============  ======  =====  ====  ======  ===============  ============  =========================='
while read line ; do
    echo $line | awk '{printf("  %3d  %-12s  %-6s  %5.1f  %4d  %6.1f  %-15s  ",$1,$2,$3,$4,$5,$6,$7);}'
    vmhost=$(echo $line | awk '{print $2;}')
    data=$($RCMDL -H $vmhost -c 'ps -p 1 -o etime | tail -1 ; uname -r' | tr -d '\r' | xargs -L2)
    echo $data | awk '{printf("%-12s  %s\n",$1,$2);}'
done < <(grep ^VM: $LOGFILE | sed -e 's/^VM: //' | sort -fu | awk '{N++; printf("  %3d  ",N); print $0;}')
echo

rm -f $LOGFILE
