#!/bin/bash

# Exit on ^C.
function sig_caught {
    exit 1
}
trap sig_caught SIGINT

echo
echo

VS=$(hostname -s)
echo "VM_SERVER:           $VS"
#virsh nodeinfo | grep -v '^$'

VS_VCPUS=$(virsh nodeinfo | grep 'CPU(s)' | awk '{print $2;}')

VS_IP=$(ifconfig | grep 172.16.191 | awk '{print $2;}' | awk -F: '{print $2;}')
#echo "IPADDR:              $VS_IP"

VS_OS=$(uname -r)
#echo "UNAME:               $VS_OS"

#echo -n "DISK: "
DISK_SIZE=$(df -h --total / | grep '^total' | awk '{print $2;}' | sed -e 's/G//')
#DISK_USED=$(df -h --total / | grep '^total' | awk '{print $3;}' | sed -e 's/G//')
DISK_AVAIL=$(df -h --total / | grep '^total' | awk '{print $4;}' | sed -e 's/G//')
#DISK_USEPER=$(df -h --total / | grep '^total' | awk '{print $5;}' | sed -e 's/\%//')
#echo "DISK_SIZE:           ${DISK_SIZE}G"
#echo "DISK_USED:           ${DISK_USED}G"
#echo "DISK_AVAIL:          ${DISK_AVAIL}G"
#echo "DISK_USEPER:         ${DISK_USEPER}%"

VS_MEM_TOTAL=$(virsh nodememstats | grep total | cut -c 9- | awk '{printf("%.1f",($1/(1024.*1024.)));}')
VS_MEM_FREE=$(virsh nodememstats | grep free | cut -c 9- | awk '{printf("%.1f",($1/(1024.*1024.)));}')
#echo "MEM_TOTAL:           ${VS_MEM_TOTAL}G"
#echo "MEM_FREE:            ${VS_MEM_FREE}G"

VS_UPTIME=$(ps -p 1 -o etime | tail -1)

VMS=($(virsh list --name | sort -fu))
NUM=0
VS_VCPUS_REM=$(( $VS_VCPUS - 2 ))
for VM in ${VMS[@]} ; do
    #echo "VM: $VM"
    #MAXVCPUS=$(virsh vcpucount $VM | grep maximum | grep live | awk '{print $3;}')
    CURVCPUS=$(virsh vcpucount $VM | grep current | grep live | awk '{print $3;}')
    #echo "    MAXCPUS: $MAXVCPUS"
    #echo "    CURCPUS: $CURVCPUS"
    MEM=$(virsh dommemstat $VM | grep actual | awk '{printf("%.1f",($2/(1024.*1024.)));}')
    #echo "    MEMORY:  ${MEM}G"
    IMGSIZE=$(virsh domblkinfo $VM vda | grep Capacity | awk '{printf("%.1f",($2/(1024.*1024.*1024.)));}')
    #echo "    IMGSIZE: ${IMGSIZE}G"
    #IMGFILE=$(virsh dumpxml $VM | grep 'source file=' | awk -F\' '{print $2;}')
    #echo "    IMGFILE: $IMGFILE"
    VMIP=$(host $VM | awk '{print $4;}')
    #echo "    VMIP:    $VMIP"

    #if (( $NUM == 0 )) ; then
#	echo
#	echo '                                       Image'
#	echo '    Guest         Server  RAM    CPUs  Size    IP'
#	echo '    ============  ======  =====  ====  ======  ==============='
    #fi
    printf 'VM: %-12s  %-6s  %5.1f  %4d  %6.1f  %-15s' $VM $VS $MEM $CURVCPUS $IMGSIZE $VMIP
    echo
    NUM=$(( $NUM + 1 ))
    VS_VCPUS_REM=$(( $VS_VCPUS_REM - $CURVCPUS ))
done
#echo

#echo
#echo '           Num     Total  Free    Total Free   Total  Free'
#echo '    Host   Guests  RAM    RAM     CPUs  CPUs   Disk   Disk    IP Address       Uptime        Kernel'
#echo '    ====== ======  ====== ======  ===== =====  ====== ======  ===============  ============  =========================='
printf "VS: %-6s %6d  " $VS $NUM
printf "%6.1f %6.1f  " $VS_MEM_TOTAL $VS_MEM_FREE
printf "%5d %5d  " $VS_VCPUS $VS_VCPUS_REM
printf "%6.1f %6.1f  " $DISK_SIZE $DISK_AVAIL
printf '%-15s  %-12s  %-26s' $VS_IP $VS_UPTIME $VS_OS
echo
#echo
