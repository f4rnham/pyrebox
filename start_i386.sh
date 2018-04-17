#!/bin/bash

if [ -z "$2" ]
then
    snapshot=""
else
    snapshot="-loadvm $2"
fi

cp pyrebox.conf.Win7SP1x86 pyrebox.conf
./pyrebox-i386 -s -monitor stdio -m 1024 -usb -device usb-tablet -drive file=$1,index=0,media=disk,format=qcow2,cache=unsafe -netdev tap,id=t0,ifname=tap0,script=no,downscript=no -device e1000,netdev=t0,id=nic0 -device rtl8139,netdev=n0 -netdev user,id=n0,smb="$PYREBOX_SHARE",smbserver=10.0.2.4 -vnc 127.0.0.1:0 ${snapshot}
