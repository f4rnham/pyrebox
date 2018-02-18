#!/bin/bash

#This script is provided as an example of a possible QEMU / Pyrebox configuration
#for a Windows XP SP3, 32 bit analysis target.

#It assumes that pyrebox.conf.WinXPSP3x86 exists, and contains the list
#of scripts to be loaded on startup, as well as the configuration parameter
#that indicates Volatility the profile to apply.

#The QEMU parameters specified will start a VM with:
#   * 256 MiB of RAM
#   * Usb support
#   * A main hard-drive, provided as a qcow2 image as the first parameter for the script
#   * Starts a VNC server on 127.0.0.1 for showing the system display
#   * Redirects the QEMU monitor to stdio (only configuration supported currently)

if [ -z "$2" ]
then
    snapshot=""
else
    snapshot="-loadvm $2"
fi

cp pyrebox.conf.Win7SP1x86 pyrebox.conf
./pyrebox-i386 -s -monitor stdio -m 1024 -usb -usbdevice tablet -drive file=$1,index=0,media=disk,format=qcow2,cache=unsafe -netdev tap,id=t0,ifname=tap0,script=no,downscript=no -device e1000,netdev=t0,id=nic0 -device rtl8139,netdev=n0 -netdev user,id=n0,smb=/mnt/hgfs/scripts/,smbserver=10.0.2.4 -vnc 127.0.0.1:0 ${snapshot}
