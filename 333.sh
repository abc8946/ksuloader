/system/bin/insmod ./kernelsu.ko  & dmesg |  tail -80 | grep "Unknown symbol"  | awk '{print $6}' >symbol
