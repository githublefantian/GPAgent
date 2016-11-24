#!/usr/bin/bash
counter=16 
rm -rf new.pcapng
cp 1120end.pcap old1.pcapng
cp 1120end.pcap old2.pcapng

while [ $counter -gt 0 ]
do
    counter=$(($counter - 1))
    #cp 1120end.pcapng old_${counter}.pcapng
    mergecap -T ether -w new.pcapng old1.pcapng old2.pcapng
    if [ $? -ne 0 ];then echo $counter && break;fi
    rm -rf old1.pcapng old2.pcapng
    mv new.pcapng old1.pcapng
    cp old1.pcapng old2.pcapng
done
 
