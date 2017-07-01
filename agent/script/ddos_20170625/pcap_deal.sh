#!/bin/bash


if [ -d /backup ]; then SRCPCAPDIR="/backup"; else SRCPCAPDIR="/home/backup"; fi
DSTPCAPDIR="/home/1105"

#SRCPCAPFILE="20170617"                         # for 228
SRCPCAPFILE="229_20170617_090100_p2p1.pcap"     # for 229
#SRCPCAPFILE="218_20170617_090153_p1p2.pcap"     # for new

FILTERCSVFILE="ipport.csv"
FILTERPCAPFILE=$SRCPCAPFILE
FILTERPCAPDIR="$DSTPCAPDIR/filter"

function BuildFileDIR() {
    [ ! -d $DSTPCAPDIR ] && mkdir -p $DSTPCAPDIR
    [ ! -d $FILTERPCAPDIR ] && mkdir -p $FILTERPCAPDIR
}


# SplitPcapBytime
function SplitPcapBytime(){
    for srcpcap in $SRCPCAPDIR/*$SRCPCAPFILE*; do
        echo -e "Split pcap file: $srcpcap ...... \n"
        editcap -A "2017-06-17 11:03:00" -B "2017-06-17 11:07:00" $srcpcap -F pcap $DSTPCAPDIR/$(basename $srcpcap) &> /dev/null
        [ ! $? -eq 0 ] && echo -e "Split pcap file: $srcpcap Failed!!!!!!! \n" 
    done
}


# FilterPcapByIpPort <csvfilename>
function FilterPcapByIpPort(){
    while read line; do
        currentip=$(echo $line | cut -d ',' -f 1)
        currentport=$(echo $line | cut -d ',' -f 2)
        
        tcpdump -Z root -r $DSTPCAPDIR/$FILTERPCAPFILE  "(src host $currentip and src port $currentport) or (dst host $currentip and dst port $currentport)" -w $FILTERPCAPDIR/${currentip}_${currentport}.pcap &> /dev/null
        
        [ ! $? -eq 0 ] && echo -e "FilterPcapByIpPort: $currentip and $ currentport Failed!!!!!!! \n" 
    done <$FILTERCSVFILE
}


# main
BuildFileDIR

echo "SplitPcapBytime……"
SplitPcapBytime

if [ -f $DSTPCAPDIR/$FILTERPCAPFILE ]; then
    FilterPcapByIpPort
fi

for file in $DSTPCAPDIR/*.pcap; do
    tcpdump -Z root -r $file "dst port 8300" -w $file.8300 &> /dev/null
done

echo "python parse_link.py $DSTPCAPDIR/*.pcap.8300"
python parse_link.py $DSTPCAPDIR/*.pcap.8300


rm -rf $DSTPCAPDIR/*pcap*
echo -e "\n\nEND!!!!!!!!!"

