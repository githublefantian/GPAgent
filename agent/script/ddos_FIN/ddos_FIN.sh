#!/bin/bash

PCAP_P1P1="/home/backup/218_20170617_090153_p1p1.pcap"
PCAP_P1P2="/home/backup/218_20170617_090153_p1p2.pcap"
#PCAP_P1P1="20170627.pcap"
#PCAP_P1P2="20170627_bak.pcap"
LOGFILE="statistics.log"
DETAILLOGFILE="detail_statistics.log"
IPPORT_P1P2="ipport_p1p2.csv"


## 验证码过滤表达式(GET 示例: GET /bidimg/get.ashx?i=ffd5377fe6a050b...)
# tcp[24:4]==0x2f626964 匹配 /bid; tcp[28:4]==696d67ef 匹配 img/ 字段; tcp[24:4]==0x2f2f6269 匹配//bi
GET_FILTER="((tcp[24:4]==0x2f626964 or tcp[24:4]==0x2f2f6269) and dst port 80)"
# 带有FIN标识
# FIN_FILTER="(tcp[tcpflags] & tcp-fin != 0)"
# GET_FIN_FILTER="(${GET_FILTER} and ${FIN_FILTER})" 
# TIMESTAMP=$(date -d '2017-06-17 11:05:00' +%s)


function DoFINStat(){
    srcpcapfile=`basename $1`
    dstpcapfile="${srcpcapfile%.*}_get.pcap"
    beforpcapfile="${srcpcapfile%.*}_get_before.pcap"
    afterpcapfile="${srcpcapfile%.*}_get_after.pcap"
    
    tcpdump -Z root -r $1 $GET_FILTER -w $dstpcapfile  ## 过滤出总的URL REQUEST
    editcap -B "2017-06-17 11:05:00" $dstpcapfile -F pcap $beforpcapfile &> /dev/null
    editcap -A "2017-06-17 11:05:00" $dstpcapfile -F pcap $afterpcapfile &> /dev/null

    echo -e "\n\n\n===${beforpcapfile}:" | tee -a $LOGFILE $DETAILLOGFILE > /dev/null
    tshark -n -q -r $beforpcapfile -z io,stat,0,"tcp.flags.fin==1" >> $LOGFILE
    tshark -n -q -r $beforpcapfile -z io,stat,60,"tcp.flags.fin==1" >> $DETAILLOGFILE
    
    echo -e "\n\n\n===${afterpcapfile}:" | tee -a $LOGFILE $DETAILLOGFILE > /dev/null
    tshark -n -q -r $afterpcapfile -z io,stat,0,"tcp.flags.fin==1" >> $LOGFILE
    tshark -n -q -r $afterpcapfile -z io,stat,60,"tcp.flags.fin==1" >> $DETAILLOGFILE
    
    rm -rf $dstpcapfile $beforpcapfile $afterpcapfile

}

# FilterPcapByIpPort <pcapfile> <ip port csv>
function FilterPcapByIpPort(){
    while read line; do
        currentip=$(echo $line | cut -d ',' -f 1)
        currentport=$(echo $line | cut -d ',' -f 2)
        
        tcpdump -Z root -r $1  "(src host $currentip and src port $currentport) or (dst host $currentip and dst port $currentport)" -w ./filter/${currentip}_${currentport}.pcap &> /dev/null
        
        [ ! $? -eq 0 ] && echo -e "FilterPcapByIpPort: $currentip and $ currentport Failed!!!!!!! \n" 
    done <$2
}


###########main############
[ ! -d ./filter ] && mkdir ./filter
echo "" | tee $LOGFILE $DETAILLOGFILE > /dev/null
rm -rf ./filter/*

echo "FilterPcapByIpPort $PCAP_P1P2 $IPPORT_P1P2......"
FilterPcapByIpPort $PCAP_P1P2 $IPPORT_P1P2
echo "DoFINStat $PCAP_P1P1......"
DoFINStat $PCAP_P1P1
echo "DoFINStat $PCAP_P1P2......"
DoFINStat $PCAP_P1P2
wait

echo -e "\nEND!!!! \n"


