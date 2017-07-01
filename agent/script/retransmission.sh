#!/bin/bash

PCAPDIR="/home/backup"
#PCAPDIR="/backup"
LOGFILE="retransmission.log"


# do_stat pcapfile port
function do_stat() {
    if [ $2 -eq 0 ]; then
        cp $1 $2.pcap
    else     
        tcpdump -Z root -r $1 "tcp port $2" -w $2.pcap
    fi
    content=$(capinfos -c -M $2.pcap)
    total=$(echo $content | grep packet | cut -d : -f 3)
    echo -e "Number of total packets(port $2):  ${total}"  >> $LOGFILE
    count=$(tshark -n -r $2.pcap -Y "tcp.analysis.retransmission" -T fields -e tcp.stream 2>/dev/null | wc -l)
    echo -e "Number of retransmission packets(port $2):  ${count}"  >> $LOGFILE
    rate=$(echo "scale=5; $count / $total * 100" | bc)
    echo -e "Rate of retransmission packets(port $2):  0${rate}%\n\n"  >> $LOGFILE
    rm -rf $2.pcap
}

# do_main pcapfile 
function do_body() {
    do_stat $1 80    # 仅针对端口80做TCP重传的统计
    do_stat $1 443   # 仅针对端口80做TCP重传的统计
    do_stat $1 843   # 仅针对端口80做TCP重传的统计
    date
    do_stat $1 8300  # 针对端口8300做TCP重传的统计，比较花时间，tshark 运行一次要1-2个小时！
    date
    do_stat $1 0     # 针对全部端口做TCP重传的统计，最花时间
}

# do_body pcapfile
function do_main() {
    editcap -A "2017-06-17 10:40:00" -B "2017-06-17 10:50:00" $1 -F pcap beforpcapfile.pcap &> /dev/null
    editcap -A "2017-06-17 11:15:00" -B "2017-06-17 11:25:00" $1 -F pcap afterpcapfile.pcap &> /dev/null
    echo -e "\n===2017-06-17 10:40:00 -- 10:50:00===\n" >> $LOGFILE
    do_body beforpcapfile.pcap
    rm -rf beforpcapfile.pcap
    echo -e "\n===2017-06-17 11:15:00 -- 11:25:00===\n" >> $LOGFILE
    do_body afterpcapfile.pcap
    rm -rf afterpcapfile.pcap
}

#####main#####
rm -rf $LOGFILE
for pcapfile in $(ls $PCAPDIR/*20170617*.pcap); do
    echo -e "\n\n======PCAP Filename: $pcapfile ======\n\n" >> $LOGFILE
    do_main $pcapfile
done

echo -e "\n\n\t END!\n"