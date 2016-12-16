#!/usr/bin/env bash

source /root/agent/agent.env

# 1:HUP 2:INT 3:QUIT 15:TERM
trap '' HUP
trap 'myexit' INT QUIT TERM


# 日志输出重定向
if [ ! $DEBUG == "yes" ]; then
exec >> ${DEFAULTLOG}${IMGLOGNAME} 2>> ${DEFAULTLOG}${IMGLOGNAME}
fi

currenttime=`date`
timestamp=`date +%s`
echo -e "[$0]====script start time:${currenttime} (${timestamp})===="


function myexit(){
    echo "[$0] stop all img_parse.sh program!"
    echo "ps aux | grep "img_parse.sh" | grep -v $$ | grep -v grep | gawk '{ print $2 }' | xargs kill -s TERM > /dev/null"
    ps aux | grep "img_parse.sh" | grep -v $$ | grep -v grep | gawk '{ print $2 }' | xargs kill -s TERM &> /dev/null
    echo "[$0] rm -rf ${TMPPCAP_DIR}/*"
    rm -rf ${TMPPCAP_DIR}/*
    currenttime=`date`
    timestamp=`date +%s`
    echo "[$0]PID: $$, myexit!"
    echo -e "[$0]====script stop time:${currenttime} (${timestamp})===="
    exit
}

[ $# -eq 0 -o "$1" == "-h" ] && echo "Usage: ./img_deal.sh <time> <unparsed nic name>" && exit

for file in ${PCAP_DIR}/*$1*.pcap; do
    [ $# -eq 2 -a "${file:0-9:4}" == "$2" ] && continue
    echo "[$0] ${AGENT_DIR}/img_parse.sh -f ${file} &"
    ${AGENT_DIR}/img_parse.sh -f ${file} &
done
wait

myexit



