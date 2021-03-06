#!/usr/bin/env bash

source /root/agent/agent.env

trap '' HUP
trap 'myexit' INT QUIT TERM


# 日志输出重定向
if [ ! $DEBUG == "yes" ]; then
exec >> ${LOG_DIR}/${PCAPFILTERNAME} 2>> ${LOG_DIR}/${PCAPFILTERNAME}
fi


currenttime=`date`
timestamp=`date +%s`
echo -e "[$0]====script start time:${currenttime} (${timestamp})===="


tcpdump_filter=$1
filelist=${2//,/ }

[ ! $# -eq 2 ] && echo -e "[$0] parameters error!\n Example: $0 <pcap-filter or ${PCAP_200_ERROR} <file1,file2,file3>\n" && exit

function myexit(){
    echo "[$0]stop all relevant tcpdump pcap filter program!"
    for fn in ${filelist}; do
        basefn=`basename ${fn}`
        echo "[$0] ps aux | grep tcpdump | grep \"${basefn%.*}\" | grep -v grep | gawk '{ print \$2 }' | xargs kill -9"
        ps aux | grep tcpdump | grep "${basefn%.*}" | grep -v grep | gawk '{ print $2 }' | xargs kill -9 2> /dev/null
    done
    currenttime=`date`
    timestamp=`date +%s`
    echo "[$0]PID: $$, myexit!"
    echo -e "[$0]====script stop time:${currenttime} (${timestamp})===="
    exit
}


if [ "${tcpdump_filter}" == "${PCAP_200_ERROR}" ]; then
    for file in ${filelist}; do
        sh ${AGENT_DIR}/extract_pcap.sh -f ${file} &
    done
else
    for file in ${filelist}; do
        basefn=`basename ${file}`
        file_suffix="_filter_${tcpdump_filter// /_}.pcap"
        file_out="${FILTERPCAP_DIR}/${basefn%.*}${file_suffix}"
        echo "tcpdump ${file} ${tcpdump_filter} ${file_out} &"
        tcpdump -Z root -r ${file} ${tcpdump_filter} -w ${file_out} &
    done
fi

wait

currenttime=`date`
timestamp=`date +%s`
echo "[$0]PID: $$, myexit!"
echo -e "[$0]====script stop time:${currenttime} (${timestamp})===="
exit
