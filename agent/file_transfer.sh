#!/usr/bin/env bash

source /root/agent/agent.env

trap '' HUP
trap 'myexit' INT QUIT TERM


# 日志输出重定向
if [ ! $DEBUG == "yes" ]; then
exec >> ${LOG_DIR}/${TRANSLOGNAME} 2>> ${LOG_DIR}/${TRANSLOGNAME}
fi

currenttime=`date`
timestamp=`date +%s`
echo -e "[$0]====script start time:${currenttime} (${timestamp})===="


dstpath="root@$1"
filelist=`cat ${AGENT_DIR}/${TRANSFERTMP}`


[ "$1x" == "x" ] && echo -e "[$0] parameters is null!" && exit

function myexit(){
    echo "[$0]del ${AGENT_DIR}/${TRANSFERTMP}"
    rm -rf ${AGENT_DIR}/${TRANSFERTMP} &> /dev/null
    echo "[$0]stop all relevant ssh program!"
    for fn in ${filelist}; do
        basefn=`basename ${fn}`
        echo "[$0] ps aux | grep scp | grep \"${basefn%.*}\" | grep -v grep | gawk '{ print \$2 }' | xargs kill -9"
        ps aux | grep scp | grep "${basefn%.*}" | grep -v grep | gawk '{ print $2 }' | xargs kill -9 2> /dev/null
    done
    currenttime=`date`
    timestamp=`date +%s`
    echo "[$0]PID: $$, myexit!"
    echo -e "[$0]====script stop time:${currenttime} (${timestamp})===="
    exit
}



for file in ${filelist}; do
    scp ${file} ${dstpath} &
done
wait

echo "[$0]del ${AGENT_DIR}/${TRANSFERTMP}"
rm -rf ${AGENT_DIR}/${TRANSFERTMP} &> /dev/null

currenttime=`date`
timestamp=`date +%s`
echo "[$0]PID: $$, myexit!"
echo -e "[$0]====script stop time:${currenttime} (${timestamp})===="
exit
