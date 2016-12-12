#!/usr/bin/env bash
source /root/agent/agent.env

# 1:HUP 2:INT 3:QUIT 15:TERM
trap '' HUP
trap 'myexit' INT QUIT TERM


# 默认只计算当日的抓包文件
datetime=`date +%Y%m%d`
filelist=`ls ${PCAP_DIR}/*${datetime}*.pcap`


# 日志输出重定向
exec >> ${DEFAULTLOG}${DEFAULTLOGNAME} 2>> ${DEFAULTLOG}${DEFAULTLOGNAME}

# 有参数
if [ "x$1" != "x" ]; then
    filelist=${1//,/ }
    for filename in ${filelist}; do
        [ ! -f ${filename} ] && echo " ${filename} is not a file or not exist!" && exit
    done
fi


for input in ${filelist}; do
    md5output=${input//.pcap/.md5}
    if [ ! -f ${md5output} ];then
        echo "[$0] md5sum ${input} > ${md5output} &"
        md5sum ${input} > ${md5output} &
    fi
done
wait
