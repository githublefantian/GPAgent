#!/usr/bin/bash

SUFFIX="_http.pcap"

# 对于验证码请求 `tcp[24:4]==0x2f626964` 可匹配 `/bid`字段， `tcp[28:4]==696d67ef` 可匹配`img/`
GET_FILTER="tcp[24:4]==0x2f626964"
# `tcp[20:2]==0x4854`匹配HTTP前两个字母`HT`
RES_FILTER="tcp[20:2]==0x4854"
FILTER="(${GET_FILTER}) or (${RES_FILTER})"


USAGE="
Usage:\n
    $0 -f <pcap/pcapng filename>
"

# 读取参数
while getopts "f:h" OPT
do 
    case $OPT in
        h)
            echo -e ${USAGE}
            exit
            ;;
        f)
            [ ! -f $OPTARG ] && echo " $OPT is not a file" && exit
            $filename=$OPTARG
            ;;
        ?)
            exit
            ;;
    esac
done


input=${filename}
output=${filename%.*}${SUFFIX}

## 过滤数据包
starttime=$(date +%s)

tcpdump -r ${input} ${FILTER} -w ${output}
if [ $? -ne 0 ];then
    echo "-------------tcpdump ${input} error!!--------------------------------"
    rm -rf ${output}
fi

endtime=$(date +%s)

echo "-------------tdpdump total time: $(( $endtime - $starttime )) seconds --------------------"
