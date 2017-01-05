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


SUCCESS_OK=0
ERROR_PARA=1
ERROR_TCPDUMP=2
ABNORMAL_EXIT=3

SUFFIX_IMG="_img.pcap"

function print_usage() {
    usage="
    Usage:\n
        $0 [-f|--file] <pcap/pcapng filename>\n
        $0 [-t|--time] <date>\n
        $0 [-d|--default] 默认过滤当天的数据\n
    Example:\n
        $0 -f file1,file2\n
        $0 -t 201602\n
        $0 -t 20160222\n
    "
    echo -e $usage
}


function myexit(){
    echo "[$0]stop all relevant program!"
    for fn in ${filelist}; do
        basefn=`basename ${fn}`
        echo "[$0] ps aux | grep \"${basefn%.*}\" | grep -v $$ | grep -v grep | gawk '{ print \$2 }' | xargs kill -9"
        ps aux | grep "${basefn%.*}" | grep -v $$ | grep -v grep | gawk '{ print $2 }' | xargs kill -9 2> /dev/null
        echo "[$0] rm -rf ${TMPPCAP_DIR}/${basefn%.*}*"
        rm -rf ${TMPPCAP_DIR}/${basefn%.*}*
    done
    currenttime=`date`
    timestamp=`date +%s`
    echo "[$0]PID: $$, myexit!"
    echo -e "[$0]====script stop time:${currenttime} (${timestamp})===="
    exit ${ABNORMAL_EXIT}
}

filelist=""
# parse parameters
[ $# -eq 0 ] && print_usage && exit ${ERROR_PARA}
while [ $# -gt 0 ]; do
    case "$1" in
        -h | --help)
            print_usage
            exit ${SUCCESS_OK}
            ;;
        -f | --file)
            shift
            [ "x$1" == "x" ] && echo "Please input the filename!" && exit ${ERROR_PARA}
            filelist=${1//,/ }
            for filename in ${filelist}; do
                [ ! -f ${filename} ] && echo " ${filename} is not a file or not exist!" && exit ${ERROR_PARA}
            done
            shift
            ;;
        -t | --time)
            shift
            [ "x$1" == "x" ] && echo "Please input the date time!" && exit ${ERROR_PARA}
            filelist=`ls ${PCAP_DIR}/*$1*.pcap`
            [ "${filelist}x" == "x" ] && echo "file is empty!" && exit ${ERROR_PARA}
            shift
            ;;
        -d | --default)
            shift
            # 默认解析当天的数据包
            datetime=`date +%Y%m%d`
            filelist=`ls ${PCAP_DIR}/*${datetime}*.pcap`
            [ "${filelist}x" == "x" ] && echo "file is empty!" && exit ${ERROR_PARA}
            ;;
        *)
            echo "Unknow argument: $1"
            print_usage
            exit ${ERROR_PARA}
            ;;
    esac
done

# pcapfile, resultdir
function filter_error_200_pcap() {
    lineno=0
    pcapfile=`basename $1`
    csvfile=${RESULT_DIR}/${pcapfile//.pcap/_error_path.csv}
    [ ! -f $csvfile ] && echo "$csvfile not exist!" && return 1

    while read line; do
        let lineno++
        if [ $lineno -ge 3 ]; then
            echo $line
            currentip=`echo $line | cut -d ',' -f 2`
            currentport=`echo $line | cut -d ',' -f 3`
            currentpcap="${currentip}_${currentport}.pcap"
            resultpcap=$2$currentpcap
            [ -f $resultpcap ] && continue
            echo "tcpdump -Z root -r $1 \"(src host $currentip and src port $currentport) or (dst host $currentip and dst port $currentport)\" -w ${resultpcap}"
            tcpdump -Z root -r $1  "(src host $currentip and src port $currentport) or (dst host $currentip and dst port $currentport)" -w ${resultpcap}
        fi
    done < $csvfile
}

# filt the data packets
begintime=$(date +%s)
for input in ${filelist}; do
    input_basename=`basename ${input}`

    # 过滤HTTP IMG数据包
    echo "[$0]tcpdump filter ......"
    output="${TMPPCAP_DIR}/${input_basename%.*}${SUFFIX_IMG}"
    starttime=$(date +%s)
    tcpdump -Z root -r ${input} ${FILTER} -w ${output} &
    wait
    echo "[$0]tcpdump filter ......wait......"
    if [ $? -ne 0 ];then
        echo "[ERROR] tcpdump ${input} error!!"
        rm -rf ${output}
        exit ${ERROR_TCPDUMP}
    else
        # 过滤响应200错误的包数据包
        resultdir="${ERROR_200_DIR}/${input_basename%.*}/"
        [ ! -d $resultdir ] && mkdir $resultdir
        echo "[$0]filter_error_200_pcap ${output} ${resultdir} &"
        filter_error_200_pcap ${output} ${resultdir} &
    fi
done
wait


for fn in ${filelist}; do
    basefn=`basename ${fn}`
    echo "[$0] rm -rf ${TMPPCAP_DIR}/${basefn%.*}*"
    rm -rf ${TMPPCAP_DIR}/${basefn%.*}*
done

finishtime=$(date +%s)
echo "[$0] \"${filelist}\" costs $(( $finishtime - $begintime )) seconds in total"

currenttime=`date`
timestamp=`date +%s`
echo "[$0]PID: $$, myexit!"
echo -e "[$0]====script stop time:${currenttime} (${timestamp})===="
exit
