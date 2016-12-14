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
SUFFIX_IMG_RESULT="_img_result.csv"
SUFFIX_PORT_RESULT="_ports_result.csv"

function print_usage() {
    usage="
    Usage:\n
        $0 [-f|--file] <pcap/pcapng filename>\n
        $0 [-t|--time] <date>\n
        $0 [-d|--default] 默认解析当天的数据\n
    Example:\n
        $0 -f file1,file2\n
        $0 -t 201602\n
        $0 -t 20160222\n
    "
    echo -e $usage
}


function myexit(){
    echo "[$0]stop all relevant program!"
    killall ports_statistics 2> /dev/null
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


# filt the data packets
split_files=""
begintime=$(date +%s)
for input in ${filelist}; do
    input_basename=`basename ${input}`

    # 统计pcap文件信息以及md5sum
    echo "[$0] pcapinfos && md5sum......"
    output="${RESULT_DIR}/${input_basename%.*}${SUFFIX_IMG_RESULT}"
    echo "[$0] capinfos ${input} -acdesSuTm > ${output} ......"
    capinfos ${input} -acdesSuTm  > ${output} &
    wait
    if [ -f ${input//.pcap/.md5} ];then
        echo "[$0] cat ${input//.pcap/.md5} | cut -d ' ' -f 1 ......"
        cat ${input//.pcap/.md5} | cut -d ' ' -f 1 >> ${output}
    else
        echo "[$0] md5sum ${input} | cut -d ' ' -f 1 ......"
        filemd5=`md5sum ${input} | cut -d ' ' -f 1`
        echo -e "\nMD5sum,${filemd5}\n\n" >> ${output}
    fi

    # 统计端口信息
    echo "[$0]ports_statistics ......"
    output="${RESULT_DIR}/${input_basename%.*}${SUFFIX_PORT_RESULT}"
    starttime=$(date +%s)
    ${AGENT_DIR}/ports_statistics ${input} ${output} ${PORTS_PERIOD} &
    wait
    echo "[$0]ports_statistics ......wait......"
    if [ $? -ne 0 ];then
        echo "[ERROR] ports_statistics ${input} error!!"
        rm -rf ${output}
        exit ${ERROR_TCPDUMP}
    else
        endtime=$(date +%s)
        echo "[$0] port statistic deal with \"${input}\" success and costs $(( $endtime - $starttime )) seconds"
    fi

    # 过滤数据包
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
        endtime=$(date +%s)
        echo "[$0] deal with \"${input}\" success and costs $(( $endtime - $starttime )) seconds"
    fi

    outputsize=`du -m ${output} | gawk '{ print $1 }'`
    # 检查配置参数
    [ ${SPLITSIZE} -gt 1999000 ] && echo "[ERROR] SPLITSIZE: ${SPLITSIZE} too big!"
    if [ ${outputsize} -gt ${SPLITSIZE} ];then
        echo "[$0] splitting and merging ${output} pcap file"
        rm -rf ${output}split*
        echo "[$0] tcpdump -Z root -r ${output} -w ${output}split -C ${SPLITSIZE_TCPDUMP}"
        tcpdump -Z root -r ${output} -w ${output}split -C ${SPLITSIZE_TCPDUMP} # && rm -rf ${output}
        split_files="${split_files} ${output}"
        # 切分后：
        # 需要将前一个pcap文件结尾的一段响应包合并到下一个pcap文件中
        # 需要将后一个pcap文件开始的一段响应包合并到上一个pcap文件中
        # 但这样会使得有响应的请求统计数据重复计算，如同一个验证码请求分别在两个pcap文件中
        # 通过后期合并处理能消除错误的统计
        index=`ls ${output}* -l | grep "${output}split" | wc -l`
        echo "[$0] ls ${output}* -l | grep ${output}split | wc -l and NO.: ${index}"
        [ ${index} -lt 2 ] && echo "[ERROR] SPLITSIZE_TCPDUMP or SPLITSIZE error!" && exit ${ERROR_TCPDUMP}
        let index--

        # 修改第一个split文件名，方便统一处理
        mv ${output}split ${output}split0
        # 拷贝最后一个split文件，方便统一处理
        cp ${output}split${index} ${output}_${index}
        # 从大到小, 逆向进行合并, mergeoutfile 是合并和的文件，最后一个split文件不用合并
        echo "[$0] merging ......"
        while : ; do
            splitinfile=${output}split${index} # 用于提取tmp.pcap，上一个处理的split文件
            let splitout=index-1
            mergeinfile=${output}split${splitout}
            mergeoutfile=${output}_${splitout}
            echo " [$0] tcpdump -Z root -r ${splitinfile} \"${RES_FILTER}\" -w tmp.pcap -c ${SPLITOVERLAP} && rm -rf ${splitinfile}"
            tcpdump -Z root -r ${splitinfile} "${RES_FILTER}" -w tmp.pcap -c ${SPLITOVERLAP} && rm -rf ${splitinfile} &
            wait
            mergecap -F pcap -w ${mergeoutfile} ${mergeinfile} tmp.pcap && rm -rf tmp.pcap &
            wait
            let index--
            [ $index -eq 0 ] && rm -rf ${output}split0 && break
        done

        thread_count=1
        for file in `ls ${output}_*`; do
            echo "[$0] python $0 ${file} --dump"
            python ${0%.*}.py ${file} --dump &
            echo "[$0] thread_count: ${thread_count}; SPLIT_PARALLER:${SPLIT_PARALLEL} ... wait ??? "
            if [ ${thread_count} -gt ${SPLIT_PARALLEL} ]; then
                echo "[$0] ... wait ...."
                wait
            else
                let thread_count++
            fi
        done
    else
        echo "[$0] python $0 ${output}"
        python ${0%.*}.py ${output} &
    fi
done
echo "[$0] ... wait ...."
wait

for file in ${split_files}; do
    echo "[info] python ${0%.*}_merge.py ${file} &"
    python ${0%.*}_merge.py ${file} &
done
echo "[$0] ... wait ...."
wait

echo "[$0] del ${output} split-files"
rm -rf ${output}_*
echo "[$0] del ${output} dump-files"
rm -rf ${output//.pcap/.dump}_*

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
exit ${SUCCESS_OK}


