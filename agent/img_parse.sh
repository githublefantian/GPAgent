#!/usr/bin/env bash
source ./agent.env

trap '' HUP

SUCCESS_OK=0
ERROR_PARA=1
ERROR_TCPDUMP=2

SUFFIX="_img.pcap"

function print_usage() {
    usage="
    Usage:\n
        $0 -f <pcap/pcapng filename>\n
    Example:\n
        $0 -f file1,file2\n
    "
    echo -e $usage
}

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
    output="${TMPPCAP_DIR}/${input_basename%.*}${SUFFIX}"
    starttime=$(date +%s)
    tcpdump -Z root -r ${input} ${FILTER} -w ${output}
    if [ $? -ne 0 ];then
        echo "[ERROR] tcpdump ${input} error!!"
        rm -rf ${output}
        exit ${ERROR_TCPDUMP}
    else
        endtime=$(date +%s)
        echo "[INFO] deal with \"${input}\" success and costs $(( $endtime - $starttime )) seconds"
    fi

    outputsize=`du -m ${output} | gawk '{ print $1 }'`
    # 检查配置参数
    [ ${SPLITSIZE} -gt 1999000 ] && echo "[ERROR] SPLITSIZE: ${SPLITSIZE} too big!"
    if [ ${outputsize} -gt ${SPLITSIZE} ];then
        echo "[INFO] splitting and merging ${output} pcap file"
        rm -rf ${output}split*
        echo "[INFO] tcpdump -Z root -r ${output} -w ${output}split -C ${SPLITSIZE_TCPDUMP}"
        tcpdump -Z root -r ${output} -w ${output}split -C ${SPLITSIZE_TCPDUMP} # && rm -rf ${output}
        split_files="${split_files} ${output}"
        # 切分后：
        # 需要将前一个pcap文件结尾的一段响应包合并到下一个pcap文件中
        # 需要将后一个pcap文件开始的一段响应包合并到上一个pcap文件中
        # 但这样会使得有响应的请求统计数据重复计算，如同一个验证码请求分别在两个pcap文件中
        # 通过后期合并处理能消除错误的统计
        index=`ls ${output}* -l | grep "${output}split" | wc -l`
        echo "[INFO] ls ${output}* -l | grep ${output}split | wc -l and NO.: ${index}"
        [ ${index} -lt 2 ] && echo "[ERROR] SPLITSIZE_TCPDUMP or SPLITSIZE error!" && exit ${ERROR_TCPDUMP}
        let index--
        mv ${output}split ${output}split0
        cp ${output}split${index} ${output}_${index}
        echo "[INFO] merging ......"
        # 从大到小, 逆向进行合并, mergeoutfile 是合并和的文件，最后一个split文件不用合并
        while : ; do
            splitinfile=${output}split${index}
            let splitout=index-1
            mergeinfile=${output}split${splitout}
            mergeoutfile=${output}_${splitout}
            echo " [INFO] tcpdump -Z root -r ${splitinfile} \"${RES_FILTER}\" -w tmp.pcap -c ${SPLITOVERLAP} && rm -rf ${splitinfile}"
            tcpdump -Z root -r ${splitinfile} "${RES_FILTER}" -w tmp.pcap -c ${SPLITOVERLAP} && rm -rf ${splitinfile}
            mergecap -F pcap -w ${mergeoutfile} ${mergeinfile} tmp.pcap && rm -rf tmp.pcap
            let index--
            [ $index -eq 0 ] && rm -rf ${output}split0 && break
        done

        thread_count=1
        for file in `ls ${output}_*`; do
            echo "[INFO] python $0 ${file} --dump"
            python ${0%.*}.py ${file} --dump &
            echo "[INFO] thread_count: ${thread_count}; SPLIT_PARALLER:${SPLIT_PARALLEL} ... wait ??? "
            if [ ${thread_count} -gt ${SPLIT_PARALLEL} ]; then
                echo "[INFO] ... wait ...."
                wait
            else
                let thread_count++
            fi
        done
    else
        echo "[INFO] python $0 ${output}"
        python ${0%.*}.py ${output} &
    fi
done
echo "[INFO] ... wait ...."
wait

for file in ${split_files}; do
    echo "[info] python ${0%.*}_merge.py ${file} &"
    python ${0%.*}_merge.py ${file} &
done
echo "[INFO] ... wait ...."
wait

echo "[INFO] del ${output} split-files"
rm -rf ${output}_*
echo "[INFO] del ${output} dump-files"
rm -rf ${output//.pcap/.dump}_*

finishtime=$(date +%s)
echo "[INFO] \"${filelist}\" costs $(( $finishtime - $begintime )) seconds in total"

exit ${SUCCESS_OK}
