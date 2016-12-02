#!/usr/bin/env bash
source ./agent.env

trap '' HUP

SUCCESS_OK=0
ERROR_PARA=1

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
        continue
    else
        endtime=$(date +%s)
        echo "[INFO] deal with \"${input}\" success and costs $(( $endtime - $starttime )) seconds"
    fi

    outputsize=`du -m ${output} | gawk '{ print $1 }'`
    if [ ${outputsize} -gt ${SPLITSIZE} ];then
        echo "[INFO] splitting and merging ${output} pcap file"
        rm -rf ${output}split*
        tcpdump -Z root -r ${output} -w ${output}split -C ${SPLITSIZE} # && rm -rf ${output}
        split_files="${split_files} ${output}"
        # 切分后：
        # 需要将前一个pcap文件结尾的一段响应包合并到下一个pcap文件中
        # 需要将后一个pcap文件开始的一段响应包合并到上一个pcap文件中
        # 但这样会使得有响应的请求统计数据重复计算，如同一个验证码请求分别在两个pcap文件中
        # 通过后期合并处理能消除错误的统计
        splitcount=`ls ${output}* -l | grep "${output}split" | wc -l`
        let splitcount--
        index=${splitcount}
        mv ${output}split ${output}split0
        while : ; do
            splitinfile=${output}split${index}
            let splitout=index-1
            mergeinfile=${output}split${splitout}
            mergeoutfile=${output}_${splitout}
            tcpdump -Z root -r ${splitinfile} "${RES_FILTER}" -w tmp.pcap -c ${SPLITOVERLAP}
            mergecap -F pcap -w ${mergeoutfile} ${mergeinfile} tmp.pcap && rm -rf tmp.pcap ${mergeinfile}
            let index--
            [ $index -eq 0 ] && break
        done
        mv ${output}split${splitcount} ${output}_${splitcount}

        for file in `ls ${output}_*`; do
            echo "[INFO] python $0 ${file} --dump"
            python ${0%.*}.py ${file} --dump &
        done
    else
        echo "[INFO] python $0 ${output}"
        python ${0%.*}.py ${output} &
    fi
done
wait

for file in ${split_files}; do
    echo "[info] python ${0%.*}_merge.py ${file} &"
    python ${0%.*}_merge.py ${file} &
done
wait

finishtime=$(date +%s)
echo "[INFO] \"${filelist}\" costs $(( $finishtime - $begintime )) seconds in total"

exit ${SUCCESS_OK}