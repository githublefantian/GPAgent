#!/usr/bin/env bash
source ./agent.env

trap '' HUP

SUCCESS_OK=0
ERROR_PARA=1

SUFFIX="_img.pcap"
SPLITSIZE=5000  # unit: million byte
SPLITOVERLAP=1000 # packet count

# GET URL EXAMPLE: `GET /bidimg/get.ashx?i=ffd5377fe6a050b...`
# `tcp[24:4]==0x2f626964` can match `/bid`; `tcp[28:4]==696d67ef` can match `img/`
GET_FILTER="tcp[24:4]==0x2f626964 and dst port 80"
# `tcp[20:2]==0x4854` can match `HT` (the first two letters of HTTP)
RES_FILTER="tcp[20:2]==0x4854 and src port 80"
FILTER="(${GET_FILTER}) or (${RES_FILTER})"

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
begintime=$(date +%s)
for input in ${filelist}; do
    output=${input%.*}${SUFFIX}
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
        tcpdump -Z root -r ${output} -w ${output}split -C ${SPLITSIZE} && rm -rf ${output}
        # 切分后：
        # 需要将前一个pcap文件结尾的一段响应包合并到下一个pcap文件中
        # 需要将后一个pcap文件开始的一段响应包合并到上一个pcap文件中
        # 但这样会使得有响应的请求统计数据重复计算，如同一个验证码请求分别在两个pcap文件中
        # 通过后期合并处理能消除响应错误的统计，但是响应成功的统计信息较难消除
        splitcount=`ls -l | grep "${output}split" | wc -l`
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
            echo "[INFO] python $0 ${file}"
            python ${0%.*}.py ${file} &
        done
    else
        echo "[INFO] python $0 ${output}"
        python ${0%.*}.py ${output} &
    fi
done

wait

finishtime=$(date +%s)
echo "[INFO] deal with \"${filelist}\" success and costs $(( $finishtime - $begintime )) seconds in total"

# merge result.csv files


exit ${SUCCESS_OK}
