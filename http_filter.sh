#!/usr/bin/bash

SUCCESS_OK=0
ERROR_PARA=1
ERROR_TCPDUMP=2

SUFFIX="_http.pcap"

# GET URL EXAMPLE: `GET /bidimg/get.ashx?i=ffd5377fe6a050b...`
# `tcp[24:4]==0x2f626964` can match `/bid`; `tcp[28:4]==696d67ef` can match `img/`
GET_FILTER="tcp[24:4]==0x2f626964"
# `tcp[20:2]==0x4854` can match `HT` (the first two letters of HTTP)
RES_FILTER="tcp[20:2]==0x4854"
FILTER="(${GET_FILTER}) or (${RES_FILTER})"

function print_usage() {
    usage="\n
    Usage:\n
        $0 -f <pcap/pcapng filename>\n
    "
    echo -e $usage
}

# parse parameters
while [ $# -gt 0 ]; do
    case "$1" in
        -h | --help)
            print_usage
            exit ${SUCCESS_OK}
            ;;
        -f | --file)
            shift
            [ "x$1" == "x" ] && echo "Please input the filename!" && exit ${ERROR_PARA}
            [ ! -f $1 ] && echo " $1 is not a file or not exist!" && exit ${ERROR_PARA}
            filename=$1
            shift
            ;;
        *)
            echo "Unknow argument: $1"
            print_usage
            exit ${ERROR_PARA}
            ;;
    esac
done

input=${filename}
output=${filename%.*}${SUFFIX}

## filt the data packets
starttime=$(date +%s)

tcpdump -r ${input} ${FILTER} -w ${output}
if [ $? -ne 0 ];then
    echo "[ERROR] tcpdump ${input} error!!"
    rm -rf ${output}
    exit ${ERROR_TCPDUMP}
else
    echo "[INFO] tcpdump ${input} success"
fi

endtime=$(date +%s)

echo "[INFO] tdpdump total time: $(( $endtime - $starttime )) seconds"

exit ${SUCCESS_OK}
