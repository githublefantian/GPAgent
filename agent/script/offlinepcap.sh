#!/usr/bin/env bash

# zip_all_pcap <output DIR>
function zip_all_pcap() {
    oldpwd=`pwd`
    cd $1
    for file in `ls`; do
        [ ! -d ${file} ] && continue
        [ ${file##*.} == "zip" ] && continue
        zip -rq ${file}.zip ${file}
    done
    cd $oldpwd
}


# filter_offline_pcap <pcap file> <CSV file absolute path(name)> <output pcap DIR(include /)>
function filter_offline_pcap() {
    lineno=0
    pcapfile=$1
    csvfile=$2
    outputdir=$3
    [ ! -f $csvfile ] && echo "$csvfile not exist!" && return 1

   # end with \n
    while read line; do
        #echo $line
        currentip=`echo $line | cut -d ':' -f 1`
        [ "$currentip" == "" ] && continue
        currentport=`echo $line | cut -d ':' -f 2`
        [ "$currentport" == "" ] && continue
        currentpcap="${currentip}_${currentport}.pcap"
        resultpcap=$outputdir$currentpcap
        [ -f $resultpcap ] && continue
        echo "[$0]tcpdump $currentip $currentport"
        tcpdump -Z root -r $pcapfile  "(src host $currentip and src port $currentport) or (dst host $currentip and dst port $currentport)" -w ${resultpcap} &> /dev/null
    done < $csvfile
    #echo "[$0] cp $csvfile $outputdir"
    cp $csvfile $outputdir
}

################### main ###########################

OFFLINEDIR="/home/offline/"
SORUCEPCAP=$1

## 1. 8300 filter
echo "[$0]8300 filter ......"
srcpcap=${SORUCEPCAP}
dstpcap=${OFFLINEDIR}8300_`basename $1`
if [ ! -f $dstpcap ]; then
    tcpdump -Z root -r $srcpcap  "port 8300" -w $dstpcap &
fi
wait


## 2. get csv files
echo "[$0]get csv files ......"
filelist=`ls ${OFFLINEDIR}*session_list.csv`
[ "${filelist}x" == "x" ] && echo "csv file is empty!" && exit 1


## 3. filtering......
echo "[$0]filtering ......"
begintime=$(date +%s)
for input in ${filelist}; do
    # mkdir
    input_basename=`basename ${input}`
    resultdir="${OFFLINEDIR}${input_basename%.*}/"
    [ ! -d $resultdir ] && mkdir $resultdir

    echo "[$0]filter_offline_pcap ${dstpcap} ${input}"
    # filter_offline_pcap <pcap file> <CSV file absolute path(name)> <output pcap DIR(include /)>
    filter_offline_pcap ${dstpcap} ${input} ${resultdir} &
done
wait

# zip_all_pcap <output DIR>
zip_all_pcap ${OFFLINEDIR}


exit 0
