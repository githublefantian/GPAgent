#!/bin/bash
trap 'pgrep netsniff-ng | xargs kill -s INT; exit' INT 

#nics="p2p1 p2p2 p2p3"
nics="em4 em2 em3"
out_dir="/home/"
period=$1

starttime=`date +%s`
endtime=$(( $starttime + $period))
echo "====starttime: $starttime, endtime: $endtime, period: $period(s)"

function stopall(){
  echo "====stopall"
  pgrep netsniff-ng | xargs kill -s INT 
}

function startprocess(){
  fn_time=`date +%Y%m%d_%H%M%S`
  filename=${fn_time}_$1
  echo "====startprocess $filename"
  netsniff-ng --in $1 --out ${out_dir}${filename}.pcap --prio-high --verbose --silent --ring-size 500MiB > ${out_dir}${filename}.log &
}

function checkall(){
  for i in $nics;do
    #echo $i
    pgrep netsniff-ng -a | grep $i > /dev/null
    if [ $? -ne 0 ];then
      startprocess $i
    fi
  done
}


#1. start
for i in $nics;do
  startprocess $i
done


#2. monitor
while :
do
  sleep 1
  currenttime=`date +%s`
  #echo "====endtime:$endtime; currenttime:$currenttime"
  if [ $endtime -le $currenttime ];then
    stopall
    exit
  else
    checkall
  fi
done
