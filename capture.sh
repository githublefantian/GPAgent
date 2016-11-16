#!/bin/bash
trap 'pgrep netsniff-ng | xargs kill -s INT; exit' INT 

defaultnics="p2p1 p2p2" # 默认抓包网卡
defaultdir="/backup/" # 默认转包文件存放目录

usage="
Usage:\n
  -d: duration_time(seconds)\n
  -s: start_time(timestamp)\n
  -e: end_time(timestamp)\n
  -n: nic devices\n
  -o: output directory
Example:\n
  ./capture.sh -d 600 -n p2p1,p2p2\n
  ./capture.sh 600 # 默认网卡抓包600秒
"

# 读取参数
while getopts "d:s:e:d:o:n:" OPT
do
  case $OPT in
    d)
      echo "====duration_time's arg: $OPTARG"
      dt=$OPTARG
      ;;
    s)
      echo "====start_time's arg: $OPTARG"
      st=$OPTARG
      ;;
    e)
      echo "====end_time's arg: $OPTARG"
      et=$OPTARG
      ;;
    n)
      echo "====nic devices' arg: $OPTARG"
      ni=${OPTARG//,/ } # 将字符串中的,替换成空格
      ;;
    o)
      echo "====output dir's arg: $OPTARG"
      od=$OPTARG
      ;;
    ?)
      echo $usage
  esac
done

# 参数处理
nics=${ni:-"$defaultnics"} #ni未定义或值为空时，使用默认网卡信息
period=${dt:-"$1"}
starttime=${st:-`date +%s`}
endtime=${et:-$(( $starttime + $period))}
out_dir=${od:-"$defaultdir"}

if [ "x$starttime" == "x" ] || [ "x$endtime" == "x" ] || \
   [ "x$nics" == "x" ] || [ $starttime -ge $endtime ]; then
  echo "====nics:$nics, starttime:$starttime, endtime:$endtime, output_dir:$out_dir"
  echo "====parameters error!"
else
  echo "====nics:$nics, starttime:$starttime, endtime:$endtime, output_dir:$out_dir"
fi

#exit

:<<COMMENT
out_dir="/home/"
period=$1
starttime=`date +%s`
endtime=$(( $starttime + $period))
echo "====starttime: $starttime, endtime: $endtime, period: $period(s)"
COMMENT

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


#1. 启动抓包
currenttime=`date +%s`
if [ $starttime -gt $currenttime ];then
  diff=$(( $starttime - $currenttime))
  echo "====start sleep $diff"
  sleep $diff
fi

for i in $nics;do
  startprocess $i
done


#2. 实时监控
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
