#!/bin/bash

# 1:HUP 2:INT 3:QUIT 15:TERM
trap '' HUP
trap 'myexit' INT QUIT TERM

defaultnics="em1 em2"                          # 默认抓包网卡
defaultdir="/backup/"                          # 默认抓包文件存放目录
defaultlog="/backup/log/capture.log"           # 默认日志文件
defaulttmp="/backup/tmp/"                   # 默认临时目录
defaultpcaptime=86400                          # 默认抓包24*60*60 秒


usage="
Usage:\n
  -d: duration_time(seconds)\n
  -s: start_time(timestamp)\n
  -e: end_time(timestamp)\n
  -n: nic devices\n
  -o: output directory
Example:\n
  ./capture.sh -d 600 -n p2p1,p2p2\n
  ./capture.sh 60*10 # 默认网卡抓包600秒
  ./capture.sh # 手动关闭
"

# 读取参数
while getopts "d:s:e:d:o:n:" OPT
do
  case $OPT in
    d)
      #echo "duration_time's arg: $OPTARG"
      let dt=$OPTARG
      #echo "duration_time's arg: $dt"
      ;;
    s)
      #echo "start_time's arg: $OPTARG"
      st=$OPTARG
      ;;
    e)
      #echo "end_time's arg: $OPTARG"
      et=$OPTARG
      ;;
    n)
      #echo "nic devices' arg: $OPTARG"
      ni=${OPTARG//,/ } # 将字符串中的,替换成空格
      ;;
    o)
      #echo "output dir's arg: $OPTARG"
      od=$OPTARG
      ;;
    ?)
      echo $usage
      ;;
  esac
done

# 日志输出重定向
exec >> ${defaultlog} 2>> ${defaultlog}

# 脚本启动处理
PIDDir=$defaulttmp$$/
rm -rf $PIDDir && mkdir -p $PIDDir # 创建进程目录
currenttime=`date`
timestamp=`date +%s`
echo -e "\n====[script start time]:$currenttime ($timestamp)===="
echo "PID: $$"
echo

# 参数处理
if [ $# -eq 0 ];then dt=$defaultpcaptime; fi
nics=${ni:-"$defaultnics"} #ni未定义或值为空时，使用默认网卡信息
period=${dt:-"$1"}
starttime=${st:-`date +%s`}
endtime=${et:-$(( $starttime + $period))}
out_dir=${od:-"$defaultdir"}

if [ "x$starttime" == "x" ] || [ "x$endtime" == "x" ] || \
   [ "x$nics" == "x" ] || [ $starttime -ge $endtime ]; then
  echo "nics:$nics, starttime:$starttime, endtime:$endtime, output_dir:$out_dir"
  echo "parameters error!"
else
  echo "nics:$nics, starttime:$starttime, endtime:$endtime, output_dir:$out_dir"
fi


:<<COMMENT
out_dir="/home/"
period=$1
starttime=`date +%s`
endtime=$(( $starttime + $period))
echo "starttime: $starttime, endtime: $endtime, period: $period(s)"
COMMENT


function myexit(){
  echo "stop all netsniff-ng"
  #killall -s SIGINT netsniff-ng
  pgrep netsniff-ng | xargs kill -s INT 2> /dev/null
  currenttime=`date`
  timestamp=`date +%s`
  echo "Exit normal!"
  echo -e "====[script stop time]:$currenttime ($timestamp)===="
  exit
}


function startprocess(){
  fn_time=`date +%Y%m%d_%H%M%S`
  filename=${fn_time}_$1
  echo "startprocess: $filename.pcap"
  netsniff-ng --in $1 --out ${out_dir}${filename}.pcap --prio-high --verbose --silent --ring-size 500MiB > ${PIDDir}${filename} &
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


#0. 定时启动
while :
do
  currenttime=`date +%s`
  if [ $starttime -gt $currenttime ];then
    sleep 1 
  else
    break
  fi
done


#1. 启动抓包(所有网卡)
for i in $nics;do
  startprocess $i
done


#2. 实时监控
while :
do
  sleep 1
  currenttime=`date +%s`
  #echo "endtime:$endtime; currenttime:$currenttime"
  if [ $endtime -le $currenttime ];then
    myexit
  else
    checkall
  fi
done
