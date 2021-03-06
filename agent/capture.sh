#!/usr/bin/env bash
source /root/agent/agent.env

# 1:HUP 2:INT 3:QUIT 15:TERM
trap '' HUP
trap 'myexit' INT QUIT TERM


# 日志输出重定向
if [ ! $DEBUG == "yes" ]; then
exec >> ${DEFAULTLOG}${DEFAULTLOGNAME} 2>> ${DEFAULTLOG}${DEFAULTLOGNAME}
fi

currenttime=`date`
timestamp=`date +%s`
echo -e "[$0]====[script start time]:${currenttime} (${timestamp})===="


usage="
Usage:\n
  -d: duration_time(seconds)\n
  -s: start_time(timestamp or 12:00:30 format)\n
  -e: end_time(timestamp)\n
  -n: nic devices\n
  -o: output directory\n
  -h: show help information\n
Example:\n
  ./capture.sh 60*10 \n
  ./capture.sh  \n
  ./capture.sh -d 600 -n p2p1,p2p2 -o /home/test   \n
  ./capture.sh -s 12:00:00 -d 600 -o /home/test \n
"

# 读取参数
while getopts "d:s:e:d:o:n:h" OPT
do
  case ${OPT} in
    d)
      let dt=${OPTARG}
      #echo "duration_time's arg: $dt"
      ;;
    s)
      #echo "start_time's arg: $OPTARG"
      st=${OPTARG}
      ;;
    e)
      #echo "end_time's arg: $OPTARG"
      et=${OPTARG}
      ;;
    n)
      #echo "nic devices' arg: $OPTARG"
      ni=${OPTARG//,/ } # 将字符串中的,替换成空格
      ;;
    o)
      #echo "output dir's arg: $OPTARG"
      od=${OPTARG}
      [ ! -d ${od} ] && echo "cannot access \"${od}\": no such dircetory" && exit
      [ ! ${od:0-1:1} == "/" ] && od=${od}/
      ;;
    h)
      echo -e ${usage}
      exit
      ;;
    ?)
      echo "Please input: \"$0 -h\""
      exit
      ;;
  esac
done


# 参数处理
if [ $# -eq 1 ];then 
  period=$1;
else
  period=${dt:-"${DEFAULTPCAPTIME}"}
fi

if [ ${#st} -eq 8 ]; then
  currentdate=`date +%F`
  currenttime="${currentdate} ${st}"
  starttime=`date -d "${currenttime}" +%s`
  #echo $currenttime $starttime
else
  starttime=${st:-`date +%s`}
fi

nics=${ni:-"${DEFAULTNICS}"} #ni未定义或值为空时，使用默认网卡信息
endtime=${et:-$(( ${starttime} + ${period} ))}
#echo $endtime
out_dir=${od:-"${DEFAULTDIR}"}
if [ "x${starttime}" == "x" ] || [ "x${endtime}" == "x" ] || \
   [ "x${nics}" == "x" ] || [ ${starttime} -ge ${endtime} ]; then
  echo "parameters error!"
  echo "nics:${nics}, starttime:${starttime}, endtime:${endtime}, periodtime:${period,} output_dir:${out_dir}"
  exit
fi


echo "nics:${nics}, starttime:${starttime}, endtime:${endtime}, periodtime:${period,} output_dir:${out_dir}"

# 脚本启动处理
PIDDir=${DEFAULTPIDDIR}$$/
rm -rf ${PIDDir} && mkdir -p ${PIDDir} # 创建进程目录
echo "PID: $$"
echo "COMMAND: $0 $*"
echo "nics:${nics}, starttime:${starttime}, endtime:${endtime}, periodtime:${period,} output_dir:${out_dir}"


:<<COMMENT
out_dir="/home/"
period=$1
starttime=`date +%s`
endtime=$(( $starttime + $period))
echo "starttime: $starttime, endtime: $endtime, period: $period(s)"
COMMENT


function myexit(){
    echo "record ifconfig info"
    echo "[`date +%Y%m%d_%H:%M`]===stop========" >> ${IFCONFIG_FILE}
    for i in ${nics};do
      ifconfig $i | grep -E "([RT]X)|(flags)" >> ${IFCONFIG_FILE}
<<<<<<< HEAD
      #startprocess $i
=======
      # startprocess $i
>>>>>>> 2f0143ac0068beb28f7109d3d25f8e8276c36a0f
    done

    echo "stop all netsniff-ng"
    #killall -s SIGINT netsniff-ng
    pgrep netsniff-ng | xargs kill -s INT 2> /dev/null
    currenttime=`date`
    timestamp=`date +%s`
    echo "PID: $$, Exit normal!"
    echo -e "[$0]====[script stop time]:${currenttime} (${timestamp})===="
    exit
}


function startprocess(){
  fn_time=`date +%Y%m%d_%H%M%S`
  filename=${DEFAULTPREFIX}${fn_time}_$1
  echo "startprocess: ${filename}.pcap"
  netsniff-ng --in $1 --out ${out_dir}${filename}.pcap --prio-high --verbose --silent --ring-size 500MiB > ${PIDDir}${filename} &
  # && md5sum ${out_dir}${filename}.pcap > ${out_dir}${filename}.md5 &
}


function checkall(){
  for i in ${nics};do
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
  if [ ${starttime} -gt ${currenttime} ];then
    sleep 1 
  else
    break
  fi
done


#1. 启动抓包(所有网卡), 并记录抓包网卡信息
date
date +%s

echo -e "\n" >> ${IFCONFIG_FILE}
echo "[`date +%Y%m%d_%H:%M`]===start========" >> ${IFCONFIG_FILE}
for i in ${nics};do
  ifconfig $i | grep -E "([RT]X)|(flags)" >> ${IFCONFIG_FILE}
  startprocess $i
done


#2. 实时监控
while :
do
  sleep 1
  currenttime=`date +%s`
  #echo "endtime:$endtime; currenttime:$currenttime"
  if [ ${endtime} -le ${currenttime} ];then
    myexit
  #else
  #  checkall
  fi
done


currenttime=`date`
timestamp=`date +%s`
echo "PID: $$, Exit normal!"
echo -e "[$0]====[script stop time]:${currenttime} (${timestamp})===="
