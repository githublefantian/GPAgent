#!/usr/bin/env bash

## 验证码过滤表达式(GET 示例: GET /bidimg/get.ashx?i=ffd5377fe6a050b...)
# tcp[24:4]==0x2f626964 匹配 /bid; tcp[28:4]==696d67ef 匹配 img/ 字段; tcp[24:4]==0x2f2f6269 匹配//bi
GET_FILTER="(tcp[24:4]==0x2f626964 or tcp[24:4]==0x2f2f6269) and dst port 80"
FRAGMENT_FILTER="(ip[6:2] & 0x3fff != 0)" # 没有分包（不是分包）
FILTER="((${GET_FILTER}) and (${FRAGMENT_FILTER}))  " 


#mkdir /home/fragment/ &> /dev/null
cd /backup/

filelist=`ls *20170415*`
#filelist=`ls *20170417*p2p1*`
for input in ${filelist}; do
    input_basename=`basename ${input}`
    # 过滤HTTP IMG && FRAGMENT数据包
    echo "[$0]tcpdump fragment filter ......"
    output="/home/fragment/"${input_basename%.*}"_fragment.pcap"
    tcpdump -Z root -r ${input} ${FILTER} -w ${output} &
done
wait

exit 0
