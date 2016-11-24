#!/usr/bin/bash

start=$(date +%s)

echo $IF_DEL_PCAPNG

for input in $(ls *.pcapng)
do
    output=${input%.*}.pcap
    # 0x696d6773为`imgs`,0x4854为`HTTP`前两个字母`HT` 
    tcpdump -r $input tcp[25:4]=0x696d6773 or tcp[20:2]=0x4854 -w $output
    if [ $? -ne 0 ];then
        echo "-------------tcpdump $input error!!--------------------------------"
        rm -rf $output 
        continue
    elif [ $IF_DEL_PCAPNG -eq 1 ];then
        echo "--------------------del $input !!--------------------------------"
        rm -rf $input
        continue
    fi
done
end=$(date +%s)
echo "-------------tdpdump total time: $(( $end - $start ))--------------------"
