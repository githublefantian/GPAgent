C:\"Program Files (x86)"\Wireshark\tshark.exe -r 1120end.pcapng 'tcp[25:4]==0x696d6773 or tcp[20:2]==0x4854' -w test.pcap


C:\Program Files (x86)\Wireshark\editcap.exe -F libpcap -T ether file.pcapng file.pcap 


C:\"Program Files (x86)"\Wireshark\tshark.exe -r 1120end.pcapng  "tcp[25:4]=0x696d6773 or tcp[20:2]=0x4854" -w test.pcap


C:\"Program Files (x86)"\Wireshark\tshark.exe -r 1120end.pcapng  "tcp[((tcp[12:1] & 0xf0) >> 2):4] = 0x47455420" -w test.pcap

C:\"Program Files (x86)"\Wireshark\tshark.exe -r 1120end.pcapng 'http.request.method == "GET"' "port 80" -w test.pcap


C:\"Program Files (x86)"\Wireshark\tshark.exe 'tcp port 80 and (((ip[2:2] - ((ip[0]&0xf)<<2)) - ((tcp[12]&0xf0)>>2)) != 0)' -R 'http.request.method == "GET" || http.request.method == "HEAD"'

tshark -F pcapng -r 1120end.pcapng (http.request.method == "GET" or http.request.method == "HEAD") -w test.pcap

tshark -r 1120end.pcapng  -2 -R "tcp[25:4]=0x696d6773 or tcp[20:2]=0x4854" -w test.pcap

tshark -n -r 1120end.pcapng  -Y  'http contains "/imgs/"' -w test.pcap

tshark -n -2 -r 1120end.pcapng -R "http.response or http.request" -w test.pcap


 


tshark -n -2 -r 1120end.pcapng -R "http.request.method=="GET" or http.response " -T fields -e http.request.uri

tshark -n -2 -r 1120end.pcapng -R "http.response " -T fields -e http.response.line | find /C "image"

and (http.response.line contains "imgs")

tshark -n -2 -r 1120end.pcapng -R "(http.request.method=="GET" and (http.request.uri contains "imgs")) or http.response " -T fields -e http.request.uri

tshark -n -2 -r 1120end.pcapng -R "(http.request.method=="GET" and (http.request.uri contains "imgs")) or http.response" -w test.pcap


tshark -n -2 -r 1120end.pcapng -R  "tcp[((tcp[12:1] & 0xf0) >> 2):4] == 0x47455420" -T fields -e http.request.uri

tshark -n -2 -r 1120end.pcapng -R  "(http.request.method=="GET" and (http.request.uri contains "imgs"))" -T fields -e http.request.uri

-T fields -E separator="," -e frame.time_epoch -e ip.src -e tcp.srcport -e ip.dst -e tcp.dstport -e http.request.uri

tshark -n -2 -F pcap -r 20.pcapng -R "http.response or (http.request.method=="GET" and (http.request.uri contains "imgs"))" -w 20_filter_total.pcap

tshark -n -2 -F pcap -r 1120end.pcapng -R "http.response or (http.request.method == 47.45.54 and (http.request.uri contains "imgs"))" -w 1120end_filter_total.pcap
http.request.uri[0:5] == "/imgs"

https://ask.wireshark.org/questions/16964/analyzing-http-protocol-using-tshark 例子
tshark -n -2 -r test.pcap -R "(http.request.method=="GET" and (http.request.uri contains "imgs")) and not http.response_in" -T fields -E separator="," -e frame.time_epoch -e ip.src -e tcp.srcport
tshark -n -2 -R "(http.request.method=="GET" and (http.request.uri contains "imgs")) and not http.response_in" -T fields -E separator="," -e frame.time_epoch -e ip.src -e tcp.srcport -r test.pcap > result74.csv

tshark -n -2 -R "(http.request.method=="GET" and (http.request.uri contains "imgs")) and not http.response_in" -T fields -E separator="," -e frame.time_epoch -e ip.src -e tcp.srcport -r 20.pcap > result74.csv

tshark: Not all the packets could be printed because there is no space left on the file system


mergecap -T ether -w 20.pcapng 10_1.pcapng 10_2.pcapng
editcap -F libpcap -T ether 20.pcapng 120.pcap

https://blog.packet-foo.com/2015/03/advanced-display-filtering/

https://www.wireshark.org/docs/man-pages/wireshark-filter.html

很有用
https://www.wireshark.org/docs/dfref/h/http.html