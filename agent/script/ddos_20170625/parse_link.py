# -*- coding:utf-8 -*-
import sys
reload(sys).setdefaultencoding('UTF-8')

import time
import os

try:
    import scapy.all as scapy
except ImportError:
    import scapy

try:
    import scapy_http.http
except ImportError:
    from scapy.layers import http


def link_statisc(pcapfile):

    ip_port_dict = {}
    ip_port_count = []
    
    pkt = scapy.PcapReader(pcapfile)
    p = pkt.read_packet()
    # p.show()
    begin_time = 1497668580 # 11:03:00
    while True:
        p = pkt.read_packet()
        if p is None:
            ip_port_count.append(len(ip_port_dict))
            break
        
        if float(p.time) >= begin_time + 10:
            ip_port_count.append(len(ip_port_dict))
            ip_port_dict.clear()
            begin_time += 10
            
        if 'TCP' in p:
            src_ip = str(p['IP'].src)
            dst_ip = str(p['IP'].dst)
            src_port = str(p['TCP'].sport)
            dst_port = str(p['TCP'].dport)
            if dst_port != "8300":
                continue
            link_key = src_ip + ':' + src_ip
            if link_key in ip_port_dict:
                continue
            else:
                ip_port_dict[link_key] = 1
    
    pkt.close()

    return ip_port_count


def p_link_statisc_info(fw, count_list=[]):
    if len(count_list) == 0:
        return 0
        
    fw.write('STATISTICAL RESULT\n')
    fw.write(',START_TIME,END_TIMEREQUEST,COUNT\n')
    tm = 1497668580
    index = 0
    for number in count_list:
        start_time = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(tm + index * 10))
        end_time = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(tm + (index + 1) * 10))
        line = ',%s,%s,%s\n' % (start_time, end_time, number)
        fw.write(line)
        index += 1


if __name__ == '__main__':
    result_file = '/home/1105/link_info.csv'
    argc = len(sys.argv)    
    with open(result_file, 'w') as fw:
        while argc > 1:
            arg = sys.argv[argc-1]
            pcap_file = arg.strip()
            print("link statisc %s\n" % pcap_file)
            result = link_statisc(pcap_file)
            fw.write('%s\n' % os.path.basename(pcap_file))
            p_link_statisc_info(fw, result)
            fw.write('\n\n')
            argc -= 1
        
        
