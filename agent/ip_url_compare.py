# -*- coding:utf-8 -*-
import sys
reload(sys).setdefaultencoding('UTF-8')

import os

try:
    import scapy.all as scapy
except ImportError:
    import scapy

try:
    import scapy_http.http
except ImportError:
    from scapy.layers import http

g_separator = '#'
g_result_dir = '/home/'
g_img_request_dict = {}

# return img_request_dict
# ip + url dict
def pcapfile_parse(pcapfile):
    img_request_dict = {}

    pkt = scapy.PcapReader(pcapfile)
    while True:
        p = pkt.read_packet()
        if p is None:
            break
        #p.show()
        if p.getlayer('HTTP Request'):
            reqdata = p['HTTP Request']
            try:
                src_ip = str(p['IP'].src)
                # dst_ip = str(p['IP'].dst)
                # src_port = str(p['TCP'].sport)
                # dst_port = str(p['TCP'].dport)
                method = reqdata.getfieldval('Method')
                # version = reqdata.getfieldval('Http-Version')
                path = reqdata.getfieldval('Path')
                # seq_str = str(p['TCP'].seq + p['IP'].len - 40) # compute the ack sequence
                if method != 'GET':
                    continue
                if -1 == path.find('/bidimg/get.ashx'):
                    continue
                request_key = src_ip + g_separator + path
                if request_key in img_request_dict:
                    img_request_dict[request_key] += 1
                    continue
                img_request_dict[request_key] = 1
                g_img_request_dict[request_key] = 1
            except Exception as e:
                print(e)
                continue

    pkt.close()

    return img_request_dict


# python ip_url_compare.py intranet_file extranet_file
if __name__ == '__main__':
    # Read parameters from agent.env
    print('start %s process!' % sys.argv[0])
    argc = len(sys.argv)
    if argc == 3:
        # get pcap file
        filein = sys.argv[1]
        fileout = sys.argv[2]
        print('parsing %s %s begin' % (filein, fileout))
        img_dict_in = pcapfile_parse(filein)
        img_dict_out = pcapfile_parse(fileout)
        print('parsing %s %s end' % (filein, fileout))
    else:
        sys.exit(1)

    # 对比输出结果
    only_in_have = {}
    only_out_have = {}

    for data in g_img_request_dict:
        if data not in img_dict_in:
            only_out_have[data] = 1
            continue
        if data not in img_dict_out:
            only_in_have[data] = 1
            continue
        g_img_request_dict[data] = only_in_have[data] - only_out_have[data]


    # 打印输出结果
    result_file = g_result_dir + os.path.basename(sys.argv[1]).replace('.pcap', '_ipurl.csv')
    print('writing to %s start' % result_file)
    with open(result_file, 'w') as fw:
        fw.write('Requests in intranet, %d\n' % len(img_dict_in))
        fw.write('Requests only in intranet, %d\n' % len(only_in_have))
        for data in only_in_have:
            info = data.split(g_separator)
            fw.write(',,%s, %s\n' % (info[0], info[1]))

        fw.write('Requests in extranet, %d\n' % len(img_dict_out))
        fw.write('Requests only in extranet: %d\n' % len(only_out_have))
        for data in only_out_have:
            info = data.split(g_separator)
            fw.write(',,%s, %s\n' % (info[0], info[1]))

        count = 0
        fw.write('Requests Diff (intranet - extranet)\n')
        for data in g_img_request_dict:
            if g_img_request_dict[data] != 0:
                count += 1
                info = data.split(g_separator)
                fw.write(',%s, %s, %d\n' % (info[0], info[1], g_img_request_dict[data]))
        fw.write('\n, %d' % count)
    print('writing to %s end' % result_file)
