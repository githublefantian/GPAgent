# -*- coding:utf-8 -*-
import sys
# reload(sys).setdefaultencoding('UTF-8')

import time
import os
import logging
import logging.handlers

try:
    import scapy.all as scapy
except ImportError:
    import scapy

try:
    # This import works from the project directory
    import scapy_http.http
except ImportError:
    # If you installed this package via pip, you just need to execute this
    from scapy.layers import http

filever = 'http-filter-v2.3.1'
# global var
PADDING = 80
g_dict_request = {}
g_dict_response = {}
g_packet_total = 0
g_time_diff = 0

class Cmy_logger(object):

    def __init__(self, logname, logger):
        # create logger
        self.logger = logging.getLogger(logger)
        self.logger.setLevel(logging.DEBUG)

        # for log file
        fh = logging.handlers.RotatingFileHandler(logname, maxBytes=30 * 1024 * 1024, backupCount=5)
        fh.setLevel(logging.DEBUG)

        # for teminal output
        ch = logging.StreamHandler()
        ch.setLevel(logging.DEBUG)

        formatter = logging.Formatter(
            '%(asctime)s - (%(processName)s|%(process)d,%(threadName)s|%(thread)d) - [%(filename)s:%(funcName)s():%(lineno)s] - [%('
            'name)s:%(lineno)s]\n  %(levelname)s: %(message)s')
        fh.setFormatter(formatter)
        ch.setFormatter(formatter)

        # add handler
        self.logger.addHandler(fh)
        self.logger.addHandler(ch)

    def getlog(self):
        return self.logger

def timefn(fn):
    def wrapped(a):
        start = time.time()
        b = fn(a)
        end = time.time()
        print("used:%d".center(PADDING, '=') %(end - start))
        return b

    return wrapped

@timefn
def http_filter(pcapfile):
    global g_dict_request, g_dict_response, g_packet_total
    max_time = 0
    request_key = ''
    #packets = scapy.rdpcap(pcapfile)
    pkt = scapy.PcapReader(pcapfile)
    while True:
        p = pkt.read_packet()
        if p is None:
            break
        epoch_time = p['Ethernet'].time
        if max_time < epoch_time:
            max_time = epoch_time

        if not p.haslayer('HTTP'):
            continue    
        g_packet_total += 1
        #p.show()
        if p.haslayer('HTTPRequest'):
            try:
                src_ip = p['IP'].src
                src_port = p['TCP'].sport
                method = p['HTTP Request'].Method
                # compute the ack sequence
                seq_str = str(p['TCP'].seq + p['IP'].len - 40)

                if method != b'GET':
                    continue
                path = p['HTTP Request'].Path
                if b'/imgs/' not in path:
                    if b'/bidimg/get.ashx' not in path:
                        continue

                request_key = src_ip.replace('.', '') + str(src_port) + seq_str
                g_dict_request[request_key] = [src_ip, src_port, epoch_time]

            except Exception as e:
                print(e)
                continue 
     
        if p.haslayer('HTTPResponse'):
            try:
                dst_ip = p['IP'].dst
                dst_port = p['TCP'].dport
                ack_no = p['TCP'].ack

                response_key = dst_ip.replace('.', '') + str(dst_port) + str(ack_no)
                g_dict_response[response_key] = ''

            except Exception as e:
                print(e)
                continue
    pkt.close()
    return max_time


if __name__ == '__main__':
    log = Cmy_logger(logname='http-filter.log', logger="main").getlog()
    log.info('start'.center(PADDING, '='))

    pcap_file = ''
    mtime = 0
    del_request = 0
    count = 0
    argc = len(sys.argv)
    if argc == 2:
        # pass a pcap file argument
        pcap_file = sys.argv[1].strip()
        log.debug('http pcap file: %s'.center(PADDING, '=') % pcap_file)
        mtime = http_filter(pcap_file)
    else:
        # auto find a pacp file in current directory
        tmp_list = os.listdir('.')
        print(tmp_list)
        for filename in tmp_list:
            if filename.endswith('.pcap')  and os.path.isfile(filename):
                pcap_file = filename
                log.debug('http pacp file: %s'.center(PADDING, '=') % pcap_file)
                tmp = http_filter(pcap_file)
                if mtime < tmp:
                    mtime = tmp

    if pcap_file == '' or not os.path.isfile(pcap_file):
        log.error('http pacp file: %s noooon exist, exit...'.center(PADDING, '=') % pcap_file)
        sys.exit(1)

     
    str_mtime = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(mtime))
    log.info('start write to result.csv'.center(PADDING, '='))

    with open('result.csv', 'w') as fw:
        fw.write('HTTP PACKET TOTALS,%d\nREQUEST TOTALS,%d\nALL RESPONSE TOTALS,%d\n' % (g_packet_total, len(g_dict_request), len(g_dict_response)))
        fw.write('\nSOURCE_IP,SOURCE_PORT,TIME,EPOCH_TIME\n')
        for key in g_dict_request.keys():
            if key not in g_dict_response:
                [src_ip, src_port, epoch_time] = g_dict_request[key]
                if mtime > 0 and epoch_time > (mtime - g_time_diff):
                    del_request += 1
                    continue
                str_time = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(epoch_time))
                line = '%s,%s,%s,%s' % (str(src_ip), str(src_port), str_time, epoch_time)
                fw.write(line + '\n')
                count += 1
         
        deadline = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(mtime - g_time_diff))
        fw.write('\nNO RESPONSE TOTALS,%d\nDEL REQUEST TOTALS,%d\nDEADLINE,%s\nMAX_TIME,%s\nDIFF_TIME,%d\n' % (count, del_request, deadline, str_mtime, g_time_diff))

        # syslog    
        log.debug('HTTP PACKET TOTALS,%d==REQUEST TOTALS,%d==ALL RESPONSE TOTALS,%d=='.center(PADDING, '=') % (g_packet_total, len(g_dict_request), len(g_dict_response)))
        log.debug('NO RESPONSE TOTALS,%d==DEL REQUEST TOTALS,%d==DEADLINE,%s==MAX_TIME,%s==DIFF_TIME,%d'.center(PADDING, '=') % (count, del_request, deadline, str_mtime, g_time_diff))
        log.info('write to result.csv end'.center(PADDING, '='))
        fw.close()
                
