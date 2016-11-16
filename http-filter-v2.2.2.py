# -*- coding:utf-8 -*-
import sys
reload(sys).setdefaultencoding('UTF-8')

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

filever = 'http-filter-v2.2.2: only support pcap'
# global var
g_dict_request = {}
g_request_total = 0L
g_response_total = 0L
g_packet_total = 0L

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

def http_filter(pcapfile):
    global g_packet_total, g_dict_request, g_request_total, g_response_total
    request_key = ''
    #packets = scapy.rdpcap(pcapfile)
    pkt = scapy.PcapReader(pcapfile)
    while True:
        p = pkt.read_packet()
        if p is None:
            break
        g_packet_total += 1
        #p.show()
        if p.getlayer('HTTP Request'):
            try:
                #print str(p['Ethernet'].time) + '\r\n'
                src_ip = p['IP'].src
                src_port = str(p['TCP'].sport)
                method = p['HTTP Request'].Method
                epoch_time = p['Ethernet'].time
                # compute the net sequence
                n_seq = str(p['TCP'].seq + p['IP'].len - 40)

                if method != 'GET':
                    continue
                
                path = p['HTTP Request'].Path
                if '/imgs/' not in path:
                    continue
                request_key = src_ip.replace('.', '') + src_port + n_seq
                g_dict_request[request_key] = [src_ip, src_port, epoch_time]
                g_request_total += 1
            
            except Exception, e:
                print e
                continue
        
        if p.getlayer('HTTP Response'):
            try:
                dst_ip = p['IP'].dst
                dst_port = str(p['TCP'].dport)
                ack_no = str(p['TCP'].ack)

                response_key = dst_ip.replace('.', '') + dst_port + ack_no
                if g_dict_request.has_key(response_key):
                    del g_dict_request[response_key]
                    g_response_total += 1

            except:
                continue
    pkt.close()


if __name__ == '__main__':
    log = Cmy_logger(logname='http-filter.log', logger="main").getlog()
    log.info('=========================== start =========================')
    
    pcap_file = ''
    argc = len(sys.argv)
    if argc == 2:
        # pass a pcap file argument
        pcap_file = sys.argv[1].strip()
        log.debug('http pcap file: %s' % pcap_file)
        http_filter(pcap_file)
    else:
        # auto find a pacp file in current directory
        tmp_list = os.listdir('.')
        print tmp_list
        for filename in tmp_list:
            if filename.endswith('.pcap') and os.path.isfile(filename):
                pcap_file = filename
                log.debug('http pcap file: %s' % pcap_file)
                http_filter(pcap_file)

    if pcap_file == '' or not os.path.isfile(pcap_file):
        log.error('http pcap file: %s noooon exist, exit...' % pcap_file)
        sys.exit(1)

     
    log.info('=============== start write to result.csv ===================')
    with open('result.csv', 'w') as fw:
        fw.write('SOURCE_IP,SOURCE_PORT,TIME,EPOCH_TIME' + '\r\n')

        for key in g_dict_request.keys():
            [src_ip, src_port, epoch_time] = g_dict_request[key]

            str_time = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(epoch_time))
            line = '%s,%s,%s,%s' % (str(src_ip), str(src_port), str_time, epoch_time)
            #print line
            fw.write(line + '\r\n')
        
        fw.write('\r\nPACKET TOTALS,%d\r\nREQUEST TOTALS,%d\r\nRESPONSE TOTALS,%d\r\n' % (g_packet_total, g_request_total, g_response_total))
        log.info('=========================== end =============================')
        fw.close()
                
