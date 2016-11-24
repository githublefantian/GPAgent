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

filever = 'http-filter-v2'

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

if __name__ == '__main__':
    log = Cmy_logger(logname='http-filter.log', logger="main").getlog()
    log.info('=================== new_start ===================')
    log.info('=================== %s ===================' % filever)
    
    pcap_file = ''
    argc = len(sys.argv)
    if argc == 2:
        # pass a pcap file argument
        pcap_file = sys.argv[1].strip()
    else:
        # auto find a pacp file in current directory
        tmp_list = os.listdir('.')
        for filename in tmp_list:
            if filename.endswith('.pcap') and os.path.isfile(filename):
                pcap_file = filename
    
    if pcap_file == '' or not os.path.isfile(pcap_file):
        log.error('http pacp file: %s noooon exist, exit...' % pcap_file)
        sys.exit(1)
    
    dict_request = {}
    request_key = ''
    request_total = 0L
    response_total = 0L
    packet_total = 0L

    log.debug('http pacp file: %s' % pcap_file)
    packets = scapy.rdpcap(pcap_file)
    #with PcapReader('pcap_file') as packets:
    for p in packets:
        packet_total += 1
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
                request_key = src_ip + src_port + n_seq
                dict_request[request_key] = [src_ip, src_port, epoch_time]
                request_total += 1
            
            except Exception, e:
                print e
                continue
        
        if p.getlayer('HTTP Response'):
            try:
                dst_ip = p['IP'].dst
                dst_port = str(p['TCP'].dport)
                ack_no = str(p['TCP'].ack)

                response_key = dst_ip + dst_port + ack_no
                if dict_request.has_key(response_key):
                    del dict_request[response_key]
                    response_total += 1

            except:
                continue
        
    #log.info('request_info:{0}'.format(dict_request)) 
    #log.info('response_info:{0}'.format(dict_response))
    
    with open('result.csv', 'w') as fw:
        fw.write('SOURCE_IP,SOURCE_PORT,TIME,EPOCH_TIME' + '\r\n')

        for key in dict_request.keys():
            [src_ip, src_port, epoch_time] = dict_request[key]

            str_time = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(epoch_time))
            line = '%s,%s,%s,%s' % (str(src_ip), str(src_port), str_time, epoch_time)
            #print line
            fw.write(line + '\r\n')
        
        fw.write('\r\nPACKET TOTALS,%d\r\nREQUEST TOTALS,%d\r\nRESPONSE TOTALS,%d\r\n' % (packet_total, request_total, response_total))
        fw.close()
                
