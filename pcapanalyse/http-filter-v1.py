# -*- coding:utf-8 -*-
import sys
reload(sys).setdefaultencoding('UTF-8')

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

filever = 'http-filter-v1.160701'


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
    request_count = 0L
    dict_response = {}
    response_count = 0L
    
    log.debug('http pacp file: %s' % pcap_file)
    packets = scapy.rdpcap(pcap_file)
    for p in packets:
        #p.show()
        if p.getlayer('HTTP Request'):
            try:
                src_ip = p['IP'].src
                dst_ip = p['IP'].dst
                src_port = p['TCP'].sport
                dst_port = p['TCP'].dport
                method = p['HTTP Request'].Method
                
                if method != 'GET':
                    continue
                
                path = p['HTTP Request'].Path
                if '/imgs' not in path:
                    continue
                request_count = request_count + 1
                dict_request[str(request_count)] = [src_ip, dst_ip, src_port, dst_port]
            
            except Exception, e:
                print e
                continue
        
        if p.getlayer('HTTP Response'):
            try:
                src_ip = p['IP'].src
                dst_ip = p['IP'].dst
                src_port = p['TCP'].sport
                dst_port = p['TCP'].dport
                # print p['HTTP Response'].Location
                response_count = response_count + 1
                dict_response[str(response_count)] = [src_ip, dst_ip, src_port, dst_port]
                
            except:
                continue
    
    log.info('request_info:{0}'.format(dict_request)) 
    log.info('response_info:{0}'.format(dict_response))
    
    for request_no in dict_request.keys():
        [src_ip, dst_ip, src_port, dst_port] = dict_request[request_no]
        for response_no in dict_response.keys():
            if dict_response[response_no] == [dst_ip, src_ip, dst_port, src_port]:
                # has response, remove it
                dict_request.pop(request_no)
                break
    
    with open('result.txt', 'w') as fw:
        for request_no in dict_request.keys():
            [src_ip, dst_ip, src_port, dst_port] = dict_request[request_no]
            line = '%s,%s' % (str(src_ip), str(src_port))
            print line
            fw.write(line + '\r\n')
        fw.close()
                