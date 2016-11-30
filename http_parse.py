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
    import scapy_http.http
except ImportError:
    from scapy.layers import http

filever = 'http-filter-v1'
PADDING = 80

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

# return (验证码总请求数, 验证码实际请求数即不包括重发的，验证码请求响应总数, 验证码请求成功总数，验证码未请求成功记录,
# 验证码响应错误记录)
@timefn
def http_filter(pcapfile):
    img_req_count = 0   # include retransmission
    img_rreq_count = 0  # not include retransmission
    img_rres_count = 0
    img_ok_count = 0    # not include retransmission
    img_request = {}
    img_err_response = {}
    img_deal_response = {}
    #dict_deal_request = {}

    #packets = scapy.rdpcap(pcapfile)
    #for p in packets:
    pkt = scapy.PcapReader(pcapfile)
    while True:
        p = pkt.read_packet()
        if p is None:
            break
        #epoch_time = p.time

        #p.show()
        if p.getlayer('HTTP Request'):
            reqdata = p['HTTP Request']
            try:
                src_ip = str(p['IP'].src)
                src_port = str(p['TCP'].sport)
                method = reqdata.getfieldval('Method')
                version = reqdata.getfieldval('Http-Version')
                path = reqdata.getfieldval('Path')
                seq_str = str(p['TCP'].seq + p['IP'].len - 40) # compute the ack sequence
                if method != 'GET':
                    continue
                if not path.startswith('/bidimg/get.ashx'):
                    continue
                img_req_count += 1
                request_key = src_ip.replace('.', '') + src_port + seq_str
                if request_key in img_deal_response:
                    continue
                img_request[request_key] = [p.time, src_ip, src_port, version]
            except Exception as e:
                print(e)
                continue

        if p.getlayer('HTTP Response'):
            try:
                dst_ip = str(p['IP'].dst)
                dst_port = str(p['TCP'].dport)
                ack_no = str(p['TCP'].ack)
                response_key = dst_ip.replace('.', '') + dst_port + ack_no

                if response_key in img_deal_response:
                    continue

                if response_key in img_request:
                    img_deal_response[response_key] = ""
                    resdata = p['HTTP Response']
                    statusline = resdata.getfieldval('Status-Line')
                    res_version = statusline[0:8]
                    res_code = statusline[9:12]
                    res_status = statusline[13:]
                    info = [img_request[response_key][0],
                            img_request[response_key][1],
                            img_request[response_key][2],
                            img_request[response_key][3],
                            p.time, str(p['IP'].src), str(p['TCP'].sport), res_version,
                            res_code, res_status,
                            ]
                    if res_code == "200":
                        contenttype = resdata.getfieldval('Content-Type')
                        if contenttype != "image/png":
                            info.append(contenttype)
                        else:
                            img_ok_count += 1
                            del img_request[response_key]
                            continue
                    if res_code in img_err_response:
                        img_err_response[res_code].append(info)
                    else:
                        img_err_response[res_code] = [info]

                    del img_request[response_key]

            except Exception as e:
                print(e)
                continue

    img_rres_count = len(img_deal_response)
    img_rreq_count = img_rres_count + len(img_request)

    pkt.close()
    del img_deal_response

    return img_req_count, img_rreq_count, img_rres_count, img_ok_count, img_request, img_err_response


if __name__ == '__main__':
    log = Cmy_logger(logname='http-filter.log', logger="main").getlog()
    log.info('start'.center(PADDING, '='))

    pcap_file = ''
    mtime, del_request, count = (0, 0, 0)
    argc = len(sys.argv)
    if argc == 2:
        # pass a pcap file argument
        arg = sys.argv[1]
        pcap_file = arg.strip()
        if pcap_file == '' or not os.path.isfile(pcap_file):
            log.error('http pacp file: %s noooon exist, exit...'.center(PADDING, '=') % pcap_file)
            sys.exit(1)
        log.debug('http pcap file: %s'.center(PADDING, '=') % pcap_file)
        total, real, response, success, no_res_dict, res_error_dict = http_filter(pcap_file)
        content_error = 0
        other_error = 0
        for key in res_error_dict.keys():
            if key != "200":
                other_error += len(res_error_dict[key])
            else:
                content_error = len(res_error_dict["200"])
    else:
        sys.exit(1)

    #str_mtime = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(mtime))
    log.info('start write to result.csv'.center(PADDING, '='))
    result_file = pcap_file.replace('.pcap', '_result.csv')
    with open(result_file, 'w') as fw:
        fw.write('ITEM,VALUE\n'
                 'IMAGE REQUEST TOTAL,%d\n'
                 'IMAGE REQUESt REAL TOTAL,%d\n'
                 'IMAGE REQUEST SUCCESS TOTAL,%d\n'
                 'IMAGE REQUEST FAILED TOTAL,%d\n'
                 'IMAGE NO-RESPONSE TOTAL,%d\n'
                 'IMAGE RESPONSE ERROR TOTAL,%d\n'
                 'IMAGE RESPONSE CONTENT-TYPE-ERROR TOTAL,%d\n'
                 'IMAGE RESPONSE STATUS-CODE-ERROR TOTAL,%d\n' % (total, real, success, real-success, real-response,
                                                                  content_error+other_error, content_error,
                                                                  other_error))
        fw.write('\n\nNO-RESPONSE PACKETS,%d\n\n' % (real-response))
        fw.write(',,REQUEST_TIME,REQUEST_TIMESTAMP,REQUEST_IP,REQUEST_PORT,REQ_HTTP-VERSION\n')
        for key in no_res_dict.keys():
            [tm, ip, port, ver] = no_res_dict[key]
            str_time = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(tm))
            line = ',,%s,%s,%s,%s,%s' % (str_time, tm, ip, port, ver)
            fw.write(line + '\n')

        fw.write('\n\nRESPONSE-ERROR PACKETS,%d\n\n' % (content_error+other_error))
        fw.write(',,REQUEST_TIME,REQ_TIMESTAMP,REQUEST_IP,REQUEST_PORT,REQ_HTTP-VERSION,'
                 'RESPONSE_TIME,RES_TIMESTAMP,RESPONSE_IP,RESPONSE_PORT,RES_HTTP-VERSION,'
                 'RES_CODE,RES_STATUS,RES_CONTENT-TYPE\n')
        for key in res_error_dict.keys():
            for data in res_error_dict[key]:
                str_time = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(data[0]))
                line = ',,%s,%s,%s,%s,%s,' % (str_time, data[0], data[1], data[2], data[3])
                str_time = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(data[4]))
                line += '%s,%s,%s,%s,%s,' % (str_time, data[4], data[5], data[6], data[7])
                if key == "200":
                    line += '%s,%s,%s\n' % (data[8], data[9], data[10])
                else:
                    line += '%s,%s\n' % (data[8], data[9])
                fw.write('%s' % line)

        log.info(('write to %s end' % result_file).center(PADDING, '='))
        fw.close()
