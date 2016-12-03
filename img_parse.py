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


filever = 'img-parse-v1'
PADDING = 80

# 保存所有验证码请求（时间顺序依次添加），每个item内容为KEY（请求包的源IP+源PORT+响应包序列号）
__img_req_list = []
# 保存所有验证码请求的响应包（时间顺序依次添加），每个item内容为KEY（响应包的目的IP+目的PORT+序列号）
# __img_res_list = []
# 保存所有响应的验证码请求包，{ 'KEY': [响应时间, 是否正常响应], } 格式
__img_res_dict = {}


def timefn(fn):
    def wrapped(a):
        start = time.time()
        b = fn(a)
        end = time.time()
        print("function: %s costs:%d ".center(PADDING, '=') % (fn.__name__, end - start))
        return b

    return wrapped

# return (验证码总请求数, 验证码实际请求数即不包括重发的，验证码请求响应总数, 验证码请求成功总数，验证码未请求成功记录,
# 验证码响应错误记录)
#@timefn
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
                __img_req_list.append([request_key, p.time, src_ip, src_port, version])
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
                    # 响应时间, 是否是正常响应, 0表示正常，1表示不正常
                    res_time = p.time - img_request[response_key][0]
                    __img_res_dict[response_key] = [res_time, False]
                    if res_code == "200":
                        contenttype = resdata.getfieldval('Content-Type')
                        if contenttype != "image/png":
                            info.append(contenttype)
                        else:
                            img_ok_count += 1
                            __img_res_dict[response_key] = [True, res_time]
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
    # Read parameters from agent.env
    from cmdmacro import DEFAULT_ENV
    logd, resultd, tmppcapd = ('', '', '')
    with open(DEFAULT_ENV, 'r') as envf:
        for line in envf.readlines():
            if line.startswith('LOG_DIR='):
                logd=line.replace('#', '=').split('=')[1].strip(' "\'\n')
            elif line.startswith('RESULT_DIR='):
                resultd=line.replace('#', '=').split('=')[1].strip(' "\'\n')
            elif line.startswith('TMPPCAP_DIR='):
                tmppcapd=line.replace('#', '=').split('=')[1].strip(' "\'\n')
            else:
                pass

    if logd == '' or resultd == '' or tmppcapd == '':
        print("Read parameters from agent.env error!")
    else:
        logd += '/'
        resultd += '/'
        tmppcapd += '/'

    from agentlog import Cmy_logger
    log = Cmy_logger(logname=(logd + 'img_parse.log'), logger="img_parse").getlog()
    log.info('start process!')

    pcap_file = ''
    mtime, del_request, count = (0, 0, 0)
    argc = len(sys.argv)
    if argc == 2 or argc == 3:
        # get pcap file
        arg = sys.argv[1]
        pcap_file = arg.strip()
        if pcap_file == '' or not os.path.isfile(pcap_file):
            log.error('http pacp file: %s noooon exist, exit...' % pcap_file)
            sys.exit(1)

        # get dump flag
        if argc == 3 and sys.argv[2].strip() == '--dump':
            import pickle
            dump_file = tmppcapd + os.path.basename(pcap_file).replace('.pcap', '.dump')
            log.info('dump and parse: %s begin' % pcap_file)
            filterdata = http_filter(pcap_file)
            pickle.dump((__img_req_list, __img_res_dict, filterdata), open(dump_file, 'w'))
            log.info('dump and parse: %s end' % pcap_file)
            sys.exit(0)

        log.info('parse %s begin' % pcap_file)
        total, real, response, success, no_res_dict, res_error_dict = http_filter(pcap_file)
        log.info('parse %s end' % pcap_file)

        # 同img_parse_merge.py 代码一样
        content_error = 0
        other_error = 0
        for key in res_error_dict.keys():
            if key != "200":
                other_error += len(res_error_dict[key])
            else:
                content_error = len(res_error_dict["200"])
    else:
        sys.exit(1)

    result_file = resultd + os.path.basename(pcap_file).replace('.pcap', '.csv')
    log.info('start write to %s' % result_file)
    with open(DEFAULT_ENV, 'w') as fw:
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

        log.info('write to %s end' % result_file)
