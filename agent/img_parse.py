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

from cmdmacro import *

from agentlog import imagelog
log = imagelog

PADDING = 80


def fntime(fn):
    def wrapped(a):
        start = time.time()
        b = fn(a)
        end = time.time()
        print(" function: [%s] costs: %d s ".center(PADDING, '=') % (fn.__name__, end - start))
        return b

    return wrapped

# 返回(请求总数包括重传数, 请求记录不包括重传dict，没有响应记录dict，响应错误记录dict, 重复响应次数(针对响应OK))
# (img_req_count, img_request, img_no_response, img_err_response, img_response_ok_repeat, img_request_multi_get)
# (total, request_dict, no_response_dict, response_err_dict, res_ok_repeat)
@fntime
def img_filter(pcapfile):
    # 总请求数，包括重传
    img_req_count = 0
    # 保存所有验证码请求, { 'KEY': [时间戳, 源IP, 源PORT, 目的IP, 目的PORT, 响应类型, 响应时间],}
    # 如 [p.time, src_ip, src_port, dst_ip, dst_port, NO_NO_RESPONSE, 0]
    img_request = {}
    # 保存目前没有响应的请求, {KEY1: [p.time, src_ip, src_port, version, path]}
    img_no_response = {}
    # 保存响应错误的请求/响应信息 {CODE1: {KEY1: LIST1, KEY2: LIST2}}
    img_err_response = {}
    # 保存重复响应的次数（只针对响应OK的进行统计）
    img_response_ok_repeat = 0

    # 保存已处理的有响应的请求 {KEY1: ""} 内容为空
    img_deal_response = {}

    # 保存请求你头中含Raw Data的信息, [多余的GET次数, RAWDATA]
    img_request_multi_get = {}

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
                dst_ip = str(p['IP'].dst)
                src_port = str(p['TCP'].sport)
                dst_port = str(p['TCP'].dport)
                method = reqdata.getfieldval('Method')
                version = reqdata.getfieldval('Http-Version')
                path = reqdata.getfieldval('Path')

                # print("\n==========flags:%d====data len:%d=====\n" % (flags, p['IP'].ihl*4 + p['TCP'].dataofs*4))
                flags = p['TCP'].flags  # an integer
                if (flags & 0x01) or (flags & 0x02):  # FIN or SYN flag activated
                    seq_str = str(p['TCP'].seq + (p['IP'].len - p['IP'].ihl * 4 - p['TCP'].dataofs * 4) + 1)  # compute the ack sequence
                else:
                    seq_str = str(p['TCP'].seq + (p['IP'].len - p['IP'].ihl * 4 - p['TCP'].dataofs * 4))  # compute the ack sequence

                if method != 'GET':
                    continue
                if -1 == path.find('/bidimg/get.ashx'):
                    continue
                img_req_count += 1
                request_key = src_ip + ':' + src_port + ':' + seq_str
                if request_key in img_deal_response:
                    continue
                img_no_response[request_key] = [p.time, src_ip, src_port, version, path]
                img_request[request_key] = [p.time, src_ip, src_port, dst_ip, dst_port, NO_NO_RESPONSE, 0]
                # 统计单个数据包中多个http请求头的情况
                if p.getlayer('Raw'):
                    get_count = str(p['Raw']).count('/bidimg/get.ashx')
                    img_request_multi_get[request_key] = [get_count, str(p['Raw'])]


            except Exception as e:
                print(e)
                continue

        if p.getlayer('HTTP Response'):
            try:
                dst_ip = str(p['IP'].dst)
                dst_port = str(p['TCP'].dport)
                ack_no = str(p['TCP'].ack)
                response_key = dst_ip + ':' + dst_port + ':' + ack_no

                if response_key in img_deal_response:
                    img_response_ok_repeat += 1
                    continue

                if response_key in img_no_response:
                    img_deal_response[response_key] = ""
                    resdata = p['HTTP Response']
                    statusline = resdata.getfieldval('Status-Line')
                    res_version = statusline[0:8]
                    res_code = statusline[9:12]
                    res_status = statusline[13:]
                    info = [img_no_response[response_key][0],
                            img_no_response[response_key][1],
                            img_no_response[response_key][2],
                            img_no_response[response_key][3],
                            p.time, str(p['IP'].src), str(p['TCP'].sport), res_version,
                            res_code, res_status,
                            ]
                    res_time = p.time - img_no_response[response_key][0]
                    img_request[response_key][6] = res_time
                    if res_code == "200":
                        contenttype = resdata.getfieldval('Content-Type')
                        if contenttype != "image/png":
                            img_request[response_key][5] = NO_CT_ERROR_RESPONSE
                            info.append(contenttype)
                            info.append(img_no_response[response_key][4])
                        else:
                            img_request[response_key][5] = NO_NORMAL_RESPONSE
                            del img_no_response[response_key]
                            continue
                    else:
                        img_request[response_key][5] = NO_CODE_ERROR_RESPONSE
                    if res_code in img_err_response:
                        img_err_response[res_code][response_key] = info
                    else:
                        img_err_response[res_code] = {response_key: info}

                    del img_no_response[response_key]

            except Exception as e:
                print(e)
                continue
    pkt.close()
    del img_deal_response

    return img_req_count, img_request, img_no_response, img_err_response, img_response_ok_repeat, img_request_multi_get


# 返回(总的响应错误数，响应200 OK错误数)
def get_err_response_sum(err_res={}):
    sum = 0
    ok_sum = 0
    for code in err_res:
        sum += len(err_res[code])
        if code == "200":
           ok_sum = len(err_res[code])

    return sum, ok_sum


def p_img_request(fw, img_request={}):
    #fw.write('TOTAL,%d\n\n' % len(img_request))
    fw.write('REQUEST_TIME,SRC_IP,SRC_PORT,DST_IP,DST_PORT,RESPONSE_VERSION,DELTA-TIME\n')
    req_list = sorted(img_request.iteritems(), key=lambda  d: d[1][0])
    for item in req_list:
        fw.write('%f,%s,%s,%s,%s,%d,%f\n' % tuple(item[1]))
    return

'''
# 验证码响应类型分类
NO_NO_RESPONSE = 0          # 没有响应
NO_NORMAL_RESPONSE = 1      # 正常响应
NO_CODE_ERROR_RESPONSE = 2  # 状态码返回错误
NO_CT_ERROR_RESPONSE = 3    # content-type 类型错误(状态码200)
'''
def p_img_request_multi_get(fw, img_request={}, img_request_multi_get={}):
    total = 0
    for key in img_request_multi_get:
        total += img_request_multi_get[key][0]
    fw.write('HTTP-MULTI-GET PACKETS,%d\n' % (len(img_request_multi_get)))
    fw.write('HTTP-MULTI-GET EXTRA-TOTAL,%d\n\n' % total)

    fw.write(',,REQUEST_TIME,SRC_IP,SRC_PORT,DST_IP,DST_PORT,RESPONSE_VERSION(NO-RES:0;NORMAL1;CODE-ERR:2;CT-ERR:3),DELTA-TIME,HTTP-GET-EXTRA-TOTAL, RAW-DATA\n')
    for key in img_request_multi_get:
        fw.write(',,%f,%s,%s,%s,%s,%d,%f' % tuple(img_request[key]))
        fw.write(',%d,%s\n' % (img_request_multi_get[key][0], img_request_multi_get[key][1].replace('\r\n', ';')))
    return


def p_img_no_reponse(fw, no_response_dict={}):
    fw.write('NO-RESPONSE PACKETS,%d\n\n' % (len(no_response_dict)))
    if len(no_response_dict) == 0:
        return 0
    fw.write(',,REQUEST_TIME,REQUEST_TIMESTAMP,REQUEST_IP,REQUEST_PORT,REQ_HTTP-VERSION,REQUEST_PATH\n')
    no_response_list = sorted(no_response_dict.iteritems(), key=lambda d: d[1][0])
    for key in no_response_list:
        [tm, ip, port, ver, path] = key[1][:5]
        str_time = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(tm))
        line = ',,%s,%f,%s,%s,%s,%s' % (str_time, tm, ip, port, ver, path)
        fw.write(line + '\n')

    return len(no_response_dict)

'''
REQ_TIMESTAMP,REQUEST_IP,REQUEST_PORT,REQ_HTTP-VERSION      # 0-3
RES_TIMESTAMP,RESPONSE_IP,RESPONSE_PORT,RES_HTTP-VERSION    # 4-7
RES_CODE,RES_STATUS,RES_CONTENT-TYPE,REQUEST_PATH           # 7-11
'''
def p_img_err_reponse_path(fw, res_error_dict={}):
    (sum, ok_error) = get_err_response_sum(res_error_dict)
    fw.write('REQUEST_TOTAL,%d\n' % ok_error)
    if ok_error == 0:
        return
    fw.write('REQUEST_TIMESTAMP,RREQUEST_IP,REQUEST_PORT,EQUEST_PATH\n')
    if "200" in res_error_dict.keys():
        res_error_list = sorted(res_error_dict["200"].iteritems(), key=lambda d: d[1][0])
        for item in res_error_list:
            data = item[1]
            line = '%f,%s,%s,%s\n' % (data[0], data[1], data[2], data[11])
            fw.write('%s' % line)

    return


'''
REQ_TIMESTAMP,REQUEST_IP,REQUEST_PORT,REQ_HTTP-VERSION      # 0-3
RES_TIMESTAMP,RESPONSE_IP,RESPONSE_PORT,RES_HTTP-VERSION    # 4-7
RES_CODE,RES_STATUS,RES_CONTENT-TYPE,REQUEST_PATH           # 7-11
'''
def p_img_err_reponse(fw, res_error_dict={}):
    (sum, ok_error) = get_err_response_sum(res_error_dict)
    fw.write('RESPONSE-ERROR PACKETS,%d\n\n' % sum)
    fw.write(',,REQUEST_TIME,REQ_TIMESTAMP,REQUEST_IP,REQUEST_PORT,REQ_HTTP-VERSION,'
    'RESPONSE_TIME,RES_TIMESTAMP,RESPONSE_IP,RESPONSE_PORT,RES_HTTP-VERSION,'
    'RES_CODE,RES_STATUS,RES_CONTENT-TYPE,REQUEST_PATH\n')
    for code in res_error_dict.keys():
        res_error_list = sorted(res_error_dict[code].iteritems(), key=lambda d: d[1][0])
        for item in res_error_list:
            data = item[1]
            str_time = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(data[0]))
            line = ',,%s,%f,%s,%s,%s,' % (str_time, data[0], data[1], data[2], data[3])
            str_time = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(data[4]))
            line += '%s,%f,%s,%s,%s,' % (str_time, data[4], data[5], data[6], data[7])
            if code == "200":
                line += '%s,%s,%s,%s\n' % (data[8], data[9], data[10], data[11])
            else:
                line += '%s,%s\n' % (data[8], data[9])
            fw.write('%s' % line)

    return sum


def p_statistic_info(fw, img_filter_result):
    (total, request_dict, no_response_dict, response_err_dict, res_ok_repeat, request_multi_get_dict) = img_filter_result
    (response_err, ok_error) = get_err_response_sum(response_err_dict)
    real = len(request_dict)
    response = real - len(no_response_dict)
    success = response - response_err

    fw.write('\nIMAGE STATISTICS\n'
             'IMAGE REQUEST TOTAL,%d\n'
             'IMAGE REQUEST REAL TOTAL,%d\n'
             'IMAGE REQUEST SUCCESS TOTAL,%d\n'
             'IMAGE REQUEST FAILED TOTAL,%d\n'
             'IMAGE NO-RESPONSE TOTAL,%d\n'
             'IMAGE RESPONSE ERROR TOTAL,%d\n'
             'IMAGE RESPONSE CONTENT-TYPE-ERROR TOTAL,%d\n'
             'IMAGE RESPONSE STATUS-CODE-ERROR TOTAL,%d\n'
             'IMAGE RESPONSE SUCCESS REPEAT TOTAL,%d\n'
             'IMAGE REQUEST HAS-RAW-DATA(MULTI-GET) TOTAL,%d\n'
             % (total, real, success, real - success, real - response, response_err,
                ok_error, response_err - ok_error, res_ok_repeat, len(request_multi_get_dict)))
    return

if __name__ == '__main__':
    # Read parameters from agent.env
    resultd, tmppcapd = (RESULTD, TMPPCAPD)
    log.info('start %s process!' % sys.argv[0])
    pcap_file = ''
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
            from pickle import dump
            dump_file = tmppcapd + os.path.basename(pcap_file).replace('.pcap', '.dump')
            log.info('dumpimg... : %s begin' % pcap_file)
            result = img_filter(pcap_file)
            dump(result, open(dump_file, 'w'))
            log.info('dumpimg...: %s end' % pcap_file)
            sys.exit(0)

        log.info('parsing %s begin' % pcap_file)
        result = img_filter(pcap_file)
        log.info('parsing %s end' % pcap_file)
    else:
        sys.exit(1)

    # 输出统计信息
    result_file = resultd + os.path.basename(pcap_file).replace('.pcap', '_result.csv')
    log.info('writing to %s start' % result_file)
    with open(result_file, 'a') as fw:
        p_statistic_info(fw, result)
        fw.write('\n\n')
        p_img_no_reponse(fw, result[2])
        fw.write('\n\n')
        p_img_err_reponse(fw, result[3])
        # 输出HTTP重复GET头信息
        fw.write('\n\n')
        p_img_request_multi_get(fw, result[1], result[5])
    log.info('writing to %s end' % result_file)

    # 输出content-type错误的IMG请求路径
    result_file = resultd + os.path.basename(pcap_file).replace('.pcap', '_error_path.csv')
    log.info('writing to %s start' % result_file)
    with open(result_file, 'w') as fw:
        p_img_err_reponse_path(fw, result[3])
    log.info('writing to %s end' % result_file)

    '''
    # 输出请求信息
    result_file = resultd + os.path.basename(pcap_file).replace('.pcap', '_request.csv')
    log.info('writing to %s start' % request_file)
    with open(request_file, 'w') as fw:
        p_img_request(fw, result[1])
    log.info('writing to %s end' % request_file)
    '''

