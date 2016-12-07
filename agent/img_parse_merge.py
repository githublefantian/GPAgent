# -*- coding:utf-8 -*-
import pickle
import os
import sys
import time

from agentlog import Cmy_logger
from cmdmacro import *
import img_parse


#倒序排序
@img_parse.fntime
def get_sorted_request(img_req_dict={}):
    img_req_list = []
    img_req_list = sorted(img_req_dict.iteritems(), key=lambda d: d[1][0], reverse=True)
    return img_req_list


# 更新错误响应字典
def update_res_error(dstdict={}, srcdict={}):
    for code in dstdict:
        if code in srcdict:
            dstdict[code].update(srcdict[code])
    for code in srcdict:
        if code not in dstdict:
            dstdict[code] = srcdict[code].copy

def update_no_res(dstdict={}, srcdict={}, dstreq={}, srcreq={}):
    # 请求在a,b 但响应只在a; key 在 srcdict, 不在 dstdic
    count = 0
    keylist = []
    for key in srcdict:
        if key not in dstdict:
            if (key in srcreq) and (key in dstreq):
                keylist.append(key)
                srcreq[key] = dstreq[key]
    for key in keylist:
        del srcdict[key]
    count += len(keylist)
    del keylist[:]
    # 请求在a,b 但响应只在b; key 在 dstdict, 不在 srcdic
    for key in dstdict:
        if key not in srcdict:
            if (key in srcreq) and (key in dstreq):
                keylist.append(key)
    for key in keylist:
        del dstdict[key]
    dstdict.update(srcdict)
    count += len(keylist)
    return count

@img_parse.fntime
def merge_dump_files(dump_file=''):
    filelist = os.listdir(os.path.dirname(dump_file))
    # 按顺序导入dump文件
    count = 0
    dump_data = []
    for file in filelist:
        if file.find(os.path.basename(dump_file)) >= 0:
            dumpin = dump_file + '_' + str(count)
            dump_data.append(pickle.load(open(dumpin, 'r')))
            count += 1

    total, img_req_dict, no_res_dict, res_error_dict = dump_data[0]
    for index in range(1, count):
        totalb, img_req_dictb, no_res_dictb, res_error_dictb = dump_data[index]
        total += totalb
        update_no_res(no_res_dict, no_res_dictb, img_req_dict, img_req_dictb)
        update_res_error(res_error_dict, res_error_dictb)
        # 一定要放在最后更新，防止影响前两个数据结构的更新
        img_req_dict.update(img_req_dictb)

    return total, img_req_dict, no_res_dict, res_error_dict


if __name__ == "__main__":
    logd, resultd, tmppcapd = ('', '', '')
    with open(DEFAULT_ENV, 'r') as envf:
        for line in envf.readlines():
            if line.startswith('LOG_DIR='):
                logd=line.replace('#', '=').split('=')[1].strip(' "\'\n')
            elif line.startswith('RESULT_DIR='):
                resultd=line.replace('#', '=').split('=')[1].strip(' "\'\n')
            elif line.startswith('TMPPCAP_DIR='):
                tmppcapd=line.replace('#', '=').split('=')[1].strip(' "\'\n')
            elif line.startswith('SPLITOVERLAP='):
                SPLIT_OVERLAP=line.replace('#', '=').split('=')[1].strip(' "\'\n')
            else:
                pass

    if logd == '' or resultd == '' or tmppcapd == '':
        print("[ERROR] Read parameters from agent.env error!")
    else:
        logd += '/'
        resultd += '/'
        tmppcapd += '/'

    log = Cmy_logger(logname=(logd + 'img_parse.log'), logger="img_parse_merge").getlog()
    log.info('start %s process!' % sys.argv[0])
    pcap_file = ''
    argc = len(sys.argv)
    if argc != 2:
        log.error("Required parameter missiong...")
        log.info("Example: %s pcapfile.pcap" % sys.argv[0])
        exit(1)
    else:
        # get pcap file
        arg = sys.argv[1]
        pcap_file = arg.strip()
        if pcap_file == '' or not os.path.isfile(pcap_file):
            log.error('http pacp file: %s noooon exist, exit...' % pcap_file)
            sys.exit(1)

    dump_file = tmppcapd + os.path.basename(pcap_file).replace('.pcap', '.dump')
    log.info('img_parse_merge.py -- merge && parse: %s begin' % pcap_file)
    result = merge_dump_files(dump_file)
    log.info('img_parse_merge.py -- merge && parse: %s end' % pcap_file)

    # 输出统计信息
    result_file = resultd + os.path.basename(pcap_file).replace('.pcap', '_result.csv')
    log.info('writing to %s start' % result_file)
    with open(result_file, 'w') as fw:
        img_parse.p_statistic_info(fw, result)
        fw.write('\n\n')
        img_parse.p_img_no_reponse(fw, result[2])
        fw.write('\n\n')
        img_parse.p_img_err_reponse(fw, result[3])
        log.info('writing to %s end' % result_file)

    # 输出content-type错误的IMG请求路径
    result_file = resultd + os.path.basename(pcap_file).replace('.pcap', '_error_path.csv')
    log.info('writing to %s start' % result_file)
    with open(result_file, 'w') as fw:
        img_parse.p_img_err_reponse_path(fw, result[3])
    log.info('writing to %s end' % result_file)

    '''
    # 输出请求信息
    request_file = resultd + os.path.basename(pcap_file).replace('.pcap', '_request.csv')
    log.info('writing to %s start' % request_file)
    with open(request_file, 'w') as fw:
        img_parse.p_img_request(fw, result[1])
    log.info('writing to %s end' % request_file)
    '''
