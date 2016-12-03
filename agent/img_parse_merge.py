# -*- coding:utf-8 -*-
import pickle
import os
import sys
import time

from agentlog import Cmy_logger
from cmdmacro import DEFAULT_ENV

# 更新错误响应字典
def uniq_item_list(srclist=[]):
    tmplist = []
    for item in srclist:
        if item not in tmplist:
            tmplist.append(item)
    del srclist
    return tmplist

def update_res_error(dstdict={}, srcdict={}):
    for key in dstdict:
        if key in srcdict:
            dstdict[key] += srcdict[key]
            dstdict[key] = uniq_item_list(dstdict[key])
    for key in srcdict:
        if key not in dstdict:
            dstdict[key] = srcdict[key]



# read env
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
    print("[error] Read parameters from agent.env error!")
else:
    logd += '/'
    resultd += '/'
    tmppcapd += '/'

log = Cmy_logger(logname=(logd + 'img_parse.log'), logger="img_parse_merge").getlog()
log.info('start process!')

log.info('img_parse_merge.py begin!')
pcap_file = ''
mtime, del_request, count = (0, 0, 0)
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
    dump_data = []
    filelist = os.listdir(os.path.dirname(dump_file))
    count = 0
    for file in filelist:
        if file.find(os.path.basename(dump_file)) >= 0:
            dumpin = dump_file + '_' + str(count)
            dump_data.append(pickle.load(open(dumpin, 'r')))
            count += 1

    log.info('merge && parse: %s begin' % pcap_file)
    (img_req_list, img_res_dict, http_filter) = dump_data[0]
    total, real, response, success, no_res_dict, res_error_dict = http_filter
    img_req_list = uniq_item_list(img_req_list)

    for index in range(1, count):
        (img_req_listb, img_res_dictb, http_filterb) = dump_data[index]
        totalb, realb, responseb, successb, no_res_dictb, res_error_dictb = http_filterb
        img_req_listb = uniq_item_list(img_req_listb)
        total += totalb
        real += realb
        response += responseb
        success += successb
        res_error_dicta = res_error_dict.copy()
        update_res_error(res_error_dict, res_error_dictb)
        no_res_dicta = no_res_dict.copy()
        no_res_dict.update(no_res_dictb)

        req_len = len(img_req_list)
        maxi = req_len if req_len < SPLIT_OVERLAP else SPLIT_OVERLAP
        req_lenb = len(img_req_listb)
        maxj = req_lenb if req_lenb < SPLIT_OVERLAP else SPLIT_OVERLAP
        keylist = []
        for i in range(0, maxi):
            for j in range(0, maxj):
                key = img_req_list[req_len-i-1][0]
                if key == img_req_listb[j][0]:
                    keylist.append(j)
                    real -= 1
                    if key in no_res_dicta:
                        if key in no_res_dictb: # 没有响应
                            pass
                        else:                   # 响应只在b
                            if key in no_res_dict: del no_res_dict[key]
                    else:
                        if key in no_res_dictb: # 响应只在a
                            if key in no_res_dict: del no_res_dict[key]
                        else:                   # 响应在a,b
                            response -= 1
                            success -= 1

        # 更新响应列表，删除重复的条目
        for i in keylist:
            key = img_req_listb[i][0]
            if key in img_res_dictb:
                del img_res_dictb[key]
            del img_req_listb[i]
        img_req_list += img_req_listb
        img_res_dict.update(img_res_dictb)

    log.info('merge && parse: %s end' % pcap_file)

    ## 同 img_parse.py 代码一样
    content_error = 0
    other_error = 0
    for key in res_error_dict.keys():
        if key != "200":
            other_error += len(res_error_dict[key])
        else:
            content_error = len(res_error_dict["200"])

    result_file = resultd + os.path.basename(pcap_file).replace('.pcap', '.csv')
    log.info('start write to %s' % result_file)
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

        log.info('write to %s end' % result_file)
