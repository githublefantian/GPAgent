# -*- coding:utf-8 -*-
import os
import sys
reload(sys).setdefaultencoding('UTF-8')
try:
    import scapy.all as scapy
except ImportError:
    import scapy


def p_protocol_stat(fw, resultdict={}):
    for key in resultdict:
        line = str(resultdict[key])
        fw.write('PORT,%s\n' % key)
        fw.write('%s\n' % line[1:len(line) - 1])

# 返回抓包开始时间和结束时间
def protocol_statistic(pcapfile="", statdict={}, period=1):

    if pcapfile == "" or statdict == {}:
        print("protocol_statistic: parameters is NULL")

    start_time = 0
    pretime = 0
    tmpdict = {} # 用于统计
    for key in statdict:
        tmpdict[key] = 0

    pkt = scapy.PcapReader(pcapfile)
    while True:
        p = pkt.read_packet()
        if p is None:
            for key in statdict:  # 将上一次统计结果更新到字典中
                statdict[key].append(tmpdict[key])
            break
        if start_time == 0:
            start_time = int(p.time)
            pretime = start_time
        if 'TCP' in p:
            try:
                src_port = str(p['TCP'].sport)
                dst_port = str(p['TCP'].dport)
                count = (int(p.time) - pretime)/period
                pretime += count * period
                while True:
                    if count == 0:  # 继续当前时间段的统计
                        if src_port in statdict:
                            tmpdict[src_port] += 1
                        elif dst_port in statdict:
                            tmpdict[dst_port] += 1
                        else:
                            pass
                        break
                    else:
                        for key in statdict:  # 将上一次统计结果更新到字典中
                            statdict[key].append(tmpdict[key])
                        for key in tmpdict: # 初始为0
                            tmpdict[key] = 0
                        count -= 1
            except Exception as e:
                print(e)
                continue
    pkt.close()

    return start_time, pretime


if __name__ == '__main__':
    # Read parameters from agent.env
    from cmdmacro import DEFAULT_ENV

    logd, resultd, tmppcapd = ('', '', '')
    with open(DEFAULT_ENV, 'r') as envf:
        for line in envf.readlines():
            if line.startswith('LOG_DIR='):
                logd = line.replace('#', '=').split('=')[1].strip(' "\'\n')
            elif line.startswith('RESULT_DIR='):
                resultd = line.replace('#', '=').split('=')[1].strip(' "\'\n')
            elif line.startswith('TMPPCAP_DIR='):
                tmppcapd = line.replace('#', '=').split('=')[1].strip(' "\'\n')
            else:
                pass

    if logd == '' or resultd == '' or tmppcapd == '':
        print("[ERROR] Read parameters from agent.env error!")
    else:
        logd += '/'
        resultd += '/'
        tmppcapd += '/'

    from agentlog import Cmy_logger
    log = Cmy_logger(logname=(logd + 'protocol_stat.log'), logger="protocol_stat").getlog()
    log.info('start %s process!' % sys.argv[0])
    pcap_file = ''
    argc = len(sys.argv)
    if argc == 4:
        # get pcap file
        arg = sys.argv[1]
        pcap_file = arg.strip()
        if not os.path.isfile(pcap_file):
            log.error('http pacp file: %s noooon exist, exit...' % pcap_file)
            sys.exit(1)
        # get port list
        arg = sys.argv[2]
        resultdict = {}
        for item in arg.split(','):
            resultdict[item] = []
        # get period
        period = int(sys.argv[3].strip())
    else:
        log.error('Example: python protocol_stst.py <pcapfile> <port1,port2,port3>')
        sys.exit(1)

    log.info('parsing %s begin' % pcap_file)
    start, end = protocol_statistic(pcap_file, resultdict, period)
    log.info('parsing %s end' % pcap_file)

    # 输出统计信息
    result_file = resultd + os.path.basename(pcap_file).replace('.pcap', '_protocol_result.csv')
    log.info('writing to %s start' % result_file)
    with open(result_file, 'w') as fw:
        fw.write('START_TIME,%d\nEND_TIME,%d\nPERIOD,%d\n\n' % (start, end, period))
        p_protocol_stat(fw, resultdict)
    log.info('writing to %s end' % result_file)
