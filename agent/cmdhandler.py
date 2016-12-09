# -*- coding: utf-8 -*-
from cmdmacro import *
import sysinfo
from agentlog import agentlog

def getsysinfo(type):
    result = {}
    if type == CPUKEY:
        result = sysinfo.getCPUInfo()
    elif type == MEMKEY:
        result = sysinfo.getMemInfo()
    elif type == DISKKEY:
        result = sysinfo.getDiskInfo()
    elif type == NTPKEY:
        result = sysinfo.getNTPStatus()
    elif type == NICKEY:
        result = sysinfo.getNICInfo()
    elif type == NICKEYRealTime:
        result = sysinfo.getNICRealTimeInfo()
    else:
        agentlog.error('error! getsysinfo:', type)

    return result

def getqueryinfo(type, para):
    result = {}
    if type == NICKEY:
        result = sysinfo.getNICInfo(para[T_VALUE].split('#'))
    elif type == NICKEYRealTime:
        result = sysinfo.getNICRealTimeInfo(para[T_VALUE].split('#'))
    else:
        agentlog.info('error! getqueryinfo:', type)

    return result

def parsestr(str=''):
    paradic = {}
    if len(str) <= 0:
        agentlog.error('len(str) error!')
    content = str.split('&')
    for i in content:
        item = i.split('=')
        if len(item) != 2:
            agentlog.error('parsestr: len(item) != 2')
            break
        paradic[item[0].strip()] = item[1].strip()

    return paradic

def mainbody(data):
    ret = {}
    agentlog.info('Received post data: %s' % data)
    try:
        if (data is not None) and (data != ''):
            para = parsestr(data)
            if para[T_TYPE] == TT_INFO:
                ret = getsysinfo(para[T_KEY])
                pass
            elif para[T_TYPE] == TT_REQ:
                ret = getqueryinfo(para[T_KEY], para)
            else:
                agentlog.error('request type error:', para[T_TYPE])
        else:
            agentlog.error('request cmd is empty')
    except Exception, e:
        agentlog.error(e)
    return ret

if __name__ == "__main__":
    input = 'type=info&key=device-cpu'
    print mainbody(input)
