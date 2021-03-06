# -*- coding: utf-8 -*-
import psutil
import commands
import time
from cmdmacro import *
import file_manage
from agentlog import agentlog, getlogaddress, changelogaddress

g_niclist = []


def getFilesInfo(para):
    file_manage.parse_filesinfo_para(para)
    fileinfo = file_manage.managefiles(FILEINFOKEY, para[TRANS_SRC].split('#'), para[TRANS_FILTER].split('#'))
    return {FILEINFOKEY: fileinfo}


def removeFiles(para):
    file_manage.parse_filesinfo_para(para)
    fileinfo = file_manage.managefiles(FILEREMOVEKEY, para[TRANS_SRC].split('#'), para[TRANS_FILTER].split('#'))
    return {FILEREMOVEKEY: fileinfo}


def getSyslogInfo():
    info = getlogaddress()
    if info:
        return {SYSLOGKEY: {"ip": info[0], "port": info[1]}}
    else:
        return {}


def setSyslogInfo(para):
    if not len(para) == 2:
        agentlog.error("set SyslogInfo para error!")
        raise AgentError("set SyslogInfo para error! (at least 2)")
    ret = changelogaddress(para[0], int(para[1]))
    return {SYSLOGKEY: ret}


def getCPUInfo(period=0.5):
    '''
    {"device-cpu": 11.1}
    '''

    cpuinfo = psutil.cpu_percent(interval=period)
    return {CPUKEY: cpuinfo}


def getMemInfo():
    '''
    {"device-mem": {"total": 8529297408, "available": 2130747392, "percent": 75.0, "used": 6398550016, "free": 2130747392}}
    '''

    meminfo = psutil.virtual_memory()._asdict()
    return {MEMKEY: meminfo}


def getDiskInfo(diskpath=DEFAULT_DISKPATH):
    '''
    {"total": 300792410112, "used": 200032780288, "free": 100759629824, "percent": 66.5}
    '''

    diskinfo = psutil.disk_usage(diskpath)._asdict()
    return {DISKKEY: diskinfo}

def getDiskFree(diskpath=DEFAULT_DISKPATH):
    return psutil.disk_usage(diskpath).free

def getNTPStatus():
    (status, output) = commands.getstatusoutput('pgrep ntpd')
    if status == 0:
        return {NTPKEY: "on"}
    else:
        return {NTPKEY: "off"}

def getNICInfo(niclist=[], controller_ip=''):
    '''
    {"networkcard": [{"ip:":"", "mac": "14:18:77:59:51:22", "name": "swf", "controller-ip": "169.254.204.46"}]}
    '''
    global g_niclist
    g_niclist = []
    nicinfo = psutil.net_if_addrs()

    if len(niclist) == 0:
        nics = DEFAULT_NICS
    else:
        nics = niclist

    for nic, addrs in nicinfo.items():
        ipaddr = ''
        macaddr = ''
        if nic not in nics:
            continue
        for addr in addrs:
            if addr.address == controller_ip:
                break
            if addr.family == 2:
                ipaddr = addr.address
            if addr.family == 17:
                macaddr = addr.address
            #nic = 'swf'
            nicitem = {'name': nic, 'controller-ip': controller_ip, 'mac': macaddr, 'ip': ipaddr}
        g_niclist.append(nicitem)

    return {NICKEY: g_niclist}


def getNICRealTimeInfo(nics=[], controller_ip=''):
    global g_niclist
    io_list = []
    if len(g_niclist) == 0:
        getNICInfo(nics, controller_ip)
    io_counters = psutil.net_io_counters(pernic=True)
    curtime = time.time()

    #agentlog.debug(str(g_niclist))
    for nic in g_niclist:
        io = io_counters[nic['name']]
        io_item = {"name": nic['name'],
                   "ip": nic['ip'],
                   "mac": nic['mac'],
                   "controller-ip": nic['controller-ip'],
                   "time": curtime,
                   "packet-counts": io.packets_recv,
                   "total-bytes": io.bytes_recv,
                   "packet-errors": io.errout,
                   "packet-drops": io.dropin,
                   }
        io_list.append(io_item)
        if DEBUG == 'yes':
            fn = 'traffic_%s.csv' % io_item['name']
            with open(fn, 'a') as traff:
                traff.write("%s,%s,%s,%s,%s\n" % (io_item['time'],\
                io_item['packet-counts'], io_item['total-bytes'], io_item['packet-errors'], io_item['packet-drops']))

    return {NICKEYRealTime: io_list}


if __name__ == "__main__":
    print(getCPUInfo())
    print(getDiskInfo('/'))
    print(getDiskInfo('/boot/'))
    print(getMemInfo())
    print(getNICInfo())
    print(getNTPStatus())
    print(getNICRealTimeInfo())
    print(getDiskFree())
    print(getFilesInfo({"value": "pcap"}))
    print(removeFiles({"value": "pcap", "filter": "copy"}))

