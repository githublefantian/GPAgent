# -*- coding: utf-8 -*-
import psutil
import commands
import time
from cmdmacro import *

g_niclist = []

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


def getDiskInfo(diskpath='/'):
    '''
    {"total": 300792410112, "used": 200032780288, "free": 100759629824, "percent": 66.5}
    '''

    diskinfo = psutil.disk_usage(diskpath)._asdict()
    return {DISKKEY: diskinfo}

def getDiskFree(diskpath='/'):
    return psutil.disk_usage(diskpath).free

def getNTPStatus():
    (status, output) = commands.getstatusoutput('pgrep ntpd')
    if status == 0:
        return {NTPKEY: "on"}
    else:
        return {NTPKEY: "off"}

def getNICInfo(nics=[], controller_ip=''):
    '''
    {"networkcard": [{"ip:":"", "mac": "14:18:77:59:51:22", "name": "swf", "controller-ip": "169.254.204.46"}]}
    '''
    global g_niclist
    g_niclist = []
    nicinfo = psutil.net_if_addrs()
    for nic, addrs in nicinfo.items():
        ipaddr = ''
        macaddr = ''
        if nic in ('lo', 'virbr0'):
            continue
        if len(nics) != 0 and (nic not in nics):
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
    if g_niclist == []:
        getNICInfo(nics, controller_ip)
    io_counters = psutil.net_io_counters(pernic=True)
    for nic in g_niclist:
        io = io_counters[nic['name']]
        io_item = {"name": nic['name'],
                   "ip": nic['ip'],
                   "mac": nic['mac'],
                   "controller-ip": nic['controller-ip'],
                   "time": time.time(),
                   "packet-counts": io.bytes_recv,
                   "total-bytes": io.packets_recv,
                   "packet-errors": io.errout,
                   "packet-drops": io.dropin,
                   }
        io_list.append(io_item)

    return {NICKEYRealTime: io_list}


if __name__ == "__main__":
    import json
    print(json.dumps(getCPUInfo()))
    print(json.dumps(getDiskInfo('/')))
    print(json.dumps(getMemInfo()))
    print(getNICInfo())
    print(getNTPStatus())
    print(getNICRealTimeInfo())
    print(getDiskFree())

