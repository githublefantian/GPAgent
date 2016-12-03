# -*- coding: utf-8 -*-
import psutil
import subprocess
import time
from cmdmacro import *

def stoppcap(pid):
    if not isinstance(pid, int):
        return (False, "PID type error")
    if psutil.pid_exists(pid):
        p = psutil.Process(pid)
        p.terminate()
        # 返回数据结构  
        return(not psutil.pid_exists(pid), "PID:%d terminate success" % pid)
    else:
        return(False, "PID:%d not exists!" %pid)

def startpcap(cmd):
    if not isinstance(cmd, str):
        return(False, "parameter type error")
    child = subprocess.Popen(cmd, shell=True)
    # 返回数据结构  
    return (True, child.pid)

def getpcapinfo(pid):
    if not isinstance(pid, int):
        return (False, "PID type error")
    if psutil.pid_exists(pid):
        # 返回数据结构  
        return(True, {})
    else:

        return(True, {})


if __name__ == "__main__":
    cmd=""
    (ret, pid) = startpcap(cmd)
