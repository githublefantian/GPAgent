# -*- coding: utf-8 -*-
import psutil
import subprocess
from cmdmacro import *
from agentlog import agentlog
import commands


def stopprocess(pid):
    if not isinstance(pid, int):
        return (False, "PID type error")
    if psutil.pid_exists(pid):
        p = psutil.Process(pid)
        # 发送 SIGTERM
        p.terminate()
        # 等待结束，防止成为僵尸进程
        ret = p.wait(timeout=1)
        # print ret, type(ret)
        if ret == 0:
            return(True, "PID:%d terminate success" % pid)
        else:
            return(False, "PID:%d terminate failed!" % pid)
    else:
        return(False, "PID:%d not exists!" %pid)

def startcmd(cmd):
    if not isinstance(cmd, str):
        return(False, "parameter type error")
    agentlog.info("startcmd:" + cmd)
    child = subprocess.Popen(cmd, shell=True)
    # 返回数据结构
    return (True, child.pid)


def getPIDinfo(pid, type=""):
    '''
    返回(True, False) 表示该PID进程已经结束
    返回(True, True) 表示该PID进程正在运行
    '''
    status = 0

    if not isinstance(pid, int):
        return (False, "PID type error")
    if psutil.pid_exists(pid):
        if type == TT_PCAP:
            (status, output) = commands.getstatusoutput('ps aux | grep capture.sh | grep -v grep')
        elif type == TT_PARSE:
            (status, output) = commands.getstatusoutput('ps aux | grep img_parse.sh | grep -v grep')
        elif type == TT_TRANS:
            (status, output) = commands.getstatusoutput('ps aux | grep file_transfer.sh | grep -v grep')
        elif type == TT_MD5:
            (status, output) = commands.getstatusoutput('ps aux | grep md5_generate.sh | grep -v grep')
        else:
            pass
        if status != 0:
            ret = stopprocess(pid)
            agentlog.info("stopprocess[%s]:  %s" % (type, str(ret)))
            return True, False
        else:
            return True, True
    else:
        return True, False


def get_exec_cmd(type, parad):
    cmd = ''
    if type == TT_PCAP:
        if T_VALUE not in parad:
            cmd = AGENTD + 'capture.sh'
        else:
            nics = parad[T_VALUE].replace('#', ',')
            cmd = AGENTD + 'capture.sh' + ' -n ' + nics
    elif type == TT_PARSE:
        if T_VALUE not in parad:
            cmd = AGENTD + "img_parse.sh -d"
        else:
            pass
    elif type == TT_TRANS:
        if T_VALUE not in parad:
            cmd = AGENTD + "file_transfer.sh"
        else:
            pass
    elif type == TT_MD5:
        if T_VALUE not in parad:
            cmd = AGENTD + "md5_generate.sh"
        else:
            pass
    else:
        pass

    return cmd


def exec_process(type, key, parad):
    if key == PROCESS_STATUS:
        if PROCESS_PID in parad:
            ret, info = getPIDinfo(int(parad[PROCESS_PID]), type)
            if not ret:
                raise AgentError(PROCESS_STATUS + ": " + info)
            else:
                if info:
                    return {STATUS_KEY: STATUS_RUN}
                else:
                    return {STATUS_KEY: STATUS_END}
        else:
            return AgentError('%s-%s lack of PID' % (type, key))
    elif key == PROCESS_STOP:
        if PROCESS_PID not in parad:
            return AgentError('%s-%s lack of PID' % (type, key))
        else:
            ret, info = stopprocess(int(parad[PROCESS_PID]))
            if not ret:
                raise AgentError(PROCESS_STOP + " : " + info)
            else:
                return {STATUS_KEY: STATUS_SUCCESS}
    elif key == PROCESS_START:
        cmd = get_exec_cmd(type, parad)
        ret, pid = startcmd(cmd)
        if not ret:
            raise AgentError("%s-%s : failed!" % (type, key))
        else:
            return {PROCESS_PID: str(pid)}
    else:
        raise AgentError("%s-%s error type!" % (type, key))


if __name__ == "__main__":
    from time import sleep

    # 抓包
    print "capture start"
    ret = exec_process("pcap", "start", {"value": "p5p2#em1"})
    #ret = exec_capture_cmd("capture-start", {"value": "p5p2#em1"})
    print ret
    pid = ret["pid"]
    sleep(2)
    ret = exec_process("pcap", "status", {"pid": pid})
    #ret = exec_capture_cmd("capture-status", {"pid": pid})
    print ret
    sleep(5)
    ret = exec_process("pcap", "stop", {"pid": pid})
    #ret = exec_capture_cmd("capture-stop", {"pid": pid})
    print ret
    while(1):
        ret = exec_process("pcap", "status", {"pid": pid})
        #ret = exec_capture_cmd("capture-status", {"pid": pid})
        if ret["status"] == "end":
            break
        print ret
        sleep(2)

    # md5校验
    print "md5 start"
    ret = exec_process("md5", "start", {})
    while(1):
        ret = exec_process("md5", "status", {'pid': pid})
        #ret = exec_parse_cmd("analyse-status", {"pid": pid})
        if ret["status"] == "end":
            break
        sleep(2)
        print ret
    print "md5 end!"

    # 解析
    sleep(2)
    print "analyse start"
    ret = exec_process("parse", "start", {})
    #ret = exec_parse_cmd("analyse-start", {})
    print ret
    pid = ret["pid"]
    while(1):
        ret = exec_process("parse", "status", {'pid': pid})
        #ret = exec_parse_cmd("analyse-status", {"pid": pid})
        if ret["status"] == "end":
            break
        sleep(2)
        print ret
    print "parse end!"
