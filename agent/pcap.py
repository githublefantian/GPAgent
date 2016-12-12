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
        if type == CAPTURE_STATUS:
            (status, output) = commands.getstatusoutput('ps aux | grep capture.sh | grep -v grep')
        elif type == PARSE_STATUS:
            (status, output) = commands.getstatusoutput('ps aux | grep img_parse.sh | grep -v grep')
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




def exec_parse_cmd(key, parad):
    if key == PARSE_STATUS:
        if PARSE_PID in parad:
            ret, info = getPIDinfo(int(parad[PARSE_PID]), key)
            if not ret:
                raise AgentError(PARSE_STATUS + ": " + info)
            else:
                if info:
                    return {STATUS_KEY: STATUS_RUN}
                else:
                    return {STATUS_KEY: STATUS_END}
        else:
            return AgentError(PARSE_STATUS + ' : lack of PARSE PID info. ')
    elif key == PARSE_STOP:
        if PARSE_PID not in parad:
            raise AgentError(PARSE_STOP + " : lack of PARSE PID info.")
        else:
            ret, info = stopprocess(int(parad[PARSE_PID]))
            if not ret:
                raise AgentError(PARSE_STOP + " : " + info)
            else:
                return {STATUS_KEY: STATUS_SUCCESS}
    elif key == PARSE_START:
        if T_VALUE not in parad:
            cmd = AGENTD + "img_parse.sh -d"
        else:
            pass
        ret, pid = startcmd(cmd)
        if not ret:
            raise AgentError(PARSE_START + " : failed!")
        else:
            return {PARSE_PID: str(pid)}
    else:
        raise AgentError(key + ": error type")
        pass


def exec_capture_cmd(key, parad):
    if key == CAPTURE_STATUS:
        if CAPTURE_PID in parad:
            ret, info = getPIDinfo(int(parad[CAPTURE_PID]), key)
            if not ret:
                raise AgentError(CAPTURE_STATUS + " : " + info)
            else:
                if info:
                    return {STATUS_KEY: STATUS_RUN}
                else:
                    return {STATUS_KEY: STATUS_END}
        else:
            return AgentError(CAPTURE_STATUS + 'lack of CAPTURE PID info. ')
    elif key == CAPTURE_STOP:
        if CAPTURE_PID not in parad:
            raise AgentError(CAPTURE_STOP + ": lack of CAPTURE PID info.")
        else:
            ret, info = stopprocess(int(parad[CAPTURE_PID]))
            if not ret:
                raise AgentError(CAPTURE_STOP + info)
            else:
                return {STATUS_KEY: STATUS_SUCCESS}
    elif key == CAPTURE_START:
        if T_VALUE not in parad:
            cmd = AGENTD + 'capture.sh'
        else:
            nics = parad[T_VALUE].replace('#', ',')
            cmd = AGENTD + 'capture.sh' + ' -n ' + nics
            pass
        ret, pid = startcmd(cmd)
        if not ret:
            raise AgentError(CAPTURE_START + "failed!")
        else:
            return {CAPTURE_PID: str(pid)}
    else:
        raise AgentError(key + ": error type")
        pass


def exec_transfer_cmd():
    pass



if __name__ == "__main__":
    from time import sleep

    # 抓包
    print "capture start"
    ret = exec_capture_cmd("capture-start", {"value": "p5p2#em1"})
    print ret
    pid = ret["pid"]
    sleep(2)
    ret = exec_capture_cmd("capture-status", {"pid": pid})
    print ret
    sleep(5)
    ret = exec_capture_cmd("capture-stop", {"pid": pid})
    print ret
    while(1):
        ret = exec_capture_cmd("capture-status", {"pid": pid})
        if ret["status"] == "end":
            break
        print ret
        sleep(2)

    # 解析
    sleep(2)
    print "analyse start"
    ret = exec_parse_cmd("analyse-start", {})
    print ret
    pid = ret["pid"]
    while(1):
        ret = exec_parse_cmd("analyse-status", {"pid": pid})
        if ret["status"] == "end":
            break
        sleep(2)
        print ret
    print "parse end!"
