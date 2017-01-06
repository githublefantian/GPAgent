# -*- coding: utf-8 -*-
import os
from cmdmacro import *
from agentlog import agentlog


def parse_filesinfo_para(parad):
    if T_VALUE in parad:
        if parad[T_VALUE] == TRANS_LOG:
            parad[TRANS_SRC] = LOGD
        elif parad[T_VALUE] == TRANS_CSV:
            parad[TRANS_SRC] = RESULTD
        elif parad[T_VALUE] == TRANS_PCAP:
            parad[TRANS_SRC] = PCAPD
        elif parad[T_VALUE] == TRANS_FILTERPCAP:
            parad[TRANS_SRC] = FILTERPCAPD
        else:
            pass
    if TRANS_FILTER not in parad:
        parad[TRANS_FILTER] = ""


def appendfileinfo(result=[], path=""):
    info = {}
    info[FILEMTIME] = os.stat(path).st_mtime
    info[FILECTIME] = os.stat(path).st_ctime
    info[FILESIZE] = os.stat(path).st_size
    info[FILENAME] = os.path.basename(path)
    info[FILEPATH] = os.path.dirname(path)
    result.append(info)
    return


def addtransferfiles(str=""):
    if str == "":
        agentlog.info("addtransferfiles parameter is null!")
        return
    with open(os.path.join(AGENTD, TRANSFERTMP), 'a') as wf:
        wf.write(str + "\n")
    return


# 管理文件，filter用来限制文件对象(仅含指定内容的文件)
def managefiles(key, dirlist=[], filter=[]):
    flag = 0
    info = []
    count = 0

    if key == "":
        agentlog.error("managefiles key is null")
        return False

    for dir in dirlist:
        if dir == "":
            agentlog.error("%s: manage files parameter is null!" % key)
            raise AgentError("%s: manage files parameter is null!" % key)
        if os.path.isdir(dir):
            for filename in os.listdir(dir):
                for item in filter:
                    if item == "":
                        break
                    # 不包含关键字
                    if filename.find(item) == -1:
                        flag = 1
                        break
                if flag == 1:
                    flag = 0
                    continue
                #agentlog.debug("%s: manage file %s" % (key, os.path.join(dir, filename)))
                if key == FILETRANSKEY:
                    addtransferfiles(os.path.join(dir, filename))
                    count += 1
                elif key == FILEREMOVEKEY:
                    os.remove(os.path.join(dir, filename))
                elif key == FILEINFOKEY:
                    appendfileinfo(info, os.path.join(dir, filename))
                else:
                    pass
        elif os.path.isfile(dir):
            #agentlog.debug("%s: manage file %s" % (key, dir))
            if key == FILETRANSKEY:
                addtransferfiles(dir)
                count += 1
            elif key == FILEREMOVEKEY:
                os.remove(dir)
            elif key == FILEINFOKEY:
                appendfileinfo(info, dir)
            else:
                pass
        else:
            agentlog.error("%s manage files parameter error: %s" % (key, dir))

    if key == FILEINFOKEY:
        return info
    elif key == FILETRANSKEY:
        return count
    else:
        return True


