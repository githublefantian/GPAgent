import logging
import logging.handlers
from cmdmacro import *
import os


def savelogcfg(ip, port):
    with open(os.path.join(AGENTD, SYSLOGCFG), 'w') as f:
        f.write("IP=%s\nPORT=%d" % (ip, port))


def readlogcfg():
    ip = 'localhost'
    port = 514
    if os.path.exists(os.path.join(AGENTD, SYSLOGCFG)):
        with open(os.path.join(AGENTD, SYSLOGCFG), 'r') as f:
            for line in f.readlines():
                if line.startswith('IP'):
                    ip = line.replace('#', '=').split('=')[1].strip(' "\'\n')
                elif line.startswith('PORT'):
                    port = int(line.replace('#', '=').split('=')[1].strip(' "\'\n'))
                else:
                    pass

    return ip, port


class Cmy_logger(object):

    def __init__(self, logname, logger):
        # create logger
        self.logger = logging.getLogger(logger)
        self.logger.setLevel(logging.DEBUG)
        # for remote unix syslog
        rh = logging.handlers.SysLogHandler(address=readlogcfg())
        #(ip, port) = readlogcfg()
        #rh = logging.handlers.SocketHandler(ip, port)
        rh.setLevel(logging.DEBUG)
        # for log file
        fh = logging.handlers.RotatingFileHandler(logname, maxBytes=30 * 1024 * 1024, backupCount=5)
        fh.setLevel(logging.DEBUG)
        # for teminal output
        ch = logging.StreamHandler()
        ch.setLevel(logging.DEBUG)
        # set formatter
        formatter = logging.Formatter(
            '%(asctime)s - (%(processName)s|%(process)d,%(threadName)s|%(thread)d) - [%(filename)s:%(funcName)s():%(lineno)s] - [%('
            'name)s:%(lineno)s]\n  %(levelname)s: %(message)s')
        rh.setFormatter(formatter)
        fh.setFormatter(formatter)
        ch.setFormatter(formatter)
        # add handler
        self.logger.addHandler(rh)
        self.logger.addHandler(fh)
        self.logger.addHandler(ch)

    def getlog(self):
        return self.logger


agentlog = Cmy_logger(logname=(os.path.join(LOGD, AGENTLOGNAME)), logger=(IP_PREFIX + "agent")).getlog()
imagelog = Cmy_logger(logname=(os.path.join(LOGD, IMGLOGNAME)), logger=(IP_PREFIX + "image")).getlog()
mergelog = Cmy_logger(logname=(os.path.join(LOGD, IMGLOGNAME)), logger=(IP_PREFIX + "merge")).getlog()
alllogs = (agentlog, imagelog, mergelog)


def getlogaddress():
    global agentlog
    for lh in agentlog.handlers:
        if isinstance(lh, logging.handlers.SysLogHandler):
            return lh.address
    return None


def changelogaddress(ip, port):
    global alllogs
    global agentlog

    oldaddress = getlogaddress()
    if (not isinstance(ip, str)) or (not isinstance(port, int)):
        agentlog.error("ip & port type error(str&int)!")
        return False
    if oldaddress and oldaddress[0] == ip and oldaddress[1] == port:
        agentlog.warning("ip & port repeat!")
        return False

    try:
        for curlog in alllogs:
            loglist = curlog.handlers
            for logh in loglist:
                if isinstance(logh, logging.handlers.SysLogHandler):
                #if isinstance(logh, logging.handlers.SocketHandler):
                    # for remote unix syslog
                    rh = logging.handlers.SysLogHandler(address=(ip, port))
                    rh.setLevel(logging.DEBUG)
                    # set formatter
                    formatter = logging.Formatter(
                        '%(asctime)s - (%(processName)s|%(process)d,%(threadName)s|%(thread)d) - [%(filename)s:%(funcName)s():%(lineno)s] - [%('
                        'name)s:%(lineno)s]\n  %(levelname)s: %(message)s')
                    rh.setFormatter(formatter)
                    # add handler
                    curlog.addHandler(rh)
                    # remove handler
                    curlog.removeHandler(logh)
                    savelogcfg(ip, port)
                    break
    except Exception as e:
        agentlog.error(e)
        return False

    return True


if __name__ == "__main__":
    for testlog in alllogs:
        print getlogaddress()
    changelogaddress("10.10.10.8", 12345)
    for testlog in alllogs:
        print getlogaddress()
