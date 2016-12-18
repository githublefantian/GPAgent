# -*- coding:utf-8 -*-

import logging
import logging.handlers
from cmdmacro import *
import os

class Cmy_logger(object):

    def __init__(self, logname, logger):
        # create logger
        self.logger = logging.getLogger(logger)
        self.logger.setLevel(logging.DEBUG)
        # for log file
        fh = logging.handlers.RotatingFileHandler(logname, maxBytes=30 * 1024 * 1024, backupCount=5)
        fh.setLevel(logging.DEBUG)
        # for teminal output
        ch = logging.StreamHandler()
        ch.setLevel(logging.DEBUG)
        formatter = logging.Formatter(
            '%(asctime)s - (%(processName)s|%(process)d,%(threadName)s|%(thread)d) - [%(filename)s:%(funcName)s():%(lineno)s] - [%('
            'name)s:%(lineno)s]\n  %(levelname)s: %(message)s')
        fh.setFormatter(formatter)
        ch.setFormatter(formatter)
        # add handler
        self.logger.addHandler(fh)
        self.logger.addHandler(ch)

    def getlog(self):
        return self.logger

agentlog = Cmy_logger(logname=(os.path.join(LOGD, AGENTLOGNAME)), logger="agent").getlog()
imagelog = Cmy_logger(logname=(os.path.join(LOGD, IMGLOGNAME)), logger="image").getlog()
mergelog = Cmy_logger(logname=(os.path.join(LOGD, IMGLOGNAME)), logger="merge").getlog()
