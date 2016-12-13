# -*- coding: utf-8 -*-
# request command
# type=req&key=device-nic&value=p5p2#p5p1
# type=info&key=device-nic

# 默认的环境配置文件路径
DEFAULT_ENV = '/root/agent/agent.env'

T_TYPE = 'type'
TT_INFO = 'info' # 无需请求参数
TT_REQ = 'req' # 需要请求参数

TT_PCAP = 'pcap' # 抓包命令
TT_PARSE = 'parse' # 分析命令
TT_TRANS = 'trans' # 文件传输
TT_MD5 = 'md5'  # 计算md5校验值
TT_REMOVE = 'remove'  # 删除文件命令


T_KEY = 'key'
CPUKEY = 'device-cpu'
DISKKEY = 'device-disk'
MEMKEY= 'device-mem'
NICKEY = 'device-nic'
NTPKEY = 'ntp-status'
NICKEYRealTime = 'nic-traffic'
FILEINFOKEY = 'file-infos'
FILEREMOVEKEY = 'file-remove'
FILETRANSKEY = TT_TRANS

T_VALUE = 'value' # 多个值则以#号分开，如： p5p1#p5p1

# 文件信息查询
# type=req&key=log&filter=201209
# type=req&src=/home/filter&filter=201209#pcap
# 文件传输类型
# type=trans&key=log&dst=192.168.2.1:/home/&filter=201209
# type=trans&src=/home/filter&dst=192.168.2.1:/home/&filter=201209#pcap
TRANS_LOG = 'log'
TRANS_PCAP = 'pcap'
TRANS_CSV = 'csv'
TRANS_TMPPCAP = 'tmppcap'
TRANS_SRC = 'src'
TRANS_DST = 'dst'
TRANS_FILTER = 'filter'


# 进程状态
STATUS_KEY = 'status'
STATUS_RUN = 'running'
STATUS_END = 'end'
STATUS_SUCCESS = 'success'
PROCESS_PID = 'pid'

# 命令类型
PROCESS_START = 'start'
PROCESS_STATUS = 'status'
PROCESS_STOP = 'stop'

# 错误信息
ERROR_INFO = 'error-info'

# 文件信息
FILENAME = 'name'
FILESIZE = 'size'
FILECTIME = 'ctime'
FILEMTIME = 'mtime'
FILEPATH = 'path'



# 验证码响应类型分类
NO_NO_RESPONSE = 0          # 没有响应
NO_NORMAL_RESPONSE = 1      # 正常响应
NO_CODE_ERROR_RESPONSE = 2  # 状态码返回错误
NO_CT_ERROR_RESPONSE = 3    # content-type 类型错误(状态码200)

# 读取配置文件参数
LOGD = ''
RESULTD = ''
TMPPCAPD = ''
with open(DEFAULT_ENV, 'r') as envf:
    for line in envf.readlines():
        if line.startswith('LOG_DIR='):
            LOGD = line.replace('#', '=').split('=')[1].strip(' "\'\n')
        elif line.startswith('RESULT_DIR='):
            RESULTD = line.replace('#', '=').split('=')[1].strip(' "\'\n')
        elif line.startswith('PCAP_DIR='):
            PCAPD = line.replace('#', '=').split('=')[1].strip(' "\'\n')
        elif line.startswith('TMPPCAP_DIR='):
            TMPPCAPD = line.replace('#', '=').split('=')[1].strip(' "\'\n')
        elif line.startswith('SPLITOVERLAP='):
            SPLIT_OVERLAP = line.replace('#', '=').split('=')[1].strip(' "\'\n')
        elif line.startswith('AGENT_DIR='):
            AGENTD = line.replace('#', '=').split('=')[1].strip(' "\'\n')
        elif line.startswith('DEFAULTNICS='):
            DEFAULT_NICS = line.replace('#', '=').split('=')[1].strip(' "\'\n').split(' ')  # list
        elif line.startswith('TRANSFERTMP='):
            TRANSFERTMP = line.replace('#', '=').split('=')[1].strip(' "\'\n')  # list
        else:
            pass

if LOGD == '' or RESULTD == '' or TMPPCAPD == '' or AGENTD == '' or PCAPD == '':
    print("[ERROR] Read parameters from agent.env error!")
else:
    LOGD += '/'
    RESULTD += '/'
    TMPPCAPD += '/'
    AGENTD += '/'
    PCAPD += '/'

class AgentError(Exception):
    def __init__(self, value):
        self.value = value

    def __str__(self):
        return repr(self.value)

