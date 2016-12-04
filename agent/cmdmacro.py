# -*- coding: utf-8 -*-

# request command
# type=req&key=device-nic&value=p5p2#p5p1
# type=info&key=device-nic

# 默认的环境配置文件路径
DEFAULT_ENV = '/root/agent/agent.env'

T_TYPE = 'type'
TT_INFO = 'info' # 无需请求参数
TT_REQ = 'req' # 需要请求参数

T_KEY = 'key'
CPUKEY = 'device-cpu'
DISKKEY = 'device-disk'
MEMKEY= 'device-mem'
NICKEY = 'device-nic'
NTPKEY = 'ntp-status'
NICKEYRealTime = 'nic-traffic'

T_VALUE = 'value' # 多个值则以#号分开，如： p5p1#p5p1


# 验证码响应类型分类
NO_NO_RESPONSE = 0          # 没有响应
NO_NORMAL_RESPONSE = 1      # 正常响应
NO_CODE_ERROR_RESPONSE = 2  # 状态码返回错误
NO_CT_ERROR_RESPONSE = 3    # content-type 类型错误(状态码200)
