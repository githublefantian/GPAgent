## 功能
本程序是一个linux平台下的网络流量捕获、记录及分析程序（后台）。主要功能包括:

1. 系统信息查询，包括CPU、内存、磁盘信息，网卡信息、时间同步状态等
2. 实时网卡流量查询
3. 高性能数据包捕获，支持多网卡、定时抓包等功能
4. 数据包分析、过滤功能
5. syslog日志
6. 其他…………

## 部署
- 依赖

1. python 2.7, scapy库，psutil库
2. 工具：tcpdump, netsniff-ng, capinfos, md5sum

- 运行

1. 将程序拷贝至`/root/`目录下
2. 运行部署脚本`sh /root/agent/deploy.sh`
3. 等待程序自动启动或手动启动`python agent.py`手动启动

- 测试

1. 键入`curl -d "type=info&key=device-mem" http://10.10.88.173:1234`命令查询内存信息
2. 返回json数据结构

```
{
    "device-mem": 
    {
        "total": 67271380992, 
        "available": 65895313408,
        "percent": 2.0,
        "used": 1040871424, 
        "free": 65713377280, 
        "active": 254767104, 
        "inactive": 290430976, 
        "buffers": 1409024, 
        "cached": 515723264,
        "shared": 41504768
    }
}
```

- 使用

1. 详见*../UserManual/Post_Manual.xlsx*
2. 日志及程序运行结果存放在`/home/`下相应子目录中

- 打印

1. 程序默认均开启了日志重定向，包括脚本，查看实施打印`tail -f /home/log/agent.log`
2. 取消日志重定向，请修改*agent.env*中的`DEBUG="yes"`

## 架构
- 主要文件说明

|文件名|备注|
|:---|:---|
|deploy.sh|程序部署脚本，开机启动和cron job设置|
|agent.env|程序配置文件|
|agent.py|主程序|
|ports_statistics.c|端口流量统计信息pps|
|capture.sh|抓包脚本程序，可独立使用`sh capture.sh -h`|
|img_parse.sh|验证码分析，可独立使用|
|extract_pcap.sh|数据包提取，可独立使用|


- 配置修改

1. 见`agent.env`文件

- 手动测试

1. 测试时，先`make`，再`python agent.py`启动程序

## 其他
generate release version
`git archive --format=tar --prefix=1.0/ v1.0 | gzip > agent-1.0.tar.gz`

IMPORTANT: Please complie ports_statistics.c frist!  
1. `make`  
2. `python agent.py`  
