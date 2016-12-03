## 抓包脚本使用说明

### 工具介绍
1. 脚本工具：capture.sh

2. 参数说明：
命令行输入 `./capture.sh -h` 可查看简要介绍
Usage:
 -d: duration_time(seconds)
 -s: start_time(timestamp or 12:00:30 format)
 -e: end_time(timestamp)
 -n: nic devices
 -o: output directory
 -h: show help information
具体参数说明如下(均为可选参数)：
`-d`: 表示抓包持续时间，以秒为单位(支持且仅支持`*`运算)，如抓包2小时可表示为 `-d 7200` 或 `-d 2*3600` 或 `2*60*60`
`-s`: 表示抓包开始时间，可以是时间戳(timestamp)，也可以是`HH:MM:SS`时间格式(默认日期为当天)，如9点开始抓包可表示为 `-d 09:00:00`
`-e`: 表示抓包结束时间，只能是时间戳(timestamp)，建议结合使用 `-s` 和 `-d` 参数
`-n`: 表示需要抓包的网卡，多个网卡要以逗号隔开，如同时抓网卡p2p1和p2p2的包，则可表示为 `-n p2p1,p2p2`
`-o`: 表示抓包文件的存放目录，生成的文件名格式为 "日期_开始时间_网卡名.pcap", 如 "20161118_185000_p2p1.pcap"
`-h`: 显示帮助信息

3. 默认设置：(上述所有参数均为可选参数)
默认参数设置如下，若要修改请直接编辑 `capture.sh` 文件
- 默认抓包网卡: `p2p1 p2p2 p2p3`
- 默认抓包持续时间: `86400` 秒，即24小时（24*60*60）
- 默认抓包文件存放目录: `/backup/`
- 默认日志目录: `/backup/log/` （存放日志文件的目录）
- 默认日志文件名: `capture.log` （可 `tail -f /backup/log/capture.log` 实时查看日志信息）
- 默认临时文件存放目录：`/backup/tmp/` （存放抓包结果信息）


### 常用举例
1. 手动启动抓包
- `./capture.sh` 在默认网卡上抓包 (退出按 `Ctrl+C`, 若不退出，则持续抓包24小时后自动退出)
- `./capture.sh -n p2p1` 仅在网卡p2p1上抓包 (退出按 `Ctrl+C`, 若不退出，则持续抓包24小时后自动退出)
- `./capture.sh -n p2p1 -d 3600` 抓包一小时后自动停止 (中途退出按 `Ctrl+C`)
- `./capture.sh -n p2p1 -d 3600 -o /home/` 抓包文件存放在/home/目录下

2. 定时启动抓包
- `./capture.sh -s 09:00:00 -d 3*60*60` 定时上午9点启动抓包，且抓包3小时后自动停止
- `./capture.sh -s 09:00:00 -d 3*3600 -n p2p1` 上午9点到12点定时对网卡p2p1进行抓包
- `./capture.sh -s 09:00:00 -d 3*3600 -n p2p1 -o /home/`

3. 抓包文件默认存放在`/backup/`目录下，`tail -f /backup/log/capture.log` 实时查看日志记录