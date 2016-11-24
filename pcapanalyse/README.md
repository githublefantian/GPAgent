## 安装
1. 解压scapy、scapy-http压缩包，`python setup.py install`安装scapy、scapy-http包
2. `pip install py2exe`
3. 修改 *C:\Python34\Lib\site-packages\scapy\arch\windows\__init__.py* 函数 get_windows_if_list() 中的 ps， 修改为
`ps = sp.Popen(['powershell', '-NoProfile', 'Get-WMIObject -class Win32_NetworkAdapter', '|', 'select Name, @{Name="InterfaceIndex";Expression={$_.Index}}, @{Name="InterfaceDescription";Expression={$_.Description}},@{Name="InterfaceGuid";Expression={$_.GUID}}, @{Name="MacAddress";Expression={$_.MacAddress.Replace(":","-")}} | where InterfaceGuid -ne $null', '|', 'fl'], stdout = sp.PIPE, universal_newlines = True)`

## 运行
`python http-filiter-v2.3.py XX.pcap`
或者
`python mysetup.py py2exe` 进行打包,生成的文件在dist目录下