## ��װ
1. ��ѹscapy��scapy-httpѹ������`python setup.py install`��װscapy��scapy-http��
2. `pip install py2exe`
3. �޸� *C:\Python34\Lib\site-packages\scapy\arch\windows\__init__.py* ���� get_windows_if_list() �е� ps�� �޸�Ϊ
`ps = sp.Popen(['powershell', '-NoProfile', 'Get-WMIObject -class Win32_NetworkAdapter', '|', 'select Name, @{Name="InterfaceIndex";Expression={$_.Index}}, @{Name="InterfaceDescription";Expression={$_.Description}},@{Name="InterfaceGuid";Expression={$_.GUID}}, @{Name="MacAddress";Expression={$_.MacAddress.Replace(":","-")}} | where InterfaceGuid -ne $null', '|', 'fl'], stdout = sp.PIPE, universal_newlines = True)`

## ����
`python http-filiter-v2.3.py XX.pcap`
����
`python mysetup.py py2exe` ���д��,���ɵ��ļ���distĿ¼��