@echo off
title http-filter程序运行脚本(win7版本)
setlocal enabledelayedexpansion
set SUFFIX=_http.pcap
set SEARCH_DIR=C:\
set SEARCH_SOFTWARE=editcap.exe
set SEARCH_RESULT=%TEMP%\editcap_path.tmp

::手动输入editcap.exe路径
REM :begain
REM echo.
REM echo %date% %time%
REM set /p EDITCAP=请将editcap.exe工具拖入框内，并按回车确认（与wireshrak.exe在同一目录下）:
REM :: echo %EDITCAP:~-11,11%

REM if ("%EDITCAP:~-12,11%" == "editcap.exe") (
    REM echo.
    REM echo 程序不合法!！！
    REM goto begain
REM ) 
REM :: pause
REM echo.
REM echo 您拖入的程序路径为：%EDITCAP%
REM echo.
REM choice /C 12 /N /M "确认请按 1; 重新拖入请按 2"：
REM if errorlevel 2 goto begain

::自动搜索editcap.exe工具
echo.
echo 开始读取系统信息……
IF NOT EXIST %SEARCH_RESULT% (
    WHERE /R %SEARCH_DIR% %SEARCH_SOFTWARE% > %SEARCH_RESULT%
)
FOR /F "DELIMS=" %%i in (%SEARCH_RESULT%) DO (
    IF "%%~ni%%~xi" == "editcap.exe" SET EDITCAP="%%i"
    IF "%%~ni%%~xi" == "Wireshark.exe" SET WIRESHARK="%%i"
)
ECHO 系统信息读取完毕……

echo.
echo 删除dist下原pcap中间文件……
del .\dist\*.pcap > NUL

::读取当前目录下的pcapng文件（文件名不能包含空格）并进行editcap转换
echo.
echo %date% %time%
echo editcap转换中……
for /F %%i in ('dir /B *.pcapng') do (
    echo %EDITCAP% -F libpcap -T ether %%i .\dist\%%~ni.pcap
    %EDITCAP% -F libpcap -T ether %%i .\dist\%%~ni.pcap
)

::读取dist目录下的pcap文件（文件名不能包含空格）并进行过滤tcpdump过滤
::URI:/bidimg/get.ashx?id=gggg 或者 /imgs/
::tcp[20:2]=0x4854 为HTTP前两个字母 HT, 过滤响应包
::tcp[25:4]=0x696d6773 为 imgs , 过滤GET /imgs/
::tcp[30:4]=0x672f6765 为 g/ge , 过滤GET /bidimg/get.ashx
echo.
echo %date% %time%
echo tcpdump过滤中……
cd dist
for /F %%i in ('dir /B *.pcap') do (
    echo tcpdump -r %%i -w %%~ni%SUFFIX% tcp[25:4]=0x696d6773 or tcp[20:2]=0x4854
    REM pause
    tcpdump -r %%i -w %%~ni%SUFFIX% tcp[20:2]=0x4854 or tcp[25:4]=0x696d6773 or tcp[30:4]=0x672f6765
    if errorlevel 1 (del %%~ni%SUFFIX% 2> NUL) else (del %%i)
)

::http-filter-v2.3.exe
echo.
echo %date% %time%
echo http-filter-v2.3.exe程序执行中……
http-filter-v2.3.exe
if not errorlevel 1 (
    echo.
    echo ......程序执行成功,请查看result.csv文件......
    move /Y result.csv .. > NUL
)
move /Y *.log .. > NUL
echo.
echo %date% %time%
echo #############################################################
echo #########请保存此终端(CMD)的执行记录(“右键”--“全选”)#########
echo #############################################################
set /P over=
set /P over=按任意键退出...