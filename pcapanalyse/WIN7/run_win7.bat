@echo off
title http-filter�������нű�(win7�汾)
setlocal enabledelayedexpansion
set SUFFIX=_http.pcap
set SEARCH_DIR=C:\
set SEARCH_SOFTWARE=editcap.exe
set SEARCH_RESULT=%TEMP%\editcap_path.tmp

::�ֶ�����editcap.exe·��
REM :begain
REM echo.
REM echo %date% %time%
REM set /p EDITCAP=�뽫editcap.exe����������ڣ������س�ȷ�ϣ���wireshrak.exe��ͬһĿ¼�£�:
REM :: echo %EDITCAP:~-11,11%

REM if ("%EDITCAP:~-12,11%" == "editcap.exe") (
    REM echo.
    REM echo ���򲻺Ϸ�!����
    REM goto begain
REM ) 
REM :: pause
REM echo.
REM echo ������ĳ���·��Ϊ��%EDITCAP%
REM echo.
REM choice /C 12 /N /M "ȷ���밴 1; ���������밴 2"��
REM if errorlevel 2 goto begain

::�Զ�����editcap.exe����
echo.
echo ��ʼ��ȡϵͳ��Ϣ����
IF NOT EXIST %SEARCH_RESULT% (
    WHERE /R %SEARCH_DIR% %SEARCH_SOFTWARE% > %SEARCH_RESULT%
)
FOR /F "DELIMS=" %%i in (%SEARCH_RESULT%) DO (
    IF "%%~ni%%~xi" == "editcap.exe" SET EDITCAP="%%i"
    IF "%%~ni%%~xi" == "Wireshark.exe" SET WIRESHARK="%%i"
)
ECHO ϵͳ��Ϣ��ȡ��ϡ���

echo.
echo ɾ��dist��ԭpcap�м��ļ�����
del .\dist\*.pcap > NUL

::��ȡ��ǰĿ¼�µ�pcapng�ļ����ļ������ܰ����ո񣩲�����editcapת��
echo.
echo %date% %time%
echo editcapת���С���
for /F %%i in ('dir /B *.pcapng') do (
    echo %EDITCAP% -F libpcap -T ether %%i .\dist\%%~ni.pcap
    %EDITCAP% -F libpcap -T ether %%i .\dist\%%~ni.pcap
)

::��ȡdistĿ¼�µ�pcap�ļ����ļ������ܰ����ո񣩲����й���tcpdump����
::URI:/bidimg/get.ashx?id=gggg ���� /imgs/
::tcp[20:2]=0x4854 ΪHTTPǰ������ĸ HT, ������Ӧ��
::tcp[25:4]=0x696d6773 Ϊ imgs , ����GET /imgs/
::tcp[30:4]=0x672f6765 Ϊ g/ge , ����GET /bidimg/get.ashx
echo.
echo %date% %time%
echo tcpdump�����С���
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
echo http-filter-v2.3.exe����ִ���С���
http-filter-v2.3.exe
if not errorlevel 1 (
    echo.
    echo ......����ִ�гɹ�,��鿴result.csv�ļ�......
    move /Y result.csv .. > NUL
)
move /Y *.log .. > NUL
echo.
echo %date% %time%
echo #############################################################
echo #########�뱣����ն�(CMD)��ִ�м�¼(���Ҽ���--��ȫѡ��)#########
echo #############################################################
set /P over=
set /P over=��������˳�...