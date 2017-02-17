call "C:\Program Files (x86)\Microsoft Visual Studio 14.0\VC\vcvarsall.bat" x86
cd /d %~dp0
call chromium-gost-env.bat

set DATETIMEVERSION=%DATE:~3,1%
if "%DATETIMEVERSION%" == " " (
:: en-us
    set DATETIMEVERSION=%DATE:~10,4%,%DATE:~4,2%,%DATE:~7,2%,%TIME:~0,2%%TIME:~3,2%
) else (
:: ru-ru
    set DATETIMEVERSION=%DATE:~6,4%,%DATE:~3,2%,%DATE:~0,2%,%TIME:~0,2%%TIME:~3,2%
)

( echo #define DATETIMEVERSION %DATETIMEVERSION%) > esptun_ver.rc

cl /c /Ox /Os /GL /GF /GS- /W4 /EHsc ../include/espio/src/espio.cpp
cl /c /Ox /Os /GL /GF /GS- /W4 /EHsc ../include/soque/src/soque.cpp
cl /c /Ox /Ot /GL /GF /GS /W4 /EHa /I../include/espio/src /I../include/soque/src /I../include/netmap/sys /Iglue ../src/esptun.c
rc -r esptun.rc

link /LTCG espio.obj soque.obj esptun.obj esptun.res ws2_32.lib /subsystem:console /OUT:esptun.exe
timeout 60
