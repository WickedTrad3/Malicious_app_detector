
set /P apk = enter apk path to decompile:

.\jadx\binjadx.bat --output-dir .\ %apk%
.\apktool\apktool d %apk%