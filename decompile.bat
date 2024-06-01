
set /P apk = enter apk path to decompile:

.\jadx\bin\jadx.bat --output-dir .\ %apk%
.\apktool\apktool d %apk%