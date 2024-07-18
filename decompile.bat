@echo off
IF "%3" == "java" (
    
  CALL "./jadx/bin/jadx" %1 --output-dir %2\jadx_decompiled
) ELSE (
  (((CALL "./apktool/apktool.bat" d %1 -f -q -o %2\apktool_decompiled) |find /I "%~0")>nul)&&pause
)