
if %3% == java (call ./jadx/bin/jadx  %1 --output-dir %2\jadx-decompiled) else (call ./apktool/apktool d %1 -o %2/apktool_decompiled) 