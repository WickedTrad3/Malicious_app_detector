

call .\bin\jadx  %1 --output-dir .\jadx-decompiled
call .\apktool d %1 -f -p .\apktool-decompiled