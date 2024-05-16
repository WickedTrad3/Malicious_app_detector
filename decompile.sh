#! /bin/bash
echo "enter apk path to decompile:"
read apk

./jadx/bin/jadx.bat --output-dir ./ $apk
./apktool/apktool d $apk