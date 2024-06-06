#! /bin/bash
echo "enter apk path to decompile:"
read apk

./jadx/bin/jadx $apk --output-dir ./
./apktool/apktool d $apk -f -p ./