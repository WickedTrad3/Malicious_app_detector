#! /bin/bash
./jadx/bin/jadx $1 --output-dir $2/jadx_decompiled
./apktool/apktool d $1 -f -p $2/apktool_decompiled