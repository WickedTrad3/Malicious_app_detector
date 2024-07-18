#! /bin/bash

if [ $3 == "java" ]
then
./jadx/bin/jadx $1 --output-dir $2/jadx_decompiled
else
./apktool/apktool d $1 -o $2/apktool_decompiled
