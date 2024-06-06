#run in linux
FROM ubuntu:22.04 as build1

WORKDIR /Malicious_app_detector
#RUN mkdir ./jadx ./apktool
#change to 
COPY ["decompile.bat", "apktool/", "jadx/", "decompile.sh", "./"]
RUN apt-get update && apt install default-jdk -y
#COPY /jadx/bin ./jadx
#COPY /apktool ./apktool