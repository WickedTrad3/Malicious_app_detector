#run in linux
FROM ubuntu:22.04 as build1

WORKDIR /tools
RUN mkdir ./jadx ./apktool
RUN apt-get update && apt install default-jdk -y
COPY /jadx/bin ./jadx
COPY /apktool ./apktool
