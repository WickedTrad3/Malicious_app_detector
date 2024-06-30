
#run in linux
FROM ubuntu:22.04 as build1


#RUN mkdir ./jadx ./apktool
#change to 
COPY .\ .
WORKDIR /Malicious_app_detector
#COPY ["decompile.sh", "apktool/", "jadx/", "decompile.sh", "./"]
RUN apt-get update -y && apt install default-jdk -y && apt-get -y install python3-pip && apt-get install -y python3 && pip install argparse
#python not working
ENTRYPOINT ["python3","./main.py"]
#COPY /jadx/bin ./jadx
#COPY /apktool ./apktool
#download python and dependencies e.g argparse