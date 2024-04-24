FROM ubuntu:22.04
#reduces size by not installing reccomended images
RUN echo 'APT::Install-Suggests "0";' >> /etc/apt/apt.conf.d/00-docker
RUN echo 'APT::Install-Recommends "0";' >> /etc/apt/apt.conf.d/00-docker

WORKDIR /malicious_app_detector

RUN apt-get update
RUN apt-get -y install git

RUN git clone -n https://github.com/skylot/jadx.git
