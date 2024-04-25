FROM ubuntu:22.04
#reduces size by not installing reccomended images
RUN echo 'APT::Install-Suggests "0";' >> /etc/apt/apt.conf.d/00-docker
RUN echo 'APT::Install-Recommends "0";' >> /etc/apt/apt.conf.d/00-docker

WORKDIR /malicious_app_detector

RUN mkdir /var/run/sshd

RUN apt-get update && apt-get install -y openssh-server
RUN echo 'root:root' | chpasswd
# set to password instead
RUN sed -i 's/PermitRootLogin prohibit-password/PermitRootLogin yes/' /etc/ssh/sshd_config
# prevent issues with systemd
RUN sed 's@session\s*required\s*pam_loginuid.so@session optional pam_loginuid.so@g' -i /etc/pam.d/sshd

EXPOSE 22

RUN apt-get update
RUN apt-get -y install git

CMD ["/usr/sbin/sshd", "-D"]

# sudo docker run -d -p 2222:22 --name my_ssh_container my_ssh_image

# RUN git clone -n https://github.com/skylot/jadx.git
