FROM centos:7

COPY ./HP_Fortify/HP_Fortify_SCA_and_Apps_4.40 /opt/fortify_linux
ENV LANG en_US.utf8
RUN yum update -y
RUN yum install epel-release -y
RUN yum install -y  git curl wget python36 gcc python36-libs python36-tools python36-devel   zlib-devel rpm-build openssl-devel python

#这个是fortify的运行程序
RUN mkdir /data && mkdir /data/fortify && mkdir /data/fortify/report && chmod 777 /data -R
RUN chmod 777 -R /opt/fortify_linux/ && ln -s /opt/fortify_linux/bin/sourceanalyzer /usr/local/bin/sourceanalyzer && ln -s /opt/fortify_linux/bin/ReportGenerator /usr/local/bin/ReportGenerator

COPY ./cobra /code/
WORKDIR /code

RUN pip3 install -r requirements.txt -i https://pypi.douban.com/simple

EXPOSE 5000
CMD ["python3", "cobra.py", "-H", "0.0.0.0", "-P", "5000"]
