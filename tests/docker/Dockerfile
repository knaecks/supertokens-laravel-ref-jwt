FROM ubuntu:16.04

RUN apt-get update && apt-get upgrade -y

RUN apt-get install build-essential -y

RUN echo "mysql-server mysql-server/root_password password root" | debconf-set-selections

RUN echo "mysql-server mysql-server/root_password_again password root" | debconf-set-selections

RUN apt install mysql-server -y

RUN usermod -d /var/lib/mysql/ mysql

RUN mkdir /var/run/mysqld

ADD ./runMySQL.sh /runMySQL.sh

RUN chmod +x /runMySQL.sh

RUN apt-get install git-core -y

RUN apt-get install software-properties-common python-software-properties -y

RUN apt-get update

RUN LC_ALL=C.UTF-8 add-apt-repository -y ppa:ondrej/php

RUN apt-get update

RUN apt-get install php7.2 php7.2-cli php7.2-common -y

RUN apt-get install php7.2-curl php7.2-gd php7.2-json php7.2-mbstring php7.2-intl php7.2-mysql php7.2-xml php7.2-zip -y

RUN cd /tmp

RUN apt-get install curl -y

RUN curl -sS https://getcomposer.org/installer | php

RUN mv composer.phar /usr/local/bin/composer

RUN composer global require "laravel/installer=~1.1"

RUN composer global require hirak/prestissimo