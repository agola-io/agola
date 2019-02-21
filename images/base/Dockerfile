FROM debian:stable

ENV DEBIAN_FRONTEND noninteractive

# install git
RUN apt-get -y update && apt-get -y install git

# slim down image
RUN apt-get clean && rm -rf /var/lib/apt/lists/* /tmp/* /var/tmp/* /usr/share/man/?? /usr/share/man/??_*