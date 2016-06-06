FROM scratch
MAINTAINER "Till Klocke"

RUN 

ADD user /
ADD certs /
ADD webroot /

VOLUME ["/certs"]
VOLUME ["/webroot"]

ADD ../letsencrypthelper /
CMD /letsencrypthelper -email $EMAIL -domain $DOMAINS