FROM scratch
MAINTAINER "Till Klocke"

ADD user /
ADD certs /
ADD webroot /

VOLUME ["/certs"]
VOLUME ["/webroot"]

ADD ./letsencrypthelper-amd64 /

CMD [ "/letsencrypthelper-amd64", \
  "-accountKey", "/user/account.key", \
  "-certPath", "/certs/server.crt", \
  "-keyPath", "/certs/server.key", \
  "-webroot", "/webroot", \
  "-email", "$EMAIL", \
  "-domain", "$DOMAINS" ]
