FROM scratch
MAINTAINER "Till Klocke"

ADD user /
ADD certs /
ADD webroot /

VOLUME ["/certs"]
VOLUME ["/webroot"]

ADD ./certbuddy-amd64 /

CMD [ "/certbuddy-amd64", \
  "-accountKey", "/user/account.key", \
  "-certPath", "/certs/server.crt", \
  "-keyPath", "/certs/server.key", \
  "-webroot", "/webroot", \
  "-email", "$EMAIL", \
  "-domain", "$DOMAINS" ]
