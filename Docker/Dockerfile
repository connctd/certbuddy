FROM scratch
MAINTAINER "Till Klocke"

ADD ca-certificates.crt /etc/ssl/certs/

ADD user /
ADD certs /
ADD webroot /

VOLUME ["/certs"]
VOLUME ["/webroot"]

ADD ./certbuddy /

ENTRYPOINT ["/certbuddy"]

CMD [ "-accountKey", "/user/account.key", \
  "-certPath", "/certs/server.crt", \
  "-keyPath", "/certs/server.key", \
  "-webroot", "/webroot", \
  "-email", "$EMAIL", \
  "-domains", "$DOMAINS" ]
