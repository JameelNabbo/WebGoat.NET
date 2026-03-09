# Vulnerable Dockerfile - Multiple security issues

FROM ubuntu:latest

ENV DB_PASSWORD=SuperSecret123!
ENV API_KEY=AKIAIOSFODNN7EXAMPLE
ARG ADMIN_TOKEN=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9

RUN apt-get update && apt-get install -y curl wget python3 openssh-server

RUN curl https://some-script.com/install.sh | bash

RUN chmod 777 /app

ADD . /app

COPY .env /app/.env
COPY id_rsa /app/keys/

EXPOSE 22
EXPOSE 80
EXPOSE 443
EXPOSE 3306
EXPOSE 5900

WORKDIR relative/path

RUN wget --no-check-certificate https://untrusted.com/binary

# No USER directive - runs as root
# No HEALTHCHECK
