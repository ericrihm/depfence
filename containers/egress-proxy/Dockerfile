# syntax=docker/dockerfile:1.7@sha256:a57df69d0ea827fb7266491f2813635de6f17269be881f696fbfdf2d83dda33e
FROM python:3.12.11-slim-bookworm@sha256:519591d6871b7bc437060736b9f7456b8731f1499a57e22e6c285135ae657bf7
RUN apt-get update \
    && apt-get install --yes --no-install-recommends ca-certificates squid \
    && rm -rf /var/lib/apt/lists/* /var/cache/apt/* \
    && mkdir -p /var/log/squid /var/spool/squid /run/squid \
    && chown -R proxy:proxy /var/log/squid /var/spool/squid /run/squid
COPY --chmod=0444 containers/egress-proxy/squid.conf /etc/squid/squid.conf
USER proxy
EXPOSE 3128
ENTRYPOINT ["squid", "-N", "-f", "/etc/squid/squid.conf"]

