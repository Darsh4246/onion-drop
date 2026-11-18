FROM alpine:latest

RUN apk update && \
    apk add --no-cache tor && \
    rm -rf /var/cache/apk/*

# Prepare directory with tor user ownership
RUN mkdir -p /var/lib/tor/oniondrop_service && \
    chown -R tor:tor /var/lib/tor && \
    chmod 700 /var/lib/tor/oniondrop_service

COPY torrc /etc/tor/torrc

USER tor

CMD ["tor", "-f", "/etc/tor/torrc"]
