FROM alpine:latest
LABEL MAINTENER="Jose Neto - jvnetobr@fedoraproject.org"

ENV \
  NGINX_AUTOINDEX=off \
  NGINX_ACCESS_LOG_LEVEL=custom \
  NGINX_CLIENT_MAX_BODY_SIZE=10M \
  NGINX_ERROR_LOG_LEVEL=notice \
  NGINX_ETAG=off \
  NGINX_FIX_DOCUMENT_ROOT_PERMISSIONS=off \
  NGINX_HTTPS_REDIRECT=on \
  NGINX_KEEPALIVE_TIMEOUT=60 \
  NGINX_ROBOTS_PERMISSION="deny all;" \
  NGINX_SENDFILE=on \
  NGINX_SERVER_HEADER="" \
  NGINX_SERVER_TOKENS=off \
  NGINX_SSL_ACCEPT_PROTOCOLS="TLSv1.2 TLSv1.3" \
  NGINX_SSL_CIPHERS="ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:DHE-RSA-AES128-GCM-SHA256:DHE-RSA-AES256-GCM-SHA384" \
  NGINX_SSL_HSTS_MAX_AGE=31536000 \
  NGINX_SSL_HTTP_VERSION="" \
  NGINX_SSL_PREF_SERVER_CIPHERS=on \
  NGINX_SSL_SESSION_CACHE=1M \
  NGINX_SSL_SESSION_TICKETS=off \
  NGINX_SSL_SESSION_TIMEOUT=1h \
  NGINX_STUB_STATUS_PERMISSION="allow 127.0.0.0/24; deny all;" \
  NGINX_TCP_NOPUSH=on \
  NGINX_WORKER_CONNECTIONS=150 \
  NGINX_WORKER_PROCESS=auto \
  TZ=America/Fortaleza

COPY ./appends/entrypoint.sh /entrypoint.sh
COPY ./appends/favicon.ico /root/

RUN \
  apk add -q --no-cache \
    acl \
    curl \
    gettext \
    moreutils \
    nginx \
    nginx-mod-http-headers-more \
    openssl \
    tzdata && \
  rm /etc/nginx/nginx.conf && \
  rm /etc/nginx/http.d/*.conf && \
  chmod 750 /entrypoint.sh

WORKDIR /root
EXPOSE 80/tcp 443/tcp
ENTRYPOINT [ "/entrypoint.sh" ]
CMD [ "nginx", "-g", "daemon off;" ]
HEALTHCHECK --interval=15s --timeout=5s --retries=3 CMD curl -k --silent --fail https://127.0.0.1/nginx-status