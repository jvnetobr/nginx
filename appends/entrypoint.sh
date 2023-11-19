#!/bin/sh -e

NGINX_CONF_DIR=/etc/nginx
NGINX_CONF_FILE=$NGINX_CONF_DIR/nginx.conf
NGINX_SSL_CERTS_DIR=$NGINX_CONF_DIR/ssl-certs
NGINX_SBS_DIR=$NGINX_CONF_DIR/http.d
NGINX_SB_DEFAULT_CONF_FILE=$NGINX_SBS_DIR/default.conf
NGINX_SBS_INCLUDES_DIR=$NGINX_SBS_DIR/includes
NGINX_SBS_INCLUDES_SSL_CONF_FILE=$NGINX_SBS_INCLUDES_DIR/default-ssl.conf
NGINX_SBS_INCLUDES_ERROR_PAGES_CONF_FILE=$NGINX_SBS_INCLUDES_DIR/default-error-pages.conf
NGINX_SBS_INCLUDES_LOCATIONS_CONF_FILE=$NGINX_SBS_INCLUDES_DIR/default-locations.conf
NGINX_WWW_BASE_DIR=/var/www/html
NGINX_STATICS_DIR=$NGINX_WWW_BASE_DIR/static
NGINX_DOCUMENT_ROOT=$NGINX_WWW_BASE_DIR/public
NGINX_DEFAULT_RUN_USER=nginx
ENV_VARS=$(awk 'BEGIN{for(v in ENVIRON) print "$"v}')

echo -e "--- Entrypoint iniciado ---\n" && \

if [ ! -f /etc/localtime ]; then
  echo -e "Definindo timezone do sistema...\n" && \
  ln -s /usr/share/zoneinfo/$(echo $TZ) /etc/localtime;
fi

echo -e "Criando diretorio(s) default...\n" && \
  mkdir -p $NGINX_STATICS_DIR && \
  echo -e "Atribuindo permissoes no(s) diretorio(s) default...\n" && \
  chown -R $NGINX_DEFAULT_RUN_USER $NGINX_STATICS_DIR

if [ ! -d $NGINX_DOCUMENT_ROOT ]; then
  echo -e "Criando diretorio DOCUMENT_ROOT...\n" && \
    mkdir -p $NGINX_DOCUMENT_ROOT && \
    echo -e "<html><h3>server on...</h3></html>" > $NGINX_STATICS_DIR/index.html && \
    ln -sf $NGINX_STATICS_DIR/index.html $NGINX_STATICS_DIR/index.htm && \
    mv /root/favicon.ico $NGINX_STATICS_DIR/favicon.ico;
fi

if [ $NGINX_FIX_DOCUMENT_ROOT_PERMISSIONS == "on" ];then
  echo -e "Corrigindo permissoes do diretorio DOCUMENT_ROOT via ACL (isto pode demorar)...\n" && \
  setfacl -R -m u:$NGINX_DEFAULT_RUN_USER:rwx $NGINX_DOCUMENT_ROOT;
fi

if [ ! -f $NGINX_CONF_FILE ]; then
  echo -e "Gerando arquivo de configuração padrao do Nginx...\n" && \
  cat > $NGINX_CONF_FILE <<EOF
user $NGINX_DEFAULT_RUN_USER;
worker_processes \${NGINX_WORKER_PROCESS};
pid /var/run/nginx.pid;
load_module modules/ngx_http_headers_more_filter_module.so;

events {
	worker_connections \${NGINX_WORKER_CONNECTIONS};
}

http {
    autoindex \${NGINX_AUTOINDEX};
    client_max_body_size \${NGINX_CLIENT_MAX_BODY_SIZE};
    default_type application/octet-stream;
    etag \${NGINX_ETAG};
    include $NGINX_SBS_DIR/*.conf;
    include $NGINX_CONF_DIR/mime.types;
    keepalive_timeout \${NGINX_KEEPALIVE_TIMEOUT};
    more_set_headers "Server: \${NGINX_SERVER_HEADER}";
    sendfile \${NGINX_SENDFILE};
    server_tokens \${NGINX_SERVER_TOKENS};
    sub_filter 'nginx' '\${NGINX_SERVER_HEADER}';
    tcp_nopush \${NGINX_TCP_NOPUSH};
	
    log_format custom '\$realip \$scheme://\$http_host:\$server_port '
      '"\$time_local" "\$request" \$status '
      '\$body_bytes_sent "\$http_referer" "\$http_user_agent" '
      '\$request_time';
    
    access_log /proc/self/fd/1 \${NGINX_ACCESS_LOG_LEVEL};
    error_log /proc/self/fd/2 \${NGINX_ERROR_LOG_LEVEL};
}
EOF
echo -e "Substituindo variaveis...\n"
  envsubst "$ENV_VARS" < $NGINX_CONF_FILE | sponge $NGINX_CONF_FILE;
fi

if [ ! -f $NGINX_SB_DEFAULT_CONF_FILE ]; then
  echo -e "Gerando arquivo de configuração server block default..." && \
  cat > $NGINX_SB_DEFAULT_CONF_FILE <<EOF
index index.htm index.html;
root $NGINX_DOCUMENT_ROOT;

server {
  listen 80 default_server;
  server_name \${HOSTNAME};
 
  set \$realip \$remote_addr;
  if (\$http_x_forwarded_for ~ "^(\d+\.\d+\.\d+\.\d+)") {
    set \$realip \$1;
  }
  if (\$http_x_forwarded_for ~ "^(([0-9a-fA-F]{1,4}:){7,7}[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,7}:|([0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,5}(:[0-9a-fA-F]{1,4}){1,2}|([0-9a-fA-F]{1,4}:){1,4}(:[0-9a-fA-F]{1,4}){1,3}|([0-9a-fA-F]{1,4}:){1,3}(:[0-9a-fA-F]{1,4}){1,4}|([0-9a-fA-F]{1,4}:){1,2}(:[0-9a-fA-F]{1,4}){1,5}|[0-9a-fA-F]{1,4}:((:[0-9a-fA-F]{1,4}){1,6})|:((:[0-9a-fA-F]{1,4}){1,7}|:)|fe80:(:[0-9a-fA-F]{0,4}){0,4}%[0-9a-zA-Z]{1,}|::(ffff(:0{1,4}){0,1}:){0,1}((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])|([0-9a-fA-F]{1,4}:){1,4}:((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9]))") {
    set \$realip \$1;
  }

  set \$https_redirect \${NGINX_HTTPS_REDIRECT};
  if (\$https_redirect = "on") {
    return 301 https://\$host\$request_uri;
  }
  
  include $NGINX_SBS_INCLUDES_DIR/*.conf;
}

server {
  listen 443 ssl \${NGINX_SSL_HTTP_VERSION};
  server_name \${HOSTNAME};
  
  set \$realip \$remote_addr;
  if (\$http_x_forwarded_for ~ "^(\d+\.\d+\.\d+\.\d+)") {
    set \$realip \$1;
  }
  if (\$http_x_forwarded_for ~ "^(([0-9a-fA-F]{1,4}:){7,7}[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,7}:|([0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,5}(:[0-9a-fA-F]{1,4}){1,2}|([0-9a-fA-F]{1,4}:){1,4}(:[0-9a-fA-F]{1,4}){1,3}|([0-9a-fA-F]{1,4}:){1,3}(:[0-9a-fA-F]{1,4}){1,4}|([0-9a-fA-F]{1,4}:){1,2}(:[0-9a-fA-F]{1,4}){1,5}|[0-9a-fA-F]{1,4}:((:[0-9a-fA-F]{1,4}){1,6})|:((:[0-9a-fA-F]{1,4}){1,7}|:)|fe80:(:[0-9a-fA-F]{0,4}){0,4}%[0-9a-zA-Z]{1,}|::(ffff(:0{1,4}){0,1}:){0,1}((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])|([0-9a-fA-F]{1,4}:){1,4}:((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9]))") {
    set \$realip \$1;
  }

  include $NGINX_SBS_INCLUDES_DIR/*.conf;
}
EOF
  echo -e "Substituindo variaveis...\n"
  envsubst "$ENV_VARS" < $NGINX_SB_DEFAULT_CONF_FILE | sponge $NGINX_SB_DEFAULT_CONF_FILE;
fi

if [ ! -d $NGINX_SBS_INCLUDES_DIR ]; then
  echo -e "Criando diretorio de includes para server blocks...\n" && \
  mkdir -p $NGINX_SBS_INCLUDES_DIR;
fi

echo -e "Gerando certificados SSL...\n" && \
  mkdir -p $NGINX_SSL_CERTS_DIR && \
  openssl req -new -newkey rsa:2048 -days 3650 -nodes -x509 -subj "/CN=$HOSTNAME" \
    -keyout $NGINX_SSL_CERTS_DIR/private.key -out $NGINX_SSL_CERTS_DIR/public.crt > /dev/null 2>&1 

if [ ! -f $NGINX_SBS_INCLUDES_SSL_CONF_FILE ]; then
  echo -e "Gerando arquivos de includes para server block default, config SSL default ..." && \
  cat > $NGINX_SBS_INCLUDES_SSL_CONF_FILE <<EOF
add_header Strict-Transport-Security "max-age=\${NGINX_SSL_HSTS_MAX_AGE}; includeSubDomains" always;
ssl_certificate $NGINX_SSL_CERTS_DIR/public.crt;
ssl_certificate_key $NGINX_SSL_CERTS_DIR/private.key;
ssl_ciphers \${NGINX_SSL_CIPHERS};
ssl_prefer_server_ciphers \${NGINX_SSL_PREF_SERVER_CIPHERS};
ssl_protocols \${NGINX_SSL_ACCEPT_PROTOCOLS};
ssl_session_cache shared:SSL:\${NGINX_SSL_SESSION_CACHE};
ssl_session_tickets \${NGINX_SSL_SESSION_TICKETS};
ssl_session_timeout \${NGINX_SSL_SESSION_TIMEOUT};
EOF
echo -e "Substituindo variaveis...\n"
  envsubst "$ENV_VARS" < $NGINX_SBS_INCLUDES_SSL_CONF_FILE | sponge $NGINX_SBS_INCLUDES_SSL_CONF_FILE;
fi

if [ ! -f $NGINX_SBS_INCLUDES_ERROR_PAGES_CONF_FILE ]; then
  echo -e "Gerando arquivos de includes para server block default, secao paginas de erro default..." && \
  cat > $NGINX_SBS_INCLUDES_ERROR_PAGES_CONF_FILE <<EOF
error_page 400 /400.html;
location = /400.html { root $NGINX_STATICS_DIR; }
error_page 401 /401.html;
location = /401.html { root $NGINX_STATICS_DIR; }
error_page 403 /403.html;
location = /403.html { root $NGINX_STATICS_DIR; }
error_page 404 /404.html;
location = /404.html { root $NGINX_STATICS_DIR; }
error_page 405 /405.html;
location = /405.html { root $NGINX_STATICS_DIR; }
error_page 413 /413.html;
location = /413.html { root $NGINX_STATICS_DIR; }
error_page 497 /497.html;
location = /497.html { root $NGINX_STATICS_DIR; }
error_page 500 /500.html;
location = /500.html { root $NGINX_STATICS_DIR; }
error_page 502 /502.html;
location = /502.html { root $NGINX_STATICS_DIR; }
error_page 503 /503.html;
location = /503.html { root $NGINX_STATICS_DIR; }
error_page 504 /504.html;
location = /504.html { root $NGINX_STATICS_DIR; }
EOF
echo -e "Substituindo variaveis...\n"
  envsubst "$ENV_VARS" < $NGINX_SBS_INCLUDES_ERROR_PAGES_CONF_FILE | sponge $NGINX_SBS_INCLUDES_ERROR_PAGES_CONF_FILE;
fi

echo -e "Gerando paginas HTML de erro estaticas...\n" && \
  COD="400 401 403 404 405 413 497 500 502 503 504" && \
  for C in $COD; do
    touch $NGINX_STATICS_DIR/$C.html
    if [ $C -eq "400" ]; then echo -e "<html><h3>$C Bad Request</h3></html>" > $NGINX_STATICS_DIR/$C.html; fi
    if [ $C -eq "401" ]; then echo -e "<html><h3>$C Unauthorized</h3></html>" > $NGINX_STATICS_DIR/$C.html; fi
    if [ $C -eq "403" ]; then echo -e "<html><h3>$C Forbidden</h3></html>" > $NGINX_STATICS_DIR/$C.html; fi
    if [ $C -eq "404" ]; then echo -e "<html><h3>$C Not found</h3></html>" > $NGINX_STATICS_DIR/$C.html; fi
    if [ $C -eq "405" ]; then echo -e "<html><h3>$C Method not allowed</h3></html>" > $NGINX_STATICS_DIR/$C.html; fi
    if [ $C -eq "413" ]; then echo -e "<html><h3>$C Large payload</h3></html>" > $NGINX_STATICS_DIR/$C.html; fi
    if [ $C -eq "497" ]; then echo -e "<html><h3>$C Internal error</h3></html>" > $NGINX_STATICS_DIR/$C.html; fi
    if [ $C -eq "500" ]; then echo -e "<html><h3>$C Internal error</h3></html>" > $NGINX_STATICS_DIR/$C.html; fi
    if [ $C -eq "502" ]; then echo -e "<html><h3>$C Bad gateway</h3></html>" > $NGINX_STATICS_DIR/$C.html; fi
    if [ $C -eq "503" ]; then echo -e "<html><h3>$C Service unavailable</h3></html>" > $NGINX_STATICS_DIR/$C.html; fi
    if [ $C -eq "504" ]; then echo -e "<html><h3>$C Gateway timeout</h3></html>" > $NGINX_STATICS_DIR/$C.html; fi
  done && \
  unset COD

if [ ! -f $NGINX_SBS_INCLUDES_LOCATIONS_CONF_FILE ]; then
  echo -e "Gerando arquivos de include para server block default, secao locations default..." && \
  cat > $NGINX_SBS_INCLUDES_LOCATIONS_CONF_FILE <<EOF
location ~* \.(js|css|png|jpg|jpeg|gif|ico)$ {
  expires max;
  access_log off;
  log_not_found off;
}

location ~ /\.ht {
  deny all;
}

location = /robots.txt {
  \${NGINX_ROBOTS_PERMISSION}
  log_not_found off;
}

location /nginx-status {
  access_log off;
  \${NGINX_STUB_STATUS_PERMISSION}
  stub_status;
}
  
location / {
  try_files \$uri \$uri/ =404;
}
EOF
echo -e "Substituindo variaveis...\n"
  envsubst "$ENV_VARS" < $NGINX_SBS_INCLUDES_LOCATIONS_CONF_FILE | sponge $NGINX_SBS_INCLUDES_LOCATIONS_CONF_FILE;
fi

ls /entrypoint.d/*.sh > /dev/null 2>&1 && \
  echo -e "\nExecutando scripts entrypoints adicionais...\n" && \
  chmod 750 /entrypoint.d/*.sh && \
  for SCRIPT in $(ls /entrypoint.d/*.sh); do
    source $SCRIPT
  done

echo -e "--- Entrypoint concluido ---\n" && \
  echo -e "Iniciando Docker CMD...\n"

exec "$@"
