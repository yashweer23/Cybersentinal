#!/bin/sh
set -eu
# Docker defaults remain 8080; Render supplies PORT and its own DNS resolver.
PORT=${PORT:-8080}
BACKEND_UPSTREAM=${BACKEND_UPSTREAM:-backend:8000}
NGINX_RESOLVER=${NGINX_RESOLVER:-auto}
PUBLIC_SCHEME=${PUBLIC_SCHEME:-auto}
case "$PORT" in ''|*[!0-9]*) echo 'Invalid frontend PORT' >&2; exit 1;; esac
if [ "$PORT" -lt 1024 ] || [ "$PORT" -gt 65535 ]; then
    echo 'Frontend PORT must be between 1024 and 65535' >&2; exit 1
fi
if ! printf '%s\n' "$BACKEND_UPSTREAM" | awk -F: '
    NF == 2 && $1 ~ /^[A-Za-z0-9][A-Za-z0-9.-]*$/ &&
    $2 ~ /^[0-9]+$/ && $2 >= 1 && $2 <= 65535 { valid=1 }
    END { exit !valid }'; then
    echo 'BACKEND_UPSTREAM must be a hostname:port' >&2; exit 1
fi
if [ "$NGINX_RESOLVER" = auto ]; then
    NGINX_RESOLVER=$(awk '$1 == "nameserver" {print $2; exit}' /etc/resolv.conf)
fi
case "$NGINX_RESOLVER" in ''|*[!0-9a-fA-F.:]*)
    echo 'NGINX_RESOLVER must be a single DNS IP address' >&2; exit 1;;
esac
case "$NGINX_RESOLVER" in *:*) NGINX_RESOLVER="[$NGINX_RESOLVER]";; esac
case "$PUBLIC_SCHEME" in
    auto) PROXY_SCHEME='$scheme';;
    https) PROXY_SCHEME=https;;
    *) echo 'PUBLIC_SCHEME must be auto or https' >&2; exit 1;;
esac
export PORT BACKEND_UPSTREAM NGINX_RESOLVER PROXY_SCHEME
# Substitute only operational values, never Nginx variables or backend secrets.
umask 077
envsubst '${PORT} ${BACKEND_UPSTREAM} ${NGINX_RESOLVER} ${PROXY_SCHEME}' \
    < /etc/nginx/templates/cybersentinel.conf.template > /tmp/nginx.conf
nginx -t -c /tmp/nginx.conf
exec nginx -c /tmp/nginx.conf -g 'daemon off;'
