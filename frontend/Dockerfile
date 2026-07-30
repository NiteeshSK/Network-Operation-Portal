# nginx:1.31-alpine was specified here previously. That tag has never been
# published upstream, so this image could not be pulled on a clean host at all.
# 1.27-alpine is the current stable line.
FROM nginx:1.27-alpine

COPY . /usr/share/nginx/html
COPY nginx.conf /etc/nginx/conf.d/default.conf

RUN test -f /usr/share/nginx/html/index.html \
 && test -f /usr/share/nginx/html/login.html

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=5 \
    CMD wget -q -O /dev/null http://127.0.0.1/login.html || exit 1
