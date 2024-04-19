FROM debian:bullseye

RUN apt-get update && apt-get install -y \
	nginx \
	openssl

COPY tools/nginx.conf /etc/nginx/
COPY tools/ssl.conf /etc/nginx/sites-available/default

CMD [ "nginx", "-g", "daemon off;" ]
