FROM busybox:1.36
RUN mkdir -p /www && echo salvage-ok > /www/index.html
EXPOSE 8080
CMD ["httpd", "-f", "-p", "8080", "-h", "/www"]
