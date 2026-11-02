FROM php:8.2-apache
RUN rm -f /var/log/apache2/access.log /var/log/apache2/error.log \
    && touch /var/log/apache2/access.log /var/log/apache2/error.log \
    && chown www-data:www-data /var/log/apache2/access.log /var/log/apache2/error.log
COPY index.php /var/www/html/index.php
