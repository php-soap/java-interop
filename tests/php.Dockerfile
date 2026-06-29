# PHP runner image for the interop PHPUnit suites. A recent php:8.5-cli, so running the suite in
# here also sidesteps host-libxml C14N differences.
# dom + openssl are built in; intl/gmp/bcmath are the extensions the middlewares need.
FROM php:8.5-cli

RUN apt-get update \
 && apt-get install -y libicu-dev libgmp-dev libxslt1-dev unzip git \
 && docker-php-ext-install intl gmp bcmath xsl \
 && rm -rf /var/lib/apt/lists/*

COPY --from=composer:2 /usr/bin/composer /usr/bin/composer
