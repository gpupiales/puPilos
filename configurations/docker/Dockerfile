FROM php:7.4-fpm

RUN apt-get update && apt-get install -y \
    libfreetype6-dev                     \
    libjpeg62-turbo-dev                  \
    libmcrypt-dev                        \
    libpng-dev                           \
    libpcre3-dev                         \
    libzip-dev                           \
    curl                                 \
    default-mysql-client                 \
    git-core

RUN docker-php-ext-install -j$(nproc) mysqli                && \
    docker-php-ext-install -j$(nproc) pdo_mysql             && \
    docker-php-ext-configure opcache --enable-opcache       && \
    docker-php-ext-install -j$(nproc) opcache               && \
    docker-php-ext-configure gd --with-freetype --with-jpeg && \
    docker-php-ext-install -j$(nproc) gd                    && \
    docker-php-ext-install -j$(nproc) zip

RUN pecl install mcrypt-1.0.3 && \
    docker-php-ext-enable mcrypt

RUN curl -sS https://getcomposer.org/installer | php -- --install-dir=/usr/local/bin --filename=composer && \
  /usr/local/bin/composer --ansi --version --no-interaction

ENV PATH="/root/.composer/vendor/bin:${PATH}"

RUN /usr/local/bin/composer global require drush/drush
RUN /usr/local/bin/composer require drupal/console:~1.0 --prefer-dist --optimize-autoloader

RUN apt-get clean \
    && rm -r /var/lib/apt/lists/*
