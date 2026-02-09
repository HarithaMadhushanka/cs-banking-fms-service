FROM php:8.4-cli

RUN apt-get update && apt-get install -y \
    git unzip libzip-dev \
  && docker-php-ext-install pdo_mysql \
  && rm -rf /var/lib/apt/lists/*

COPY --from=composer:2 /usr/bin/composer /usr/bin/composer

WORKDIR /var/www

CMD ["sh", "-c", "composer install --no-interaction --prefer-dist && php artisan serve --host=0.0.0.0 --port=8000"]
