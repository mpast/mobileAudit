#!/bin/sh
python manage.py makemigrations
python manage.py migrate
python manage.py loaddata data
python manage.py collectstatic --noinput
uwsgi --http 0.0.0.0:8000 --enable-threads --processes 2 --threads 1 --module app.config.wsgi