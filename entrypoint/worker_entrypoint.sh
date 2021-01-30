#!/bin/sh
mkdir -p /app/app/logs
celery --app app.worker.celery worker --concurrency 4 --loglevel INFO