#!/bin/sh
celery --app app.worker.celery worker --concurrency 4 --loglevel INFO