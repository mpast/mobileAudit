#!/bin/sh
celery --app app.worker.celery worker --concurrency 1 --loglevel INFO