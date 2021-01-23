from celery import shared_task
from app import analysis

@shared_task
def task_create_scan(scan):
    analysis.analyze_apk(scan)