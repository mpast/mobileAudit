from app import analysis
from app.models import Scan
from celery import shared_task, current_task
from celery.result import AsyncResult
from django.http import HttpResponse
import json

@shared_task
def task_create_scan(scan):
    current_task.update_state(state = 'STARTED',
                meta = {'current': 1, 'total': 100, 'status': 'In Progress'})
    analysis.analyze_apk(current_task, scan)

def scan_state(request, id):
    scan = Scan.objects.get(pk=id)
    job = AsyncResult(scan.task)
    try:
        data = job.info or job.result
    except Exception as e:
        print(e)
    return HttpResponse(json.dumps(data), content_type='application/json')