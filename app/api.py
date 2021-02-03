from app.models import *
from app.serializers import *
from app import analysis
from rest_framework import viewsets, permissions
from rest_framework.parsers import MultiPartParser, FormParser
from app.worker.tasks import task_create_scan

class IsUserOrReadOnly(permissions.BasePermission):
    def has_object_permission(self, request, view, obj):
        if request.method in ['PUT', 'PATCH']:
            return obj.user == request.user
        return True

class ApplicationViewSet(viewsets.ModelViewSet):
    serializer_class = ApplicationSerializer
    queryset = Application.objects.all()
    permission_classes = (permissions.IsAuthenticatedOrReadOnly, IsUserOrReadOnly)
    
    def perform_create(self, serializer):
        obj = serializer.save(user=self.request.user)

class ScanViewSet(viewsets.ModelViewSet):
    serializer_class = ScanSerializer
    queryset = Scan.objects.all()
    permission_classes = (permissions.IsAuthenticatedOrReadOnly, IsUserOrReadOnly)
    parser_classes = (MultiPartParser, FormParser)
    
    def perform_create(self, serializer):
        scan = serializer.save(user=self.request.user, status='In progress', progress=1)
        task_id = task_create_scan.delay(scan.id)
        scan.task = task_id.id
        scan.save()
 
class FindingViewSet(viewsets.ModelViewSet):
    serializer_class = FindingSerializer
    queryset = Finding.objects.all()
    permission_classes = (permissions.IsAuthenticatedOrReadOnly, IsUserOrReadOnly)

    def perform_create(self, serializer):
        obj = serializer.save(user=self.request.user)
