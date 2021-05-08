from app.models import *
from app.serializers import *
from app import analysis
from rest_framework import viewsets, permissions
from rest_framework.parsers import MultiPartParser, FormParser
from rest_framework.decorators import action
from app.worker.tasks import task_create_scan
from rest_framework import viewsets, mixins, status
from django.db.models import Q
from django_filters import rest_framework as filters

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

           
    @action(detail=True, methods=['GET'], name='Get findings for scan')
    def scan(self, request, pk=None):
        if (pk != None):
            scan = Scan.objects.get(pk=pk)
            queryset = Finding.objects.filter(scan=scan).order_by('id')
        else:
            queryset = Finding.objects.all().order_by('id')
            
        page = self.paginate_queryset(queryset)
        if page is not None:
            serializer = self.get_serializer(page, many=True)
            return self.get_paginated_response(serializer.data)
        serializer = self.get_serializer(queryset, many=True)


class PermissionViewSet(viewsets.ModelViewSet):
    serializer_class = PermissionSerializer
    queryset = Permission.objects.all()
    permission_classes = (permissions.IsAuthenticatedOrReadOnly, IsUserOrReadOnly)

    def perform_create(self, serializer):
        obj = serializer.save(user=self.request.user)

           
    @action(detail=True, methods=['GET'], name='Get findings for scan')
    def scan(self, request, pk=None):
        if (pk != None):
            scan = Scan.objects.get(pk=pk)
            queryset = Permission.objects.filter(scan=scan).order_by('id')
        else:
            queryset = Permission.objects.all().order_by('id')
        page = self.paginate_queryset(queryset)
        if page is not None:
            serializer = self.get_serializer(page, many=True)
            return self.get_paginated_response(serializer.data)
        serializer = self.get_serializer(queryset, many=True)
