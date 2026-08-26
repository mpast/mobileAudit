from app.models import *
from app.serializers import *
from app import analysis
from rest_framework import viewsets, permissions
from rest_framework.parsers import MultiPartParser, FormParser
from rest_framework.decorators import action
from app.worker.tasks import task_create_scan
from rest_framework import viewsets, mixins, status
from django.db.models import Q
from django.shortcuts import get_object_or_404
from django_filters import rest_framework as filters
from app.access import (
    can_access_app,
    grant_guest_app_access,
    grant_guest_scan_access,
    guest_app_ids,
    guest_scan_ids,
)
from rest_framework.exceptions import PermissionDenied


class IsAuthenticatedOrGuestCreate(permissions.BasePermission):
    """Allow public creation while leaving unsafe object changes owner-only."""

    def has_permission(self, request, view):
        return request.method in permissions.SAFE_METHODS or request.method == 'POST' or request.user.is_authenticated

class IsUserOrReadOnly(permissions.BasePermission):
    def has_object_permission(self, request, view, obj):
        if request.method in permissions.SAFE_METHODS:
            return True
        return request.user.is_authenticated and obj.user == request.user

class ApplicationViewSet(viewsets.ModelViewSet):
    serializer_class = ApplicationSerializer
    queryset = Application.objects.all()
    permission_classes = (IsAuthenticatedOrGuestCreate, IsUserOrReadOnly)

    def get_queryset(self):
        if self.request.user.is_authenticated:
            return Application.objects.filter(
                Q(user=self.request.user) | Q(pk__in=guest_app_ids(self.request))
            )
        return Application.objects.filter(pk__in=guest_app_ids(self.request))
    
    def perform_create(self, serializer):
        if self.request.user.is_authenticated:
            serializer.save(user=self.request.user)
        else:
            app = serializer.save()
            grant_guest_app_access(self.request, app)

class ScanViewSet(viewsets.ModelViewSet):
    serializer_class = ScanSerializer
    queryset = Scan.objects.all()
    permission_classes = (IsAuthenticatedOrGuestCreate, IsUserOrReadOnly)
    parser_classes = (MultiPartParser, FormParser)

    def get_queryset(self):
        if self.request.user.is_authenticated:
            return Scan.objects.filter(
                Q(user=self.request.user) | Q(pk__in=guest_scan_ids(self.request))
            )
        return Scan.objects.filter(pk__in=guest_scan_ids(self.request))
    
    def perform_create(self, serializer):
        app = serializer.validated_data.get('app')
        if app is not None and not can_access_app(self.request, app):
            raise PermissionDenied('You do not have access to this application.')

        save_kwargs = {'status': 'In progress', 'progress': 1}
        if self.request.user.is_authenticated and (app is None or app.user_id is not None):
            save_kwargs['user'] = self.request.user
        scan = serializer.save(**save_kwargs)
        if scan.user_id is None:
            grant_guest_scan_access(self.request, scan)
        task_id = task_create_scan.delay(scan.id)
        scan.task = task_id.id
        scan.save()

class FindingViewSet(viewsets.ModelViewSet):
    serializer_class = FindingSerializer
    queryset = Finding.objects.all()
    permission_classes = (permissions.IsAuthenticatedOrReadOnly, IsUserOrReadOnly)

    def get_queryset(self):
        if self.request.user.is_authenticated:
            return Finding.objects.filter(
                Q(scan__user=self.request.user) | Q(scan_id__in=guest_scan_ids(self.request))
            )
        return Finding.objects.filter(scan_id__in=guest_scan_ids(self.request))

    def perform_create(self, serializer):
        obj = serializer.save(user=self.request.user)

           
    @action(detail=True, methods=['GET'], name='Get findings for scan')
    def scan(self, request, pk=None):
        if (pk != None):
            scan_queryset = Scan.objects.filter(pk__in=guest_scan_ids(request))
            if request.user.is_authenticated:
                scan_queryset = Scan.objects.filter(
                    Q(user=request.user) | Q(pk__in=guest_scan_ids(request))
                )
            scan = get_object_or_404(scan_queryset, pk=pk)
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

    def get_queryset(self):
        if self.request.user.is_authenticated:
            return Permission.objects.filter(
                Q(scan__user=self.request.user) | Q(scan_id__in=guest_scan_ids(self.request))
            )
        return Permission.objects.filter(scan_id__in=guest_scan_ids(self.request))

    def perform_create(self, serializer):
        obj = serializer.save(user=self.request.user)

           
    @action(detail=True, methods=['GET'], name='Get findings for scan')
    def scan(self, request, pk=None):
        if (pk != None):
            scan_queryset = Scan.objects.filter(pk__in=guest_scan_ids(request))
            if request.user.is_authenticated:
                scan_queryset = Scan.objects.filter(
                    Q(user=request.user) | Q(pk__in=guest_scan_ids(request))
                )
            scan = get_object_or_404(scan_queryset, pk=pk)
            queryset = Permission.objects.filter(scan=scan).order_by('id')
        else:
            queryset = Permission.objects.all().order_by('id')
        page = self.paginate_queryset(queryset)
        if page is not None:
            serializer = self.get_serializer(page, many=True)
            return self.get_paginated_response(serializer.data)
        serializer = self.get_serializer(queryset, many=True)
