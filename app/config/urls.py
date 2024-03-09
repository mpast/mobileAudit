from django.contrib import admin
from django.urls import path, include, re_path
from app import views, api
from rest_framework import routers
from rest_framework.authtoken.views import obtain_auth_token
from drf_yasg.views import get_schema_view
from drf_yasg import openapi
from app.worker.tasks import scan_state

schema_view = get_schema_view(
    openapi.Info(
        title="Mobile Audit API",
        default_version='v1',
        description="Version 1 of the API",
        contact=openapi.Contact(email="pastorabanades@gmail.com"),
        license=openapi.License(name="GNU v3"),
    ),
    public=True,
)

# API router
router = routers.DefaultRouter()
router.register(r'app', api.ApplicationViewSet)
router.register(r'scan', api.ScanViewSet)
router.register(r'finding', api.FindingViewSet)
router.register(r'permission', api.PermissionViewSet)

# App paths
urlpatterns = [
    path('', views.home, name='home'),
    path('home/', views.home, name='home'),
    path('app/create', views.create_app, name='create_app'),
    path('app/<int:id>', views.app, name='app'),
    path('scan/<int:id>', views.scan, name='scan'),
    path('findings/', views.findings, name='findings'),
    path('findings/<int:scan_id>', views.findings, name='findings'),
    path('finding/create', views.create_finding, name='create_finding'),
    path('finding/create/<int:scan_id>', views.create_finding, name='create_finding'),
    path('finding/<int:id>', views.finding, name='finding'),
    path('finding/edit/<int:id>', views.edit_finding, name='edit_finding'),
    path('finding/file/<int:id>', views.finding_view_file, name='finding_view_file'),
    path('file/<int:id>', views.view_file, name='view_file'),
    path('scan/create', views.create_scan, name='create_scan'),
    path('scan/create/<int:app_id>', views.create_scan, name='create_scan'),
    path('scan/delete/<int:scan_id>', views.delete_scan, name='delete_scan'),
    path('patterns/', views.patterns, name="patterns"),
    path('permissions/', views.permissions, name="permissions"),
    path('malware/', views.malware, name="malware"),
    path('export/<int:id>', views.export, name="export"),
    path('update_virustotal/<int:scan_id>', views.update_virustotal, name="update_virustotal"),
    #path('admin/', admin.site.urls),
    path('accounts/login/', views.user_login, name="login"),
    path('accounts/register/', views.user_register, name="register"),
    path('accounts/logout/', views.user_logout, name='logout'),
    path('accounts/profile/', views.user_profile, name='profile'),
    path('api/v1/auth-token/', obtain_auth_token, name='api_token_auth'),
    path('api/v1/', include(router.urls)),
    path('scan_state/<int:id>', scan_state, name="scan_state"),
    re_path(r'^swagger(?P<format>\.json|\.yaml)$', schema_view.without_ui(cache_timeout=0), name='schema-json'),
    re_path(r'^swagger/$', schema_view.with_ui('swagger', cache_timeout=0), name='schema-swagger-ui'),
    re_path(r'^redoc/$', schema_view.with_ui('redoc', cache_timeout=0), name='schema-redoc'),
    
]