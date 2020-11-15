from django.contrib import admin
from django.urls import path
from app import views
from django.conf.urls import url

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
]