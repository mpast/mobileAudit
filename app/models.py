from django.db import models
import os
from django.core.exceptions import ValidationError
from django.conf import settings
from django.contrib.auth.models import User
from django.db.models.signals import post_save
from django.dispatch import receiver

class Profile(models.Model):
    user = models.OneToOneField(User, on_delete=models.CASCADE)
    first_name = models.CharField(max_length=100, blank=True)
    last_name = models.CharField(max_length=100, blank=True)
    email = models.EmailField(max_length=150)

    def __str__(self):
        return self.user.username

    @receiver(post_save, sender=User)
    def update_profile_signal(sender, instance, created, **kwargs):
        if created:
            Profile.objects.create(user=instance)
        instance.profile.save()

def validate_file_extension(value):
    ext = os.path.splitext(value.name)[1]
    valid_extensions = ['.apk']
    if not ext.lower() in valid_extensions:
        raise ValidationError(u'Unsupported file extension.')

class Severity(models.TextChoices):
    CR = ('CR', 'Critical')
    HI = ('HI', 'High')
    ME = ('ME', 'Medium')
    LO = ('LO', 'Low')
    NO = ('NO', 'None')
    
    def __str__(self):
        return self.get_severity_display()

class Status(models.TextChoices):
    VF = ('VF', 'Verified')
    FP = ('FP', 'False Positive')
    TP = ('TP', 'True Positive')
    MI = ('MI', 'Mitigated')
    UK = ('UK', 'Unknown')
    TD = ('TD', 'To Do')

    def __str__(self):
        return self.get_status_display()

class Application(models.Model):
    id = models.AutoField(primary_key=True)
    name = models.CharField(max_length=255, blank=False)
    description = models.CharField(max_length=255, blank=False)
    user = models.ForeignKey(User, on_delete=models.PROTECT)
    created_on = models.DateTimeField(auto_now_add=True, null=True)
    updated_on = models.DateTimeField(auto_now=True, null=True)

class Scan(models.Model):
    id = models.AutoField(primary_key=True)
    app = models.ForeignKey(Application, on_delete=models.CASCADE)
    name = models.CharField(max_length=255, blank=True)
    apk = models.FileField(upload_to='apk/', blank=False, validators=[validate_file_extension])
    description = models.CharField(max_length=255, blank=False)
    defectdojo_id = models.IntegerField(blank=True, default=0)
    user = models.ForeignKey(User, on_delete=models.PROTECT)
    status = models.CharField(max_length=50,blank=True, null=True)
    progress = models.IntegerField(blank=True, null=True)
    findings = models.IntegerField(blank=True, null=True, default=0)
    apk_name = models.CharField(max_length=255, blank=True, null=True)
    file_size = models.CharField(max_length=255, blank=True, null=True)
    md5 = models.CharField(max_length=255, blank=True, null=True)
    sha1 = models.CharField(max_length=255, blank=True, null=True)
    sha256 = models.CharField(max_length=255, blank=True, null=True)
    package = models.CharField(max_length=255, blank=True, null=True)
    icon = models.TextField(blank=True, null=True)
    version_code = models.CharField(max_length=50, blank=True, null=True)
    version_name = models.CharField(max_length=50, blank=True, null=True)
    min_sdk_version = models.CharField(max_length=50, blank=True, null=True)
    max_sdk_version = models.CharField(max_length=50, blank=True, null=True)
    target_sdk_version = models.CharField(max_length=50, blank=True, null=True)
    effective_target_sdk_version = models.CharField(max_length=50, blank=True, null=True)
    manifest = models.TextField(blank=True, null=True)
    task = models.CharField(max_length=50, blank=True, null=True)
    created_on = models.DateTimeField(auto_now_add=True, null=True)
    updated_on = models.DateTimeField(auto_now=True, null=True)

class Cwe(models.Model):
    cwe = models.IntegerField(primary_key=True)
    description = models.TextField()
    created_on = models.DateTimeField(auto_now_add=True, null=True)
    updated_on = models.DateTimeField(auto_now=True, null=True)

class Risk(models.Model):
    risk = models.IntegerField(primary_key=True)
    description = models.TextField()
    reference = models.TextField()
    created_on = models.DateTimeField(auto_now_add=True, null=True)
    updated_on = models.DateTimeField(auto_now=True, null=True)

class Pattern(models.Model):
    id = models.AutoField(primary_key=True)
    default_cwe = models.ForeignKey(Cwe, on_delete=models.CASCADE)
    default_risk = models.ForeignKey(Risk, on_delete=models.CASCADE, null=True)
    default_name = models.TextField()
    default_description = models.TextField(blank=True)
    default_severity = models.CharField(
        max_length=10,
        choices=Severity.choices
    )
    default_mitigation = models.TextField(blank=True)
    pattern = models.TextField()
    active = models.BooleanField(default=True)
    created_on = models.DateTimeField(auto_now_add=True, null=True)
    updated_on = models.DateTimeField(auto_now=True, null=True)

class Finding(models.Model):
    id = models.AutoField(primary_key=True)
    scan = models.ForeignKey(Scan, on_delete=models.CASCADE)
    type = models.ForeignKey(Pattern, on_delete=models.CASCADE, blank=True, null=True)
    name = models.CharField(max_length=512, blank=False)
    path = models.CharField(max_length=1024, blank=False)
    line_number = models.IntegerField(null=True)
    line = models.TextField()
    snippet = models.TextField()
    match = models.TextField(blank=True, null=True)
    status = models.CharField(
        max_length=50,
        choices=Status.choices
    )
    severity = models.CharField(
        max_length=10,
        choices=Severity.choices
    )
    description = models.TextField()
    mitigation = models.TextField(blank=True, null=True)
    cwe = models.ForeignKey(Cwe, on_delete=models.CASCADE)
    risk = models.ForeignKey(Risk, on_delete=models.CASCADE, null=True)
    user = models.ForeignKey(User, on_delete=models.PROTECT)
    defectdojo_id = models.IntegerField(blank=True, default=0)
    created_on = models.DateTimeField(auto_now_add=True, null=True)
    updated_on = models.DateTimeField(auto_now=True, null=True)

class Activity(models.Model):
    id = models.AutoField(primary_key=True)
    scan = models.ForeignKey(Scan, on_delete=models.CASCADE)
    name = models.TextField()
    main = models.BooleanField(default=False)
    exported = models.BooleanField(default=False)
    created_on = models.DateTimeField(auto_now_add=True, null=True)
    updated_on = models.DateTimeField(auto_now=True, null=True)

class PermissionType(models.Model):
    id = models.AutoField(primary_key=True)
    name = models.TextField(unique=True)
    type = models.CharField(max_length=50)
    default_severity = models.CharField(
        max_length=10,
        choices=Severity.choices
    )
    created_on = models.DateTimeField(auto_now_add=True, null=True)
    updated_on = models.DateTimeField(auto_now=True, null=True)

class Permission(models.Model):
    id = models.AutoField(primary_key=True)
    scan = models.ForeignKey(Scan, on_delete=models.CASCADE)
    permission = models.ForeignKey(PermissionType, on_delete=models.CASCADE)
    severity = models.CharField(
        max_length=10,
        choices=Severity.choices
    )
    created_on = models.DateTimeField(auto_now_add=True, null=True)
    updated_on = models.DateTimeField(auto_now=True, null=True)

class Component(models.Model):
    id = models.AutoField(primary_key=True)
    scan = models.ForeignKey(Scan, on_delete=models.CASCADE)
    name = models.TextField()
    type = models.TextField()
    created_on = models.DateTimeField(auto_now_add=True, null=True)
    updated_on = models.DateTimeField(auto_now=True, null=True)

class IntentFilter(models.Model):
    id = models.AutoField(primary_key=True)
    scan = models.ForeignKey(Scan, on_delete=models.CASCADE)
    name = models.TextField()
    action = models.TextField()
    component = models.ForeignKey(Component, on_delete=models.CASCADE)
    created_on = models.DateTimeField(auto_now_add=True, null=True)
    updated_on = models.DateTimeField(auto_now=True, null=True)

class Certificate(models.Model):
    id = models.AutoField(primary_key=True)
    scan = models.ForeignKey(Scan, on_delete=models.CASCADE)
    version = models.CharField(max_length=10, blank=True)
    sha1 = models.CharField(max_length=255, blank=True)
    sha256 = models.CharField(max_length=255, blank=True)
    issuer = models.TextField(blank=True)
    subject = models.TextField(blank=True)
    hash_algorithm = models.TextField(blank=True)
    signature_algorithm = models.TextField(blank=True)
    serial_number = models.TextField(blank=True)
    contents =  models.TextField(blank=True)
    created_on = models.DateTimeField(auto_now_add=True, null=True)
    updated_on = models.DateTimeField(auto_now=True, null=True)

class String(models.Model):
    id = models.AutoField(primary_key=True)
    scan = models.ForeignKey(Scan, on_delete=models.CASCADE)
    finding = models.ForeignKey(Finding, on_delete=models.CASCADE)
    type = models.CharField(max_length=255)
    value = models.TextField(blank=True)
    created_on = models.DateTimeField(auto_now_add=True, null=True)
    updated_on = models.DateTimeField(auto_now=True, null=True)

class DatabaseInfo(models.Model):
    id = models.AutoField(primary_key=True)
    scan = models.ForeignKey(Scan, on_delete=models.CASCADE)
    table = models.CharField(max_length=255)
    info = models.TextField(blank=True)
    created_on = models.DateTimeField(auto_now_add=True, null=True)
    updated_on = models.DateTimeField(auto_now=True, null=True)

class File(models.Model):
    id = models.AutoField(primary_key=True)
    scan = models.ForeignKey(Scan, on_delete=models.CASCADE)
    type = models.CharField(max_length=255)
    name = models.CharField(max_length=255)
    path = models.CharField(max_length=255)
    created_on = models.DateTimeField(auto_now_add=True, null=True)
    updated_on = models.DateTimeField(auto_now=True, null=True)

class Malware(models.Model):
    id = models.AutoField(primary_key=True)
    date = models.CharField(max_length=255, null=True)
    url = models.TextField(blank=True, null=True)
    ip = models.TextField(blank=True, null=True)
    reverse_lookup = models.TextField(blank=True, null=True)
    description = models.TextField(blank=True, null=True)
    asp = models.CharField(max_length=255, null=True)
    geolocation = models.TextField(blank=True, null=True)
    created_on = models.DateTimeField(auto_now_add=True, null=True)
    updated_on = models.DateTimeField(auto_now=True, null=True)

class Domain(models.Model):
    id = models.AutoField(primary_key=True)
    scan = models.ForeignKey(Scan, on_delete=models.CASCADE)
    finding = models.ForeignKey(Finding, on_delete=models.CASCADE)
    domain = models.TextField(blank=True)
    malware = models.ForeignKey(Malware, on_delete=models.CASCADE, null=True)
    created_on = models.DateTimeField(auto_now_add=True, null=True)
    updated_on = models.DateTimeField(auto_now=True, null=True)

class VirusTotalScan(models.Model):
    id = models.AutoField(primary_key=True)
    identifier = models.CharField(max_length=255, null=True)
    type = models.CharField(max_length=255, null=True)
    scan = models.ForeignKey(Scan, on_delete=models.CASCADE)
    date = models.DateTimeField(null=True)
    md5 = models.CharField(max_length=255, null=True)
    sha256 = models.CharField(max_length=255, null=True)
    ssdeep = models.CharField(max_length=255, null=True)
    link = models.TextField(blank=True, null=True)
    harmless = models.IntegerField(blank=True, default=0)
    malicious = models.IntegerField(blank=True, default=0)
    suspicious = models.IntegerField(blank=True, default=0)
    undetected = models.IntegerField(blank=True, default=0)
    unsupported = models.IntegerField(blank=True, default=0)
    type_unsupported = models.IntegerField(blank=True, default=0)
    failure = models.IntegerField(blank=True, default=0)
    timeout = models.IntegerField(blank=True, default=0)
    uploaded = models.BooleanField(default=False)
    first_seen = models.DateTimeField(null=True)
    first_submission = models.DateTimeField(null=True)
    last_submission = models.DateTimeField(null=True)
    reputation = models.IntegerField(blank=True, default=0)
    times_submitted = models.IntegerField(blank=True, default=0)
    votes_harmless = models.IntegerField(blank=True, default=0)
    votes_malicious = models.IntegerField(blank=True, default=0)
    magic = models.CharField(max_length=255, null=True)
    type_description = models.CharField(max_length=255, null=True)
    created_on = models.DateTimeField(auto_now_add=True, null=True)
    updated_on = models.DateTimeField(auto_now=True, null=True)

class Antivirus(models.Model):
    id = models.AutoField(primary_key=True)
    scan = models.ForeignKey(Scan, on_delete=models.CASCADE)
    virus_scan = models.ForeignKey(VirusTotalScan, on_delete=models.CASCADE)
    name = models.CharField(max_length=255, null=True)
    category = models.CharField(max_length=255, null=True)
    version = models.CharField(max_length=255, null=True)
    result = models.CharField(max_length=255, null=True)
    method = models.CharField(max_length=255, null=True)
    update = models.CharField(max_length=255, null=True)
    created_on = models.DateTimeField(auto_now_add=True, null=True)
    updated_on = models.DateTimeField(auto_now=True, null=True)