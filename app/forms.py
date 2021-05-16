from django import forms
from app.models import *
from django.forms import ModelChoiceField
from django.contrib.auth.forms import UserCreationForm
from django.contrib.auth.models import User

class ApplicationModelChoiceField(ModelChoiceField):
    def label_from_instance(self, obj):
        return "Application #%s - %s" % (obj.id, obj.name)

class ScanModelChoiceField(ModelChoiceField):
    def label_from_instance(self, obj):
        return "Scan #%s - %s - %s" % (obj.id, obj.app.name, obj.description)

class CweModelChoiceField(ModelChoiceField):
    def label_from_instance(self, obj):
        return "CWE #%s - %s" % (obj.cwe, obj.description)

class RiskModelChoiceField(ModelChoiceField):
    def label_from_instance(self, obj):
        return "OWASP M%s - %s" % (obj.risk, obj.description)

class SignUpForm(UserCreationForm):
    first_name = forms.CharField(max_length=100, help_text='Last Name')
    last_name = forms.CharField(max_length=100, help_text='Last Name')
    email = forms.EmailField(max_length=150, help_text='Email')

    class Meta:
        model = User
        fields = ('username', 'first_name', 'last_name', 'email', 'password1', 'password2')

class ProfileForm(forms.ModelForm):
    first_name = forms.CharField(max_length=100, help_text='Last Name')
    last_name = forms.CharField(max_length=100, help_text='Last Name')
    email = forms.EmailField(max_length=150, help_text='Email')

    class Meta:
        model = Profile
        fields = ('first_name', 'last_name', 'email')

class ScanForm(forms.ModelForm):
    app = ApplicationModelChoiceField(queryset=Application.objects.all())
    class Meta:   
        model = Scan
        fields = ('description', 'apk', 'app', 'defectdojo_id')
       
class ApplicationForm(forms.ModelForm):
    class Meta:
        model = Application
        fields = ('name', 'description', )

class FindingForm(forms.ModelForm):
    scan = ScanModelChoiceField(queryset=Scan.objects.all())
    cwe = CweModelChoiceField(queryset=Cwe.objects.all())
    risk = RiskModelChoiceField(queryset=Risk.objects.all())
    class Meta:   
        model = Finding
        fields = ('scan', 'name', 'description', 'severity', 'status', 'path', 'line_number', 'line', 'snippet', 'cwe', 'risk', 'mitigation', 'defectdojo_id')