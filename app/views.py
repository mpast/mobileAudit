from django.shortcuts import render, redirect
from django.core.files.storage import FileSystemStorage
from django.urls import reverse
from django.contrib import messages
from django.contrib.auth import login, logout, authenticate
from django.contrib.auth.models import User
from django.contrib.auth.forms import AuthenticationForm
from django.contrib.auth.decorators import login_required
from django.conf import settings
from django.http import HttpResponse
from django.template.loader import get_template
import pdfkit, requests, logging
from app.forms import ScanForm, ApplicationForm, FindingForm, SignUpForm, ProfileForm
from app import analysis
from app.models import *
from app.worker.tasks import task_create_scan
from app.integration import get_report_virus_total

logger = logging.getLogger('app')

def user_register(request):
    form = SignUpForm(request.POST or None)
    if request.method == "POST":
        if form.is_valid():
            user = form.save()
            user.refresh_from_db()
            user.profile.first_name = form.cleaned_data.get('first_name')
            user.profile.last_name = form.cleaned_data.get('last_name')
            user.profile.email = form.cleaned_data.get('email')
            user.save()
            username = form.cleaned_data.get('username')
            password = form.cleaned_data.get('password1')
            user = authenticate(username=username, password=password)
            login(request, user)
            return redirect('home')
    return render(request, 'register.html', {
        'form': form,
    })

def user_login(request):
    form = AuthenticationForm()
    if request.method == "POST":
        form = AuthenticationForm(data=request.POST)
        if form.is_valid():
            username = form.cleaned_data['username']
            password = form.cleaned_data['password']
            user = authenticate(username=username, password=password)
            if user is not None:
                login(request, user)
                return redirect('home')

    return render(request, "login.html", {
        'form': form,
    })

@login_required
def user_logout(request):
    if (request.method == "POST"):
        logout(request)
    return redirect('home')

@login_required
def user_profile(request):
    if request.method == "POST":
        form = ProfileForm(request.POST)
        if form.is_valid():
            user = request.user
            user.profile.first_name = form.cleaned_data.get('first_name')
            user.profile.last_name = form.cleaned_data.get('last_name')
            user.profile.email = form.cleaned_data.get('email')
            user.save()       
            messages.success(request, 'Form submission successful')
    else:
        form = ProfileForm(instance=request.user.profile)
    return render(request, 'profile.html', {
        'form': form,
    })

def home(request):
    apps = Application.objects.all().order_by('id')
    scans = Scan.objects.all().order_by('id')
    scans_data = {}
    for scan in scans:
        scans_data[scan.id] = {
            'findings': get_findings_by_severity(scan.id),
            'antivirus' : ''
        }
        try:
            scans_data[scan.id]['antivirus'] = VirusTotalScan.objects.filter(scan=scan.id).latest('created_on')
        except Exception as e:
            logger.debug(e)

    return render(request, 'home.html', {
        'apps': apps,
        'scans': scans,
        'patterns': Pattern.objects.all(),
        'scans_data': scans_data,
        'settings': settings,
    })

def order_findings_by_categories(findings):
    finding_list = {}
    for finding in findings:
        if (finding.type):
            category_id = finding.type.id
        else:
            category_id = 1
        if not category_id in finding_list.keys():
            finding_list[category_id] = []
        finding_list[category_id].append(finding)
    return finding_list

def get_findings_by_severity(scan_id):
    return {
        'Critical': Finding.objects.filter(scan=scan_id, severity=Severity.CR).count(),
        'High': Finding.objects.filter(scan=scan_id, severity=Severity.HI).count(),
        'Medium': Finding.objects.filter(scan=scan_id, severity=Severity.ME).count(),
        'Low': Finding.objects.filter(scan=scan_id, severity=Severity.LO).count(),
        'None': Finding.objects.filter(scan=scan_id, severity=Severity.NO).count(),
    }


def get_components_intents(scan_id):
    components = Component.objects.filter(scan=scan_id)
    components_intents = list()
    for component in components:
        intents = IntentFilter.objects.filter(component=component)
        components_intents.append((component, intents))
    return components_intents

@login_required
def scan(request, id):
    scan = Scan.objects.get(pk=id)
    certificates = Certificate.objects.filter(scan=id).order_by('id')
    permissions = Permission.objects.filter(scan=id).order_by('id')
    activities = Activity.objects.filter(scan=id).order_by('id')
    components_intents = get_components_intents(id)
    strings = String.objects.filter(scan=id).order_by('type')
    findings = Finding.objects.filter(scan=id).exclude(severity=Severity.NO).order_by('id')
    findings_by_category = order_findings_by_categories(findings)
    database = DatabaseInfo.objects.filter(scan=scan)
    files = File.objects.filter(scan=scan)
    findings_by_severity = get_findings_by_severity(id)
    best_practices = Finding.objects.filter(scan=id, severity=Severity.NO).order_by('id')
    all_practices = Pattern.objects.filter(default_severity=Severity.NO).order_by('id')
    try:
        antivirus_scan = VirusTotalScan.objects.filter(scan=scan).latest('created_on')
        antivirus = Antivirus.objects.filter(virus_scan=antivirus_scan).order_by('id')
    except Exception:
        antivirus_scan = False
        antivirus = False
    return render(request, 'scan.html', {
        'scan' : scan,
        'permissions': permissions,
        'findings': findings,
        'certificates': certificates,
        'categories': Pattern.objects.all().order_by('id'),
        'findings_ordered': findings_by_category,
        'findings_by_severity': findings_by_severity,
        'all_practices': all_practices,
        'best_practices': best_practices,
        'activities': activities,
        'components_intents': components_intents,
        'files': files,
        'strings' : strings,
        'database': database,
        'antivirus_scan': antivirus_scan,
        'antivirus': antivirus,
        'settings': settings,
    })

@login_required
def create_scan(request, app_id = ''):
    if request.method == 'POST':
        form = ScanForm(request.POST, request.FILES)
        if form.is_valid():
            scan = form.save(commit=False)
            scan.user = request.user
            scan.status = 'In Progress'
            scan.progress = 1
            scan.save()
            task_id = task_create_scan.delay(scan.id)
            scan.task = task_id.id
            scan.save()
            messages.success(request, 'Form submission successful')
            return redirect(reverse('scan', kwargs={"id": scan.id}))
    else:
        if (app_id == ''):
            form = ScanForm()
        else:
            app = Application.objects.get(pk=app_id)
            form = ScanForm(initial={'app': app})
    if (settings.DEFECTDOJO_ENABLED == False):
        form.fields.pop('defectdojo_id')
    return render(request, 'create_scan.html', {
        'form': form,
    })
@login_required
def delete_scan(request, scan_id=''):
    if request.method == 'POST':
        scan = Scan.objects.get(pk=scan_id)
        if (scan.user == request.user):
            scan.delete()
            messages.success(request, 'Removed successfully')
            return redirect('home')
    messages.warning(request, 'Removed successfully')
    return redirect('home')

@login_required
def app(request, id):
    app = Application.objects.get(pk=id)
    scans = Scan.objects.filter(app=app.id).order_by('id')
    scans_data = {}
    chart_labels = []
    chart_data = []
    for scan in scans:
        scans_data[scan.id] = {
            'findings': get_findings_by_severity(scan.id),
            'antivirus' : ''
        }
        chart_labels.append("Scan #" + str(scan.id) + " - " + scan.description)
        chart_data.append(scan.findings)
        try:
            scans_data[scan.id]['antivirus'] = VirusTotalScan.objects.filter(scan=scan.id).latest('created_on')
        except Exception as e:
            logger.error(e)
    return render(request, 'app.html', {
        'app': app,
        'scans': scans,
        'scans_data': scans_data,
        'chart_data': chart_data,
        'chart_labels': chart_labels,
        'settings': settings,
    })

@login_required
def create_app(request):
    if request.method == 'POST':
        form = ApplicationForm(request.POST)
        if form.is_valid():
            obj = form.save(commit=False)
            obj.user = request.user
            form_saved = obj.save()
            return redirect(reverse('create_scan', kwargs={"app_id": obj.id}))
    else:
        form = ApplicationForm()
    return render(request, 'create_app.html', {
        'form': form,
    })

@login_required
def findings(request, scan_id=''):
    findings = []
    scan = ''
    if request.method == 'POST':
        delete = request.POST.get("delete_findings", "")
        edit = request.POST.get("edit_findings", "")
        view = request.POST.get("view_findings", "")
        status = request.POST.get("status", "")
        severity = request.POST.get("severity", "")
        push_dojo = request.POST.get("push_dojo", "")
        scan = request.POST.get("scan", "")
        findings_list = request.POST.items()
        ok = False
        for finding, value in findings_list:
            try:
                finding = int(finding)
                if isinstance(finding, int):
                    f = Finding.objects.get(pk=finding)
                    if (delete):
                        s = Scan.objects.get(pk=scan)
                        f.delete()
                        s.findings = s.findings - 1
                        s.save()
                        return redirect(reverse('scan', kwargs={"id": scan}))
                    else:
                        if (edit):
                            if (status):
                                f.status = status
                            if (severity):
                                f.severity = severity
                            f.save()
                            ok = True
                        findings.append(f)
                    if (push_dojo and settings.DEFECTDOJO_ENABLED):
                        analysis.create_finding_on_dojo(f)
            except Exception as e:
                logger.debug(e)
        if (edit and ok):
            messages.success(request, 'Edited successfully')
    else:
        if (scan_id):
            findings = Finding.objects.filter(scan=scan_id).exclude(severity=Severity.NO).order_by('id')
        else:
            findings = Finding.objects.all().exclude(severity=Severity.NO).order_by('id')
    return render(request, 'findings.html', {
        'findings': findings,
        'scan': scan,
        'settings': settings,
    })

@login_required
def finding(request, id):
    finding = Finding.objects.get(pk=id)
    return render(request, 'finding.html', {
        'finding': finding,
        'settings': settings,
    })

@login_required
def create_finding(request, scan_id = ''):
    if request.method == 'POST':
        form = FindingForm(request.POST)
        if form.is_valid():
            obj = form.save(commit=False)
            obj.user = request.user
            form_saved = obj.save()
            scan = obj.scan
            scan.findings = int(scan.findings) + 1
            scan.save()
            messages.success(request, 'Form submission successful')
            return render(request, 'create_finding.html', {
                'form': form,
                'finding': obj.id
            })
    else:
        if (scan_id == ''):
            form = FindingForm()
        else:
            scan = Scan.objects.get(pk=scan_id)
            form = FindingForm(initial={'scan': scan})
    return render(request, 'create_finding.html', {
        'form': form,
    })

@login_required
def edit_finding(request, id):
    if request.method == 'POST':
        finding = Finding.objects.get(pk=id)
        form = FindingForm(request.POST, instance=finding)
        if form.is_valid():
            obj = form.save(commit=False)
            obj.user = request.user
            form_saved = obj.save()
            messages.success(request, 'Form submission successful')
    else:
        finding = Finding.objects.get(pk=id)
        form = FindingForm(instance=finding, initial={'status': finding.status, 'severity': finding.severity})
    return render(request, 'edit_finding.html', {
        'form': form,
        'finding': id,
    })

@login_required
def finding_view_file(request, id):
    finding = Finding.objects.get(pk=id)
    lines = analysis.get_lines(finding)
    return render(request, 'file.html', {
        'lines': lines,
        'finding': finding.line_number,
    })

@login_required
def view_file(request, id):
    f = File.objects.get(pk=id)
    lines = analysis.get_lines(path=f.path)
    return render(request, 'file.html', {
        'lines': lines,
    })

@login_required
def patterns(request):
    if request.method == 'POST':
        status = request.POST.get("status", "")
        patterns = request.POST.items()
        for pattern, value in patterns:
            try:
                pattern = int(pattern)
                if isinstance(pattern, int):
                    p = Pattern.objects.get(pk=pattern)
                    if (status == 'active'):
                        p.active = True
                    elif (status == 'inactive'):
                        p.active = False
                    p.save()
            except Exception as e:
                logger.error(e)
    patterns = Pattern.objects.all()
    return render(request, 'patterns.html', {
        'patterns': patterns,
    })

@login_required
def permissions(request):
    permissions = PermissionType.objects.all()
    return render(request, 'permissions.html', {
        'permissions': permissions,
    })

@login_required
def malware(request):
    malwares = Malware.objects.all()
    return render(request, 'malware.html', {
        'malwares': malwares,
    })

@login_required
def update_virustotal(request, scan_id):
    scan = Scan.objects.get(pk=scan_id)
    get_report_virus_total(scan, scan.sha256)
    return redirect(reverse('scan', kwargs={"id": scan_id}))

def append_pdf(pdf, output):
    [output.addPage(pdf.getPage(page_num)) for page_num in range(pdf.numPages)]

@login_required
def export(request, id):
    scan = Scan.objects.get(pk=id)
    t = get_template('export.html')
    certificates = Certificate.objects.filter(scan=id)
    permissions = Permission.objects.filter(scan=id)
    activities = Activity.objects.filter(scan=id)
    components_intents = get_components_intents(id)
    strings = String.objects.filter(scan=id).order_by('type')
    findings = Finding.objects.filter(scan=id).exclude(severity=Severity.NO).order_by('id')
    findings_by_category = order_findings_by_categories(findings)
    database = DatabaseInfo.objects.filter(scan=scan)
    files = File.objects.filter(scan=scan)
    findings_by_severity = get_findings_by_severity(id)
    best_practices = Finding.objects.filter(scan=id, severity=Severity.NO)
    all_practices = Pattern.objects.filter(default_severity=Severity.NO)
    try:
        antivirus_scan = VirusTotalScan.objects.filter(scan=scan).latest('created_on')
        antivirus = Antivirus.objects.filter(virus_scan=antivirus_scan)
    except Exception:
        antivirus_scan = False
        antivirus = False
    c = {
        'scan' : scan,
        'permissions': permissions,
        'findings': findings,
        'certificates': certificates,
        'categories': Pattern.objects.all(),
        'findings_ordered': findings_by_category,
        'findings_by_severity': findings_by_severity,
        'all_practices': all_practices,
        'best_practices': best_practices,
        'activities': activities,
        'components_intents': components_intents,
        'files': files,
        'strings' : strings,
        'database': database,
        'antivirus_scan': antivirus_scan,
        'antivirus': antivirus,
        'settings': settings,
    }

    html = t.render(c)
    options = {
        'page-size': 'Letter',
        'encoding': "UTF-8",
    }
    pdf = pdfkit.from_string(html, False, options)
    
    response = HttpResponse(pdf, content_type='application/pdf')
    response['Content-Disposition'] = "attachment; filename = scan.pdf"
    return response