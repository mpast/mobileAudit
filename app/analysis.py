from androguard.core.bytecodes.apk import APK
from androguard.core.bytecodes.dvm import DalvikVMFormat
from androguard.core.analysis.analysis import Analysis
from androguard.core.androconf import show_logging
from django.conf import settings
import logging, os, threading, hashlib, re, linecache, base64, requests, json, urllib
from app.models import *
from app import permissions, patterns
from pygments import highlight
from pygments.lexers import PythonLexer
from pygments.formatters import HtmlFormatter
from pygments.lexers import guess_lexer, guess_lexer_for_filename
from datetime import datetime

logger = logging.getLogger('app')

APK_PATH = ""
DECOMPILE_PATH = ""

def start_analysis(apk):
    scan = Scan(apk=apk, app=apk.app, description=apk.description, status='Starting', progress=1, user=apk.user)
    scan.save()
    t = threading.Thread(target=analyze_apk, args=(apk, scan))
    t.start()
    return scan

def set_hash_app(apk):
    if not apk.sha256:
        f = apk.apk.open('rb')
        sha1 = hashlib.sha1()
        md5 = hashlib.md5()
        sha256 = hashlib.sha256()
        if f.multiple_chunks():
            for chunk in f.chunks():
                md5.update(chunk)
                sha1.update(chunk)
                sha256.update(chunk)
        else:
            md5.update(f.read())
            sha1.update(f.read())
            sha256.update(f.read())
        apk.md5 = md5.hexdigest()
        apk.sha1 = sha1.hexdigest()
        apk.sha256 = sha256.hexdigest()
        apk.file_size = apk.apk.size
        apk.save()
        f.close()
    return apk


def analyze_apk(apk, scan):
    # Enable log output
    #show_logging(level=logging.DEBUG)
    global APK_PATH
    global DECOMPILE_PATH
    APK_PATH = settings.BASE_DIR + apk.apk.url
    DECOMPILE_PATH = os.path.splitext(APK_PATH)[0]
    try:
        scan.status = 'In progress'
        scan.progress = 1
        scan.save()
        logger.debug(scan.status)
        a = APK(APK_PATH)
        apk = set_hash_app(apk)
        scan.status = 'Getting info of apk'
        scan.progress = 5
        scan.save()
        logger.debug(scan.status)
        apk = get_info_apk(a, apk)
        scan.status = 'Getting info of certificates'
        scan.progress = 10
        scan.save()
        logger.debug(scan.status)
        certificates = get_info_certificate(a, apk)
        if (settings.VIRUSTOTAL_ENABLED):
            scan.status = 'Getting info of VT'
            scan.progress = 15
            scan.save()
            logger.debug(scan.status)
            report = get_report_virus_total(scan, apk.sha256)
            if (not report and settings.VIRUSTOTAL_UPLOAD):
                scan.status = 'Upload to VT'
                scan.save()
                upload_virus_total(scan, APK_PATH, apk.sha256)
        scan.status = 'Decompiling'
        scan.progress = 20
        scan.save()
        logger.debug(scan.status)
        decompile_jadx()
        if (a.get_app_icon()):
            update_icon(apk, DECOMPILE_PATH + '/resources/' + a.get_app_icon())
        scan.status = 'Finding vulnerabilities'
        scan.progress = 40
        scan.save()
        logger.debug(scan.status)
        findings = get_tree_dir(scan)
        scan.status = 'Finished'
        scan.progress = 100
        scan.apk.finished_on = datetime.now()
        scan.save()
        logger.debug(scan.status)
    except Exception as e:
        scan.progress = 100
        scan.status = "Error"
        scan.apk.finished_on = datetime.now()
        scan.save()
        import traceback
        traceback.print_exc()
        print(e)

def decompile_jadx():
    if (not os.path.isdir(DECOMPILE_PATH)):
        #execute jadx command
        os.system('jadx -d {} {}'.format(DECOMPILE_PATH, APK_PATH))
    # now we have sources/resources decompiled

def update_icon(apk, path):
    encoded_string = ''
    try:
        with open(path, 'rb') as image_file:
            encoded_string = base64.b64encode(image_file.read()).decode("utf-8")
            apk.icon = encoded_string
            apk.save()
    except Exception as e:
        logger.error("no icon")  

def get_info_apk(a, apk):
    set_hash_app(apk)
    apk.package = a.get_package()
    apk.name = a.get_app_name()
    apk.version_code = a.get_androidversion_code()
    apk.version_name = a.get_androidversion_name()
    apk.min_sdk_version = a.get_min_sdk_version()
    apk.max_sdk_version = a.get_max_sdk_version()
    apk.target_sdk_version = a.get_target_sdk_version()
    apk.effective_target_sdk_version = a.get_effective_target_sdk_version()
    apk.manifest = a.get_android_manifest_axml().get_xml()
    apk.save()

    permissions = a.get_permissions()
    for permission in permissions:
        try:
            permission_type = PermissionType.objects.get(name=permission)
        except Exception as e:
            permission_type = PermissionType(name=permission, type='Other', default_severity=Severity.HI)
            permission_type.save()
        p = Permission(apk=apk, permission=permission_type, severity=permission_type.default_severity)
        p.save()
    
    #Activities and their intent-filters
    for activity in a.get_activities():
        get_intent_filter(a, apk, 'activity', activity)

    #Services and their intent-filters:
    for service in a.get_services():
        get_intent_filter(a, apk, 'service', service)
    
    #Receivers and their intent-filters:
    for receiver in a.get_receivers():
        get_intent_filter(a, apk, 'receiver', receiver)
    
    #Providers and their intent-filters:
    for provider in a.get_providers():
        get_intent_filter(a, apk, 'provider', provider)
    
    return apk

def get_intent_filter(a, apk, type, name):
    component = Component(name=name, apk=apk, type=type)
    component.save()
    main = False
    launcher = False
    main_activity = False
    for action, intent_name in a.get_intent_filters(type, name).items():
        for intent in intent_name:
            if (action == 'action' and intent == 'android.intent.action.MAIN'):
                main = True
            if (action == 'category' and intent == 'android.intent.category.LAUNCHER'):
                launcher = True
            intent = IntentFilter(name=intent, apk=apk, action=action, component=component)
            intent.save()
    if (type == 'activity'):
        if (main and launcher):
            main_activity = True
        activity = Activity(name=name, apk=apk, main=main_activity)
        activity.save()


def get_info_certificate(a, apk):
    # first check if this APK is signed
    certificates = list()
    if a.is_signed():
        # Iterate over all certificates
        for cert in a.get_certificates():
            # Each cert is now a asn1crypt.x509.Certificate object
            # From the Certificate object, we can query stuff like:
            c = Certificate(
                apk=apk,
                version = '{}'.format('v1, v2, v3' if a.is_signed_v1() and a.is_signed_v2() and a.is_signed_v3() else 'v1' if a.is_signed_v1() else 'v2' if a.is_signed_v2() else 'v3'),
                sha1 = cert.sha1, #the sha1 fingerprint
                sha256 = cert.sha256,  # the sha256 fingerprint
                issuer = cert.issuer.human_friendly,  # issuer
                subject = cert.subject.human_friendly,  # subject, usually the same
                hash_algorithm = cert.hash_algo,  # hash algorithm
                signature_algorithm = cert.signature_algo,  # Signature algorithm
                serial_number = cert.serial_number,  # Serial number
                contents = cert.contents # The DER coded bytes of the certificate itself
            )
            c.save()
            certificates.append(c)
    return certificates


def get_tree_dir(scan):
    dir = DECOMPILE_PATH
    for dirpath, dirs, files in os.walk(dir): 
        for filename in files:
            fname = os.path.join(dirpath, filename)
            extension = os.path.splitext(fname)[1]
            if (extension == '.db' or extension == '.sqlite3' or extension =='.sql'):
                get_info_database(scan, fname)
            else:
                if (extension == '.java' or  extension == '.kt' or extension == '.xml'):
                    try:
                        prev_line = ''
                        for i, line in enumerate(open(fname, mode="r", encoding="utf-8")):
                            find_patterns(i + 1, prev_line, line, fname, dir, scan)
                            prev_line = line
                    except Exception as e:
                        logger.error('ERROR {} {}'.format(e, fname))
                    if (filename == 'AndroidManifest.xml'):
                        get_info_file(scan, fname, dir)
                else:
                    get_info_file(scan, fname, dir)


def find_patterns(i, prev_line, line, name, dir, scan):
    patterns = Pattern.objects.filter(active=True)
    findings = list()
    url = ''
    m = ''
    for p in patterns:
        pattern = re.compile(p.pattern, re.IGNORECASE)  
        try:
            for match in re.finditer(pattern, line):
                type = ''
                match_str = match.group()
                if (p.id == 8):
                    type = 'IP'
                elif (p.id == 9):
                    type = 'URL'
                    try:
                        if "schemas.android.com" in line:
                            break
                        url = urllib.parse.urlsplit(match_str)
                        if (settings.MALWAREDB_ENABLED):
                            m = Malware.objects.get(url__icontains=url.netloc)
                            print("found  " + match_str)
                    except Exception as e:
                        logger.error("not found " + match_str)
                elif (p.id == 10):
                    type = 'email'
                elif (p.id == 11):
                    type = 'DNI'
                elif (p.id == 12):
                    type = 'username'
                elif (p.id == 13):
                    type = 'credentials'
                elif (p.id == 14):
                    type = 'sensitive info'
                elif (p.id == 15):
                    type = 'connection'
                elif(p.id == 21):
                    try:
                        int(match_str, 16)
                        type = 'hex'
                    except Exception as e:
                        break
                elif (p.id == 22):
                    if (base64.b64encode(base64.b64decode(match_str)) != match_str):
                        break
                    type = 'base64'
                finding = Finding(
                    scan = scan,
                    path = name.replace(dir, ""),
                    line_number = i,
                    line = line,
                    snippet = prev_line + '\n' + line + '\n' + linecache.getline(name, i + 1),
                    match = match_str,
                    status = Status.TD,
                    type = p,
                    name = p.default_name,
                    description = p.default_description,
                    severity = p.default_severity,
                    mitigation = p.default_mitigation,
                    cwe = p.default_cwe,
                    user = scan.user
                )
                finding.save()
                scan.findings = int(scan.findings) + 1
                findings.append(finding)
                scan.save()
                if (type != ''):
                    s = String(type = type, value = match_str, scan = scan, finding = finding)
                    s.save()
                    if (type == 'URL'):
                        if (m):
                            u = Domain(scan = scan, domain = url.netloc, finding = finding, malware = m)
                        else:
                            u = Domain(scan = scan, domain = url.netloc, finding = finding)
                        u.save()
        except Exception as e:
            logger.debug(e)
            
    return findings
            
def get_lines(finding='', path=''):
    formatter = HtmlFormatter(linenos=False, cssclass="source")
    if (finding):
        APK_PATH = settings.BASE_DIR + finding.scan.apk.apk.url
        DECOMPILE_PATH = os.path.splitext(APK_PATH)[0]
        path = DECOMPILE_PATH + finding.path
    lines = []
    try:
        extension = os.path.splitext(path)[1]
        if (not extension == '.html' and not extension == '.js'):
            with open(path, encoding="utf-8") as f:
                for i, line in enumerate(f):
                    try:
                        if (i == 1):
                            lexer = guess_lexer_for_filename(path, line)
                        highlighted = highlight(line, lexer, formatter)
                        lines.append(highlighted)
                    except Exception as e:
                        if (line):
                            lines.append(line)
    except Exception as e:
        try:
            with open(path, encoding="utf-8") as f:
                for i, line in enumerate(f):
                    lines.append(line) 
        except Exception as e:
            logger.error(e)
    return lines

def create_finding_on_dojo(finding):
        data = {
            'title': finding.name,
            'description': '####Description\n' + finding.description + '\n####Snippet \n' + finding.snippet,
            'severity': finding.get_severity_display(),
            'cwe': finding.cwe.cwe,
            'found_by': [
                1
            ],
            'reporter': 1,
            'date': finding.created_on.strftime("%Y-%m-%d"),
            #'product': product_id,
            #'engagement': engagement_id,
            'test': finding.scan.apk.defectdojo_id,
            'impact': "N/A",
            'active': True,
            #'verified': verified,
            'mitigation': finding.mitigation if finding.mitigation != '' else 'N/A',
            #'references': references,
            #'build_id' : build,
            'line' : finding.line_number,
            'file_path' : finding.path,
            'static_finding' : True,
            #'dynamic_finding' : dynamic_finding,
            'duplicate': False,
        }
        
        if (finding.status == 'True Positive'):
            data['false_p'] = False
            data['verified'] = True
            data['under_review'] = False
        elif (finding.status == 'False Positive'):
            data['false_p'] = True
            data['verified'] = False
            data['under_review'] = False
        else:
            data['false_p'] = False
            data['verified'] = False
            data['under_review'] = True
    
        severity = 1
        if (finding.severity == 'CR'):
            severity = 10
        elif (finding.severity == 'HI'):
            severity = 8
        elif (finding.severity == 'ME'):
            severity = 6
        elif (finding.severity == 'LO'):
            severity = 3

        data['numerical_severity'] = severity
        
        json_data = json.dumps(data)
        logger.debug(json_data)
        
        headers = {
            'content-type': 'application/json',
            'Authorization': 'Token ' + settings.DEFECTDOJO_API_KEY
        }
        try:
            response = requests.post(settings.DEFECTDOJO_API_URL + 'findings/', data = json_data, headers = headers, verify = False)
            json_response = response.json()
            print(json_response)
            if (json_response['id']):
                finding.defectdojo_id = json_response['id']
                finding.save()
        except Exception as e:
            logger.error(e)

def get_info_file(scan, fname, dir):
    type = ''
    try:
        extension = os.path.splitext(fname)[1]
        if (extension == '.jpg' or fname == '.jpeg' or extension == '.png' or extension == '.gif' or extension == '.bmp' or extension == '.ico' or extension == '.svg'):
            type = 'image'
        elif (extension == '.mp4' or extension == '.mp3' or extension == '.avi' or extension == '.mkv' or extension == '.m4a'):
            type = 'media'
        elif (extension == '.xml'):
            type = 'xml'
        elif (extension == '.html'):
            type = 'html'
        elif (extension == '.properties'):
            type = 'properties'
        else:
            type = 'other'
        f = File(scan = scan, type = type, name = fname.replace(dir, ""), path = fname)
        f.save()
    except Exception as e:
        logger.error(e)

def get_info_database(scan, path):
    import sqlite3
    try:
        con = sqlite3.connect(path)
        # creating cursor
        cur = con.cursor()
        # reading all table names
        
        table_list = cur.execute("SELECT name FROM sqlite_master WHERE type = 'table'")
        try:
            for table in [_[0] for _ in table_list]:
                print(table)
                try:
                    table_info_list = cur.execute("SELECT * FROM " + table)
                    # here is you table list
                    for table_info in [_[0] for _ in table_info_list]:
                        db = DatabaseInfo(scan=scan, table=table, info=table_info)
                        db.save()
                except Exception as e:
                    logger.error(e)
        except Exception as e:
            print(e)
        # Be sure to close the connection
        con.close()
    except Exception as e:
        f = open(path)
        table_info = f.read() 
        db = DatabaseInfo(scan=scan, table='None', info=table_info)
        db.save()

def process_virus_total(scan, response, uploaded = False):
    logger.debug("Process VT")
    try:
        json_response = response.json()
        link = ''
        if (json_response['data']):
            data = json_response['data']
            attributes = json_response['data']['attributes']
            virus_scan = VirusTotalScan(
                identifier = data['id'],
                type = data['type'],
                link = data['links']['self'],
                scan = scan,
                times_submitted = attributes['times_submitted'],
                reputation = attributes['reputation'],
                sha256 = attributes['sha256'],
                md5 = attributes['md5'],
                ssdeep = attributes['ssdeep'],
                harmless = attributes['last_analysis_stats']['harmless'],
                malicious = attributes['last_analysis_stats']['malicious'],
                suspicious = attributes['last_analysis_stats']['suspicious'],
                votes_harmless = attributes['total_votes']['harmless'],
                votes_malicious = attributes['total_votes']['malicious'],
                magic = attributes['magic'],
                type_description = attributes['type_description'],
                uploaded = uploaded,
            )
            if 'first_seen_itw_date' in attributes:
                virus_scan.first_seen = datetime.fromtimestamp(attributes['first_seen_itw_date'])
            if ('first_submission_date' in attributes):
                virus_scan.first_submission = datetime.fromtimestamp(attributes['first_submission_date'])
            if ('last_submission_date' in attributes):
                virus_scan.last_submission = datetime.fromtimestamp(attributes['last_submission_date'])
            if ('last_analysis_date' in attributes):
                virus_scan.date = datetime.fromtimestamp(attributes['last_analysis_date'])
            if 'unsupported' in attributes['last_analysis_stats']:
                virus_scan.unsupported = attributes['last_analysis_stats']['unsupported']
            if 'undetected' in attributes['last_analysis_stats']:
                virus_scan.undetected = attributes['last_analysis_stats']['undetected']
            if 'timeout' in attributes['last_analysis_stats']:
                virus_scan.timeout = attributes['last_analysis_stats']['timeout']
            if 'failure' in attributes['last_analysis_stats']:
                virus_scan.failure = attributes['last_analysis_stats']['failure']
            if 'type-unsupported' in attributes['last_analysis_stats']:
                virus_scan.type_unsupported = attributes['last_analysis_stats']['type-unsupported']
            virus_scan.save()
            scans = attributes['last_analysis_results']
            for key, value in scans.items():
                antivirus = Antivirus(
                    scan = scan,
                    virus_scan = virus_scan,
                    name = value['engine_name'],
                    version = value['engine_version'],
                    update = value['engine_update'],
                    category = value['category'],
                    method = value['method'],
                )
                if value['result'] is not None:
                    antivirus.result = value['result']
                antivirus.save()
            return True
    except Exception as e:
        import traceback
        traceback.print_exc()
        print(e)
    return False

def get_report_virus_total(scan, sha256, uploaded = False):
    logger.debug("Get Report of VT")
    try:
        url = settings.VIRUSTOTAL_API_URL_V3 + 'files/' + sha256
        headers = {
            'x-apikey': settings.VIRUSTOTAL_API_KEY,
            'Accept-Encoding': 'gzip, deflate',
        }
        try:
            response = requests.get(
                url,
                headers = headers,
                verify = True
            )
            if response.status_code == 403:
                logger.error('VT Permission denied')
                return False
        except Exception:
            logger.error('VT Connection error')
            return False
        return process_virus_total(scan, response, uploaded)         
    except Exception as e:
        logger.error('VT Error')
        return False

def upload_virus_total(scan, file_path, sha256):
    logger.debug("Upload to VT")
    try:
        files = {
            'file': open(file_path, 'rb'),
        }
        url = settings.VIRUSTOTAL_API_URL_V2 + 'scan'
        data = {
            'apikey': settings.VIRUSTOTAL_API_KEY,
        }
        try:
            response = requests.post(
                url,
                files = files,
                data = data,
                verify = True
            )
            if response.status_code == 403:
                logger.error('VT Permission denied')
                return False
            json_response = response.json()
            print(json_response)
            if 'scan_id' in json_response:
                return get_report_virus_total(scan, sha256, True)
        except Exception:
            logger.error('VT Connection Error')
            return False
    except Exception as e:
        logger.error('VT Upload Error')
        return False

def upload_virus_total_v3(scan, file_path):
    logger.debug("Upload to VT")
    try:
        url = settings.VIRUSTOTAL_API_URL_V3 + 'files'
        headers = {
            'x-apikey': settings.VIRUSTOTAL_API_KEY,
            'Accept-Encoding': 'gzip, deflate',
        }
        data = {
            'file': open(file_path, 'rb'),
        }
        try:
            response = requests.post(
                url,
                headers = headers,
                data = data,
                verify = True
            )
            print(response)
            if response.status_code == 403:
                logger.error('VT Permission denied')
                return False
            json_response = response.json()
            print(json_response)
            if 'data' in json_response:
                return get_report_virus_total(scan, json_response['data']['id'], True)
        except Exception:
            logger.error('VT Connection Error')
            import traceback
            traceback.print_exc()
            return False
    except Exception as e:
        logger.error('VT Upload Error')
        return False