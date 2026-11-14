from androguard.core.apk import APK
from django.conf import settings
import logging, os, threading, hashlib, re, linecache, base64, urllib, shutil, signal, subprocess, tempfile
from binascii import Error as Base64Error
from django.core.exceptions import SuspiciousFileOperation
from app.models import *
from pygments import highlight
from pygments.lexers import PythonLexer
from pygments.formatters import HtmlFormatter
from pygments.lexers import guess_lexer, guess_lexer_for_filename
from datetime import datetime
from app.integration import *

logger = logging.getLogger('app')

APK_PATH = ""
DECOMPILE_PATH = ""

def set_hash_app(scan):
    if not scan.sha256:
        f = scan.apk.open('rb')
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
        scan.md5 = md5.hexdigest()
        scan.sha1 = sha1.hexdigest()
        scan.sha256 = sha256.hexdigest()
        scan.file_size = scan.apk.size
        scan.save()
        f.close()
    return scan


def analyze_apk(task, scan_id):
    # Start the APK analysis
    global APK_PATH
    global DECOMPILE_PATH
    scan = None
    try:
        scan = Scan.objects.get(pk=scan_id)
        APK_PATH = settings.BASE_DIR + scan.apk.url
        DECOMPILE_PATH = os.path.splitext(APK_PATH)[0]
        scan.status = 'In Progress'
        scan.progress = 3
        scan.save()
        task.update_state(state = 'STARTED',
                meta = {'current': scan.progress, 'total': 100, 'status': scan.status})
        logger.debug(scan.status)
        a = APK(APK_PATH)
        scan = set_hash_app(scan)
        scan.status = 'Getting info of apk'
        scan.progress = 5
        scan.save()
        task.update_state(state = 'STARTED',
                meta = {'current': scan.progress, 'total': 100, 'status': scan.status})
        logger.debug(scan.status)
        scan = get_info_apk(a, scan)
        scan.status = 'Getting info of certificates'
        scan.progress = 10
        scan.save()
        task.update_state(state = 'STARTED',
                meta = {'current': scan.progress, 'total': 100, 'status': scan.status})
        logger.debug(scan.status)
        get_info_certificate(a, scan)
        if (settings.VIRUSTOTAL_ENABLED):
            scan.status = 'Getting info of VT'
            scan.progress = 15
            scan.save()
            task.update_state(state = 'STARTED',
                meta = {'current': scan.progress, 'total': 100, 'status': scan.status})
            logger.debug(scan.status)
            report = get_report_virus_total(scan, scan.sha256)
            if (not report and settings.VIRUSTOTAL_UPLOAD):
                scan.status = 'Upload to VT'
                scan.save()
                upload_virus_total(scan, APK_PATH, scan.sha256)
        scan.status = 'Decompiling'
        scan.progress = 20
        scan.save()
        task.update_state(state = 'STARTED',
                meta = {'current': scan.progress, 'total': 100, 'status': scan.status})
        logger.debug(scan.status)
        decompile_jadx(APK_PATH, DECOMPILE_PATH)
        if (a.get_app_icon()):
            update_icon(scan, DECOMPILE_PATH + '/resources/' + a.get_app_icon())
        scan.status = 'Finding vulnerabilities'
        scan.progress = 40
        task.update_state(state = 'STARTED',
                meta = {'current': scan.progress, 'total': 100, 'status': scan.status})
        scan.save()
        logger.debug(scan.status)
        detection_errors = get_tree_dir(scan)
        scan.status = 'Finished with detection errors' if detection_errors else 'Finished'
        scan.progress = 100
        scan.finished_on = datetime.now()
        scan.save()
        task.update_state(state = 'STARTED',
                meta = {'current': scan.progress, 'total': 100, 'status': scan.status})
        logger.debug(scan.status)
    except Exception as e:
        if scan is not None:
            scan.progress = 100
            scan.status = "Error"
            scan.finished_on = datetime.now()
            scan.save()
        logger.exception(e)
        raise


def _has_decompiled_output(output_path):
    for directory in ('sources', 'resources'):
        directory_path = os.path.join(output_path, directory)
        if not os.path.isdir(directory_path):
            continue
        for _, _, files in os.walk(directory_path):
            if files:
                return True
    return False


def _cleanup_decompile_output(output_path, marker_path):
    shutil.rmtree(output_path, ignore_errors=True)
    try:
        os.remove(marker_path)
    except FileNotFoundError:
        pass


def _has_valid_completion_marker(marker_path):
    try:
        with open(marker_path, 'rb') as marker:
            return marker.read() == b'complete\n'
    except OSError:
        return False


def _write_completion_marker(marker_path):
    marker_directory = os.path.dirname(marker_path) or '.'
    temporary_path = None
    try:
        with tempfile.NamedTemporaryFile(
            mode='w',
            encoding='utf-8',
            dir=marker_directory,
            prefix=os.path.basename(marker_path) + '.',
            delete=False,
        ) as marker:
            temporary_path = marker.name
            marker.write('complete\n')
            marker.flush()
            os.fsync(marker.fileno())
        os.replace(temporary_path, marker_path)
    except Exception:
        if temporary_path is not None:
            try:
                os.remove(temporary_path)
            except FileNotFoundError:
                pass
        raise


def _capture_output_tail(stream, tail, limit=4000):
    for chunk in iter(lambda: stream.read(4096), b''):
        tail.extend(chunk)
        if len(tail) > limit:
            del tail[:-limit]


def _terminate_process_group(process):
    try:
        os.killpg(process.pid, signal.SIGTERM)
    except ProcessLookupError:
        return

    try:
        process.wait(timeout=5)
    except subprocess.TimeoutExpired:
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        process.wait()

def decompile_jadx(apk_path=None, output_path=None, timeout=None):
    apk_path = apk_path or APK_PATH
    output_path = output_path or DECOMPILE_PATH
    timeout = timeout or getattr(settings, 'JADX_TIMEOUT_SECONDS', 900)
    marker_path = output_path + '.jadx-complete'

    if _has_valid_completion_marker(marker_path) and _has_decompiled_output(output_path):
        return

    _cleanup_decompile_output(output_path, marker_path)
    command = ['jadx', '-d', output_path, apk_path]
    output_tail = bytearray()
    try:
        process = subprocess.Popen(
            command,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            start_new_session=True,
        )
        output_reader = threading.Thread(
            target=_capture_output_tail,
            args=(process.stdout, output_tail),
            daemon=True,
        )
        output_reader.start()
        process.wait(timeout=timeout)
    except subprocess.TimeoutExpired as exc:
        _terminate_process_group(process)
        output_reader.join(timeout=5)
        _cleanup_decompile_output(output_path, marker_path)
        error_output = bytes(output_tail[-4000:]).decode(
            'utf-8',
            errors='replace',
        ).strip()
        detail = ': {}'.format(error_output) if error_output else ''
        raise RuntimeError(
            'JADX decompilation timed out after {} seconds{}'.format(
                timeout,
                detail,
            )
        ) from exc
    except OSError as exc:
        if 'process' in locals():
            _terminate_process_group(process)
        _cleanup_decompile_output(output_path, marker_path)
        raise RuntimeError('Unable to execute JADX: {}'.format(exc)) from exc

    output_reader.join(timeout=5)
    error_output = bytes(output_tail[-4000:]).decode(
        'utf-8',
        errors='replace',
    ).strip()
    if process.returncode not in (0, 3):
        _cleanup_decompile_output(output_path, marker_path)
        raise RuntimeError(
            'JADX decompilation failed with exit code {}: {}'.format(
                process.returncode,
                error_output or 'No error output',
            )
        )

    if not _has_decompiled_output(output_path):
        _cleanup_decompile_output(output_path, marker_path)
        raise RuntimeError(
            'JADX decompilation produced no source or resource files'
        )

    if process.returncode == 3:
        logger.warning(
            'JADX completed with partial decompilation (exit code 3); '
            'continuing with usable output. Output tail: %s',
            error_output or 'No error output',
        )

    _write_completion_marker(marker_path)

def update_icon(scan, path):
    encoded_string = ''
    try:
        with open(path, 'rb') as image_file:
            encoded_string = base64.b64encode(image_file.read()).decode("utf-8")
            scan.icon = encoded_string
            scan.save()
    except Exception as e:
        logger.error("no icon")  


def get_info_apk(a, scan):
    set_hash_app(scan)
    scan.package = a.get_package()
    scan.apk_name = a.get_app_name()
    scan.version_code = a.get_androidversion_code()
    scan.version_name = a.get_androidversion_name()
    scan.min_sdk_version = a.get_min_sdk_version()
    scan.max_sdk_version = a.get_max_sdk_version()
    scan.target_sdk_version = a.get_target_sdk_version()
    scan.effective_target_sdk_version = a.get_effective_target_sdk_version()
    scan.manifest = a.get_android_manifest_axml().get_xml()
    scan.save()

    permissions = a.get_permissions()
    for permission in permissions:
        try:
            permission_type = PermissionType.objects.get(name=permission)
        except Exception as e:
            permission_type = PermissionType(name=permission, type='Other', default_severity=Severity.HI)
            permission_type.save()
        p = Permission(scan=scan, permission=permission_type, severity=permission_type.default_severity)
        p.save()
    
    #Activities and their intent-filters
    for activity in a.get_activities():
        get_intent_filter(a, scan, 'activity', activity)

    #Services and their intent-filters:
    for service in a.get_services():
        get_intent_filter(a, scan, 'service', service)
    
    #Receivers and their intent-filters:
    for receiver in a.get_receivers():
        get_intent_filter(a, scan, 'receiver', receiver)
    
    #Providers and their intent-filters:
    for provider in a.get_providers():
        get_intent_filter(a, scan, 'provider', provider)
    
    return scan

def get_intent_filter(a, scan, type, name):
    component = Component(name=name, scan=scan, type=type)
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
            intent = IntentFilter(name=intent, scan=scan, action=action, component=component)
            intent.save()
    if (type == 'activity'):
        if (main and launcher):
            main_activity = True
        activity = Activity(name=name, scan=scan, main=main_activity)
        activity.save()


def get_info_certificate(a, scan):
    # first check if this APK is signed
    certificates = list()
    if a.is_signed():
        # Iterate over all certificates
        for cert in a.get_certificates():
            # Each cert is now a asn1crypt.x509.Certificate object
            # From the Certificate object, we can query stuff like:
            c = Certificate(
                scan=scan,
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


ASSET_TEXT_EXTENSIONS = {'.json', '.properties', '.js', '.txt', '.html', '.yaml', '.yml', '.ini', '.cfg', '.conf'}


def get_tree_dir(scan):
    directory = DECOMPILE_PATH
    compiled_patterns, errors = load_patterns()
    # Source-only API rules are meaningless in packaged configuration or text assets.
    secret_patterns = [(rule, pattern) for rule, pattern in compiled_patterns
                       if rule.pk in (12, 13, 15) or 100 <= rule.pk <= 133
                       or rule.default_name == 'Embedded private-key envelope']
    asset_limit = getattr(settings, 'DETECTION_MAX_ASSET_BYTES', 2 * 1024 * 1024)
    for dirpath, dirs, files in os.walk(directory):
        dirs.sort()
        for filename in sorted(files):
            name = os.path.join(dirpath, filename)
            extension = os.path.splitext(name)[1].lower()
            if extension in {'.db', '.sqlite3', '.sql'}:
                get_info_database(scan, name)
                continue
            source = extension in {'.java', '.kt', '.xml'}
            asset = extension in ASSET_TEXT_EXTENSIONS
            if source or asset:
                try:
                    if source:
                        with open(name, encoding='utf-8') as file:
                            content = file.read()
                    else:
                        with open(name, 'rb') as file:
                            data = file.read(asset_limit + 1)
                        if len(data) > asset_limit or b'\0' in data:
                            errors += 1
                            reason = 'size limit exceeded' if len(data) > asset_limit else 'binary data'
                            logger.debug('Skipping text analysis of asset %s: %s', name, reason)
                            content = None
                        else:
                            content = data.decode('utf-8')
                    if content is not None:
                        rules = compiled_patterns if source else secret_patterns
                        errors += find_patterns(1, '', content, name, directory, scan, rules)
                except (OSError, UnicodeError, ValueError):
                    errors += 1
                    logger.exception('Could not analyze text file %s', name)
            if not source or filename == 'AndroidManifest.xml':
                get_info_file(scan, name, directory)
    return errors


def load_patterns():
    """Compile one ordered rule snapshot and isolate invalid administrator rules."""
    compiled = []
    errors = 0
    for rule in Pattern.objects.filter(active=True).select_related('default_cwe', 'default_risk').order_by('pk'):
        try:
            compiled.append((rule, re.compile(rule.pattern, re.MULTILINE)))
        except re.error:
            errors += 1
            logger.error('Skipping invalid detection rule %s', rule.pk)
    return compiled, errors


def get_position(match):
    return match.span()


def get_match_lines(content, position):
    start, end = position
    first = content.rfind('\n', 0, start) + 1
    last = content.find('\n', max(start, end - 1))
    if last == -1:
        last = len(content)
    return content.count('\n', 0, start) + 1, content[first:last]


def find_patterns(i, prev_line, line, name, dir, scan, compiled_patterns=None):
    errors = 0
    if compiled_patterns is None:
        compiled_patterns, errors = load_patterns()
    for p, pattern in compiled_patterns:
        try:
            for match in pattern.finditer(line):
                if match.group():
                    type = ''
                    url = None
                    m = None
                    match_str = match.group()
                    if (p.id == 8):
                        type = 'IP'
                    elif (p.id == 9):
                        type = 'URL'
                        try:
                            url = urllib.parse.urlsplit(match_str)
                            host = url.hostname
                        except ValueError:
                            continue
                        if host == 'schemas.android.com':
                            continue
                        if settings.MALWARE_ENABLED and host:
                            for candidate in Malware.objects.filter(url__icontains=host):
                                try:
                                    candidate_host = urllib.parse.urlsplit(
                                        candidate.url if '://' in candidate.url else '//' + candidate.url
                                    ).hostname
                                except ValueError:
                                    continue
                                if candidate_host == host:
                                    m = candidate
                                    break
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
                        except ValueError:
                            continue
                    elif (p.id == 22):
                        try:
                            decoded = base64.b64decode(match_str, validate=True)
                            if base64.b64encode(decoded).decode('ascii') != match_str:
                                continue
                        except (ValueError, Base64Error):
                            continue
                        type = 'base64'

                    match_lines = get_match_lines(line, get_position(match))
                    snippet = match_lines[1]
                    position = match_lines[0]
                    if (not snippet):
                        snippet = line
                
                    finding = Finding(
                        scan = scan,
                        path = name.replace(dir, ""),
                        line_number = position,
                        line = match_str,
                        snippet = snippet,
                        match = match_str,
                        status = Status.TD,
                        type = p,
                        name = p.default_name,
                        description = p.default_description,
                        severity = p.default_severity,
                        mitigation = p.default_mitigation,
                        cwe = p.default_cwe,
                        risk = p.default_risk,
                        user = scan.user
                    )
                    finding.save()
                    scan.findings = int(scan.findings) + 1
                    scan.save()
                    if (type != ''):
                        s = String(type = type, value = match_str, scan = scan, finding = finding)
                        s.save()
                        if type == 'URL' and url.hostname:
                            if (m):
                                u = Domain(scan = scan, domain = url.hostname, finding = finding, malware = m)
                            else:
                                u = Domain(scan = scan, domain = url.hostname, finding = finding)
                            u.save()
        except Exception:
            errors += 1
            logger.exception('Detection rule %s failed for %s', p.pk, name)
    return errors

def get_lines(finding='', path=''):
    formatter = HtmlFormatter(linenos=False, cssclass="source")
    if (finding):
        decompile_path = os.path.realpath(os.path.splitext(finding.scan.apk.path)[0])
        path = os.path.realpath(
            os.path.join(decompile_path, finding.path.lstrip('/\\'))
        )
        try:
            contained = os.path.commonpath([decompile_path, path]) == decompile_path
        except ValueError:
            contained = False
        if not contained:
            raise SuspiciousFileOperation('Finding path is outside the scan decompile directory.')
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
                logger.error(table)
                try:
                    table_info_list = cur.execute("SELECT * FROM " + table)
                    # here is you table list
                    for table_info in [_[0] for _ in table_info_list]:
                        db = DatabaseInfo(scan=scan, table=table, info=table_info)
                        db.save()
                except Exception as e:
                    logger.error(e)
        except Exception as e:
            logger.error(e)
        # Be sure to close the connection
        con.close()
    except Exception as e:
        f = open(path)
        table_info = f.read() 
        db = DatabaseInfo(scan=scan, table='None', info=table_info)
        db.save()
