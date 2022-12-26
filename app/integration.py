import logging, json, requests
from datetime import datetime
from app.models import VirusTotalScan, Antivirus
from django.conf import settings

logger = logging.getLogger('app')

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
        logger.error(e)
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
            logger.debug(json_response)
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
            logger.debug(response)
            if response.status_code == 403:
                logger.error('VT Permission denied')
                return False
            json_response = response.json()
            logger.debug(json_response)
            if 'data' in json_response:
                return get_report_virus_total(scan, json_response['data']['id'], True)
        except Exception:
            logger.error('VT Connection Error')
            logger.error(e)
            return False
    except Exception as e:
        logger.error('VT Upload Error')
        return False

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
        'test': finding.scan.defectdojo_id if finding.scan.defectdojo_id else 1,
        'impact': "N/A",
        'active': True,
        #'verified': verified,
        'mitigation': finding.mitigation if finding.mitigation != '' else 'N/A',
        'references': finding.risk.reference,
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
        logger.debug(json_response)
        if ('id' in json_response and json_response['id']):
            finding.defectdojo_id = json_response['id']
            finding.save()
        else:
            logger.error(json_response)
    except Exception as e:
        logger.error(e)
