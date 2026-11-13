from django.db import migrations


# Update only unchanged shipped defaults; preserve administrator customizations.
UPDATES = {3: {'pattern': ('(openFileOutput|openFileInput|getSharedPreferences|SharedPreferences\\.Editor|getCacheDir|getExternalCacheDirs|getExternalStorageState|openOrCreateDatabase|createTempFile|getExternalFilesDir|getExternal|FileOutPutStream|getWritableDatabase|getReadableDatabasegetCacheDir)',
                 '(openFileOutput|openFileInput|getSharedPreferences|SharedPreferences\\.Editor|getCacheDir|getExternalCacheDirs|getExternalStorageState|openOrCreateDatabase|createTempFile|getExternalFilesDir|getExternal|FileOutPutStream|getWritableDatabase|getReadableDatabase|getCacheDir)')},
 4: {'pattern': ('(getConnectionInfo|getSSID|getConfiguredNetworks|getNetworkId|getIpAddress|getMacAddressgetNetworkInterfaces|getInetAddresses|getHostAddress)',
                 '(getConnectionInfo|getSSID|getConfiguredNetworks|getNetworkId|getIpAddress|getMacAddress|getNetworkInterfaces|getInetAddresses|getHostAddress)')},
 10: {'pattern': ('[w.-]{1,20}@[w-]{1,20}\\.[w]{2,10}',
                  '(?<![A-Za-z0-9._%+-])[A-Za-z0-9._%+-]{1,64}@(?=[A-Za-z0-9.-]{1,253}(?![A-Za-z0-9-]|\\.[A-Za-z0-9-]))(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\\.){1,126}[A-Za-z]{2,63}(?![A-Za-z0-9-]|\\.[A-Za-z0-9-])')},
 12: {'pattern': ('(admin|login|user|username|usr|usuario|root)s*=s*".*"',
                  '\\b(?:admin|login|user|username|usr|usuario|root)\\s*=\\s*"[^"\\r\\n]+"')},
 13: {'pattern': ('(pass|pwd|password|secret|key|contrasenia)s*=s*".*"',
                  '\\b(?:pass|pwd|password|secret|key|contrasenia)\\s*=\\s*"[^"\\r\\n]+"')},
 15: {'pattern': ('(://[^ ]{1,$WILDCARD_SHORT}:[^ ]{1,$WILDCARD_SHORT}@|openOrCreateDatabase\\()',
                  '(?:://[^\\s:/@]{1,128}:[^\\s/@]{1,128}@|openOrCreateDatabase\\()')},
 19: {'default_description': ('The application is making HTTP requests',
                              'HTTP client API usage is an inventory indicator; it does not establish '
                              'insecure transport or a TLS validation bypass.'),
      'default_mitigation': ('The application may be vulnerable to MITM attacks, check if the connections '
                             'are secure.',
                             'Review effective network security policy and TLS validation behavior.'),
      'default_name': ('HTTP Request', 'HTTP client usage'),
      'default_severity': ('HI', 'NO')},
 116: {'default_description': ('There are sensitive information into the source code',
                               'A service-account configuration contains embedded private-key material. '
                               'Public service-account metadata alone is not a secret.'),
       'pattern': ("'type', Severity.HI, 'service_account'",
                   '"type"\\s*:\\s*"service_account"(?=[^{}]{0,8192}"private_key"\\s*:\\s*"-----BEGIN (?:RSA '
                   ')?PRIVATE KEY-----)')},
 205: {'default_description': ('The application verifies the certificate with SSL Pinning',
                               'A certificate-pinning API is referenced. This does not establish that '
                               'pinning is configured, effective, or reached at runtime.'),
       'default_name': ('Conection Verification/SSL Pinning', 'Certificate pinning API indicator'),
       'pattern': ('(PinningHelper\\.getPinnedHttpsURLConnection|PinningHelper\\.getPinnedHttpClient|PinningSSLSocketFactory|TrustManager|onReceivedSslError|HostnameVerifier|CertificatePinner)',
                   '(PinningHelper\\.getPinnedHttpsURLConnection|PinningHelper\\.getPinnedHttpClient|PinningSSLSocketFactory|CertificatePinner)')}}

SHIPPED_PATTERNS = {3: '(openFileOutput|openFileInput|getSharedPreferences|SharedPreferences\\.Editor|getCacheDir|getExternalCacheDirs|getExternalStorageState|openOrCreateDatabase|createTempFile|getExternalFilesDir|getExternal|FileOutPutStream|getWritableDatabase|getReadableDatabasegetCacheDir)',
 4: '(getConnectionInfo|getSSID|getConfiguredNetworks|getNetworkId|getIpAddress|getMacAddressgetNetworkInterfaces|getInetAddresses|getHostAddress)',
 10: '[w.-]{1,20}@[w-]{1,20}\\.[w]{2,10}',
 12: '(admin|login|user|username|usr|usuario|root)s*=s*".*"',
 13: '(pass|pwd|password|secret|key|contrasenia)s*=s*".*"',
 15: '(://[^ ]{1,$WILDCARD_SHORT}:[^ ]{1,$WILDCARD_SHORT}@|openOrCreateDatabase\\()',
 19: '(HttpsURLConnection|HttpsURLConnection|HttpURLConnection|org\\.apache\\.http|HttpRequest|HttpPost|HttpClient|HttpResponse|AndroidHttpClient|AbstractHttpClient|URLConnection|openConnection|openStream|TrustAllSSLSocket\\-Factory|AllTrustSSLSocketFactory|NonValidatingSSLSocketFactory|SSLCertificateSocketFactory|ALLOW_ALL_HOSTNAME_VERIFIER|\\.setDefaultHostnameVerifier\\(|NullHostnameVerifier\\()',
 116: "'type', Severity.HI, 'service_account'",
 205: '(PinningHelper\\.getPinnedHttpsURLConnection|PinningHelper\\.getPinnedHttpClient|PinningSSLSocketFactory|TrustManager|onReceivedSslError|HostnameVerifier|CertificatePinner)'}

NEW_RULE = {'active': True,
 'default_cwe': 200,
 'default_description': 'A PKCS#8 or OpenSSH private-key envelope is embedded in an application file. Review '
                        'whether private-key material is distributed with the application.',
 'default_mitigation': 'Remove embedded private keys and rotate any exposed credentials.',
 'default_name': 'Embedded private-key envelope',
 'default_risk': 7,
 'default_severity': 'HI',
 'pattern': '-----BEGIN (?:ENCRYPTED |OPENSSH )?PRIVATE KEY-----'}


def repair_rules(apps, schema_editor):
    Pattern = apps.get_model('app', 'Pattern')
    database = schema_editor.connection.alias
    for pk, fields in UPDATES.items():
        if not Pattern.objects.using(database).filter(pk=pk, pattern=SHIPPED_PATTERNS[pk]).exists():
            continue
        for field, (previous, replacement) in fields.items():
            Pattern.objects.using(database).filter(pk=pk, **{field: previous}).update(**{field: replacement})
    # Avoid numeric-ID assumptions and do not overwrite a custom rule with ID 133.
    if apps.get_model('app', 'Cwe').objects.using(database).filter(pk=NEW_RULE['default_cwe']).exists():
        fields = dict(NEW_RULE)
        fields['default_cwe_id'] = fields.pop('default_cwe')
        fields['default_risk_id'] = fields.pop('default_risk')
        if not apps.get_model('app', 'Risk').objects.using(database).filter(pk=fields['default_risk_id']).exists():
            fields['default_risk_id'] = None
        Pattern.objects.using(database).get_or_create(default_name=fields.pop('default_name'), defaults=fields)


class Migration(migrations.Migration):
    dependencies = [('app', '0007_scan_guest_session_fingerprint')]
    operations = [migrations.RunPython(repair_rules, migrations.RunPython.noop)]
