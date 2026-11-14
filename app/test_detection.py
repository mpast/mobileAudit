import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile
from importlib import import_module
from types import SimpleNamespace
from unittest.mock import patch

from django.apps import apps
from django.db import connection
from django.test.utils import CaptureQueriesContext

from django.test import SimpleTestCase, TestCase, override_settings

from app import analysis
from app.models import Cwe, Domain, Finding, Malware, Pattern, Scan, String


@override_settings(MALWARE_ENABLED=False)
class DetectionTests(TestCase):
    def setUp(self):
        self.scan = Scan.objects.create(name='Detection regression', apk='sample.apk')
        self.cwe = Cwe.objects.create(cwe=200, description='Information exposure')

    def rule(self, pk, expression):
        return Pattern.objects.create(
            pk=pk, pattern=expression, default_cwe=self.cwe,
            default_name='Test rule', default_severity='LO',
        )

    def detect(self, content, **kwargs):
        return analysis.find_patterns(1, '', content, '/scan/Test.java', '/scan', self.scan, **kwargs)

    def test_namespace_url_does_not_hide_real_endpoints(self):
        self.rule(9, r'https?://[^\s"<>]+')
        self.detect('<root xmlns:android="http://schemas.android.com/apk/res/android">\n'
                    '<url>https://api.example.com/v1</url></root>')
        self.assertEqual(list(String.objects.values_list('value', flat=True)),
                         ['https://api.example.com/v1'])
        self.assertEqual(Domain.objects.get().domain, 'api.example.com')

    def test_invalid_url_does_not_suppress_next_url(self):
        self.rule(9, r'https?://[^\s]+')
        self.detect('https://[invalid https://api.example.com')
        self.assertEqual(list(Domain.objects.values_list('domain', flat=True)), ['api.example.com'])

    def test_invalid_base64_does_not_suppress_valid_candidate(self):
        self.rule(22, r'\S+')
        self.detect('not-base64 SGVsbG8gd29ybGQ=')
        self.assertEqual(list(String.objects.values_list('type', 'value')),
                         [('base64', 'SGVsbG8gd29ybGQ=')])

    def test_noncanonical_base64_is_rejected_without_stopping(self):
        self.rule(22, r'\S+')
        self.detect('Zh== Zg==')
        self.assertEqual(list(String.objects.values_list('value', flat=True)), ['Zg=='])

    def test_invalid_regex_does_not_suppress_other_rules(self):
        self.rule(1, '(')
        self.rule(2, 'danger')
        self.detect('danger')
        self.assertEqual(Finding.objects.get().type_id, 2)

    @override_settings(MALWARE_ENABLED=True)
    def test_malware_match_is_not_reused_for_next_domain(self):
        self.rule(9, r'https?://\S+')
        malware = Malware.objects.create(url='malicious.example')
        self.detect('https://malicious.example https://clean.example')
        self.assertEqual(list(Domain.objects.order_by('pk').values_list('malware_id', flat=True)),
                         [malware.pk, None])

    def test_match_at_next_line_start_has_correct_evidence(self):
        self.rule(1, 'danger')
        self.detect('safe\ndanger')
        finding = Finding.objects.get()
        self.assertEqual((finding.line_number, finding.snippet), (2, 'danger'))

    def test_multiline_match_preserves_complete_evidence(self):
        self.rule(1, 'first\nsecond')
        self.detect('safe\nfirst\nsecond\nafter')
        finding = Finding.objects.get()
        self.assertEqual((finding.line_number, finding.snippet), (2, 'first\nsecond'))

    def test_tree_compiles_one_snapshot_for_all_files(self):
        self.rule(1, 'danger')
        with tempfile.TemporaryDirectory() as directory:
            for name in ('One.java', 'Two.kt'):
                Path(directory, name).write_text('danger')
            with patch.object(analysis, 'DECOMPILE_PATH', directory), CaptureQueriesContext(connection) as queries:
                self.assertEqual(analysis.get_tree_dir(self.scan), 0)
        rule_queries = [query for query in queries if 'FROM "app_pattern"' in query['sql']]
        self.assertEqual(len(rule_queries), 1)
        self.assertEqual(Finding.objects.count(), 2)

    def test_assets_scan_secrets_and_inventory_without_source_api_rules(self):
        self.rule(1, 'danger')
        self.rule(13, r'password\s*=\s*"[^"\n]+"')
        with tempfile.TemporaryDirectory() as directory:
            Path(directory, 'config.properties').write_text('password = "private-value"; danger')
            with patch.object(analysis, 'DECOMPILE_PATH', directory):
                self.assertEqual(analysis.get_tree_dir(self.scan), 0)
        self.assertEqual(Finding.objects.get().type_id, 13)
        self.assertEqual(self.scan.file_set.count(), 1)

    @override_settings(DETECTION_MAX_ASSET_BYTES=8)
    def test_oversized_and_binary_assets_report_incomplete_coverage(self):
        self.rule(13, 'secret')
        with tempfile.TemporaryDirectory() as directory:
            Path(directory, 'large.txt').write_text('secret' * 10)
            Path(directory, 'binary.txt').write_bytes(b'\0secret')
            with patch.object(analysis, 'DECOMPILE_PATH', directory), patch.object(analysis, 'logger') as logger:
                self.assertEqual(analysis.get_tree_dir(self.scan), 2)
            logger.exception.assert_not_called()
            self.assertEqual(logger.debug.call_count, 2)
        self.assertFalse(Finding.objects.exists())
        self.assertEqual(self.scan.file_set.count(), 2)

    @override_settings(DETECTION_MAX_ASSET_BYTES=8)
    def test_asset_at_size_limit_is_scanned(self):
        self.rule(13, 'secret')
        with tempfile.TemporaryDirectory() as directory:
            Path(directory, 'config.txt').write_bytes(b'secret!!')
            with patch.object(analysis, 'DECOMPILE_PATH', directory):
                self.assertEqual(analysis.get_tree_dir(self.scan), 0)
        self.assertEqual(Finding.objects.get().type_id, 13)
        self.assertEqual(self.scan.file_set.count(), 1)

    def test_unreadable_asset_still_reports_analysis_failure(self):
        with tempfile.TemporaryDirectory() as directory:
            name = str(Path(directory, 'config.txt'))
            Path(name).write_text('secret')
            with patch.object(analysis, 'DECOMPILE_PATH', directory), \
                    patch('builtins.open', side_effect=OSError('Permission denied')), \
                    patch.object(analysis, 'get_info_file') as inventory, \
                    patch.object(analysis, 'logger') as logger:
                self.assertEqual(analysis.get_tree_dir(self.scan), 1)
            logger.exception.assert_called_once_with('Could not analyze text file %s', name)
            inventory.assert_called_once_with(self.scan, name, directory)

    def test_migration_repairs_defaults_but_preserves_customizations(self):
        migration = import_module('app.migrations.0008_repair_detection_rules')
        previous = migration.UPDATES[12]['pattern'][0]
        default = self.rule(12, previous)
        custom = self.rule(13, 'custom credential expression')
        custom_http = self.rule(19, 'custom TLS check')
        custom_http.default_severity = 'HI'
        custom_http.save()
        migration.repair_rules(apps, SimpleNamespace(connection=connection))
        default.refresh_from_db()
        custom.refresh_from_db()
        self.assertRegex('username = "alice"', default.pattern)
        self.assertEqual(custom.pattern, 'custom credential expression')
        custom_http.refresh_from_db()
        self.assertEqual(custom_http.default_severity, 'HI')
        self.assertEqual(Pattern.objects.filter(default_name='Embedded private-key envelope').count(), 1)
        migration.repair_rules(apps, SimpleNamespace(connection=connection))
        self.assertEqual(Pattern.objects.filter(default_name='Embedded private-key envelope').count(), 1)

    def test_new_private_key_rule_is_scanned_in_assets_with_database_assigned_id(self):
        rule = self.rule(1000, r'-----BEGIN (?:ENCRYPTED |OPENSSH )?PRIVATE KEY-----')
        rule.default_name = 'Embedded private-key envelope'
        rule.save()
        with tempfile.TemporaryDirectory() as directory:
            Path(directory, 'config.json').write_text('"-----BEGIN OPENSSH PRIVATE KEY-----"')
            with patch.object(analysis, 'DECOMPILE_PATH', directory):
                self.assertEqual(analysis.get_tree_dir(self.scan), 0)
        self.assertEqual(Finding.objects.get().type_id, rule.pk)



class ShippedRuleTests(SimpleTestCase):
    def setUp(self):
        fixture = Path(__file__).parent / 'fixtures' / 'data.json'
        self.rules = {item['pk']: item['fields']['pattern']
                      for item in json.loads(fixture.read_text()) if item['model'] == 'app.pattern'}

    def test_all_shipped_patterns_compile(self):
        for pk, expression in self.rules.items():
            with self.subTest(rule=pk):
                re.compile(expression, re.MULTILINE)

    def test_repaired_patterns_match_realistic_examples(self):
        cases = {
            3: ('getReadableDatabase()', 'readDatabase()'),
            4: ('getNetworkInterfaces()', 'getNetwork()'),
            10: ('audit.user@example.com', 'audit.user.example.com'),
            12: ('username = "alice"', 'username = account.name'),
            13: ('password = "private-value"', 'password = credentials.get()'),
            15: ('jdbc://alice:private-value@database', 'jdbc://database'),
            116: ('"type": "service_account", "private_key": "-----BEGIN PRIVATE KEY-----\\nabc"',
                  '"type": "service_account", "client_email": "public@example.com"'),
        }
        for pk, (positive, negative) in cases.items():
            with self.subTest(rule=pk):
                self.assertRegex(positive, self.rules[pk])
                self.assertNotRegex(negative, self.rules[pk])

    def test_pinning_indicator_does_not_claim_generic_tls_api_is_secure(self):
        for value in ('TrustManager', 'HostnameVerifier', 'onReceivedSslError'):
            with self.subTest(value=value):
                self.assertNotRegex(value, self.rules[205])

    def test_private_key_envelopes_exclude_public_keys_and_existing_rsa_rule(self):
        for value in ('PRIVATE KEY', 'ENCRYPTED PRIVATE KEY', 'OPENSSH PRIVATE KEY'):
            with self.subTest(value=value):
                self.assertRegex('-----BEGIN ' + value + '-----', self.rules[133])
        for value in ('PUBLIC KEY', 'RSA PUBLIC KEY', 'RSA PRIVATE KEY'):
            with self.subTest(value=value):
                self.assertNotRegex('-----BEGIN ' + value + '-----', self.rules[133])

    def test_email_rule_bounds_lengths_and_rejects_long_non_email_input(self):
        expression = self.rules[10]
        self.assertRegex('a' * 64 + '@example.com', expression)
        self.assertNotRegex('a' * 65 + '@example.com', expression)
        self.assertNotRegex('a@' + 'label.' * 50 + 'example.com', expression)
        # Isolate pathological matching so a regression cannot hang the suite.
        result = subprocess.run(
            [sys.executable, '-c',
             'import re, sys; sys.exit(bool(re.search(sys.argv[1], sys.stdin.read())))',
             expression],
            input='a.' * 64000, text=True, capture_output=True, timeout=5,
        )
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_email_rule_accepts_sentence_punctuation_without_truncating_domains(self):
        expression = re.compile(self.rules[10])
        for text in ('Contact support@example.com.', 'Contact support@example.com,',
                     '(support@example.com)', 'support@example.com; contact us'):
            with self.subTest(text=text):
                self.assertEqual(expression.search(text).group(), 'support@example.com')
        maximum_domain = '.'.join(['a' * 63] * 3 + ['a' * 61])
        self.assertEqual(len(maximum_domain), 253)
        self.assertEqual(expression.search('a@' + maximum_domain + '.').group(),
                         'a@' + maximum_domain)
        self.assertIsNone(expression.search('a@' + maximum_domain + 'a.'))
        self.assertIsNone(expression.search('a@' + 'a' * 64 + '.com.'))
