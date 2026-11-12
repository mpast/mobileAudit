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
            with patch.object(analysis, 'DECOMPILE_PATH', directory):
                self.assertEqual(analysis.get_tree_dir(self.scan), 2)
        self.assertFalse(Finding.objects.exists())
        self.assertEqual(self.scan.file_set.count(), 2)

    def test_new_private_key_rule_is_scanned_in_assets_with_database_assigned_id(self):
        rule = self.rule(1000, r'-----BEGIN (?:ENCRYPTED |OPENSSH )?PRIVATE KEY-----')
        rule.default_name = 'Embedded private-key envelope'
        rule.save()
        with tempfile.TemporaryDirectory() as directory:
            Path(directory, 'config.json').write_text('"-----BEGIN OPENSSH PRIVATE KEY-----"')
            with patch.object(analysis, 'DECOMPILE_PATH', directory):
                self.assertEqual(analysis.get_tree_dir(self.scan), 0)
        self.assertEqual(Finding.objects.get().type_id, rule.pk)
