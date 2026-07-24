import os
import json
from io import BytesIO
import signal
import subprocess
import tempfile
from unittest.mock import MagicMock, call, patch

from django.test import SimpleTestCase, override_settings

from app import analysis
from app.worker import tasks


class DecompileJadxTests(SimpleTestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.output_path = os.path.join(self.temp_dir.name, 'decompiled')
        self.apk_path = os.path.join(self.temp_dir.name, 'sample.apk')

    def tearDown(self):
        self.temp_dir.cleanup()

    def create_valid_output(self):
        sources_path = os.path.join(self.output_path, 'sources')
        os.makedirs(sources_path)
        with open(os.path.join(sources_path, 'Main.java'), 'w') as source:
            source.write('class Main {}')

    @patch('app.analysis.subprocess.Popen')
    def test_decompile_jadx_runs_in_new_session_and_marks_valid_output(self, popen):
        process = MagicMock(pid=123, returncode=0)
        process.stdout = BytesIO()
        process.wait.side_effect = lambda timeout: self.create_valid_output()
        popen.return_value = process

        analysis.decompile_jadx(self.apk_path, self.output_path, timeout=30)

        popen.assert_called_once_with(
            ['jadx', '-d', self.output_path, self.apk_path],
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            start_new_session=True,
        )
        process.wait.assert_called_once_with(timeout=30)
        self.assertTrue(os.path.isfile(self.output_path + '.jadx-complete'))

    @patch('app.analysis.subprocess.Popen')
    def test_decompile_jadx_cleans_stale_output_before_retry(self, popen):
        os.makedirs(os.path.join(self.output_path, 'sources'))
        stale_path = os.path.join(self.output_path, 'sources', 'stale.java')
        with open(stale_path, 'w') as stale_file:
            stale_file.write('stale')
        process = MagicMock(pid=123, returncode=0)
        process.stdout = BytesIO()
        process.wait.side_effect = lambda timeout: self.create_valid_output()
        popen.return_value = process

        analysis.decompile_jadx(self.apk_path, self.output_path, timeout=30)

        self.assertFalse(os.path.exists(stale_path))
        self.assertTrue(os.path.isfile(self.output_path + '.jadx-complete'))

    @patch('app.analysis.subprocess.Popen')
    def test_decompile_jadx_retries_when_completion_marker_is_invalid(self, popen):
        self.create_valid_output()
        marker_path = self.output_path + '.jadx-complete'
        with open(marker_path, 'w') as marker:
            marker.write('')
        process = MagicMock(pid=123, returncode=0)
        process.stdout = BytesIO()
        process.wait.side_effect = lambda timeout: self.create_valid_output()
        popen.return_value = process

        analysis.decompile_jadx(self.apk_path, self.output_path, timeout=30)

        popen.assert_called_once()
        with open(marker_path, 'rb') as marker:
            self.assertEqual(marker.read(), b'complete\n')

    @patch('app.analysis.os.replace', wraps=os.replace)
    @patch('app.analysis.subprocess.Popen')
    def test_decompile_jadx_writes_completion_marker_atomically(
        self,
        popen,
        replace,
    ):
        process = MagicMock(pid=123, returncode=0)
        process.stdout = BytesIO()
        process.wait.side_effect = lambda timeout: self.create_valid_output()
        popen.return_value = process

        analysis.decompile_jadx(self.apk_path, self.output_path, timeout=30)

        source_path, destination_path = replace.call_args.args
        self.assertEqual(destination_path, self.output_path + '.jadx-complete')
        self.assertEqual(
            os.path.dirname(source_path),
            os.path.dirname(destination_path),
        )
        self.assertNotEqual(source_path, destination_path)

    @patch('app.analysis.subprocess.Popen')
    def test_decompile_jadx_raises_on_non_zero_exit(self, popen):
        process = MagicMock(pid=123, returncode=1)
        process.stdout = BytesIO(b'res1 must be zero!')
        process.wait.side_effect = lambda timeout: os.mkdir(self.output_path)
        popen.return_value = process

        with self.assertRaisesRegex(RuntimeError, 'res1 must be zero'):
            analysis.decompile_jadx(self.apk_path, self.output_path, timeout=30)

        self.assertFalse(os.path.exists(self.output_path))

    @patch('app.analysis.subprocess.Popen')
    def test_decompile_jadx_limits_failure_output_to_last_4000_bytes(self, popen):
        process = MagicMock(pid=123, returncode=1)
        process.stdout = BytesIO(b'prefix' + (b'x' * 4000))
        process.wait.side_effect = lambda timeout: os.mkdir(self.output_path)
        popen.return_value = process

        with self.assertRaises(RuntimeError) as raised:
            analysis.decompile_jadx(self.apk_path, self.output_path, timeout=30)

        message = str(raised.exception)
        self.assertNotIn('prefix', message)
        self.assertTrue(message.endswith('x' * 4000))

    @patch('app.analysis.logger.warning')
    @patch('app.analysis.subprocess.Popen')
    def test_decompile_jadx_accepts_partial_exit_with_valid_output(
        self,
        popen,
        warning,
    ):
        process = MagicMock(pid=123, returncode=3)
        process.stdout = BytesIO(b'ERROR - finished with errors, count: 12')
        process.wait.side_effect = lambda timeout: self.create_valid_output()
        popen.return_value = process

        analysis.decompile_jadx(self.apk_path, self.output_path, timeout=30)

        self.assertTrue(os.path.isfile(self.output_path + '.jadx-complete'))
        warning.assert_called_once_with(
            'JADX completed with partial decompilation (exit code 3); '
            'continuing with usable output. Output tail: %s',
            'ERROR - finished with errors, count: 12',
        )

    @patch('app.analysis.subprocess.Popen')
    def test_decompile_jadx_rejects_partial_exit_with_empty_output(self, popen):
        process = MagicMock(pid=123, returncode=3)
        process.stdout = BytesIO(b'ERROR - finished with errors, count: 12')
        process.wait.side_effect = lambda timeout: os.mkdir(self.output_path)
        popen.return_value = process

        with self.assertRaisesRegex(
            RuntimeError,
            'produced no source or resource files',
        ):
            analysis.decompile_jadx(self.apk_path, self.output_path, timeout=30)

        self.assertFalse(os.path.exists(self.output_path))
        self.assertFalse(os.path.exists(self.output_path + '.jadx-complete'))

    @patch('app.analysis.os.killpg')
    @patch('app.analysis.subprocess.Popen')
    def test_decompile_jadx_terminates_process_group_on_timeout(self, popen, killpg):
        process = MagicMock(pid=123)
        process.stdout = BytesIO()
        process.wait.side_effect = [
            subprocess.TimeoutExpired(cmd='jadx', timeout=30),
            0,
        ]
        popen.return_value = process

        with self.assertRaisesRegex(RuntimeError, 'timed out after 30 seconds'):
            analysis.decompile_jadx(self.apk_path, self.output_path, timeout=30)

        killpg.assert_called_once_with(123, signal.SIGTERM)
        self.assertEqual(
            process.wait.call_args_list,
            [call(timeout=30), call(timeout=5)],
        )

    @patch('app.analysis.subprocess.Popen')
    def test_decompile_jadx_rejects_empty_success_output(self, popen):
        process = MagicMock(pid=123, returncode=0)
        process.stdout = BytesIO()
        process.wait.side_effect = lambda timeout: os.mkdir(self.output_path)
        popen.return_value = process

        with self.assertRaisesRegex(RuntimeError, 'produced no source or resource files'):
            analysis.decompile_jadx(self.apk_path, self.output_path, timeout=30)

        self.assertFalse(os.path.exists(self.output_path))
        self.assertFalse(os.path.exists(self.output_path + '.jadx-complete'))

    @override_settings(BASE_DIR='/tmp')
    @patch('app.analysis.get_info_certificate')
    @patch('app.analysis.get_info_apk')
    @patch('app.analysis.set_hash_app')
    @patch('app.analysis.APK')
    @patch('app.analysis.Scan.objects.get')
    @patch('app.analysis.decompile_jadx')
    def test_decompile_error_sets_terminal_scan_status(
        self,
        decompile_jadx,
        get_scan,
        apk,
        set_hash_app,
        get_info_apk,
        get_info_certificate,
    ):
        scan = MagicMock()
        scan.apk.url = '/sample.apk'
        get_scan.return_value = scan
        set_hash_app.return_value = scan
        get_info_apk.return_value = scan
        decompile_jadx.side_effect = RuntimeError('decompilation failed')
        task = MagicMock()

        with self.assertRaisesRegex(RuntimeError, 'decompilation failed'):
            analysis.analyze_apk(task, 1)

        self.assertEqual(scan.status, 'Error')
        self.assertEqual(scan.progress, 100)
        self.assertIsNotNone(scan.finished_on)
        scan.save.assert_called()
        self.assertFalse(
            any(
                update.kwargs.get('meta', {}).get('status') == 'Error'
                for update in task.update_state.call_args_list
            )
        )


class ScanStateTests(SimpleTestCase):
    @patch('app.worker.tasks.AsyncResult')
    @patch('app.worker.tasks.Scan.objects.get')
    def test_scan_state_serializes_celery_failure_exception(
        self,
        get_scan,
        async_result,
    ):
        scan = MagicMock(task='task-id', progress=100, status='Error')
        get_scan.return_value = scan
        async_result.return_value.info = RuntimeError('decompilation failed')

        response = tasks.scan_state(MagicMock(), 1)

        self.assertEqual(response.status_code, 200)
        self.assertEqual(
            json.loads(response.content),
            {
                'current': 100,
                'total': 100,
                'status': 'Error',
                'error': 'decompilation failed',
            },
        )

    @patch('app.worker.tasks.AsyncResult')
    @patch('app.worker.tasks.Scan.objects.get')
    def test_scan_state_returns_ordinary_result_dict_unchanged(
        self,
        get_scan,
        async_result,
    ):
        progress = {'current': 40, 'total': 100, 'status': 'In Progress'}
        get_scan.return_value = MagicMock(task='task-id')
        async_result.return_value.info = None
        async_result.return_value.result = progress

        response = tasks.scan_state(MagicMock(), 1)

        self.assertEqual(json.loads(response.content), progress)
