#!/usr/bin/python3
"""Weather visual rendering and inert endpoint submission; no real phones or AMI."""
import configparser
import importlib.util
import contextlib
import io
import json
from pathlib import Path
import sys
import tempfile
import unittest
import xml.etree.ElementTree as ET
from unittest import mock

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location('weather_visual_delivery', ROOT / 'slsmassnotifyserver/bin/sls_mass_notify/sls_notify.py')
NOTIFY = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(NOTIFY)


class WeatherVisualRendering(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix='sls-weather-image-')
        self.addCleanup(temporary.cleanup)
        self.web = Path(temporary.name) / 'web'
        self.web.mkdir(mode=0o755)
        self.config = configparser.ConfigParser(interpolation=None)
        self.config.read_dict({'visual': {'web_dir': str(self.web), 'public_base_url': 'https://pbx.example.invalid/sls_mass_notify',
                                        'image_width': '480', 'image_height': '272'},
                               'ami': {'host': '127.0.0.1', 'username': 'fixture', 'password': 'fixture'},
                               'api': {'events_file': str(Path(temporary.name) / 'events.jsonl')}})
        policy = self.web.parent / 'disabled-cluster.config'
        policy.write_text('{"enterprise_cluster":{"enabled":false}}')
        policy.chmod(0o600)
        mock.patch.object(NOTIFY._cluster_guard, 'CONFIG', policy).start()
        mock.patch.object(NOTIFY, 'PHONE_VISUAL_STATE', self.web.parent / 'visual-state').start()
        self.alert = NOTIFY.synthetic_alert('Manual NWS Test', 'Test', 'Configured NWS zone',
            'PBX TEST - Simulated Manual NWS Test. This visual alert was triggered from the FreePBX Mass Notifications testing page.',
            45, 'pbx-gui-test-fixture')
        self.addCleanup(mock.patch.stopall)
        mock.patch.object(NOTIFY.socket, 'create_connection', side_effect=AssertionError('Live AMI forbidden')).start()

    def test_actual_manual_weather_renderer_produces_color_phone_image(self):
        payload = NOTIFY.build_xml(self.config, self.alert)
        root = ET.fromstring(payload)
        self.assertEqual(root.tag, 'YealinkIPPhoneImageScreen', payload)
        image = root.find('Image')
        self.assertIsNotNone(image)
        self.assertEqual((image.attrib['width'], image.attrib['height']), ('480', '272'))
        filename = image.text.rsplit('/', 1)[1]
        self.assertTrue((self.web / filename).read_bytes().startswith(b'\x89PNG\r\n\x1a\n'))

    def test_announcement_renderer_control_uses_same_image_screen_protocol(self):
        payload = NOTIFY.build_announcement_image_xml(self.config, 'Fixture announcement', 'Announcement', '#215d8b')
        self.assertEqual(ET.fromstring(payload).tag, 'YealinkIPPhoneImageScreen')

    def test_explicit_text_only_phone_override_stays_text(self):
        payload = NOTIFY.build_phone_xml_for_format(self.config, 'yealink_text', 'alert', alert=self.alert)
        self.assertEqual(ET.fromstring(payload).tag, 'YealinkIPPhoneTextScreen')

    def push(self, fmt='yealink_image', render_failure=False, target_count=1):
        class InertAmi:
            def __init__(self): self.actions = []
            def __enter__(self): return self
            def __exit__(self, *args): pass
            def action(self, fields, complete_event=None):
                self.actions.append(fields)
                return {'Response': 'Success', 'Message': 'inert accepted'}, []
        ami = InertAmi()
        endpoints = {str(1000 + index): {'format': fmt, 'formats': [fmt], 'contacts': [
            {'format': fmt, 'contact': f'sip:{1000 + index}@192.0.2.{10 + index}:5060', 'user_agent': 'private fixture'}]}
            for index in range(target_count)}
        output = io.StringIO()
        with contextlib.ExitStack() as stack:
            stack.enter_context(mock.patch.object(NOTIFY, 'AmiClient', return_value=ami))
            stack.enter_context(mock.patch.object(NOTIFY, 'get_registered_endpoint_info', return_value=endpoints))
            stack.enter_context(mock.patch.object(NOTIFY, 'pjsip_notify_capabilities', return_value={'contact_uri_usable': False}))
            if render_failure:
                stack.enter_context(mock.patch.object(NOTIFY, 'render_alert_image', side_effect=OSError('private fixture renderer unavailable')))
            stack.enter_context(contextlib.redirect_stdout(output))
            try:
                NOTIFY.push_alert(self.config, self.alert, print_results=True, retries=False,
                    targets=set(endpoints), api_publish=False, require_all_targets=True, is_test=True)
            except NOTIFY.NotifyBatchError as error:
                failure = error
            else:
                failure = None
        records = [json.loads(line.split(' ', 1)[1]) for line in output.getvalue().splitlines()
                   if line.startswith('SLS_NOTIFY_RESULT ')]
        self.assertEqual(len(records), 1)
        return ami.actions, records[0], failure

    def test_explicit_image_format_reports_render_failure_instead_of_silent_text_success(self):
        actions, result, failure = self.push(render_failure=True)
        self.assertIsNotNone(failure, 'The selected image-only format silently degraded to text and reported success')
        self.assertEqual(actions, [], 'A failed explicit image payload must not be reported as an accepted image')
        self.assertEqual(result['targets'][0]['error_category'], 'payload_build_failed')

    def test_standard_yealink_still_has_resilient_text_fallback(self):
        actions, result, failure = self.push(fmt='yealink', render_failure=True)
        self.assertIsNone(failure)
        self.assertEqual(len(actions), 1)
        payload = next(value.removeprefix('Content=') for value in actions[0]['Variable'] if value.startswith('Content='))
        self.assertEqual(ET.fromstring(payload).tag, 'YealinkIPPhoneTextScreen')
        self.assertEqual(result['targets'][0].get('payload_kind'), 'text')

    def test_actual_weather_image_submission_retains_safe_payload_evidence(self):
        actions, result, failure = self.push()
        self.assertIsNone(failure)
        self.assertEqual(len(actions), 1)
        payload = next(value.removeprefix('Content=') for value in actions[0]['Variable'] if value.startswith('Content='))
        self.assertEqual(ET.fromstring(payload).tag, 'YealinkIPPhoneImageScreen')
        self.assertEqual(result['targets'][0].get('payload_kind'), 'image')
        self.assertEqual(result['targets'][0].get('media_scheme'), 'https')
        self.assertEqual(result['targets'][0].get('media_port'), 443)
        self.assertNotIn('https://pbx.example.invalid', json.dumps(result))
        self.assertFalse(result['handset_delivery_confirmed'])

    def test_explicit_image_target_reuses_the_already_rendered_weather_image(self):
        actions, result, failure = self.push()
        self.assertIsNone(failure)
        self.assertEqual(len(actions), 1)
        self.assertEqual(len(list(self.web.glob('alert_*.png'))), 1,
                         'The same Weather alert was rendered again for an explicit image target')

    def test_multiple_explicit_image_targets_share_one_validated_asset(self):
        actions, result, failure = self.push(target_count=3)
        self.assertIsNone(failure)
        self.assertEqual(len(actions), 3)
        images = [ET.fromstring(next(value.removeprefix('Content=') for value in action['Variable']
                    if value.startswith('Content='))).findtext('Image') for action in actions]
        self.assertEqual(len(set(images)), 1)
        self.assertEqual(len(list(self.web.glob('alert_*.png'))), 1)
        self.assertEqual(result['submitted_targets'], 3)

    def test_direct_explicit_image_builder_does_not_override_render_failure_with_text(self):
        with mock.patch.object(NOTIFY, 'render_alert_image', side_effect=OSError('private fixture unavailable')):
            with self.assertRaises(OSError):
                NOTIFY.build_phone_xml_for_format(self.config, 'yealink_image', 'alert', alert=self.alert)

    def test_custom_phone_image_port_and_capability_are_retained_without_leaking_link(self):
        import base64
        self.config['visual'].update(public_base_url='https://pbx.example.invalid:8443/sls_mass_notify',
            phone_capabilities='yes', phone_capability_key=base64.b64encode(b'x' * 32).decode(),
            phone_capability_generation='a' * 16)
        actions, result, failure = self.push()
        self.assertIsNone(failure)
        payload = next(value.removeprefix('Content=') for value in actions[0]['Variable'] if value.startswith('Content='))
        link = ET.fromstring(payload).findtext('Image')
        self.assertTrue(link.startswith('https://pbx.example.invalid:8443/sls_mass_notify/alert_'))
        self.assertIn('sls_sig=', link)
        self.assertEqual(result['targets'][0].get('media_port'), 8443)
        self.assertNotIn('sls_sig', json.dumps(result))


if __name__ == '__main__':
    unittest.main()
