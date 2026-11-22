#!/usr/bin/env python3
"""Render the real composer beside native-sized Dashboard cards in Chromium."""
import base64
import json
import os
from pathlib import Path
import socket
import subprocess
import sys
import tempfile
import time
import unittest

ROOT = Path(__file__).resolve().parents[1]
MODULE = ROOT / 'slsmassnotifyserver'
if (os.environ.get('SLS_TEST_NAMESPACE') != 'entered'
        or os.environ.get('SLS_TEST_PARENT_NET_NS') in (None, '', os.readlink('/proc/self/ns/net'))):
    raise SystemExit('Use the isolated fixture runner; no browser was started.')
driver = os.environ.get('SLS_UI_PYTHON_PATH')
browser = os.environ.get('SLS_UI_CHROMIUM')
jquery = os.environ.get('SLS_UI_JQUERY')
if not driver or not browser or not jquery or not Path(browser).is_file() or not Path(jquery).is_file():
    raise SystemExit('Local Chromium, driver and jQuery are required; no downloads or production browsing occurred.')
sys.path.insert(0, driver)
from playwright.sync_api import sync_playwright


class DashboardWidgetFit(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        temporary = tempfile.TemporaryDirectory(prefix='sll-dashboard-fit-')
        cls.addClassCleanup(temporary.cleanup)
        cls.base = Path(temporary.name)
        (cls.base / 'jquery.js').write_bytes(Path(jquery).read_bytes())
        # The native Dashboard wrapper and standard form geometry are inert
        # presentation fixtures. The SLL metadata, markup and scripts are real.
        php = r'''<?php
function load_view($path,$variables=[]){extract($variables);ob_start();include $path;return ob_get_clean();}
$route=parse_url($_SERVER['REQUEST_URI'],PHP_URL_PATH);
if($route==='/jquery.js'){header('Content-Type: application/javascript');readfile(__DIR__.'/jquery.js');return;}
if($route==='/modules/slsmassnotifyserver/views/audience_source_picker.js'){
 header('Content-Type: application/javascript');readfile(MODULE.'/views/audience_source_picker.js');return;
}
if($route==='/config.php'){header('Content-Type: application/json');echo '{"success":true,"state":"idle","active":false}';return;}
if($route!=='/'){http_response_code(404);return;}
require MODULE.'/dashboard/sections/SlsMassNotifyAnnouncement.class.php';
$section=new \FreePBX\modules\Dashboard\Sections\SlsMassNotifyAnnouncement();
$metadata=$section->getSections([])[0];
$cardWidth=isset($_GET['narrow'])?($_GET['narrow']==='280'?'280px':'360px'):$metadata['width'];
$setup_complete=true;$csrf_token=str_repeat('a',64);
$announcement_targets=[['extension'=>'1001','name'=>str_repeat('Long handset name ',8),'registered'=>true]];
$announcement_group_targets=$announcement_targets;
$announcement_desktop_clients=[['client_id'=>'cli_fixture','username'=>'fixture-desktop','name'=>str_repeat('Long desktop name ',8),'enabled'=>true]];
$announcement_tones=['opening_fixture_with_a_long_readable_recording_name','closing_fixture'];
$announcement_groups=[];$announcement_webhooks=[];$outbound_voice_recipients=[];
?><!doctype html><html><head><meta name="viewport" content="width=device-width,initial-scale=1">
<style>
*{box-sizing:border-box}body{margin:0;padding:16px;font:14px Arial,sans-serif;color:#333;background:#fff}
.page{display:flex;flex-wrap:wrap;align-items:flex-start;gap:20px}.item{max-width:100%;min-width:0}
.displaybox{border-radius:4px;position:relative;border:1px solid #ddd;box-shadow:6px 10px 11px -2px rgba(163,163,163,.49)}
.displaybox .title-bar{border-radius:4px 4px 0 0;font-weight:bold;background:#f5f5f5;border-bottom:1px solid #ddd;color:#6f6f6f;text-align:center;font-size:120%;padding:1px}
.displaybox .content{border-radius:0 0 4px 4px;background:#fff;padding:5px;font-size:95%}
.native-box{padding:10px;border:1px solid #ddd;border-radius:4px;background:#fff;box-shadow:none;margin:5px 0 10px}
.native-box h4{font-size:14px;margin:0 0 9px}.container-fluid{padding:0 15px}.row{margin:0 -15px}.row:after{content:'';display:table;clear:both}
[class*=col-sm-]{position:relative;min-height:1px;padding:0 15px;width:100%}
@media(min-width:768px){.col-sm-7{float:left;width:58.333333%}.col-sm-5{float:left;width:41.666667%}.col-sm-4{float:left;width:33.333333%}.col-sm-6{float:left;width:50%}}
.form-group{margin-bottom:15px}.form-control{display:block;width:100%;height:34px;padding:6px 12px;font:14px Arial,sans-serif;color:#555;border:1px solid #ccc;border-radius:4px;background:#fff}
textarea.form-control{height:auto}label{display:inline-block;max-width:100%;margin-bottom:5px;font-weight:700}.checkbox label,.checkbox-inline{font-weight:400}
.checkbox,.checkbox-inline{position:relative;padding-left:20px}.checkbox input[type=checkbox],.checkbox-inline input[type=checkbox]{position:absolute;margin:3px 0 0 -20px}
.btn{display:inline-block;padding:6px 12px;font:14px/1.42857143 Arial,sans-serif;text-align:center;white-space:nowrap;vertical-align:middle;border:1px solid transparent;border-radius:4px;cursor:pointer}
.btn-default{color:#333;background:#fff;border-color:#ccc}.btn-primary{color:#fff;background:#337ab7;border-color:#2e6da4}.btn-sm{padding:5px 10px;font-size:12px}.btn-xs{padding:1px 5px;font-size:12px}.btn-link{color:#337ab7;background:transparent}
.text-muted,.help-block{color:#777}.help-block{display:block;margin:5px 0 10px}.badge{display:inline-block;padding:3px 7px;font-size:12px;font-weight:700;color:#fff;background:#777;border-radius:10px}
.label{padding:.2em .6em .3em;font-size:75%;font-weight:700;color:#fff;border-radius:.25em}.label-success{background:#5cb85c}.label-info{background:#5bc0de}.modal{display:none}[hidden]{display:none!important}
</style><script src="/jquery.js"></script></head><body>
<main class="page">
<section class="item" id="native-neighbor" style="width:550px"><div class="displaybox"><div class="title-bar">System Overview</div><div class="content"><div class="container-fluid"><div class="native-box"><h4>Summary</h4><p>System services are running.</p><label for="native-input">Native card control</label><input class="form-control" id="native-input" value="Unchanged neighboring widget"><button type="button" class="btn btn-default" id="native-button">Details</button></div></div></div></div></section>
<section class="item" id="sll-widget" style="width:<?php echo htmlspecialchars($cardWidth); ?>"><div class="displaybox"><div class="title-bar"><?php echo htmlspecialchars($metadata['title']); ?></div><div class="content"><?php include MODULE.'/dashboard/views/sections/sls-mass-notify-announcement.php'; ?></div></div></section>
</main></body></html>
'''.replace('MODULE', json.dumps(str(MODULE)))
        (cls.base / 'router.php').write_text(php)
        with socket.socket() as sock:
            sock.bind(('127.0.0.1', 0)); port = sock.getsockname()[1]
        cls.url = 'http://127.0.0.1:' + str(port)
        log = (cls.base / 'server.log').open('w')
        cls.addClassCleanup(log.close)
        cls.server = subprocess.Popen(['php', '-S', '127.0.0.1:' + str(port), str(cls.base / 'router.php')],
                                      cwd=cls.base, stdout=log, stderr=log)
        def stop():
            if cls.server.poll() is None:
                cls.server.terminate()
                try: cls.server.wait(timeout=3)
                except subprocess.TimeoutExpired: cls.server.kill(); cls.server.wait(timeout=3)
        cls.addClassCleanup(stop)
        deadline = time.monotonic() + 5
        while True:
            try:
                with socket.create_connection(('127.0.0.1', port), timeout=.1): break
            except OSError:
                if cls.server.poll() is not None or time.monotonic() > deadline:
                    raise RuntimeError('Private Dashboard server failed: ' + (cls.base / 'server.log').read_text()[-1000:])
                time.sleep(.03)
        cls.playwright = sync_playwright().start()
        cls.addClassCleanup(cls.playwright.stop)
        cls.browser = cls.playwright.chromium.launch(executable_path=browser, headless=True,
                                                   args=['--no-sandbox', '--disable-dev-shm-usage'])
        cls.addClassCleanup(cls.browser.close)

    def setUp(self):
        self.context = self.browser.new_context(viewport={'width': 1440, 'height': 1000})
        self.addCleanup(self.context.close)
        self.page = self.context.new_page()
        self.errors = []
        self.page.on('pageerror', lambda error: self.errors.append(str(error)))
        self.external = []
        def route(request):
            if request.request.url.startswith(self.url + '/'):
                request.continue_()
            else:
                self.external.append(request.request.url); request.abort()
        self.page.route('**/*', route)

    def load(self, narrow=False, mobile=False):
        if mobile: self.page.set_viewport_size({'width': 360, 'height': 900})
        self.page.goto(self.url + ('/?narrow=' + str(narrow) if narrow else '/'))
        self.page.locator('#dashboard_announcement_body').wait_for()
        self.assertEqual(self.errors, [])

    def capture(self, label):
        if os.environ.get('SLS_HOME_UI_CAPTURE') == '1':
            png = self.page.screenshot(full_page=True)
            print('HOME_UI_SCREENSHOT ' + json.dumps({'name': label, 'png': base64.b64encode(png).decode()}), flush=True)

    def assert_contained(self):
        self.assertEqual(self.external, [], 'Widget attempted an external request')
        metrics = self.page.locator('#dashboard-sls-mass-notify-announcement').evaluate('''root=>{
            const box=root.getBoundingClientRect();
            return {width:box.width,scroll:root.scrollWidth,client:root.clientWidth,
              escaped:[...root.querySelectorAll('input:not([type=hidden]),select,textarea,button,summary,img,audio')]
               .filter(node=>node.getClientRects().length&&getComputedStyle(node).display!=='none'&&!node.closest('.modal'))
               .filter(node=>{const r=node.getBoundingClientRect();return r.left<box.left-2||r.right>box.right+2})
               .map(node=>node.id||node.tagName)};
        }''')
        self.assertLessEqual(metrics['scroll'], metrics['client'] + 2, metrics)
        self.assertEqual(metrics['escaped'], [], metrics)
        self.assertEqual(self.errors, [])

    def test_widget_has_native_dashboard_card_width_and_surface(self):
        self.load()
        self.capture('desktop')
        native = self.page.locator('#native-neighbor').bounding_box()
        own = self.page.locator('#sll-widget').bounding_box()
        self.assertAlmostEqual(own['width'], native['width'], delta=1,
                               msg='SLL card must fit the same Dashboard column as native cards')
        style = self.page.locator('.sls-step-card').first.evaluate('''n=>{const s=getComputedStyle(n);return {shadow:s.boxShadow,radius:s.borderRadius,color:s.color}}''')
        reference = self.page.locator('.native-box').evaluate('''n=>{const s=getComputedStyle(n);return {shadow:s.boxShadow,radius:s.borderRadius,color:s.color}}''')
        self.assertEqual(style, reference, 'Inner SLL surface must use the native neutral card treatment')
        self.assert_contained()

    def test_narrow_card_reflows_on_a_wide_screen(self):
        self.load(narrow=True)
        self.capture('narrow-card-wide-screen')
        message = self.page.locator('#dashboard_announcement_body').bounding_box()
        audio = self.page.locator('.sls-option-box').bounding_box()
        self.assertGreater(audio['y'], message['y'] + message['height'],
                           'Audio options must stack below the message in a narrow card even on a wide screen')
        self.assertGreater(message['width'], 250, 'The message field was squeezed by a viewport-only breakpoint')
        self.assert_contained()

    def test_expanded_targets_and_colored_preview_stay_inside_mobile_card(self):
        self.load(mobile=True)
        for panel in self.page.locator('#dashboard-sls-mass-notify-announcement-form > .sls-step-card .sls-destination-panel').all():
            panel.locator('summary').click()
        self.page.locator('#dashboard_announcement_colored').check()
        self.page.locator('#dashboard_announcement_body').fill('Long announcement ' * 20)
        self.page.locator('#dashboard_announcement_title').fill('A long title for the color sample')
        self.capture('mobile-expanded')
        self.assert_contained()
        self.assertLessEqual(self.page.evaluate('document.documentElement.scrollWidth'), 360)

    def test_scoped_styling_keeps_neighbor_controls_unchanged(self):
        self.load(narrow=True)
        styles = self.page.locator('#native-input').evaluate('''node=>{
          const style=getComputedStyle(node),button=getComputedStyle(document.getElementById('native-button'));
          return {height:style.height,font:style.fontSize,radius:style.borderRadius,button:button.height};}''')
        self.assertEqual(styles, {'height': '34px', 'font': '14px', 'radius': '4px', 'button': '34px'})
        self.page.locator('.sls-destination-panel summary').first.focus()
        self.page.keyboard.press('Enter')
        self.assertTrue(self.page.locator('.sls-destination-panel').first.evaluate('(node)=>node.open'))
        self.assert_contained()

    def test_very_narrow_card_keeps_preview_controls_and_designer_usable(self):
        self.load(narrow=280)
        self.page.locator('#dashboard_announcement_colored').check()
        self.page.locator('#dashboard_announcement_title').fill('Long preview heading')
        self.assert_contained()
        message = self.page.locator('#dashboard_announcement_body').bounding_box()
        audio = self.page.locator('.sls-option-box').bounding_box()
        self.assertGreater(audio['y'], message['y'] + message['height'])


if __name__ == '__main__':
    unittest.main()
