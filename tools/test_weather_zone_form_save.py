#!/usr/bin/python3
"""Real Weather form encoding reaches strict saves, with inert host/storage adapters."""
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from urllib.parse import parse_qsl, urlencode

if os.environ.get('SLS_TEST_NAMESPACE') != 'entered':
    raise SystemExit('Use tools/run_isolated_tests.sh; no browser or module was loaded.')
driver = os.environ.get('SLS_UI_PYTHON_PATH')
browser = os.environ.get('SLS_UI_CHROMIUM')
if not driver or not browser or not Path(browser).is_file():
    raise SystemExit('Required private Chromium fixture is unavailable; no Weather save was executed.')
sys.dont_write_bytecode = True
sys.path.insert(0, driver)
from playwright.sync_api import sync_playwright

ROOT = Path(__file__).resolve().parents[1]
PHP = r'''<?php
declare(strict_types=1);
interface BMO {}
function load_view($path,$variables=[]){return '';}
require MODULE.'/Slsmassnotifyserver.class.php';
final class WeatherFormModule extends \FreePBX\modules\Slsmassnotifyserver {
 public function getConfiguredPjsipExtensionNumbers(){return ['1000','1001'];}
 public function getAllPjsipExtensions(){return [];}
 public function getAvailableTones(){return [];}
 public function getAvailablePiperVoices(){return [['path'=>self::PIPER_AMY_VOICE,'available'=>true],['path'=>self::PIPER_VOICE,'available'=>true]];}
}
$reflection=new ReflectionClass(\FreePBX\modules\Slsmassnotifyserver::class);
$module=(new ReflectionClass(WeatherFormModule::class))->newInstanceWithoutConstructor();
$invoke=static function($name,...$arguments)use($reflection,$module){return $reflection->getMethod($name)->invokeArgs($module,$arguments);};
$invokeArgs=static function($name,array &$arguments)use($reflection,$module){return $reflection->getMethod($name)->invokeArgs($module,$arguments);};
$method=$reflection->getMethod('saveSettings');$lines=file($method->getFileName());
$save=implode('',array_slice($lines,$method->getStartLine()-1,$method->getEndLine()-$method->getStartLine()+1));
preg_match_all('/self::([A-Z][A-Z_0-9]*)/',$save,$constantNames);$constants='';
foreach(array_unique($constantNames[1])as$name){$constants.='const '.$name.' = '.var_export($reflection->getConstant($name),true).';';}
eval('class WeatherFormSave { '.$constants.'
  public $current; public $saved=null; public $writes=0; public $invoke; public $invokeArgs; public $protectedSource=null;
 private function getActiveSettings(){return $this->current;}
 private function getPendingSettings(){return null;}
 private function isSetupComplete($settings){return true;}
  private function persistPendingSettings($settings){$this->saved=$this->protectedSource===null?$settings:($this->invoke)("normalizeSettings",$settings,$this->protectedSource);++$this->writes;}
 public function getAvailableTones(){return [];}
 public function getDesktopClients($settings){return [];}
 private function importSystemSoundAsTone($selection,$prefix,&$errors){throw new RuntimeException("Unexpected recording import");}
 private function resolvePiperVoiceInput(array $input,string $field,$current,string $fallback,array $known,array $ready,array &$errors,string $label):string {
  $arguments=[$input,$field,$current,$fallback,$known,$ready,&$errors,$label];return ($this->invokeArgs)("resolvePiperVoiceInput",$arguments);
 }
 public function __call($name,$arguments){return ($this->invoke)($name,...$arguments);}
 '.$save.'}');
$settings=$invoke('getDefaultSettings');$settings['enabled']='1';$settings['nws_opening_tone']='';$settings['nws_closing_tone']='';
$settings['public_pbx_host']='fixture.example.invalid';$settings['desktop_clients']=[];
$settings['operator_access']=\SLS\MassNotify\OperatorAccess::normalize(['enabled'=>true,'portal_enabled'=>true,'passkeys_enabled'=>false,'accounts'=>[]]);
$settings['discord_webhooks']=[['id'=>'discord_primary','name'=>'Fixture Discord','url'=>'https://discord.com/api/webhooks/1/inert','enabled'=>'1']];
$settings['generic_webhooks']=[['id'=>'generic_primary','name'=>'Fixture archive','url'=>'https://example.invalid/inert','enabled'=>'1']];
$settings['nws_zones']=[
 ['id'=>'zone_first','name'=>'First fixture zone','zone'=>'TXZ163','extensions'=>['1000'],'discord_webhook_ids'=>['discord_primary'],'generic_webhook_ids'=>['generic_primary'],'quiet_critical_events'=>['Tornado Warning','Flash Flood Warning']],
 ['id'=>'zone_second','name'=>'Second fixture zone','zone'=>'TXC491','extensions'=>['1001'],'discord_webhook_ids'=>[],'generic_webhook_ids'=>[],'quiet_critical_events'=>['Tornado Warning']]];
if(($argv[1]??'')==='render'){
 $available_extensions=[['extension'=>'1000','name'=>'Fixture phone','registered'=>true],['extension'=>'1001','name'=>'Other fixture phone','registered'=>true]];
 $available_voices=[['path'=>\FreePBX\modules\Slsmassnotifyserver::PIPER_AMY_VOICE,'name'=>'Amy']];
 $hero_image='';$csrf_token=str_repeat('b',64);$show_test_section=false;
 include MODULE.'/views/settings.php';return;
}
$wire=stream_get_contents(STDIN);
if(($argv[1]??'')==='api'){
 $input=json_decode($wire,true,32,JSON_THROW_ON_ERROR);$answer=$invoke('validateAndNormalizeControlConfigPatch',$input);
 if(!$answer['errors']){
  try{$invoke('normalizeSettings',$invoke('mergeControlConfigPatch',$settings,$answer['patch']));}
  catch(DomainException|InvalidArgumentException $error){$answer['errors'][]=$error->getMessage();}
 }
 echo json_encode($answer);return;
}
parse_str($wire,$input);$fixture=new WeatherFormSave();$fixture->invoke=$invoke;$fixture->invokeArgs=$invokeArgs;
if(in_array($argv[1]??'', ['already-empty','remove-zones'], true)){
 $settings['enabled']='0';
 $settings['quiet_hours_enabled']='1';
 $settings['quiet_hours_start']='23:00';
 $settings['quiet_hours_end']='05:00';
 $settings['quiet_critical_events']=['Tornado Warning'];
 if($argv[1]==='already-empty'){$settings['nws_zones']=[];$settings['nws_zone']='';$settings['alert_recipients']=[];}
}
if(($argv[1]??'')==='legacy-preservation'){
 $settings['announcement_groups']=[['id'=>'grp_aaaaaaaaaaaa','name'=>'Saved legacy phone group','extensions'=>['1002'],'desktop_clients'=>[],
  'voice_recipient_ids'=>[],'email_recipient_ids'=>[],'sms_recipient_ids'=>[]]];
 $settings['live_paging']=array_replace(\SLS\MassNotify\LivePagingConfig::defaults(),['enabled'=>'1','extension'=>'799','allowed_callers'=>['1000'],
  'groups'=>[['group_id'=>'grp_aaaaaaaaaaaa','menu_number'=>1,'require_pin'=>'0','pin_length'=>4,'pin_hash'=>'']]]);
 $fixture->protectedSource=$settings;
 $fixture->current=$invoke('normalizeSettings',$settings,$settings);
}else{$fixture->current=$settings;}
$answer=$fixture->saveSettings($input);
echo json_encode(['result'=>$answer,'saved'=>$fixture->saved,'writes'=>$fixture->writes,'input'=>$input,'original'=>$settings],JSON_THROW_ON_ERROR);
'''.replace('MODULE', json.dumps(str(ROOT / 'slsmassnotifyserver')))


class WeatherZoneFormSave(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        temporary = tempfile.TemporaryDirectory(prefix='sll-weather-form-')
        cls.addClassCleanup(temporary.cleanup)
        cls.script = Path(temporary.name) / 'fixture.php'
        cls.script.write_text(PHP)
        subprocess.run(['php', '-l', str(cls.script)], check=True, capture_output=True)
        cls.markup = subprocess.run(['php', str(cls.script), 'render'], check=True,
                                    capture_output=True, text=True).stdout
        cls.playwright = sync_playwright().start()
        cls.addClassCleanup(cls.playwright.stop)
        cls.browser = cls.playwright.chromium.launch(executable_path=browser, headless=True,
            args=['--no-sandbox', '--disable-dev-shm-usage'])
        cls.addClassCleanup(cls.browser.close)

    def setUp(self):
        self.context = self.browser.new_context()
        self.addCleanup(self.context.close)
        self.context.route('**/*', lambda route: route.abort())
        self.page = self.context.new_page()
        self.errors = []
        self.page.on('pageerror', lambda error: self.errors.append(str(error)))
        self.page.set_content(self.markup)
        self.page.wait_for_function('document.querySelectorAll("[data-zone-empty]").length===4')

    def wire(self):
        return self.page.locator('#sls-weather-settings-form').evaluate(
            'form=>new URLSearchParams(new FormData(form)).toString()')

    def save(self, wire=None):
        process = subprocess.run(['php', str(self.script), 'save'], input=self.wire() if wire is None else wire,
                                 capture_output=True, text=True, timeout=10)
        self.assertEqual(process.returncode, 0, process.stderr)
        return json.loads(process.stdout)

    def replaced(self, field, values, *, indexed=True):
        prefix = 'nws_zones[0][' + field + ']'
        pairs = [(key, value) for key, value in parse_qsl(self.wire(), keep_blank_values=True)
                 if key != prefix and not key.startswith(prefix + '[')]
        pairs.extend((prefix + ('[]' if indexed else ''), value) for value in values)
        return urlencode(pairs)

    def add(self, name='New test group'):
        self.page.locator('#sls-zone-add').click()
        row = self.page.locator('[data-zone-editor]').last
        row.locator('[data-zone-field="name"]').fill(name)
        row.locator('[data-zone-field="zone"]').fill('TXZ165')
        row.locator('[data-zone-extension][value="1000"]').check()
        return row

    def test_actual_three_zone_post_saves_selected_and_empty_destinations(self):
        row = self.add()
        row.locator('[data-zone-field="quiet_critical_events"]').fill('Tornado Warning, Severe Thunderstorm Warning')
        answer = self.save()
        self.assertTrue(answer['result']['success'], answer['result'])
        self.assertEqual(answer['writes'], 1)
        zones = answer['saved']['nws_zones']
        self.assertEqual(len(zones), 3)
        self.assertEqual(zones[0]['discord_webhook_ids'], ['discord_primary'])
        self.assertEqual(zones[0]['generic_webhook_ids'], ['generic_primary'])
        for zone in zones[1:]:
            self.assertEqual(zone['discord_webhook_ids'], [])
            self.assertEqual(zone['generic_webhook_ids'], [])
        self.assertEqual(zones[0]['quiet_critical_events'], ['Tornado Warning', 'Flash Flood Warning'])
        for field in ('quiet_hours_enabled', 'quiet_hours_start', 'quiet_hours_end', 'quiet_critical_events'):
            self.assertEqual(answer['saved'][field], zones[0][field])
        self.assertEqual(zones[2]['quiet_critical_events'], ['Tornado Warning', 'Severe Thunderstorm Warning'])
        for key in ('discord_webhooks', 'generic_webhooks', 'public_pbx_host', 'ami', 'control_api', 'operator_access'):
            self.assertEqual(answer['saved'][key], answer['original'][key])
        self.assertEqual(self.errors, [])

    def test_browser_quiet_hour_picker_matches_saved_policy_for_existing_and_new_zones(self):
        self.add('Picker fixture')
        for row in (self.page.locator('[data-zone-editor]').first, self.page.locator('[data-zone-editor]').last):
            for field in ('quiet_hours_start', 'quiet_hours_end'):
                picker = row.locator('[data-zone-field="' + field + '"]')
                picker.fill('23:15')
                self.assertTrue(picker.evaluate('e => e.validity.stepMismatch'))
                picker.fill('23:00')
                self.assertTrue(picker.evaluate('e => e.checkValidity()'))

    def test_removing_first_zone_promotes_the_remaining_zones_quiet_policy(self):
        self.page.once('dialog', lambda dialog: dialog.accept())
        self.page.locator('[data-zone-remove]').first.click()
        remaining = self.page.locator('[data-zone-editor]').first
        remaining.locator('[data-zone-field="quiet_hours_enabled"]').select_option('1')
        remaining.locator('[data-zone-field="quiet_hours_start"]').fill('20:00')
        remaining.locator('[data-zone-field="quiet_hours_end"]').fill('04:00')
        remaining.locator('[data-zone-field="quiet_critical_events"]').fill('Flash Flood Warning')
        answer = self.save()
        self.assertTrue(answer['result']['success'], answer['result'])
        self.assertEqual(answer['writes'], 1)
        zones = answer['saved']['nws_zones']
        self.assertEqual([zone['name'] for zone in zones], ['Second fixture zone'])
        expected = {'quiet_hours_enabled': '1', 'quiet_hours_start': '20:00',
                    'quiet_hours_end': '04:00', 'quiet_critical_events': ['Flash Flood Warning']}
        for field, value in expected.items():
            self.assertEqual(zones[0][field], value)
            self.assertEqual(answer['saved'][field], value)

    def test_saving_without_zones_preserves_saved_quiet_hours_and_bypasses(self):
        self.page.on('dialog', lambda dialog: dialog.accept())
        self.page.locator('#enabled').select_option('0')
        remove = self.page.locator('[data-zone-remove]')
        while remove.count():
            remove.first.click()
        wire = parse_qsl(self.wire(), keep_blank_values=True)
        self.assertIn(('nws_zones_present', '1'), wire)
        self.assertFalse(any(key.startswith('nws_zones[') for key, _ in wire))
        wire = urlencode([(k, v) for k, v in wire if k != 'test_email_subject'] +
                         [('test_email_subject', 'Updated fixture subject')])
        fields = ('quiet_hours_enabled', 'quiet_hours_start', 'quiet_hours_end', 'quiet_critical_events')
        for previous in ('already-empty', 'remove-zones'):
            with self.subTest(previous=previous):
                process = subprocess.run(['php', str(self.script), previous], input=wire,
                    capture_output=True, text=True, timeout=10, check=True)
                answer = json.loads(process.stdout)
                self.assertTrue(answer['result']['success'], answer['result'])
                self.assertEqual(answer['writes'], 1)
                self.assertEqual(answer['saved']['nws_zones'], [])
                self.assertEqual(answer['saved']['test_email_subject'], 'Updated fixture subject')
                self.assertEqual({k: answer['saved'][k] for k in fields},
                                 {k: answer['original'][k] for k in fields})

    def test_weather_save_preserves_selected_legacy_group_after_last_phone_deletion(self):
        self.add('Weather change after phone deletion')
        process = subprocess.run(['php', str(self.script), 'legacy-preservation'],
            input=self.wire(), capture_output=True, text=True, timeout=10)
        self.assertEqual(process.returncode, 0, process.stderr)
        answer = json.loads(process.stdout)
        self.assertTrue(answer['result']['success'], answer['result'])
        self.assertEqual(answer['writes'], 1)
        self.assertEqual(answer['saved']['announcement_groups'], answer['original']['announcement_groups'])
        self.assertEqual(answer['saved']['live_paging'], answer['original']['live_paging'])
        self.assertEqual(answer['saved']['announcement_groups'][0]['id'], 'grp_aaaaaaaaaaaa')
        self.assertEqual(answer['saved']['announcement_groups'][0]['extensions'], ['1002'])
        self.assertEqual(len(answer['saved']['nws_zones']), 3)
        self.assertEqual(answer['saved']['nws_zones'][-1]['name'], 'Weather change after phone deletion')
        self.assertEqual(self.errors, [])

    def test_remove_and_add_reindexes_without_reusing_or_losing_routes(self):
        self.add('Third fixture zone')
        self.page.once('dialog', lambda dialog: dialog.accept())
        self.page.locator('[data-zone-editor]').nth(1).locator('[data-zone-remove]').click()
        self.add('Replacement fixture zone')
        answer = self.save()
        self.assertTrue(answer['result']['success'], answer['result'])
        self.assertEqual([zone['name'] for zone in answer['saved']['nws_zones']],
                         ['First fixture zone', 'Third fixture zone', 'Replacement fixture zone'])
        self.assertEqual(len({zone['id'] for zone in answer['saved']['nws_zones']}), 3)

    def test_explicitly_removing_all_groups_is_not_replaced_by_old_saved_routes(self):
        while self.page.locator('[data-zone-editor]').count():
            self.page.once('dialog', lambda dialog: dialog.accept())
            self.page.locator('[data-zone-editor]').first.locator('[data-zone-remove]').click()
        enabled = self.save()
        self.assertFalse(enabled['result']['success'], 'An enabled service must require a group after removal')
        self.assertEqual(enabled['writes'], 0)
        self.page.locator('#enabled').select_option('0')
        disabled = self.save()
        self.assertTrue(disabled['result']['success'], disabled['result'])
        self.assertEqual(disabled['saved']['nws_zones'], [])
        self.assertEqual(disabled['saved']['nws_zone'], '')
        self.assertEqual(disabled['saved']['alert_recipients'], [])

    def test_duplicate_noncanonical_nested_and_scalar_webhook_ids_still_refuse(self):
        for values, indexed in ((['discord_primary', 'discord_primary', ''], True),
                                ([' discord_primary', ''], True), (['', 'discord_primary', ''], True),
                                (['', ''], True), (['discord_primary'], False)):
            with self.subTest(values=values, indexed=indexed):
                answer = self.save(self.replaced('discord_webhook_ids', values, indexed=indexed))
                self.assertFalse(answer['result']['success'])
                self.assertEqual(answer['writes'], 0)
                self.assertIn('discord webhook ids', ' '.join(answer['result']['errors']))

    def test_unknown_saved_destination_is_not_enabled_by_form_decoding(self):
        answer = self.save(self.replaced('generic_webhook_ids', ['unknown_destination', '']))
        self.assertFalse(answer['result']['success'])
        self.assertEqual(answer['writes'], 0)
        self.assertIn('unavailable notification destination', ' '.join(answer['result']['errors']))

    def test_malformed_critical_event_lists_and_duplicates_still_refuse(self):
        for values in (['Tornado Warning,Tornado Warning'], ['Unrecognized Event'], ['Tornado Warning,,Flash Flood Warning'],
                       ['Tornado Warning\x00'], ['Tornado Warning' * 600]):
            with self.subTest(values=values):
                answer = self.save(self.replaced('quiet_critical_events', values, indexed=False))
                self.assertFalse(answer['result']['success'])
                self.assertEqual(answer['writes'], 0)
                self.assertIn('critical-event bypass', ' '.join(answer['result']['errors']))
        prefix = 'nws_zones[0][quiet_critical_events]'
        pairs = [(key, value) for key, value in parse_qsl(self.wire(), keep_blank_values=True)
                 if key != prefix and not key.startswith(prefix + '[')]
        pairs.append((prefix + '[unreviewed]', 'Tornado Warning'))
        answer = self.save(urlencode(pairs))
        self.assertFalse(answer['result']['success'])
        self.assertIn('critical-event bypasses must be an array', ' '.join(answer['result']['errors']))

    def test_form_adapter_requires_the_explicit_weather_form_marker(self):
        pairs = [(key, value) for key, value in parse_qsl(self.wire(), keep_blank_values=True) if key != 'nws_zones_present']
        answer = self.save(urlencode(pairs))
        self.assertFalse(answer['result']['success'])
        self.assertEqual(answer['writes'], 0)
        self.assertIn('Saved destination IDs must be canonical', ' '.join(answer['result']['errors']))

    def test_no_javascript_array_wrapped_csv_and_empty_text_are_valid_form_inputs(self):
        context = self.browser.new_context(java_script_enabled=False)
        self.addCleanup(context.close)
        context.route('**/*', lambda route: route.abort())
        page = context.new_page()
        page.set_content(self.markup)
        wire = page.locator('#sls-weather-settings-form').evaluate('form=>new URLSearchParams(new FormData(form)).toString()')
        answer = self.save(wire)
        self.assertTrue(answer['result']['success'], answer['result'])
        self.assertEqual(answer['saved']['nws_zones'][1]['discord_webhook_ids'], [])
        self.assertEqual(answer['saved']['nws_zones'][1]['generic_webhook_ids'], [])
        answer = self.save(self.replaced('quiet_critical_events', [''], indexed=False))
        self.assertTrue(answer['result']['success'], answer['result'])

    def test_json_api_remains_strict_and_does_not_decode_html_form_sentinels(self):
        zone = {'id': 'strict_api', 'name': 'API fixture', 'zone': 'TXZ163', 'extensions': ['1000']}
        for field, value in (('discord_webhook_ids', ['']), ('generic_webhook_ids', ['generic_primary', '']),
                             ('quiet_critical_events', 'Tornado Warning')):
            with self.subTest(field=field):
                process = subprocess.run(['php', str(self.script), 'api'],
                    input=json.dumps({'nws_zones': [dict(zone, **{field: value})]}),
                    capture_output=True, text=True, timeout=10)
                self.assertEqual(process.returncode, 0, process.stderr)
                self.assertTrue(json.loads(process.stdout)['errors'])


if __name__ == '__main__':
    unittest.main()
