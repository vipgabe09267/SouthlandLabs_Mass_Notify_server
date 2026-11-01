#!/usr/bin/python3
"""Actual sender + PHP policy, private settings, inert MTA/cluster effects only."""
import copy
from datetime import datetime, timezone
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import time
import types
import unittest
from unittest import mock

if os.environ.get('SLS_TEST_NAMESPACE') != 'entered':
    raise SystemExit('Run through the isolated test wrapper.')
sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[1]
MODULE = ROOT/'slsmassnotifyserver'
RUNTIME = MODULE/'bin/sls_mass_notify'
spec = importlib.util.spec_from_file_location('deep_email_child', RUNTIME/'sls_announcement_email.py')
email = importlib.util.module_from_spec(spec); spec.loader.exec_module(email)


class EmailChildAuthority(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='sls-deep-email-child-'); self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name); self.config = self.root/'mass-notifications.config'; self.calls = []; self.finished = []
        self.clock = int(time.time()); self.clock_file = self.root/'clock'; self.clock_file.write_text(str(self.clock))
        self.identifier = 'email_'+'a'*24
        self.settings = {'runtime_enabled': True, 'announcement_email': {'enabled': '1', 'recipients': [
            {'id': self.identifier, 'name': 'Private fixture', 'address': 'private@example.com', 'enabled': '1'}]},
            'mail_from_name': 'PBX', 'mail_from_domain': 'example.com', 'mail_from_local_part': 'notify',
            'control_api': {'enabled': '1', 'credentials': []}}
        self.write()
        # Only filesystem path constants/require paths differ in these private copies.
        policy = (MODULE/'DeliveryAuthorization.php').read_text()
        policy = policy.replace('__DIR__ . ', repr(str(MODULE))+' . ')
        # A private namespace clock exercises actual currentCredential expiry.
        policy = policy.replace('namespace SLS\\MassNotify;', 'namespace SLS\\MassNotify;\nfunction time(): int { return (int)file_get_contents('+repr(str(self.clock_file))+'); }')
        policy = policy.replace("public const CONFIG = '/var/lib/asterisk/SLS_Mass_Notifications_Plugin/mass-notifications.config';",
                                'public const CONFIG = '+repr(str(self.config))+';')
        self.policy = self.root/'DeliveryAuthorization.php'; self.policy.write_text(policy)
        helper = (MODULE/'bin/sls_mass_notify_delivery_authorization.php').read_text().replace(
            "'/var/www/html/admin/modules/slsmassnotifyserver/DeliveryAuthorization.php'", repr(str(self.policy)))
        self.helper = self.root/'authorize.php'; self.helper.write_text(helper)
        self.real_run = subprocess.run
        self.payload = {'recipient_id': self.identifier, 'address': 'private@example.com',
            'sender': {'name': 'PBX', 'address': 'notify@example.com'}, 'title': 'Inert boundary fixture',
            'message': 'No production mailer is used.', 'is_test': False, 'severity': 'info',
            'message_id': '<sls-'+'b'*32+'-'+'a'*24+'@example.com>', 'created_at': '2026-10-28T10:00:00Z'}
        self.bind_context()

    def write(self):
        self.config.write_text(json.dumps(self.settings)); self.config.chmod(0o600)

    def bind_context(self):
        code = 'require $argv[1];echo \\SLS\\MassNotify\\DeliveryAuthorization::emailTargetHash(json_decode(file_get_contents($argv[2]),true),$argv[3]);'
        result = self.real_run(['/usr/bin/php', '-r', code, str(self.policy), str(self.config), self.identifier], capture_output=True, check=True)
        self.payload['authorization'] = {'recipient_id': self.identifier, 'target_hashes': [result.stdout.decode()],
                                        'expires_at': int(time.time())+300, 'schedule_deadline': None}

    def policy_run(self, command, **kwargs):
        self.assertEqual(command, ['/usr/bin/php', '/usr/local/bin/sls_mass_notify/sls_mass_notify_delivery_authorization.php', '--email'])
        return self.real_run(['/usr/bin/php', str(self.helper), '--email'], **kwargs)

    def send(self, change=None, *, at='admission', payload=None, popen_error=None, exit_code=0, finish_error=None):
        owner = self
        class InertMta:
            returncode = exit_code
            def __init__(self, *args, **kwargs):
                owner.calls.append(args[0])
                if popen_error: raise popen_error
            def communicate(self, wire, timeout): owner.assertIn(b'No production mailer', wire)
        def admission(*args):
            if change and at == 'admission': change()
        def begin(*args, **kwargs):
            if change and at == 'cluster': change()
            return {'private_claim': 'consumed'}
        def finish(claim, **kwargs):
            self.finished.append((claim, kwargs))
            if finish_error: raise finish_error
        transport = types.SimpleNamespace(**vars(subprocess)); transport.run = self.policy_run; transport.Popen = InertMta
        with mock.patch.object(email, 'subprocess', transport), \
             mock.patch.object(email._mail_admission, 'reserve', side_effect=admission), \
             mock.patch.object(email._cluster_guard, 'begin', side_effect=begin), \
             mock.patch.object(email._cluster_guard, 'finish', side_effect=finish):
            return email.submit(self.payload if payload is None else payload, logo_paths=())

    def test_unchanged_real_policy_accepts_one_inert_mta(self):
        self.assertEqual(self.send()['state'], 'accepted'); self.assertEqual(len(self.calls), 1)

    def producer_envelope(self, automation='omitted'):
        """Use the actual PHP delivery loop, with only private policy/MTA adapters."""
        php = r'''require $argv[1];
        class ProducerBoundaryFixture {
            use \FreePBX\modules\SlsAnnouncementDelivery;
            public $settings,$hashes,$sent=[];
            private function getActiveSettings(){return $this->settings;}
            private function announcementEmailTargets($settings){return $settings['targets'];}
            private function announcementEmailFingerprint($target){return hash('sha256',json_encode([$target['id'],$target['address'],$target['sender']['name'],$target['sender']['address']]));}
            private function announcementEmailAuthorizationHashes($id,$fingerprint){return $this->hashes;}
            private function automationContextPermitted($context){return is_array($context);}
            protected function submitAnnouncementEmail(array $envelope):array{$this->sent[]=$envelope;return ['state'=>'accepted','retryable'=>false,'detail'=>'Inert producer capture'];}
            public function capture($input){
                $p=$input['payload'];$id=$p['recipient_id'];
                $target=['id'=>$id,'address'=>$p['address'],'sender'=>$p['sender']];
                $this->settings=['runtime_enabled'=>true,'targets'=>[$id=>$target],'control_api'=>['enabled'=>'0']];
                $this->hashes=$p['authorization']['target_hashes'];
                $target['fingerprint']=$this->announcementEmailFingerprint($target);$target['message_id']=$p['message_id'];
                $request=['email_recipient_ids'=>[$id],'email_targets'=>[$id=>$target],
                    'email_attempt_id'=>'job_'.str_repeat('c',32),'email_expires_at'=>$p['authorization']['expires_at'],
                    'title'=>$p['title'],'message'=>$p['message'],'is_test'=>$p['is_test'],'email_severity'=>$p['severity'],
                    'delivery_timestamp'=>$p['created_at']];
                if($input['include_automation']){$request['automation_context']=$input['automation'];}
                $rows=[];$this->deliverAnnouncementEmailTargets($request,$rows,static function(){});
                return $this->sent;
            }
        }
        $input=json_decode(stream_get_contents(STDIN),true,32,JSON_THROW_ON_ERROR);
        echo json_encode((new ProducerBoundaryFixture())->capture($input),JSON_THROW_ON_ERROR);'''
        result=self.real_run(['/usr/bin/php','-r',php,str(MODULE/'AnnouncementDelivery.php')],
            input=json.dumps({'payload':self.payload,'include_automation':automation!='omitted',
                'automation':None if automation=='omitted' else automation}),capture_output=True,text=True,timeout=10)
        self.assertEqual(result.returncode,0,result.stderr)
        envelopes=json.loads(result.stdout)
        self.assertEqual(len(envelopes),1,result.stdout)
        return envelopes[0]

    def test_manual_null_automation_from_php_producer_reaches_validated_inert_mta(self):
        for context in ('omitted',None):
            with self.subTest(automation=context):
                payload=self.producer_envelope(context)
                self.calls=[]
                try:
                    result=self.send(payload=payload)
                except email.InputError as error:
                    self.fail('The actual PHP manual-announcement envelope was rejected before the MTA: '+str(error))
                self.assertEqual(result['state'],'accepted')
                self.assertEqual(len(self.calls),1)
                self.assertNotIn('automation_context',payload['authorization'])

    def test_php_producer_keeps_real_automation_context_for_child_revalidation(self):
        context={'automation_id':'private_fixture','revision':'a'*64}
        payload=self.producer_envelope(context)
        self.assertEqual(payload['authorization']['automation_context'],context)
        email.validate(payload)

    def test_explicit_malformed_child_automation_context_stays_rejected_before_mta(self):
        for context in (None,False,'invalid',[]):
            with self.subTest(context=context):
                payload=copy.deepcopy(self.payload);payload['authorization']['automation_context']=context
                with self.assertRaises(email.InputError):self.send(payload=payload)
                self.assertFalse(self.calls)

    def test_guard_metadata_does_not_change_existing_cluster_intent(self):
        seen=[]
        def begin(*args,**kwargs): seen.append(args[2]); return None
        transport=types.SimpleNamespace(**vars(subprocess));transport.run=self.policy_run;transport.Popen=mock.Mock(side_effect=OSError('inert unavailable MTA'))
        with mock.patch.object(email,'subprocess',transport),mock.patch.object(email._mail_admission,'reserve'),mock.patch.object(email._cluster_guard,'begin',side_effect=begin):
            email.submit(self.payload,logo_paths=())
        self.assertEqual(seen,[{key:value for key,value in self.payload.items()if key!='authorization'}])

    def test_relevant_changes_during_admission_or_cluster_never_start_mta(self):
        original = copy.deepcopy(self.settings)
        for at in ('admission', 'cluster'):
            for change in ('address', 'sender', 'disable', 'runtime'):
                with self.subTest(at=at, change=change):
                    self.settings = copy.deepcopy(original); self.write(); self.bind_context(); self.calls = []; self.finished = []
                    def mutate():
                        if change == 'address': self.settings['announcement_email']['recipients'][0]['address'] = 'changed@example.com'
                        elif change == 'sender': self.settings['mail_from_domain'] = 'changed.example.com'
                        elif change == 'disable': self.settings['announcement_email']['enabled'] = '0'
                        else: self.settings['runtime_enabled'] = False
                        self.write()
                    result = self.send(mutate, at=at)
                    self.assertFalse(self.calls); self.assertEqual(result['state'], 'rejected')
                    self.assertEqual(result['error_code'], 'email_authorization_changed')
                    self.assertIs(result['submission_started'], False); self.assertIs(result['retryable'], False)
                    self.assertEqual(self.finished, [({'private_claim': 'consumed'}, {'uncertain': False, 'category': 'submission_suppressed', 'timeout': 1})])

    def test_unrelated_mfa_write_does_not_suppress_unchanged_email(self):
        def mutate(): self.settings['operator_auth'] = {'inert_totp_counter': 42}; self.write()
        self.assertEqual(self.send(mutate)['state'], 'accepted'); self.assertEqual(len(self.calls), 1)

    def test_known_suppression_retains_consumed_claim_if_receipt_is_fenced(self):
        def mutate(): self.settings['runtime_enabled']=False;self.write()
        result=self.send(mutate,finish_error=email._cluster_guard.ClusterFenced('private receipt fence'))
        self.assertFalse(self.calls);self.assertFalse(result['submission_started'])
        self.assertEqual(result['error_code'],'email_authorization_changed')
        self.assertEqual(self.finished,[({'private_claim':'consumed'},{'uncertain':False,'category':'submission_suppressed','timeout':1})])

    def test_known_no_submit_receipt_cannot_add_an_unbounded_wait(self):
        def mutate():self.settings['runtime_enabled']=False;self.write()
        result=self.send(mutate,finish_error=email._cluster_guard.ClusterFenced('private receipt timeout'))
        self.assertFalse(self.calls);self.assertFalse(result['submission_started'])
        self.assertLessEqual(self.finished[0][1].get('timeout',14),1)

    def test_real_transport_uncertainty_is_not_erased_by_policy_guard(self):
        result=self.send(exit_code=-15)
        self.assertEqual(len(self.calls),1);self.assertEqual(result['state'],'uncertain');self.assertFalse(result['retryable'])
        self.assertNotEqual(result.get('submission_started'),False);self.assertFalse(self.finished)

    def test_legacy_sender_and_missing_recipient_flag_keep_same_projection(self):
        del self.settings['mail_from_domain']; del self.settings['mail_from_local_part']
        self.settings['mail_from_addr'] = 'notify@example.com'
        del self.settings['announcement_email']['recipients'][0]['enabled']
        self.settings['announcement_email']['enabled'] = True
        self.write(); self.bind_context()
        self.assertEqual(self.send()['state'], 'accepted'); self.assertEqual(len(self.calls), 1)

    def test_lifetime_and_schedule_deadline_after_cluster_are_known_no_submit(self):
        base = int(time.time())
        for field in ('expires_at', 'schedule_deadline'):
            with self.subTest(field=field):
                self.bind_context(); self.payload['authorization'][field] = base+5; self.calls = []; self.finished = []
                clock = [base]
                with mock.patch.object(email.time, 'time', side_effect=lambda: clock[0]):
                    result = self.send(lambda: clock.__setitem__(0, base+10), at='cluster')
                self.assertFalse(self.calls); self.assertFalse(result['submission_started'])
                self.assertEqual(self.finished[0][1], {'uncertain': False, 'category': 'submission_suppressed', 'timeout': 1})

    def test_real_scoped_principal_revocation_after_admission_is_blocked(self):
        code = 'require $argv[1];echo json_encode(\\SLS\\MassNotify\\ApiSecurity::issue(["name"=>"inert","scopes"=>["send"],"audience"=>["unrestricted"=>false,"email_recipient_ids"=>[$argv[2]]]])["credential"]);'
        credential = json.loads(self.real_run(['/usr/bin/php', '-r', code, str(self.policy), self.identifier], capture_output=True, check=True).stdout)
        self.settings['control_api']['credentials'] = [credential]; self.write(); self.bind_context()
        self.payload['authorization']['api_credential_id'] = credential['id']
        def mutate(): self.settings['control_api']['credentials'] = []; self.write()
        result = self.send(mutate)
        self.assertFalse(self.calls); self.assertFalse(result['submission_started'])

    def test_actual_principal_expiry_during_cluster_wait_is_blocked(self):
        code = 'require $argv[1];echo json_encode(\\SLS\\MassNotify\\ApiSecurity::issue(["name"=>"inert","scopes"=>["send"],"audience"=>["unrestricted"=>true],"expires_at"=>(int)$argv[2]])["credential"]);'
        credential = json.loads(self.real_run(['/usr/bin/php', '-r', code, str(self.policy), str(self.clock+5)], capture_output=True, check=True).stdout)
        self.settings['control_api']['credentials'] = [credential]; self.write(); self.bind_context()
        self.payload['authorization']['api_credential_id'] = credential['id']
        result = self.send(lambda: self.clock_file.write_text(str(self.clock+10)), at='cluster')
        self.assertFalse(self.calls); self.assertFalse(result['submission_started'])
        self.assertEqual(self.finished[0][1], {'uncertain': False, 'category': 'submission_suppressed', 'timeout': 1})

    def test_time_consumed_by_last_policy_read_cannot_outlive_email_or_principal(self):
        code = 'require $argv[1];echo json_encode(\\SLS\\MassNotify\\ApiSecurity::issue(["name"=>"inert","scopes"=>["send"],"audience"=>["unrestricted"=>true],"expires_at"=>(int)$argv[2]])["credential"]);'
        for boundary in ('email','principal'):
            with self.subTest(boundary=boundary):
                self.clock_file.write_text(str(self.clock));self.calls=[];self.finished=[];self.bind_context()
                if boundary=='email':self.payload['authorization']['expires_at']=self.clock+5
                else:
                    credential=json.loads(self.real_run(['/usr/bin/php','-r',code,str(self.policy),str(self.clock+5)],capture_output=True,check=True).stdout)
                    self.settings['control_api']['credentials']=[credential];self.write()
                    self.payload['authorization']['api_credential_id']=credential['id']
                clock=[self.clock];reads=[0];actual_policy=self.policy_run
                def delayed_policy(command,**kwargs):
                    result=actual_policy(command,**kwargs);reads[0]+=1
                    if reads[0]==2:
                        clock[0]=self.clock+10;self.clock_file.write_text(str(clock[0]))
                    return result
                with mock.patch.object(self,'policy_run',side_effect=delayed_policy),mock.patch.object(email.time,'time',side_effect=lambda:clock[0]):
                    result=self.send()
                self.assertEqual(reads[0],2);self.assertFalse(self.calls)
                self.assertFalse(result['submission_started']);self.assertFalse(result['retryable'])

    def test_actual_weather_source_cleared_during_admission_is_blocked(self):
        import sls_notification_destinations as destinations
        import sls_weather_channels as weather
        self.settings.update(enabled='1', nws_zones=[{'id':'north','name':'North','zone':'TXC491','quiet_hours_enabled':'0','quiet_critical_events':[]}])
        self.write(); self.bind_context()
        feature = {'id':'private-alert','properties':{'event':'Heat Advisory','status':'Actual','messageType':'Alert',
            'expires':datetime.fromtimestamp(self.clock+300,timezone.utc).isoformat()}}
        validity = destinations.weather_source_validity('nws','north',feature=feature,
            chain_key='Heat Advisory|private-alert',zone='TXC491',observed_at=self.clock)
        observation = self.root/'weather-delivery.json'
        def observe(active):
            observation.write_text(json.dumps({'snapshots':{'north':{'zone':'TXC491','observed_at':self.clock,
                'active':{validity['chain_key']:feature} if active else {}}}})); observation.chmod(0o640)
        observe(True)
        self.payload['authorization']['weather_context'] = {'source_validity':validity,'event':'Heat Advisory','severity':'','deadline_at':self.clock+300}
        actual_authorize = weather.authorize
        with mock.patch.object(weather,'DATA',self.root), mock.patch.object(weather,'authorize',side_effect=lambda config,context:actual_authorize(config,context,directory=self.root)):
            self.assertEqual(self.send()['state'],'accepted'); self.assertEqual(len(self.calls),1)
            self.calls=[];self.finished=[]
            result=self.send(lambda:observe(False))
        self.assertFalse(self.calls);self.assertFalse(result['submission_started'])
        self.assertEqual(self.finished[0][1],{'uncertain':False,'category':'submission_suppressed','timeout':1})

    def test_weather_source_expiry_during_last_policy_read_never_starts_mta(self):
        import sls_notification_destinations as destinations
        import sls_weather_channels as weather
        self.settings.update(enabled='1', nws_zones=[{'id':'north','name':'North','zone':'TXC491','quiet_hours_enabled':'0','quiet_critical_events':[]}])
        self.write(); self.bind_context()
        feature = {'id':'private-alert','properties':{'event':'Heat Advisory','status':'Actual','messageType':'Alert',
            'expires':datetime.fromtimestamp(self.clock+5,timezone.utc).isoformat()}}
        validity = destinations.weather_source_validity('nws','north',feature=feature,
            chain_key='Heat Advisory|private-alert',zone='TXC491',observed_at=self.clock)
        self.assertEqual(validity['expires_at'],self.clock+5)
        observation = self.root/'weather-delivery.json'
        observation.write_text(json.dumps({'snapshots':{'north':{'zone':'TXC491','observed_at':self.clock,
            'active':{validity['chain_key']:feature}}}})); observation.chmod(0o640)
        self.payload['authorization']['weather_context'] = {'source_validity':validity,'event':'Heat Advisory','severity':'','deadline_at':self.clock+300}
        actual_authorize = weather.authorize
        actual_policy = self.policy_run
        for advance in (4,5,10):
            with self.subTest(advance=advance):
                self.clock_file.write_text(str(self.clock));self.calls=[];self.finished=[]
                clock=[self.clock];reads=[0];source_checks=[]
                def authorize(config,context):
                    reply=actual_authorize(config,context,directory=self.root)
                    source_checks.append(reply['status']);return reply
                def delayed_policy(command,**kwargs):
                    reply=actual_policy(command,**kwargs);reads[0]+=1
                    if reads[0]==2:clock[0]=self.clock+advance
                    return reply
                with mock.patch.object(weather,'DATA',self.root),mock.patch.object(weather,'authorize',side_effect=authorize), \
                     mock.patch.object(self,'policy_run',side_effect=delayed_policy),mock.patch.object(email.time,'time',side_effect=lambda:clock[0]):
                    result=self.send()
                self.assertEqual(reads[0],2);self.assertEqual(source_checks,['eligible','eligible'])
                if advance<5:
                    self.assertEqual(result['state'],'accepted');self.assertEqual(len(self.calls),1)
                else:
                    self.assertFalse(self.calls);self.assertEqual(result['state'],'rejected')
                    self.assertFalse(result['submission_started']);self.assertFalse(result['retryable'])
                    self.assertEqual(self.finished,[({'private_claim':'consumed'},{'uncertain':False,'category':'submission_suppressed','timeout':1})])

    def test_unavailable_policy_helper_never_starts_mta(self):
        with mock.patch.object(self, 'policy_run', side_effect=subprocess.TimeoutExpired('inert helper', 1)):
            result = self.send()
        self.assertFalse(self.calls); self.assertFalse(result['submission_started']); self.assertFalse(self.finished)

    def test_bad_policy_replies_are_known_no_submit(self):
        for output in (b'{"allowed":1}',b'{"allowed":true,"allowed":true}',b'x'*256,b'[]'):
            with self.subTest(output=output),mock.patch.object(self,'policy_run',return_value=subprocess.CompletedProcess('inert',0,stdout=output)):
                result=self.send()
            self.assertFalse(self.calls);self.assertFalse(result['submission_started'])

    def test_old_payload_remains_an_exact_transport_contract(self):
        payload = {key: value for key, value in self.payload.items() if key != 'authorization'}
        with mock.patch.object(self, 'policy_run', side_effect=AssertionError('legacy contract invoked new policy')):
            self.assertEqual(self.send(payload=payload)['state'], 'accepted')

    def test_malformed_or_foreign_context_never_starts_mta(self):
        for context in (None, {}, {**self.payload['authorization'], 'recipient_id': 'email_'+'c'*24},
                        {**self.payload['authorization'], 'unknown': True}, {**self.payload['authorization'], 'expires_at': True}):
            with self.subTest(context=context), self.assertRaises(email.InputError):
                self.send(payload={**self.payload, 'authorization': context})
        self.assertFalse(self.calls)


if __name__ == '__main__': unittest.main()
