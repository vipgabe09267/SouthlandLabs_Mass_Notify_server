#!/usr/bin/python3
"""Inert Weather retry boundary probes; no transport or production state."""
import copy
from datetime import datetime, timezone
from email import policy
from email.parser import BytesParser
import importlib.util
import json
import os
from pathlib import Path
import socket
import subprocess
import sys
import tempfile
import time
import unittest
from unittest import mock

if os.environ.get('SLS_TEST_NAMESPACE') != 'entered':
    raise SystemExit('Use the unchanged isolated test wrapper.')
sys.dont_write_bytecode=True
ROOT=Path(__file__).resolve().parents[1]
RUNTIME=ROOT/'slsmassnotifyserver/bin/sls_mass_notify'
sys.path.insert(0,str(RUNTIME))
spec=importlib.util.spec_from_file_location('deep_retry_boundary',RUNTIME/'sls_notification_destinations.py')
module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)


class WeatherBoundary(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory(prefix='sls-deep-retry-boundary-')
        self.addCleanup(self.temp.cleanup)
        self.directory=Path(self.temp.name)
        self.state=self.directory/'external-deliveries-north.json'
        self.clock=[1100]
        self.calls=[];self.handoffs=[]
        self.patch=mock.patch.object(module.time,'time',side_effect=lambda:self.clock[0])
        self.patch.start();self.addCleanup(self.patch.stop)
        self.config={'enabled':'1','discord_webhooks':[],'generic_webhooks':[],
            'nws_zones':[{'id':'north','name':'North','zone':'TXC491',
                'email_recipients':['alerts@example.invalid'],
                'discord_webhook_ids':[],'generic_webhook_ids':[],
                'quiet_hours_enabled':'0','quiet_critical_events':[]}]}
        self.feature={'id':'provider-alert-1','properties':{'event':'Heat Advisory','status':'Actual',
            'messageType':'Alert','expires':self.iso(2000)}}
        self.validity=module.weather_source_validity('nws','north',feature=self.feature,
            chain_key='Heat Advisory|provider-alert-1',zone='TXC491',observed_at=1000)
        self.observe(self.feature)
        self.key=module.queue_external_delivery(self.state,self.config,'chain-1','Heat Advisory',
            'Synthetic protected retry body',event='Heat Advisory',source='nws',
            email_recipients='alerts@example.invalid',now=1000,source_validity=self.validity,
            channel_snapshot={'voice_recipient_ids':['voice_'+'a'*24],
                'sms_recipient_ids':[],'fingerprints':{'voice_'+'a'*24:'f'*64}})

    @staticmethod
    def iso(epoch):return datetime.fromtimestamp(epoch,timezone.utc).isoformat()

    def observe(self,feature):
        path=self.directory/'weather-delivery.json'
        path.write_text(json.dumps({'snapshots':{'north':{'zone':'TXC491','observed_at':1100,
            'active':{self.validity['chain_key']:feature} if feature else {}}}}))
        path.chmod(0o640)

    def execute(self,change=None,uncertain=False):
        record=json.loads(self.state.read_text())['deliveries'][self.key]
        self.assertEqual(module.validate_external_weather(record,self.config,self.directory,1100)[:2],('eligible',''))
        def handoff(command,**kwargs):
            self.assertEqual(command[:3],['/usr/bin/timeout','40','/usr/bin/php'])
            self.assertEqual(Path(command[3]).name,'sls_mass_notify_weather_channels.php')
            self.handoffs.append(json.loads(kwargs['input']))
            if change:change()
            if uncertain:raise subprocess.TimeoutExpired(command,45)
            return subprocess.CompletedProcess(command,0,stdout=json.dumps({'success':True,
                'status':'queued','message':'Synthetic channel job queued','job_id':'job_'+'d'*32}),stderr='')
        def email(*args):self.calls.append(args[-1]);return True
        with mock.patch.object(module.subprocess,'run',side_effect=handoff):
            result=module.retry_external_deliveries(self.state,self.config,'nws',live=True,
                email_sender=email,webhook_dispatcher=lambda *a,**k:[])
        self.assertEqual(len(self.handoffs),1)
        record=json.loads(self.state.read_text())['deliveries'][self.key]
        print('SLS_BOUNDARY_PROBE '+json.dumps({'test':self.id(),'email_calls':len(self.calls),
            'email_pending':record['email_pending'],'channels_pending':record['channels_pending'],
            'channels_uncertain':bool(record.get('channels_uncertain')),
            'current_source_decision':module.validate_external_weather(record,self.config,self.directory,self.clock[0])[:2],
            'receipts':{key:value['status'] for key,value in record.get('destination_receipts',{}).items()}}),flush=True)
        return result,record

    def test_unchanged_source_keeps_the_positive_handoff_and_email(self):
        result,record=self.execute()
        self.assertEqual(self.calls,['alerts@example.invalid'])
        self.assertEqual(record['channel_job_id'],'job_'+'d'*32)
        self.assertFalse(record['channels_pending'])

    def test_cancellation_during_first_handoff_suppresses_later_email(self):
        result,record=self.execute(lambda:self.observe(None))
        self.assertFalse(self.calls,'Cancelled source still submitted a later email')
        self.assertEqual(record['channel_job_id'],'job_'+'d'*32)
        self.assertEqual(record['terminal_status'],'partial_cancelled')

    def test_expiry_during_first_handoff_suppresses_later_email(self):
        result,record=self.execute(lambda:self.clock.__setitem__(0,2001))
        self.assertFalse(self.calls,'Expired source still submitted a later email')

    def test_retry_record_expiry_during_first_handoff_stops_later_email(self):
        with module._locked_retry_state(self.state) as locked:
            state=module._load_retry_state(locked)
            state['deliveries'][self.key]['expires_at']=1101
            module._write_retry_state(locked,state)
        result,record=self.execute(lambda:self.clock.__setitem__(0,1102))
        self.assertEqual(module.validate_external_weather(record,self.config,self.directory,self.clock[0])[:2],('eligible',''))
        self.assertFalse(self.calls,'Retry record lifetime expired but a later email still started')
        self.assertEqual(record['destination_receipts']['channels:sms_external_voice']['status'],'queued')
        self.assertEqual(record['terminal_status'],'partial_cancelled')

    def test_quiet_boundary_during_first_handoff_defers_email(self):
        previous=os.environ.get('TZ');os.environ['TZ']='UTC';time.tzset()
        try:
            self.config['nws_zones'][0].update(quiet_hours_enabled='1',quiet_hours_start='00:19',quiet_hours_end='00:20')
            result,record=self.execute(lambda:self.clock.__setitem__(0,1141))
            self.assertFalse(self.calls,'Quiet-hours boundary still submitted a later email')
            self.assertTrue(record['email_pending'],'Deferred unsent email must remain pending')
        finally:
            if previous is None:os.environ.pop('TZ',None)
            else:os.environ['TZ']=previous
            time.tzset()

    def test_uncertain_first_handoff_survives_cancellation_without_replay(self):
        result,record=self.execute(lambda:self.observe(None),uncertain=True)
        self.assertTrue(record.get('channels_uncertain'))
        self.assertFalse(record['channels_pending'])
        self.assertFalse(self.calls,'Unconfirmed first effect must not authorize later cancelled email')
        self.assertEqual(record['terminal_status'],'partial_cancelled')
        self.assertEqual(module.external_delivery_status(self.state,'nws','chain-1'),'uncertain')

    def webhook_record(self,email=False):
        self.state=self.directory/'webhook-boundary.json'
        self.config['generic_webhooks']=[{'id':name,'name':name,'url':'https://hooks.example.invalid/'+name,'enabled':'1'}
            for name in ('first','second')]
        self.config['nws_zones'][0]['generic_webhook_ids']=['first','second']
        self.key=module.queue_external_delivery(self.state,self.config,'webhook-chain','Heat Advisory',
            'Synthetic protected retry body',event='Heat Advisory',source='nws',
            email_recipients='alerts@example.invalid' if email else '',now=1000,source_validity=self.validity,
            channel_snapshot={'voice_recipient_ids':[],'sms_recipient_ids':[],'fingerprints':{}})

    def webhook_run(self,change_after_email=None,change_after_first_hook=None,uncertain_first=False):
        calls=[]
        def email(*args):
            self.calls.append(args[-1])
            if change_after_email:change_after_email()
            return True
        def transport(url,kind,payload,*args,**kwargs):
            calls.append(url.rsplit('/',1)[-1])
            if len(calls)==1 and change_after_first_hook:change_after_first_hook()
            if len(calls)==1 and uncertain_first:
                raise module.DestinationError('request_timeout',submission_possible=True)
            return 204,''
        def dispatcher(*args,**kwargs):
            return module.dispatch_webhook_destinations(*args,transport=transport,enforce_wall_clock=False,**kwargs)
        with mock.patch.object(module.subprocess,'run',side_effect=AssertionError('Unexpected channel subprocess')):
            result=module.retry_external_deliveries(self.state,self.config,'nws',live=True,
                email_sender=email,guarded_webhook_dispatcher=dispatcher)
        record=json.loads(self.state.read_text())['deliveries'][self.key]
        print('SLS_WEBHOOK_BOUNDARY '+json.dumps({'test':self.id(),'email_calls':len(self.calls),
            'webhook_transport_calls':calls,'current_source_decision':module.validate_external_weather(record,self.config,self.directory,self.clock[0])[:2],
            'receipts':{key:value['status'] for key,value in record.get('destination_receipts',{}).items()}}),flush=True)
        return calls,record

    def test_unchanged_source_submits_both_webhook_endpoints(self):
        self.webhook_record()
        calls,record=self.webhook_run()
        self.assertEqual(calls,['first','second'])
        self.assertEqual(record['terminal_status'],'complete')

    def test_cancellation_after_email_suppresses_all_later_webhooks(self):
        self.webhook_record(email=True)
        calls,record=self.webhook_run(change_after_email=lambda:self.observe(None))
        self.assertEqual(self.calls,['alerts@example.invalid'])
        self.assertEqual(calls,[])
        self.assertEqual(record['destination_receipts']['email:email']['status'],'accepted')
        self.assertIn(record['terminal_status'],['cancelled','partial_cancelled'],
            'Source cancellation was relabelled as complete after an earlier accepted email')

    def test_cancellation_between_webhooks_suppresses_the_second_post(self):
        self.webhook_record()
        calls,record=self.webhook_run(change_after_first_hook=lambda:self.observe(None))
        self.assertEqual(calls,['first'],'Source cancellation did not stop the second webhook endpoint')
        self.assertEqual(record['destination_receipts']['generic:first']['status'],'accepted')
        self.assertEqual(record['terminal_status'],'partial_cancelled')

    def test_uncertain_first_webhook_stays_uncertain_after_later_source_cancellation(self):
        self.webhook_record()
        calls,record=self.webhook_run(change_after_first_hook=lambda:self.observe(None),uncertain_first=True)
        self.assertEqual(calls,['first'])
        self.assertEqual(record['destination_receipts']['generic:first']['status'],'uncertain')
        self.assertEqual(record['destination_receipts']['generic:second']['status'],'cancelled')
        self.assertIn('generic:first',record['webhook_uncertain'])
        self.assertEqual(record['terminal_status'],'partial_cancelled')
        self.assertEqual(module.external_delivery_status(self.state,'nws','webhook-chain'),'uncertain')
        calls,record=self.webhook_run()
        self.assertEqual(calls,[],'A previously uncertain POST was replayed after source cancellation')

    def test_quiet_hours_between_webhooks_retries_only_the_unsent_endpoint(self):
        previous=os.environ.get('TZ');os.environ['TZ']='UTC';time.tzset()
        try:
            self.webhook_record()
            self.config['nws_zones'][0].update(quiet_hours_enabled='1',quiet_hours_start='00:19',quiet_hours_end='00:20')
            calls,record=self.webhook_run(change_after_first_hook=lambda:self.clock.__setitem__(0,1141))
            self.assertEqual(calls,['first'])
            self.assertEqual(record['webhook_pending'],['generic:second'])
            self.assertFalse(record.get('webhook_uncertain'))
            self.clock[0]=1201
            calls,record=self.webhook_run()
            self.assertEqual(calls,['second'],'Previously accepted first endpoint was replayed')
            self.assertEqual(record['terminal_status'],'complete')
        finally:
            if previous is None:os.environ.pop('TZ',None)
            else:os.environ['TZ']=previous
            time.tzset()

    def test_webhook_target_changed_between_handoffs_cannot_expand_original_audience(self):
        self.webhook_record()
        calls,record=self.webhook_run(change_after_first_hook=lambda:self.config['generic_webhooks'][1].update(
            url='https://different.example.invalid/second'))
        self.assertEqual(calls,['first'])
        self.assertEqual(record['destination_receipts']['generic:second']['status'],'cancelled')
        self.assertFalse(record.get('webhook_uncertain'))
        self.assertEqual(record['terminal_status'],'partial_cancelled')

    def real_email(self,change=None,queue=True):
        import sls_branded_email
        if queue:
            self.state=self.directory/'last-email-boundary.json'
            self.key=module.queue_external_delivery(self.state,self.config,'last-email','Heat Advisory',
                'Synthetic protected retry body',event='Heat Advisory',source='nws',
                email_recipients=' '.join(self.config['nws_zones'][0]['email_recipients']),
                now=1000,source_validity=self.validity,
                channel_snapshot={'voice_recipient_ids':[],'sms_recipient_ids':[],'fingerprints':{}})
        sendmail=[]
        self.messages=[]
        def admission(*args):
            if change:change()
        def submit(command,**kwargs):
            self.assertEqual(command[0],'/usr/sbin/sendmail')
            sendmail.append(command)
            self.messages.append(BytesParser(policy=policy.default).parsebytes(kwargs['input']))
            return subprocess.CompletedProcess(command,0)
        with mock.patch.object(sls_branded_email.Path,'is_file',return_value=True),\
             mock.patch.object(sls_branded_email.os,'access',return_value=True),\
             mock.patch.object(sls_branded_email,'read_logo',return_value=None),\
             mock.patch.object(sls_branded_email._cluster_guard,'fence_legacy',return_value=None),\
             mock.patch.object(sls_branded_email._mail_admission,'reserve',side_effect=admission),\
             mock.patch.object(module.subprocess,'run',side_effect=submit),\
             mock.patch.dict(os.environ,{'SLS_WORKER_DEADLINE_EPOCH':''}):
            module.retry_external_deliveries(self.state,self.config,'nws',live=True)
        record=json.loads(self.state.read_text())['deliveries'][self.key]
        return sendmail,record

    def test_real_email_positive_control_submits_after_admission(self):
        calls,record=self.real_email()
        self.assertEqual(len(calls),1)
        self.assertEqual(record['destination_receipts']['email:email']['status'],'accepted')

    def test_real_email_cancellation_during_admission_proves_no_submission(self):
        calls,record=self.real_email(lambda:self.observe(None))
        self.assertEqual(calls,[])
        self.assertEqual(record['destination_receipts']['email:email']['status'],'cancelled')
        self.assertFalse(record.get('email_uncertain'))
        self.assertFalse(record['email_pending'])
        self.assertEqual(record['terminal_status'],'cancelled')

    def test_real_email_expiry_during_admission_proves_no_submission(self):
        calls,record=self.real_email(lambda:self.clock.__setitem__(0,2001))
        self.assertEqual(calls,[])
        self.assertEqual(record['destination_receipts']['email:email']['error'],'source_expired')
        self.assertFalse(record.get('email_uncertain'))

    def test_recipient_removed_during_mail_admission_defers_only_narrowed_envelope(self):
        self.config['nws_zones'][0]['email_recipients']=['alerts@example.invalid','removed@example.invalid']
        calls,record=self.real_email(lambda:self.config['nws_zones'][0].update(email_recipients=['alerts@example.invalid']))
        self.assertEqual(calls,[],'Prepared email still included a recipient removed during admission')
        self.assertEqual(record['email_recipients'],'alerts@example.invalid')
        self.assertEqual(record['destination_receipts']['email:email']['status'],'deferred')
        self.assertTrue(record['email_pending'])
        self.assertFalse(record.get('email_uncertain'))
        calls,record=self.real_email(queue=False)
        self.assertEqual(len(calls),1)
        self.assertEqual(str(self.messages[0]['Bcc']),'alerts@example.invalid')
        self.assertEqual(record['terminal_status'],'partial_cancelled')

    def test_legacy_injected_email_callback_keeps_its_positional_contract(self):
        self.webhook_record(email=True)
        emails=[]
        def legacy(config,subject,body,event,severity,recipients):
            emails.append(recipients)
            return True
        module.retry_external_deliveries(self.state,self.config,'nws',live=True,email_sender=legacy,
            webhook_dispatcher=lambda *args,**kwargs:[{'type':'generic','id':name,'status':'accepted'} for name in ('first','second')])
        self.assertEqual(emails,['alerts@example.invalid'])

    def test_configuration_read_failure_after_first_effect_keeps_receipt_and_pending_email(self):
        first=[True]
        def read_config():
            if first[0]:return self.config
            raise ValueError('synthetic unavailable protected configuration')
        def handoff(command,**kwargs):
            first[0]=False
            return subprocess.CompletedProcess(command,0,stdout=json.dumps({'success':True,
                'status':'queued','message':'Synthetic queued job','job_id':'job_'+'d'*32}),stderr='')
        with mock.patch.object(module.subprocess,'run',side_effect=handoff):
            module.retry_external_deliveries(self.state,self.config,'nws',live=True,
                configuration_reader=read_config,email_sender=lambda *args:self.fail('No authority for email'))
        record=json.loads(self.state.read_text())['deliveries'][self.key]
        self.assertEqual(record['destination_receipts']['channels:sms_external_voice']['status'],'queued')
        self.assertTrue(record['email_pending'])
        self.assertFalse(record.get('email_uncertain'))
        self.assertFalse(record.get('completed_at'))
        self.assertFalse(record.get('worker_claim'))

    def test_real_email_quiet_boundary_during_admission_retains_unsent_message(self):
        previous=os.environ.get('TZ');os.environ['TZ']='UTC';time.tzset()
        try:
            self.config['nws_zones'][0].update(quiet_hours_enabled='1',quiet_hours_start='00:19',quiet_hours_end='00:20')
            calls,record=self.real_email(lambda:self.clock.__setitem__(0,1141))
            self.assertEqual(calls,[])
            self.assertEqual(record['destination_receipts']['email:email']['status'],'deferred')
            self.assertTrue(record['email_pending'])
            self.assertFalse(record.get('email_uncertain'))
            self.assertFalse(record.get('completed_at'))
        finally:
            if previous is None:os.environ.pop('TZ',None)
            else:os.environ['TZ']=previous
            time.tzset()

    def tls_run(self,cancel=False,claim_change=None,email=False):
        self.webhook_record(email=email)
        requests=[]
        self.cluster_finishes=[]
        claims=[]
        owner=self
        class Connection:
            sock=None
            def connect(self):
                if cancel:owner.observe(None)
            def request(self,*args,**kwargs):requests.append(args)
            def getresponse(self):
                return type('Reply',(),{'status':204,'getheader':lambda self,*args:''})()
            def close(self):pass
        def resolver(*args,**kwargs):
            return [(socket.AF_INET,socket.SOCK_STREAM,6,'',('8.8.8.8',443))]
        def dispatcher(*args,**kwargs):
            return module.dispatch_webhook_destinations(*args,transport=module._request_once,
                resolver=resolver,enforce_wall_clock=False,**kwargs)
        def begin(*args,**kwargs):
            claim={'private_claim':len(claims)+1};claims.append(claim)
            if claim_change:claim_change(len(claims))
            return claim
        def finish(claim,**kwargs):self.cluster_finishes.append((claim,kwargs))
        with mock.patch.object(module,'_PinnedHTTPSConnection',return_value=Connection()),\
             mock.patch.object(module._cluster_guard,'begin',side_effect=begin),\
             mock.patch.object(module._cluster_guard,'finish',side_effect=finish):
            module.retry_external_deliveries(self.state,self.config,'nws',live=True,
                email_sender=lambda *args:(self.calls.append(args[-1])or True),guarded_webhook_dispatcher=dispatcher)
        return requests,json.loads(self.state.read_text())['deliveries'][self.key]

    def test_real_tls_positive_control_posts_both_endpoints(self):
        requests,record=self.tls_run()
        self.assertEqual(len(requests),2)
        self.assertEqual(record['terminal_status'],'complete')

    def test_source_cancelled_during_tls_is_suppressed_before_http_request(self):
        requests,record=self.tls_run(cancel=True)
        self.assertEqual(requests,[],'Weather authority was not rechecked after TLS setup')
        self.assertFalse(record.get('webhook_uncertain'))
        self.assertEqual(record['destination_receipts']['generic:first']['status'],'cancelled')
        self.assertEqual(record['terminal_status'],'cancelled')

    def test_real_consumed_claim_source_cancellation_keeps_accepted_email_without_post(self):
        requests,record=self.tls_run(claim_change=lambda count:self.observe(None),email=True)
        self.assertEqual(requests,[]);self.assertEqual(self.calls,['alerts@example.invalid'])
        self.assertEqual(record['destination_receipts']['email:email']['status'],'accepted')
        self.assertEqual(record['terminal_status'],'partial_cancelled');self.assertFalse(record.get('webhook_uncertain'))
        self.assertEqual(self.cluster_finishes,[({'private_claim':1},{'uncertain':False,'category':'submission_suppressed','timeout':1})])

    def test_second_real_consumed_claim_cancellation_keeps_first_webhook_acceptance(self):
        requests,record=self.tls_run(claim_change=lambda count:self.observe(None)if count==2 else None)
        self.assertEqual(len(requests),1)
        self.assertEqual(record['destination_receipts']['generic:first']['status'],'accepted')
        self.assertEqual(record['destination_receipts']['generic:second']['status'],'cancelled')
        self.assertEqual(record['terminal_status'],'partial_cancelled');self.assertFalse(record.get('webhook_uncertain'))
        self.assertEqual(self.cluster_finishes[-1],({'private_claim':2},{'uncertain':False,'category':'submission_suppressed','timeout':1}))

    def test_quiet_boundary_during_real_consumed_claim_retains_unsent_pending(self):
        previous=os.environ.get('TZ');os.environ['TZ']='UTC';time.tzset()
        try:
            self.config['nws_zones'][0].update(quiet_hours_enabled='1',quiet_hours_start='00:19',quiet_hours_end='00:20')
            requests,record=self.tls_run(claim_change=lambda count:self.clock.__setitem__(0,1141))
            self.assertEqual(requests,[]);self.assertEqual(record['webhook_pending'],['generic:first','generic:second'])
            self.assertFalse(record.get('webhook_uncertain'));self.assertFalse(record.get('completed_at'))
            self.assertEqual(self.cluster_finishes,[({'private_claim':1},{'uncertain':False,'category':'submission_suppressed','timeout':1})])
        finally:
            if previous is None:os.environ.pop('TZ',None)
            else:os.environ['TZ']=previous
            time.tzset()

    def test_quiet_hours_after_email_defer_webhooks_without_replaying_email(self):
        previous=os.environ.get('TZ');os.environ['TZ']='UTC';time.tzset()
        try:
            self.webhook_record(email=True)
            self.config['nws_zones'][0].update(quiet_hours_enabled='1',quiet_hours_start='00:19',quiet_hours_end='00:20')
            calls,record=self.webhook_run(change_after_email=lambda:self.clock.__setitem__(0,1141))
            self.assertEqual(calls,[]);self.assertEqual(len(self.calls),1)
            self.assertFalse(record['email_pending']);self.assertEqual(len(record['webhook_pending']),2)
            self.clock[0]=1201
            calls,record=self.webhook_run()
            self.assertEqual(calls,['first','second']);self.assertEqual(len(self.calls),1,'Accepted email was replayed after quiet hours')
        finally:
            if previous is None:os.environ.pop('TZ',None)
            else:os.environ['TZ']=previous
            time.tzset()

    def test_production_entrypoint_refreshes_config_before_later_email(self):
        import sls_branded_email
        for change in ('source_disabled','recipient_removed'):
            with self.subTest(change=change):
                self.calls=[]
                self.state=self.directory/(change+'.json')
                self.key=module.queue_external_delivery(self.state,self.config,change,'Heat Advisory',
                    'Synthetic protected retry body',event='Heat Advisory',source='nws',
                    email_recipients='alerts@example.invalid',now=1000,source_validity=self.validity,
                    channel_snapshot={'voice_recipient_ids':['voice_'+'a'*24],
                        'sms_recipient_ids':[],'fingerprints':{}})
                config_path=self.directory/(change+'.config')
                config_path.write_text(json.dumps(self.config));config_path.chmod(0o640)
                changed=copy.deepcopy(self.config)
                if change=='source_disabled':changed['enabled']='0'
                else:changed['nws_zones'][0]['email_recipients']=[]
                def handoff(command,**kwargs):
                    self.assertEqual(Path(command[-1]).name,'sls_mass_notify_weather_channels.php')
                    config_path.write_text(json.dumps(changed));config_path.chmod(0o640)
                    return subprocess.CompletedProcess(command,0,stdout=json.dumps({'success':True,
                        'status':'queued','message':'Synthetic channel queued','job_id':'job_'+'d'*32}),stderr='')
                def email(*args,**kwargs):self.calls.append(args[-1]);return True
                with mock.patch.object(module.subprocess,'run',side_effect=handoff),\
                     mock.patch.object(sls_branded_email,'send_branded_email',side_effect=email),\
                     mock.patch.object(sys,'argv',['sls_notification_destinations.py',str(config_path),'--retry-state',str(self.state)]),\
                     mock.patch.dict(os.environ,{'SLS_NOTIFICATION_LIVE':'1','SLS_NOTIFICATION_TEST':'0',
                         'SLS_NOTIFICATION_DRY_RUN':'0','SLS_DESTINATION_SOURCE':'nws','SLS_EXTERNAL_RETRY_ONLY':'1'}):
                    module.main()
                record=json.loads(self.state.read_text())['deliveries'][self.key]
                print('SLS_CONFIG_BOUNDARY '+json.dumps({'change':change,'email_calls':len(self.calls),
                    'fresh_source_decision':module.validate_external_weather(record,module._config_crypto.read_config(config_path),self.directory,self.clock[0])[:2],
                    'fresh_group_email_recipients':changed['nws_zones'][0]['email_recipients']}),flush=True)
                self.assertFalse(self.calls,'Production retry used stale configuration after '+change)


if __name__=='__main__':unittest.main()
