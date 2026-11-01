#!/usr/bin/python3
"""Inert exact voicemail helper authority probes; no AMI/MTA/PBX transport."""
from contextlib import contextmanager
import copy
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import pwd
import sys
import tempfile
import unittest
from unittest import mock

if os.environ.get('SLS_TEST_NAMESPACE') != 'entered':
    raise SystemExit('Run only through the unchanged isolated test wrapper.')
sys.dont_write_bytecode=True
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'slsmassnotifyserver/bin/sls_mass_notify'))
import sls_voicemail as vm
import sls_notification_destinations as destinations
import sls_phone_admission as phone


class NativeTargetBoundary(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory(prefix='sls-vm-authority-');self.addCleanup(self.temp.cleanup)
        self.root=Path(self.temp.name);self.clock=[1100]
        self.config={'enabled':'1','runtime_enabled':True,'ami':{},'nws_zones':[{'id':'north','name':'North',
            'zone':'TXC491','extensions':['1001'],'email_recipients':[],
            'quiet_hours_enabled':'0','quiet_critical_events':[]}]}
        self.feature={'id':'provider-alert-1','properties':{'event':'Heat Advisory','status':'Actual',
            'messageType':'Alert','expires':datetime.fromtimestamp(2000,timezone.utc).isoformat()}}
        self.validity=destinations.weather_source_validity('nws','north',feature=self.feature,
            chain_key='Heat Advisory|provider-alert-1',zone='TXC491',observed_at=1000)
        self.parent={'service':'nws','vm_fallback':{'scope':'north',
            'scope_hash':vm.scope_fingerprint(self.config,'nws','north'),
            'weather_context':{'event':'Heat Advisory','severity':'','source_validity':self.validity}}}
        self.token='a'*32;self.source='b'*32
        self.target={'source_token':self.source,'mailbox':'1001@default','sound':vm.canonical_sound(self.source)}
        self.save_config();self.observe()
        self.time=mock.patch.object(destinations.time,'time',side_effect=lambda:self.clock[0]);self.time.start();self.addCleanup(self.time.stop)

    def save_config(self,value=None):
        path=self.root/'mass-notifications.config'
        path.write_text(json.dumps(self.config if value is None else value));path.chmod(0o640)
        account=pwd.getpwnam('asterisk');os.chown(path,account.pw_uid,account.pw_gid)

    def observe(self,cancel=False):
        path=self.root/'weather-delivery.json'
        path.write_text(json.dumps({'snapshots':{'north':{'zone':'TXC491','observed_at':1100,
            'active':{} if cancel else {self.validity['chain_key']:self.feature}}}}));path.chmod(0o640)

    def check(self,change=None,store=None):
        owner=self
        class Store:
            directory=owner.root
            def voicemail_target(self,*args):return owner.target
            @contextmanager
            def locked(self):yield {'batches':{owner.source:owner.parent}}
        class Ami:
            def mailboxes(self,recipients):
                if change:change()
                return {'1001':'1001@default'}
        media=mock.MagicMock();media.path=self.root;media.validate.return_value={'duration_seconds':2}
        with mock.patch.object(vm,'native_transport_guard'),mock.patch.object(vm,'VoicemailMedia',return_value=media),\
             mock.patch.object(vm,'check_mailbox_audio'):
            return vm.check_native_target(store or Store(),self.token,'1001',copy.deepcopy(self.config),Ami())

    def test_unchanged_source_positive_control_authorizes_exact_target(self):
        self.assertEqual(self.check(),self.target)

    def test_cancelled_source_during_mailbox_io_is_refused(self):
        with self.assertRaises(vm.PhoneAdmissionError):
            self.check(lambda:self.observe(cancel=True))

    def test_revoked_configuration_during_mailbox_io_is_refused(self):
        changed=copy.deepcopy(self.config);changed['nws_voicemail_enabled']='0'
        with self.assertRaises(vm.PhoneAdmissionError):
            self.check(lambda:self.save_config(changed))

    def test_expired_source_during_mailbox_io_is_refused(self):
        with self.assertRaises(vm.PhoneAdmissionError):
            self.check(lambda:self.clock.__setitem__(0,2001))

    def real_claim(self):
        store=phone.PhoneAdmissionStore(self.root,clock=lambda:self.clock[0])
        generation='c'*32;store.collector_heartbeat(generation)
        inventory={'complete':True,'started_tick':self.clock[0],'generation':generation,
            'boot_id':store.boot_id,'channels':[]}
        fallback={'schema':1,'scope':'north','scope_hash':self.parent['vm_fallback']['scope_hash'],
            'source_sound':'SLS_Mass_Notifications_Plugin/tts/fixture','sound':None,
            'weather_context':self.parent['vm_fallback']['weather_context'],
            'live_origin':None,'live_group':None,'expires_at':1900,'expires_tick':1900,
            'targets':{'1001':{'dials':[],'mailbox':'1001@default','claimed_token':None}}}
        source=store.admit({'1001':[]},25,inventory,service='nws',correlation='vm-native-boundary',vm_fallback=fallback)
        sound=vm.canonical_sound(source)
        store.attach_voicemail_sound(source,fallback['source_sound'],sound)
        self.clock[0]+=1;inventory['started_tick']=self.clock[0]
        child=store.admit_voicemail(source,'1001',25,inventory,'1001@default',sound)
        self.source=source;self.token=child
        self.target=store.voicemail_target(child,'1001')
        return store

    def test_real_reserved_child_positive_control_keeps_exact_claim(self):
        store=self.real_claim();before=(self.root/'phone-admission.json').read_bytes()
        self.assertEqual(self.check(store=store),self.target)
        self.assertEqual((self.root/'phone-admission.json').read_bytes(),before)

    def test_cancellation_never_reopens_or_erases_real_reserved_deposit(self):
        store=self.real_claim();before=(self.root/'phone-admission.json').read_bytes()
        refused=False
        try:self.check(lambda:self.observe(cancel=True),store=store)
        except vm.PhoneAdmissionError:refused=True
        self.assertEqual((self.root/'phone-admission.json').read_bytes(),before,
            'Late source suppression erased or reopened a previously consumed voicemail claim')
        retained=phone.read_private_json('phone-admission.json',self.root)
        self.assertEqual(retained['batches'][self.source]['vm_fallback']['targets']['1001']['claimed_token'],self.token)
        self.assertEqual(retained['batches'][self.token]['status'],'reserved')
        self.assertTrue(refused,'Cancelled source still authorized a new deposit from the reserved child')


if __name__=='__main__':unittest.main()
