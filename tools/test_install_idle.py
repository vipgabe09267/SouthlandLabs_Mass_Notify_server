#!/usr/bin/python3
"""Read-only quiescence checks using private state/process/spool/channel fixtures."""
import hashlib
import importlib.util
import json
import os
import sys
from pathlib import Path
import tempfile
import threading
import unittest
from copy import deepcopy
from unittest import mock

ROOT=Path(__file__).resolve().parents[1]
spec=importlib.util.spec_from_file_location('idle_fixture',ROOT/'slsmassnotifyserver/bin/sls_mass_notify/sls_install_idle.py')
m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)

class Idle(unittest.TestCase):
    def setUp(self):
        temp=tempfile.TemporaryDirectory(prefix='sls-install-idle-');self.addCleanup(temp.cleanup)
        self.base=Path(temp.name);self.data=self.base/'data';self.data.mkdir(mode=0o750)
        self.proc=self.base/'proc';self.proc.mkdir()
        self.spools=[self.base/'outgoing',self.base/'spool-tmp']
        for directory in self.spools:directory.mkdir()
        self.module=self.base/'module/module.xml';self.module.parent.mkdir();self.module.write_bytes(b'<module/>')
        self.subsystem=self.module.with_name('PhoneEventService.php');self.subsystem.write_bytes(b'<?php')
        self.channels='';self.command_calls=0
        def channels():self.command_calls+=1;return self.channels
        self.check=m.IdleCheck(self.data,module=self.module,proc=self.proc,spools=self.spools,channels=channels,boot_id='fixture-boot',monotonic=lambda:100,clock=lambda:1000,subsystem_paths=(self.subsystem,self.base/'collector-unit',self.base/'runtime-collector'))
        self.token='a'*32
        self.state={'schema':1,'collector':{'generation':'b'*32,'boot_id':'fixture-boot','heartbeat_tick':99},'batches':{self.token:{'status':'closed','created_at':1,'closed_at':2,'detail':'private destination'}}}
        self.save('phone-admission.json',self.state)
    def save(self,name,value):
        path=self.data/name;path.parent.mkdir(parents=True,exist_ok=True);path.write_text(json.dumps(value));path.chmod(0o640);return path
    def baseline(self):
        path=self.base/'baseline.json';path.write_text(json.dumps(self.check.inspect()));path.chmod(0o600);return path
    def process(self,args):
        directory=self.proc/'999999';directory.mkdir(exist_ok=True);(directory/'cmdline').write_bytes(b'\0'.join(value.encode() for value in args)+b'\0')
    def test_idle_stale_collector_can_be_repaired_without_rewriting_history(self):
        self.state['collector']['heartbeat_tick'] = 1
        self.save('phone-admission.json', self.state)
        before = (self.data/'phone-admission.json').read_bytes()
        with self.assertRaises(m.IdleError): self.check.inspect()
        report = self.check.inspect(repair_collector=True)
        self.assertEqual(report['closed_phone_batches'], 1)
        self.assertEqual(before, (self.data/'phone-admission.json').read_bytes())
        self.process(['python3', 'sls_mass_notify_phone_agi.py'])
        with self.assertRaises(m.IdleError): self.check.inspect(repair_collector=True)

    def test_orphan_repair_requires_final_reconciliation_and_preserves_closed_rows(self):
        orphan = 'd'*32
        self.state['batches'][orphan] = {'status': 'reserved', 'created_at': 2}
        self.save('phone-admission.json', self.state)
        path = self.base/'repair-before.json'
        path.write_text(json.dumps(self.check.inspect(repair_collector=True))); path.chmod(0o600)
        with self.assertRaises(m.IdleError): self.check.inspect(path)
        self.state['batches'][orphan]['status'] = 'closed'
        self.state['batches'][orphan]['closed_at'] = 3
        self.save('phone-admission.json', self.state)
        self.check.inspect(path)

    def test_history_inspection_is_read_only_and_never_prints_tokens_or_destinations(self):
        path=self.data/'phone-admission.json';before=path.read_bytes();info=path.stat()
        result=self.check.inspect();encoded=json.dumps(result)
        self.assertEqual(result['closed_phone_batches'],1)
        self.assertNotIn(self.token,encoded);self.assertNotIn('private destination',encoded)
        self.assertEqual(path.read_bytes(),before)
        self.assertEqual((path.stat().st_mtime_ns,path.stat().st_ino),(info.st_mtime_ns,info.st_ino))
        self.assertEqual(self.command_calls,1)
    def test_heartbeat_change_allowed_but_closed_record_mutation_or_removal_rejected(self):
        before=self.baseline()
        self.state['collector']['generation']='c'*32;self.state['collector']['heartbeat_tick']=100;self.save('phone-admission.json',self.state)
        self.check.inspect(before)
        self.state['batches'][self.token]['closed_at']=3;self.save('phone-admission.json',self.state)
        with self.assertRaisesRegex(m.IdleError,'changed or disappeared'):self.check.inspect(before)
        self.state['batches']={};self.save('phone-admission.json',self.state)
        with self.assertRaisesRegex(m.IdleError,'changed or disappeared'):self.check.inspect(before)
    def test_new_closed_history_is_allowed(self):
        before=self.baseline();self.state['batches']['d'*32]={'status':'closed','closed_at':3};self.save('phone-admission.json',self.state)
        self.assertEqual(self.check.inspect(before)['closed_phone_batches'],2)

    def test_collector_atomic_commit_waits_for_the_read_only_history_snapshot(self):
        sys.path.insert(0,str(ROOT/'slsmassnotifyserver/bin/sls_mass_notify'))
        import sls_phone_admission as phone
        path=self.data/'phone-admission.json';path.unlink()
        store=phone.PhoneAdmissionStore(self.data,clock=lambda:1000,monotonic=lambda:100,boot_id='fixture-boot')
        store.collector_heartbeat('b'*32)
        token=store.admit({'1000':['PJSIP/1000/sip:fixture@192.0.2.1']},25,
            {'complete':True,'started_tick':100,'generation':'b'*32,'boot_id':'fixture-boot','channels':[]},service='manual')
        with store.locked() as state:state['batches'][token].update(status='closed',closed_at=1000)
        before=self.baseline();inode=path.stat().st_ino
        original_read=os.read;started=threading.Event();finished=threading.Event();errors=[];committed_during_read=[]
        def update():
            try:store.collector_heartbeat('c'*32)
            except BaseException as error:errors.append(error)
            finally:finished.set()
        writer=threading.Thread(target=update)
        def read(fd,size):
            if not started.is_set() and os.fstat(fd).st_ino==inode:
                started.set();writer.start()
                committed_during_read.append(finished.wait(.15))
            return original_read(fd,size)
        try:
            with mock.patch.object(m.os,'read',side_effect=read):
                report=self.check.inspect(before)
        finally:
            if started.is_set():writer.join(timeout=3)
        self.assertTrue(started.is_set())
        self.assertTrue(finished.is_set())
        self.assertEqual(errors,[])
        self.assertEqual(committed_during_read,[False])
        self.assertEqual(report['closed_phone_batches'],1)
        self.check.inspect(before)

    def test_collector_retention_expiry_during_upgrade_keeps_history_verification_valid(self):
        # Reproduce the reported 22 -> 19 transition with the real store and
        # collector transaction, without invoking a PBX or a delivery transport.
        sys.path.insert(0,str(ROOT/'slsmassnotifyserver/bin/sls_mass_notify'))
        import sls_phone_admission as phone
        (self.data/'phone-admission.json').unlink()
        now=[1800000000-phone.HISTORY_SECONDS+1];tick=[100.0]
        store=phone.PhoneAdmissionStore(self.data,clock=lambda:now[0],
            monotonic=lambda:tick[0],boot_id='fixture-boot')
        generation='b'*32;store.collector_heartbeat(generation)
        old=[]
        for index in range(22):
            now[0]=1800000000-phone.HISTORY_SECONDS+(1 if index<3 else 3600)
            inventory={'complete':True,'started_tick':tick[0],
                'generation':generation,'boot_id':'fixture-boot','channels':[]}
            token=store.admit({'1000':['PJSIP/1000/sip:fixture@192.0.2.1']},25,inventory,service='manual')
            with store.locked() as state:
                state['batches'][token].update(status='closed',closed_at=now[0])
            if index<3:old.append(token)
        now[0]=1800000000;store.collector_heartbeat(generation)
        self.check.clock=lambda:now[0];self.check.monotonic=lambda:tick[0]
        before=self.baseline()
        original=json.loads((self.data/'phone-admission.json').read_text())['batches']
        self.assertEqual(len(original),22)
        now[0]+=2;tick[0]+=2
        # A collector restart after activation takes a real ledger transaction.
        store.collector_heartbeat('c'*32)
        retained=json.loads((self.data/'phone-admission.json').read_text())['batches']
        self.assertEqual(len(retained),19)
        self.assertTrue(all(token not in retained for token in old))
        self.assertTrue(all(row==original[token] for token,row in retained.items()))
        result=self.check.inspect(before)
        self.assertTrue(result['ok']);self.assertEqual(result['retired_phone_batches'],3)

    def test_legacy_baseline_missing_rows_require_matching_private_evidence_and_expiry(self):
        self.check.clock=lambda:1000000
        before=self.baseline();legacy=json.loads(before.read_text());legacy.pop('phone_history_retention')
        before.write_text(json.dumps(legacy))
        proof=self.base/'old-phone-evidence.json';proof.write_text(json.dumps(self.state));proof.chmod(0o600)
        self.state['batches']={};path=self.save('phone-admission.json',self.state)
        unchanged=[(p,p.read_bytes(),p.stat().st_ino,p.stat().st_mtime_ns) for p in (before,proof,path)]
        with self.assertRaisesRegex(m.IdleError,'without retention evidence'):self.check.inspect(before)
        result=self.check.inspect(before,history_evidence=proof)
        self.assertTrue(result['ok']);self.assertEqual(result['retired_phone_batches'],1)
        for p,body,inode,mtime in unchanged:
            self.assertEqual((p.read_bytes(),p.stat().st_ino,p.stat().st_mtime_ns),(body,inode,mtime))

    def test_recovery_evidence_is_retained_privately_without_overwriting_live_history(self):
        before=self.baseline()
        proof=self.base/'pre-upgrade-phone.json';proof.write_text(json.dumps(self.state));proof.chmod(0o600)
        transaction=self.base/'protected-recovery';transaction.mkdir(mode=0o700)
        retained=transaction/'history-evidence.json'
        live=self.data/'phone-admission.json'
        original=(live.read_bytes(),live.stat().st_ino,live.stat().st_mtime_ns,proof.read_bytes())
        m.retain_history_evidence(before,proof,retained)
        self.assertEqual(json.loads(retained.read_text()),{'schema':1,'batches':self.state['batches']})
        self.assertEqual(retained.stat().st_mode&0o777,0o600)
        inode=retained.stat().st_ino
        m.retain_history_evidence(before,proof,retained)
        self.assertEqual(retained.stat().st_ino,inode)
        self.assertEqual(original,(live.read_bytes(),live.stat().st_ino,live.stat().st_mtime_ns,proof.read_bytes()))
        changed=deepcopy(self.state);changed['collector']['heartbeat_tick']=98
        proof.write_text(json.dumps(changed))
        m.retain_history_evidence(before,proof,retained)
        self.assertEqual(retained.stat().st_ino,inode)
        changed['batches'][self.token]['detail']='unverified replacement'
        proof.write_text(json.dumps(changed))
        with self.assertRaisesRegex(m.IdleError,'does not match'):
            m.retain_history_evidence(before,proof,retained)
        self.assertEqual(retained.stat().st_ino,inode)

    def test_matching_history_evidence_can_be_completed_from_multiple_old_backups(self):
        self.check.clock=lambda:1000000
        b,c,d='b'*32,'c'*32,'d'*32
        self.state['batches'][b]={'status':'closed','closed_at':3,'detail':'second baseline row'}
        self.state['batches'][c]={'status':'closed','closed_at':4,'detail':'third baseline row'}
        self.save('phone-admission.json',self.state);before=self.baseline()
        legacy=json.loads(before.read_text());legacy.pop('phone_history_retention');before.write_text(json.dumps(legacy))
        first={'schema':1,'collector':{'old':'unneeded'},'batches':{
            self.token:deepcopy(self.state['batches'][self.token]),
            b:{'status':'active','created_at':1},d:{'status':'closed','closed_at':1}}}
        second={'schema':1,'batches':{b:deepcopy(self.state['batches'][b]),c:deepcopy(self.state['batches'][c])}}
        a=self.base/'backup-a.json';a.write_text(json.dumps(first));a.chmod(0o600)
        z=self.base/'backup-b.json';z.write_text(json.dumps(second));z.chmod(0o600)
        raw=(a.read_bytes(),z.read_bytes())
        destination=self.base/'recovery';destination.mkdir(mode=0o700)
        retained=destination/'history-evidence.json'
        self.state['batches']={};live=self.save('phone-admission.json',self.state);live_before=live.read_bytes()
        m.retain_history_evidence(before,a,retained)
        proof=json.loads(retained.read_text());self.assertEqual(set(proof['batches']),{self.token})
        with self.assertRaisesRegex(m.IdleError,'without retention evidence'):
            self.check.inspect(before,history_evidence=retained)
        m.retain_history_evidence(before,z,retained)
        merged=json.loads(retained.read_text());self.assertEqual(set(merged['batches']),{self.token,b,c})
        self.assertEqual(merged['batches'][self.token],proof['batches'][self.token])
        result=self.check.inspect(before,history_evidence=retained)
        self.assertEqual(result['retired_phone_batches'],3)
        self.assertEqual((a.read_bytes(),z.read_bytes()),raw)
        self.assertEqual(live.read_bytes(),live_before)

    def test_recovery_evidence_rejects_unsafe_sources_and_unmatched_records(self):
        before=self.baseline()
        transaction=self.base/'protected-recovery';transaction.mkdir(mode=0o700)
        retained=transaction/'history-evidence.json'
        proof=self.base/'pre-upgrade-phone.json';proof.write_text(json.dumps(self.state));proof.chmod(0o640)
        with self.assertRaises(m.IdleError):m.retain_history_evidence(before,proof,retained)
        self.assertFalse(retained.exists())
        proof.chmod(0o600)
        altered=deepcopy(self.state);altered['batches'][self.token]['detail']='unapproved alternate record'
        proof.write_text(json.dumps(altered))
        with self.assertRaisesRegex(m.IdleError,'does not match'):
            m.retain_history_evidence(before,proof,retained)
        self.assertFalse(retained.exists())
        proof.write_text(json.dumps(self.state))
        outside=self.base/'outside';outside.write_bytes(b'preserved')
        retained.symlink_to(outside)
        with self.assertRaises(OSError):m.retain_history_evidence(before,proof,retained)
        self.assertEqual(outside.read_bytes(),b'preserved')

    def test_legacy_evidence_never_authorizes_modified_or_unexpired_missing_history(self):
        self.check.clock=lambda:1000000
        before=self.baseline();legacy=json.loads(before.read_text());legacy.pop('phone_history_retention');before.write_text(json.dumps(legacy))
        proof=self.base/'old-phone-evidence.json';forged=deepcopy(self.state);forged['batches'][self.token]['closed_at']=3
        proof.write_text(json.dumps(forged));proof.chmod(0o600)
        self.state['batches']={};self.save('phone-admission.json',self.state)
        with self.assertRaisesRegex(m.IdleError,'does not match'):self.check.inspect(before,history_evidence=proof)
        self.state['batches'][self.token]={'status':'closed','closed_at':999999,'detail':'unexpired'}
        self.save('phone-admission.json',self.state);before=self.baseline()
        legacy=json.loads(before.read_text());legacy.pop('phone_history_retention');before.write_text(json.dumps(legacy))
        proof.write_text(json.dumps(self.state));self.state['batches']={};self.save('phone-admission.json',self.state)
        with self.assertRaisesRegex(m.IdleError,'before expiry'):self.check.inspect(before,history_evidence=proof)

    def test_retention_policy_cannot_be_shortened_or_retyped(self):
        before=self.baseline();original=json.loads(before.read_text())
        cases=[{'schema':True,'seconds':604800,'closed_at':{}},
               {'schema':1,'seconds':1,'closed_at':{}},
               {'schema':1,'seconds':'604800','closed_at':{}},
               {'schema':1,'seconds':604800,'closed_at':{'f'*64:2}},
               {'schema':1,'seconds':604800,'closed_at':{hashlib.sha256(self.token.encode()).hexdigest():True}}]
        for policy in cases:
            with self.subTest(policy=policy):
                value=deepcopy(original);value['phone_history_retention']=policy;before.write_text(json.dumps(value))
                with self.assertRaisesRegex(m.IdleError,'retention baseline'):self.check.inspect(before)

    def test_expired_history_that_is_still_present_must_not_be_modified(self):
        self.check.clock=lambda:1000000;before=self.baseline()
        self.state['batches'][self.token]['detail']='changed';self.save('phone-admission.json',self.state)
        with self.assertRaisesRegex(m.IdleError,'changed or disappeared'):self.check.inspect(before)

    def test_history_at_the_retention_boundary_is_still_required(self):
        self.check.clock=lambda:604802;before=self.baseline();self.state['batches']={};self.save('phone-admission.json',self.state)
        with self.assertRaisesRegex(m.IdleError,'before expiry'):self.check.inspect(before)
        self.check.clock=lambda:604802.01
        self.assertEqual(self.check.inspect(before)['retired_phone_batches'],1)
    def test_active_reserved_and_corrupt_phone_batches_stop_installation(self):
        for status in ('active','reserved',None):
            self.state['batches'][self.token]['status']=status;self.save('phone-admission.json',self.state)
            with self.assertRaisesRegex(m.IdleError,'unclosed'):self.check.inspect()

    def test_ambiguous_phone_history_is_refused_without_rewriting_it(self):
        path=self.data/'phone-admission.json';valid=json.dumps(self.state)
        for addition in (',"batches":{}',',"unused":1e309',',"unused":NaN'):
            with self.subTest(addition=addition):
                raw=valid[:-1]+addition+'}';path.write_text(raw);before=path.stat()
                with self.assertRaises(m.IdleError):self.check.phone_history(True)
                self.assertEqual(path.read_text(),raw)
                self.assertEqual((path.stat().st_ino,path.stat().st_mtime_ns),(before.st_ino,before.st_mtime_ns))
        path.write_text(valid.replace('"heartbeat_tick": 99','"heartbeat_tick": 9.9e1'))
        self.assertEqual(len(self.check.phone_history(True)),1)
        self.state['schema']=True;self.save('phone-admission.json',self.state)
        with self.assertRaisesRegex(m.IdleError,'cannot be inspected'):self.check.phone_history(True)
    def voicemail_batch(self):
        return {'status':'closed','created_at':900,'closed_at':999,
                'channels':{'contact':{'kind':'contact','dial':'PJSIP/1000','ended_at':999,
                                       'answered_at':None,'joined_at':None,'dial_status':'NOANSWER'}},
                'vm_fallback':{'sound':'sls-voicemail/'+self.token,'expires_at':1100,'expires_tick':200,
                               'targets':{'1000':{'dials':['PJSIP/1000'],'claimed_token':None}}}}
    def test_old_collector_pending_voicemail_refuses_upgrade_without_changing_history(self):
        self.state['batches'][self.token]=self.voicemail_batch()
        path=self.save('phone-admission.json',self.state);before=path.read_bytes();inode=path.stat().st_ino
        for repair in (False,True):
            with self.assertRaisesRegex(m.IdleError,'voicemail fallback is pending'):
                self.check.inspect(repair_collector=repair)
        self.assertEqual(path.read_bytes(),before);self.assertEqual(path.stat().st_ino,inode)
    def test_completed_or_ineligible_voicemail_does_not_block_upgrade(self):
        variants=[];base=self.voicemail_batch()
        claimed=deepcopy(base);claimed['vm_fallback']['targets']['1000']['claimed_token']='d'*32;variants.append(claimed)
        failed=deepcopy(base);failed['voicemail_failures']={'1000':'phone_voicemail_mailbox_changed'};variants.append(failed)
        for field,value in (('answered_at',998),('joined_at',998),('outcome_uncertain',True),('ended_at',None),('dial_status','ANSWER')):
            item=deepcopy(base);item['channels']['contact'][field]=value;variants.append(item)
        for field,value in (('expires_at',1000),('expires_tick',100)):
            item=deepcopy(base);item['vm_fallback'][field]=value;variants.append(item)
        unrecorded=deepcopy(base);unrecorded['vm_fallback']['sound']=None;variants.append(unrecorded)
        for batch in variants:
            with self.subTest(batch=batch):
                self.state['batches'][self.token]=batch;self.save('phone-admission.json',self.state)
                self.assertTrue(self.check.inspect()['ok'])
    def test_offline_contact_voicemail_is_pending_and_uninstall_exception_stays_strict(self):
        batch=self.voicemail_batch();batch['vm_fallback']['targets']['1000']['dials']=[];batch['channels']={}
        self.state['batches'][self.token]=batch;self.save('phone-admission.json',self.state)
        with self.assertRaisesRegex(m.IdleError,'voicemail fallback is pending'):self.check.inspect()
        self.assertEqual(len(self.check.phone_history(False,allow_pending_voicemail=True)),1)
        self.state['batches'][self.token]['status']='active';self.save('phone-admission.json',self.state)
        with self.assertRaisesRegex(m.IdleError,'unclosed'):
            self.check.phone_history(False,allow_pending_voicemail=True)
    def test_malformed_voicemail_expiry_targets_and_claims_fail_closed(self):
        base=self.voicemail_batch();variants=[]
        for value in (None,True,float('inf'),'later'):
            item=deepcopy(base);item['vm_fallback']['expires_tick']=value;variants.append(item)
        for key,value in (('targets',[]),('targets',{'1000':{'dials':'bad'}})):
            item=deepcopy(base);item['vm_fallback'][key]=value;variants.append(item)
        claim=deepcopy(base);claim['vm_fallback']['targets']['1000']['claimed_token']='bad';variants.append(claim)
        invalid_unicode=deepcopy(base);invalid_unicode['channels']['contact']['dial']='PJSIP/\ud800';variants.append(invalid_unicode)
        for batch in variants:
            self.state['batches'][self.token]=batch;path=self.save('phone-admission.json',self.state);before=path.read_bytes()
            with self.assertRaises(m.IdleError):self.check.inspect()
            self.assertEqual(path.read_bytes(),before)
    def test_voicemail_history_cardinality_is_bounded_before_matching(self):
        batch=self.voicemail_batch()
        batch['vm_fallback']['targets']={str(index):{'dials':[],'claimed_token':None}
                                         for index in range(m.MAX_PHONE_TARGETS+1)}
        self.state['batches'][self.token]=batch;self.save('phone-admission.json',self.state)
        with self.assertRaisesRegex(m.IdleError,'inspection bounds'):self.check.inspect()
        batch=self.voicemail_batch()
        batch['channels']={str(index):{'kind':'contact','dial':'PJSIP/'+str(index),'ended_at':999,
                                      'answered_at':None,'joined_at':None,'dial_status':'NOANSWER'}
                           for index in range(m.MAX_PHONE_CHANNELS+1)}
        self.state['batches'][self.token]=batch;self.save('phone-admission.json',self.state)
        with self.assertRaisesRegex(m.IdleError,'inspection bounds'):self.check.inspect()
    def test_enabled_idle_paging_is_supported_without_reading_configuration(self):
        self.save('mass-notifications.config',{'live_paging':{'enabled':'1'},'secret':'do not read'})
        self.assertTrue(self.check.inspect()['ok'])
    def test_fresh_missing_state_allowed_but_installed_missing_ledger_refused(self):
        (self.data/'phone-admission.json').unlink()
        with self.assertRaisesRegex(m.IdleError,'missing'):self.check.inspect()
        self.module.unlink();(self.data/'audio-reservations.lock').unlink();self.data.rmdir()
        report=self.check.inspect()
        self.assertFalse(report['phone_collector_required']);self.assertEqual(report['phone_history'],{})
    def test_genuine_legacy_installation_without_any_collector_marker_can_upgrade(self):
        self.subsystem.unlink();(self.data/'phone-admission.json').unlink()
        report=self.check.inspect()
        self.assertTrue(report['installed']);self.assertFalse(report['phone_collector_required'])
        for marker in (self.base/'collector-unit',self.base/'runtime-collector'):
            marker.write_bytes(b'present modern subsystem')
            with self.assertRaisesRegex(m.IdleError,'missing'):self.check.inspect()
            marker.unlink()
    def test_installed_collector_requires_matching_boot_and_fresh_finite_heartbeat(self):
        for tick in (80,101,True,float('nan')):
            self.state['collector']['heartbeat_tick']=tick;self.save('phone-admission.json',self.state)
            with self.assertRaises(m.IdleError):self.check.inspect()
        self.state['collector']['heartbeat_tick']=99;self.state['collector']['boot_id']='old-boot';self.save('phone-admission.json',self.state)
        with self.assertRaisesRegex(m.IdleError,'identity'):self.check.inspect()
    def heartbeat(self, **changes):
        anchor = self.state['collector']
        pulse = {'schema': 1, 'generation': anchor['generation'], 'boot_id': anchor['boot_id'],
                 'anchor_tick': anchor['heartbeat_tick'], 'heartbeat_tick': 99}
        pulse.update(changes)
        path = self.save('phone-collector-heartbeat.json', pulse)
        os.chown(path, -1, m.pwd.getpwnam('asterisk').pw_gid)
        return path

    def test_fresh_bound_sidecar_accepts_old_anchor_without_changing_history(self):
        self.state['collector']['heartbeat_tick'] = 1
        ledger = self.save('phone-admission.json', self.state)
        pulse = self.heartbeat()
        before = [(p.read_bytes(), p.stat().st_ino, p.stat().st_mtime_ns) for p in (ledger, pulse)]
        baseline = self.baseline()
        self.assertTrue(self.check.inspect(baseline)['ok'])
        self.assertEqual(before, [(p.read_bytes(), p.stat().st_ino, p.stat().st_mtime_ns) for p in (ledger, pulse)])
        self.state['batches'][self.token]['closed_at'] = 4
        self.save('phone-admission.json', self.state)
        with self.assertRaisesRegex(m.IdleError, 'changed or disappeared'):
            self.check.inspect(baseline)

    def test_sidecar_requires_current_generation_boot_and_exact_numeric_anchor(self):
        self.state['collector']['heartbeat_tick'] = 1
        self.save('phone-admission.json', self.state)
        for changes in ({'generation': 'c'*32}, {'boot_id': 'previous-boot'},
                        {'anchor_tick': 2}, {'anchor_tick': True}, {'anchor_tick': '1'}):
            with self.subTest(changes=changes):
                self.heartbeat(**changes)
                with self.assertRaises(m.IdleError): self.check.inspect()

    def test_invalid_or_expired_sidecar_never_refreshes_collector(self):
        for tick in (80, 101, True, '99', None):
            with self.subTest(tick=tick):
                self.heartbeat(heartbeat_tick=tick)
                with self.assertRaises(m.IdleError): self.check.inspect()
        for changes in ({'schema': True}, {'schema': 2}, {'unexpected': 1}):
            self.heartbeat(**changes)
            with self.assertRaises(m.IdleError): self.check.inspect()
        path = self.heartbeat()
        for raw in ('{bad', '{"schema":1,"schema":1}', '{"heartbeat_tick":NaN}'):
            path.write_text(raw)
            with self.assertRaises(m.IdleError): self.check.inspect()

    def test_sidecar_from_previous_generation_can_use_fresh_legacy_anchor(self):
        self.heartbeat(generation='c'*32)
        self.assertTrue(self.check.inspect()['ok'])
        (self.data/'phone-collector-heartbeat.json').unlink()
        self.assertTrue(self.check.inspect()['ok'])

    def test_sidecar_rejects_unsafe_metadata_and_preserves_target(self):
        path = self.heartbeat(); body = path.read_bytes()
        for mode in (0o644, 0o660, 0o740):
            path.chmod(mode)
            with self.assertRaisesRegex(m.IdleError, 'permissions'): self.check.inspect()
        path.chmod(0o640)
        victim = self.base/'pulse-victim'; victim.write_bytes(body)
        for kind in ('symlink', 'hardlink', 'fifo'):
            path.unlink()
            if kind == 'symlink': path.symlink_to(victim)
            elif kind == 'hardlink': os.link(victim, path)
            else: os.mkfifo(path)
            with self.assertRaises((m.IdleError, OSError)): self.check.inspect()
            self.assertEqual(victim.read_bytes(), body)
        path.unlink(); path = self.heartbeat()
        with path.open('wb') as handle: handle.truncate(1025)
        with self.assertRaisesRegex(m.IdleError, 'oversized'): self.check.inspect()

    def test_manual_test_live_paging_phone_agi_and_supervisor_stop_installation(self):
        for args in (['bash','/usr/local/bin/sls_mass_notify/sls_mass_notify_test.sh'],['php','sls_mass_notify_live_paging.php'],['python3','sls_mass_notify_phone_agi.py'],['php','sls_mass_notify_announcement_worker.php','--supervise'],['php','sls_mass_notify_announcement_worker.php','job_'+'e'*32]):
            with self.subTest(args=args):
                self.process(args)
                with self.assertRaises(m.IdleError):self.check.inspect()
        self.process(['php','sls_mass_notify_announcement_worker.php','--health-check'])
        self.assertTrue(self.check.inspect()['ok'])
    def test_enterprise_supervisors_and_response_helpers_stop_installation_without_killing_them(self):
        executions = [
            ['php', '/usr/local/bin/sls_mass_notify/sls_mass_notify_cluster_worker.php', mode]
            for mode in ('--watch', '--edge-watch', '--once', '--edge-once', '--initialize', '--status')
        ]
        executions += [
            ['php', '/usr/local/bin/sls_mass_notify/sls_mass_notify_cluster_effect.php'],
            ['php', '/usr/local/bin/sls_mass_notify/sls_mass_notify_incident_response.php'],
        ]
        state = (self.data / 'phone-admission.json').read_bytes()
        for args in executions:
            with self.subTest(args=args):
                self.process(args)
                command = self.proc / '999999/cmdline'
                original = command.read_bytes()
                with self.assertRaisesRegex(m.IdleError, 'stop its external supervisor'):
                    self.check.inspect()
                self.assertEqual(command.read_bytes(), original)
                self.assertEqual((self.data / 'phone-admission.json').read_bytes(), state)
        self.process(['php', '/tmp/unrelated.php', '--watch'])
        self.assertTrue(self.check.inspect()['ok'])
    def test_pending_jobs_and_call_spools_are_not_deleted_to_make_idle(self):
        jobs=self.data/'announcement-jobs';jobs.mkdir();marker=jobs/('pending_job_'+'e'*32+'.mark');marker.touch()
        with self.assertRaisesRegex(m.IdleError,'queued'):self.check.inspect()
        self.assertTrue(marker.exists());marker.unlink()
        for spool in self.spools:
            call=spool/'sls_fixture.call';call.write_bytes(b'private call')
            with self.assertRaisesRegex(m.IdleError,'call files'):self.check.inspect()
            self.assertEqual(call.read_bytes(),b'private call');call.unlink()
    def test_reservations_require_expiry_and_malformed_timestamps_fail_closed(self):
        for state in ({'recipients':{'1000':1001},'media':{}}, {'recipients':{},'media':{},'waiting':{'a'*32:{'recipients':['1000'],'priority':1,'created':999,'expires':1001,'heartbeat':1001,'media_name':'fixture.wav','duration':1}}}, {'recipients':{'1000':'malformed'},'media':{}}, {'recipients':{},'media':{},'waiting':{'ticket':{}}}):
            self.save('audio-reservations.json',state)
            with self.assertRaises(m.IdleError):self.check.inspect()
        self.save('audio-reservations.json',{'recipients':{'1000':999},'media':{},'waiting':{}})
        self.assertTrue(self.check.inspect()['ok'])
    def test_active_sls_channels_refused_and_unrelated_calls_left_alone(self):
        self.channels='PJSIP/ordinary!'+'!'.join(['ordinary']*12)
        self.assertTrue(self.check.inspect()['ok'])
        self.channels='Local/1000@sls-phone-origin!'+'!'.join(['ordinary']*12)
        with self.assertRaisesRegex(m.IdleError,'channel is active'):self.check.inspect()
        self.channels='Asterisk failed to provide channel inventory'
        with self.assertRaisesRegex(m.IdleError,'unrecognized'):self.check.inspect()
    def test_links_special_files_and_unprotected_baseline_rejected_without_mutation(self):
        path=self.data/'phone-admission.json';body=path.read_bytes();path.unlink()
        victim=self.base/'victim';victim.write_bytes(body);victim.chmod(0o600)
        for kind in ('symlink','hardlink','fifo'):
            if kind=='symlink':path.symlink_to(victim)
            elif kind=='hardlink':os.link(victim,path)
            else:os.mkfifo(path)
            with self.assertRaises((m.IdleError,OSError)):self.check.inspect()
            self.assertEqual(victim.read_bytes(),body);self.assertEqual(victim.stat().st_mode & 0o777,0o600);path.unlink()
        path.write_bytes(body);path.chmod(0o640)
        baseline=self.baseline();baseline.chmod(0o644)
        with self.assertRaisesRegex(m.IdleError,'baseline mode'):self.check.inspect(baseline)
    def test_parent_symlink_and_oversized_state_rejected(self):
        alias=self.base/'alias';alias.symlink_to(self.data);self.check.data=alias
        with self.assertRaises(OSError):self.check.inspect()
        self.check.data=self.data
        path=self.data/'phone-admission.json'
        with path.open('wb') as handle:handle.truncate(m.MAX_STATE+1)
        with self.assertRaisesRegex(m.IdleError,'oversized'):self.check.inspect()
    def test_busy_state_and_inplace_change_fail_without_rewrites(self):
        import fcntl
        path=self.data/'phone-admission.json'
        with path.open('rb') as handle:
            fcntl.flock(handle,fcntl.LOCK_EX|fcntl.LOCK_NB)
            with self.assertRaisesRegex(m.IdleError,'busy'):self.check.inspect()
        original=m.os.read;changed=False;inode=path.stat().st_ino
        def mutate(fd,size):
            nonlocal changed
            body=original(fd,size)
            if not changed and os.fstat(fd).st_ino==inode:
                changed=True
                with path.open('ab') as output:output.write(b' ')
            return body
        with mock.patch.object(m.os,'read',side_effect=mutate):
            with self.assertRaisesRegex(m.IdleError,'changed'):self.check.inspect()

if __name__=='__main__':unittest.main()
