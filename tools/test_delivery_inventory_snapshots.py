#!/usr/bin/python3
"""Real private JSON writers and summary readers; no PBX, mail or service calls."""
import json
import os
from pathlib import Path
import pwd
import subprocess
import sys
import tempfile
import unittest


for label, kind in [('MOUNT', 'mnt'), ('NET', 'net'), ('PID', 'pid')]:
    if (os.environ.get('SLS_TEST_NAMESPACE') != 'entered'
            or os.environ.get('SLS_TEST_PARENT_' + label + '_NS')
            in (None, '', os.readlink('/proc/self/ns/' + kind))):
        raise SystemExit('Fresh private namespaces required; no product helpers ran.')

PRELUDE = r'''
import contextlib, fcntl, io, json, os, select, stat, subprocess, sys, time
from pathlib import Path
from unittest import mock
sys.dont_write_bytecode = True
sys.path.insert(0, '/usr/local/bin/sls_mass_notify')
import sls_storage_maintenance as storage
root=Path(sys.argv[1]);data=root/'data';data.mkdir(mode=0o750)
storage.WEB=root/'web';storage.WEB.mkdir(mode=0o755)
(data/'mass-notifications.config').write_text('{}')
(data/'mass-notifications.config').chmod(0o640)
now=1800000000
def write(name, value):
    target=data/name;target.write_text(json.dumps(value));target.chmod(0o640);return target
def summary():return storage.storage_summary(data,now)
def emit(value):print(json.dumps(value),flush=True)
'''

WRITER = r'''
import json,os,select,sys
from pathlib import Path
sys.dont_write_bytecode=True
sys.path.insert(0,'/usr/local/bin/sls_mass_notify')
target=Path(sys.argv[1]);kind=sys.argv[2]
def await_commit():
    print('WRITER_READY',flush=True)
    if not select.select([sys.stdin],[],[],5)[0] or sys.stdin.readline()!='commit\n':
        raise RuntimeError('Private summary did not release the bounded writer')
if kind.startswith('audit:'):
    from unittest import mock
    import sls_storage_maintenance as storage
    _,security,forwarding=kind.split(':');real_replace=os.replace
    def paused_replace(*args,**kwargs):
        await_commit();return real_replace(*args,**kwargs)
    with mock.patch.object(os,'replace',side_effect=paused_replace):
        assert storage.record_audit_health(target.parent,'audit_fixture_failure',security=security=='1',forwarding=forwarding=='1')
    raise SystemExit(0)
if kind=='weather':
    import sls_weather_queue as weather
    lease=weather.state_lock(target.parent)
else:
    import sls_notification_destinations as external
    lease=external._locked_retry_state(target)
with lease as value:
    if kind=='weather':
        value['dispatch_metrics']={'updated_at':1800000000,'max_workers':2,'running':0,
            'oldest_queued_age_seconds':0,'oldest_running_age_seconds':0,'deadline_misses':0}
    else:
        value=external._load_retry_state(target)
        value['attempt_sequence']+=1
    await_commit()
    if kind!='weather':external._write_retry_state(target,value)
'''


class DeliveryInventorySnapshots(unittest.TestCase):
    def native(self, body, timeout=15):
        account=pwd.getpwnam('asterisk')
        with tempfile.TemporaryDirectory(prefix='sls-summary-fixture-') as name:
            root=Path(name);root.chmod(0o750);os.chown(root,account.pw_uid,account.pw_gid)
            result=subprocess.run(['/usr/sbin/runuser','-u','asterisk','--','/usr/bin/python3','-I','-c',PRELUDE+body,str(root)],
                capture_output=True,text=True,timeout=timeout)
            self.assertEqual(result.returncode,0,result.stderr)
            return json.loads(result.stdout),result.stderr

    def raced_summary(self, kind):
        # Removing proper snapshot coordination must reproduce the original
        # false inventory fault using a real production atomic writer.
        body=r'''
kind=KIND
target=write('weather-delivery.json',{'schema':1,'jobs':{},'snapshots':{}}) if kind=='weather' else write('external-deliveries-fixture.json',{'version':1,'attempt_sequence':0,'deliveries':{}})
before=target.stat().st_ino
writer=subprocess.Popen([sys.executable,'-I','-c',__WRITER_BODY__,str(target),kind],stdin=subprocess.PIPE,
    stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True)
real_flock=fcntl.flock;released=[]
try:
    assert select.select([writer.stdout],[],[],5)[0], 'Writer did not become ready'
    assert writer.stdout.readline()=='WRITER_READY\n'
    def synchronized(fd, operation):
        descriptor=fd if isinstance(fd,int) else fd.fileno()
        path=os.readlink('/proc/self/fd/'+str(descriptor))
        if not released and (path==str(target) or path==str(target)+'.lock' or path==str(data/'weather-delivery.lock')):
            released.append(True);writer.stdin.write('commit\n');writer.stdin.flush();writer.stdin.close();writer.stdin=None
            out,err=writer.communicate(timeout=5)
            assert writer.returncode==0,err
        return real_flock(fd,operation)
    with mock.patch.object(fcntl,'flock',side_effect=synchronized):observed=summary()
    assert released, 'Summary never inspected the actual source'
    assert target.stat().st_ino!=before, 'Production writer did not replace the inode'
    emit(observed)
finally:
    if writer.poll() is None:writer.kill();writer.wait(timeout=2)
'''.replace('KIND',repr(kind)).replace('__WRITER_BODY__',repr(WRITER))
        return self.native(body)

    def test_actual_weather_atomic_commit_does_not_become_external_inventory_fault(self):
        result,_=self.raced_summary('weather')
        self.assertEqual(result['queue_errors'],0)
        self.assertFalse(result['queue_scan_incomplete'])
        self.assertFalse(result.get('weather_scan_incomplete'))
        self.assertEqual(result.get('inspection_issues'),[])

    def test_actual_external_outbox_atomic_commit_has_complete_counts(self):
        result,_=self.raced_summary('external')
        self.assertEqual(result['queue_errors'],0)
        self.assertFalse(result['queue_scan_incomplete'])
        self.assertEqual(result['queue_files_scanned'],1)
        self.assertEqual(result.get('inspection_issues'),[])

    def test_actual_audit_health_atomic_commits_keep_current_fault_and_history(self):
        for security in (False,True):
            for forwarding in (False,True):
                with self.subTest(security=security,forwarding=forwarding):
                    result,_=self.native(r'''
security=SECURITY;forwarding=FORWARDING
write('mass-notifications.config',{'control_api':{'audit_syslog':'1'}})
stem=('security-audit' if security else 'control-api-audit')+('-forwarding' if forwarding else '-fault')
target=write(stem+'.json',{'active':False,'failed_records':0,'error_code':''})
before=target.stat().st_ino
writer=subprocess.Popen([sys.executable,'-I','-c',__WRITER_BODY__,str(target),'audit:'+str(int(security))+':'+str(int(forwarding))],
    stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True)
real_flock=fcntl.flock;released=[]
try:
    assert select.select([writer.stdout],[],[],5)[0]
    assert writer.stdout.readline()=='WRITER_READY\n'
    def synchronized(fd,operation):
        descriptor=fd if isinstance(fd,int) else fd.fileno()
        path=os.readlink('/proc/self/fd/'+str(descriptor))
        if not released and path in (str(target),str(data/(stem+'.lock'))):
            released.append(True);writer.stdin.write('commit\n');writer.stdin.flush();writer.stdin.close();writer.stdin=None
            out,err=writer.communicate(timeout=5);assert writer.returncode==0,err
        return real_flock(fd,operation)
    with mock.patch.object(fcntl,'flock',side_effect=synchronized):value=summary()
    assert released and target.stat().st_ino!=before
    emit(value)
finally:
    if writer.poll() is None:writer.kill();writer.wait(timeout=2)
'''.replace('SECURITY',repr(security)).replace('FORWARDING',repr(forwarding)).replace('__WRITER_BODY__',repr(WRITER)))
                    prefix=('security_audit_' if security else 'audit_')+('forwarding_' if forwarding else '')
                    self.assertEqual(result['queue_errors'],0)
                    self.assertEqual(result['inspection_issues'],[])
                    self.assertTrue(result[prefix+('active' if forwarding else 'fault_active')])
                    self.assertEqual(result[prefix+'failed_records'],1)
                    self.assertEqual(result[prefix+('error' if forwarding else 'failure_code')],'audit_fixture_failure')

    def test_real_inode_lock_contention_remains_bounded_and_unknown(self):
        result,log=self.native(r'''
target=write('external-deliveries-fixture.json',{'version':1,'deliveries':{}})
with target.open('r+b') as held:
    fcntl.flock(held,fcntl.LOCK_EX);started=time.monotonic();value=summary();elapsed=time.monotonic()-started
emit({'summary':value,'elapsed':elapsed})
''')
        self.assertLess(result['elapsed'],3.5)
        self.assertEqual(result['summary']['queue_errors'],1)
        self.assertTrue(result['summary']['queue_scan_incomplete'])
        self.assertIn({'component':'external','code':'snapshot_busy'},result['summary'].get('inspection_issues',[]))
        self.assertIn('external',log)
        self.assertNotIn('external-deliveries-fixture.json',log)

    def test_weather_corruption_is_attributed_without_external_error(self):
        result,log=self.native("(data/'weather-delivery.json').write_text('{secret-provider-payload');emit(summary())")
        self.assertEqual(result['queue_errors'],0)
        self.assertTrue(result.get('weather_scan_incomplete'))
        self.assertIn({'component':'weather','code':'invalid'},result.get('inspection_issues',[]))
        self.assertNotIn('secret-provider-payload',log)

    def test_missing_inventory_collections_cannot_claim_empty_success(self):
        for name, component, flag in (
                ('external-deliveries-fixture.json', 'external', 'queue_scan_incomplete'),
                ('weather-delivery.json', 'weather', 'weather_scan_incomplete')):
            with self.subTest(component=component):
                result,_=self.native('write('+repr(name)+',{});emit(summary())')
                self.assertTrue(result[flag])
                self.assertIn({'component':component,'code':'invalid'},result['inspection_issues'])

    def test_both_audit_inspection_failures_keep_real_fault_flags(self):
        result,_=self.native(r'''
(data/'control-api-audit-fault.json').write_text('{broken')
(data/'security-audit-fault.json').write_text('{broken')
emit(summary())
''')
        self.assertEqual(result['queue_errors'],0)
        self.assertTrue(result['audit_fault_active'])
        self.assertTrue(result['security_audit_fault_active'])
        self.assertIn({'component':'control_audit','code':'invalid'},result.get('inspection_issues',[]))
        self.assertIn({'component':'security_audit','code':'invalid'},result.get('inspection_issues',[]))

    def test_external_invalid_json_and_duplicate_keys_remain_real_faults(self):
        for payload in ('{broken','{"deliveries":{},"deliveries":{}}','{"deliveries":NaN}'):
            with self.subTest(payload=payload):
                result,_=self.native("(data/'external-deliveries-fixture.json').write_text("+repr(payload)+");emit(summary())")
                self.assertEqual(result['queue_errors'],1)
                self.assertTrue(result['queue_scan_incomplete'])
                self.assertIn({'component':'external','code':'invalid'},result.get('inspection_issues',[]))

    def test_external_unsafe_targets_preserve_victim_and_are_never_healthy(self):
        for kind in ('symlink','hardlink','fifo'):
            with self.subTest(kind=kind):
                result,_=self.native(r'''
victim=write('victim',{'deliveries':{}});before=victim.read_bytes();target=data/'external-deliveries-fixture.json'
kind=KIND
if kind=='symlink':target.symlink_to(victim)
elif kind=='hardlink':os.link(victim,target)
else:os.mkfifo(target,0o640)
value=summary();emit({'summary':value,'victim_unchanged':before==victim.read_bytes()})
'''.replace('KIND',repr(kind)))
                self.assertTrue(result['victim_unchanged'])
                self.assertEqual(result['summary']['queue_errors'],1)
                self.assertIn({'component':'external','code':'unsafe'},result['summary'].get('inspection_issues',[]))

    def test_optional_absence_does_not_create_writer_mutexes(self):
        result,_=self.native("before=set(data.iterdir());value=summary();emit({'summary':value,'created':sorted(p.name for p in set(data.iterdir())-before)})")
        self.assertEqual(result['created'],['storage-summary.json'])
        self.assertEqual(result['summary'].get('inspection_issues'),[])
        self.assertFalse(result['summary'].get('weather_scan_incomplete'))

    def test_read_only_weather_inspection_does_not_establish_missing_history(self):
        result,_=self.native(r'''
import sls_weather_queue as weather
with weather.state_lock(data,write=False) as state:
    assert state['jobs']=={}
assert (data/'weather-delivery.lock').read_bytes()==b''
assert not (data/'weather-delivery.json').exists()
emit(summary())
''')
        self.assertFalse(result['weather_scan_incomplete'])
        self.assertEqual(result['inspection_issues'],[])

    def test_established_missing_weather_history_is_unknown(self):
        result,_=self.native("(data/'weather-delivery.lock').write_bytes(b'SLS_WEATHER_OUTBOX_V1\\n');emit(summary())")
        self.assertEqual(result['queue_errors'],0)
        self.assertTrue(result.get('weather_scan_incomplete'))
        self.assertIn({'component':'weather','code':'unreadable'},result.get('inspection_issues',[]))

    def test_initialized_external_marker_cannot_hide_missing_queue_as_empty(self):
        result,_=self.native(r'''
import sls_atomic_json as atomic
target=data/'external-deliveries-fixture.json'
with atomic.locked_json(target,runtime_owner=True) as value:value['deliveries']={}
assert (data/(target.name+'.lock')).read_bytes()==b'SLS_JSON_V1\n'
target.unlink()
emit(summary())
''')
        self.assertEqual(result['queue_errors'],1)
        self.assertTrue(result['queue_scan_incomplete'])
        self.assertIn({'component':'external','code':'unreadable'},result['inspection_issues'])

    def test_uninitialized_external_mutex_is_not_delivery_loss(self):
        result,_=self.native(r'''
(data/'external-deliveries-fixture.json.lock').write_bytes(b'')
emit(summary())
''')
        self.assertEqual(result['queue_errors'],0)
        self.assertFalse(result['queue_scan_incomplete'])
        self.assertEqual(result['queue_files_scanned'],0)

    def test_queue_scan_limits_stay_explicit(self):
        result,_=self.native(r'''
for index in range(5):write('external-deliveries-'+str(index)+'.json',{'deliveries':{}})
with mock.patch.object(storage,'MAX_QUEUE_FILES',3):emit(summary())
''')
        self.assertTrue(result['queue_scan_incomplete'])
        self.assertEqual(result['queue_files_scanned'],3)
        self.assertIn({'component':'external','code':'scan_limit'},result.get('inspection_issues',[]))

    def test_persistent_read_permission_failure_is_not_transient(self):
        result,_=self.native("target=write('external-deliveries-fixture.json',{'deliveries':{}});target.chmod(0);emit(summary())")
        self.assertEqual(result['queue_errors'],1)
        self.assertIn({'component':'external','code':'unreadable'},result.get('inspection_issues',[]))

    def test_legacy_atomic_replacement_retries_but_preserves_retention_reader(self):
        result,_=self.native(r'''
target=write('external-deliveries-fixture.json',{'deliveries':{}})
real_flock=fcntl.flock;replaced=[]
def replace_once(fd,operation):
    descriptor=fd if isinstance(fd,int) else fd.fileno()
    if not replaced and os.readlink('/proc/self/fd/'+str(descriptor))==str(target):
        replaced.append(True)
        replacement=write('replacement',{'deliveries':{'pending':{'created_at':now-30,'email_pending':True}}})
        os.replace(replacement,target)
    return real_flock(fd,operation)
with mock.patch.object(fcntl,'flock',side_effect=replace_once):value=summary()
assert replaced
replaced.clear();parent=storage.open_directory(data)
try:
    with mock.patch.object(fcntl,'flock',side_effect=replace_once):
        try:storage.read_at(parent,target.name,4096)
        except RuntimeError:retention_rejected=True
        else:retention_rejected=False
finally:os.close(parent)
emit({'summary':value,'retention_rejected':retention_rejected})
''')
        self.assertEqual(result['summary']['queue_errors'],0)
        self.assertEqual(result['summary']['pending_external'],1)
        self.assertEqual(result['summary']['oldest_pending_at'],1800000000-30)
        self.assertEqual(result['summary']['inspection_issues'],[])
        self.assertTrue(result['retention_rejected'])

    def test_repeated_atomic_changes_remain_unknown_after_bounded_retries(self):
        result,_=self.native(r'''
target=write('external-deliveries-fixture.json',{'deliveries':{}})
real_flock=fcntl.flock;replacements=[]
def replace_each(fd,operation):
    descriptor=fd if isinstance(fd,int) else fd.fileno()
    if os.readlink('/proc/self/fd/'+str(descriptor))==str(target):
        replacements.append(True);os.replace(write('replacement',{'deliveries':{}}),target)
    return real_flock(fd,operation)
started=time.monotonic()
with mock.patch.object(fcntl,'flock',side_effect=replace_each):value=summary()
emit({'summary':value,'replacements':len(replacements),'elapsed':time.monotonic()-started})
''')
        self.assertEqual(result['replacements'],3)
        self.assertLess(result['elapsed'],3.5)
        self.assertEqual(result['summary']['queue_errors'],1)
        self.assertIn({'component':'external','code':'snapshot_changed'},result['summary']['inspection_issues'])

    def test_disappearing_established_optional_source_is_not_empty_success(self):
        result,_=self.native(r'''
target=write('weather-delivery.json',{'jobs':{}});real_flock=fcntl.flock;removed=[]
def remove_once(fd,operation):
    descriptor=fd if isinstance(fd,int) else fd.fileno()
    if not removed and os.readlink('/proc/self/fd/'+str(descriptor))==str(target):
        removed.append(True);target.unlink()
    return real_flock(fd,operation)
with mock.patch.object(fcntl,'flock',side_effect=remove_once):value=summary()
assert removed
emit(value)
''')
        self.assertEqual(result['queue_errors'],0)
        self.assertTrue(result['weather_scan_incomplete'])
        self.assertIn({'component':'weather','code':'unreadable'},result['inspection_issues'])

    def test_actual_writer_mutex_contention_does_not_read_unknown_state(self):
        result,_=self.native(r'''
target=write('external-deliveries-fixture.json',{'deliveries':{}})
lock=data/(target.name+'.lock');lock.write_bytes(b'SLS_JSON_V1\n');lock.chmod(0o640)
with lock.open('rb') as held:
    fcntl.flock(held,fcntl.LOCK_EX);started=time.monotonic();value=summary();elapsed=time.monotonic()-started
emit({'summary':value,'elapsed':elapsed})
''')
        self.assertLess(result['elapsed'],3.5)
        self.assertEqual(result['summary']['queue_errors'],1)
        self.assertIn({'component':'external','code':'snapshot_busy'},result['summary']['inspection_issues'])

    def test_retry_bytes_count_against_original_scan_budget(self):
        result,_=self.native(r'''
target=write('external-deliveries-fixture.json',{'deliveries':{}})
size=target.stat().st_size;real_flock=fcntl.flock;real_read=os.read;replaced=[];read_sizes=[]
def replace_once(fd,operation):
    descriptor=fd if isinstance(fd,int) else fd.fileno()
    if not replaced and os.readlink('/proc/self/fd/'+str(descriptor))==str(target):
        replaced.append(True);os.replace(write('replacement',{'deliveries':{}}),target)
    return real_flock(fd,operation)
def count_reads(fd,maximum):
    raw=real_read(fd,maximum)
    if os.readlink('/proc/self/fd/'+str(fd)).startswith(str(target)):read_sizes.append(len(raw))
    return raw
with mock.patch.object(storage,'MAX_REFERENCE_BYTES',size+size//2),mock.patch.object(fcntl,'flock',side_effect=replace_once),mock.patch.object(os,'read',side_effect=count_reads):
    value=summary()
emit({'summary':value,'bytes_read':sum(read_sizes),'limit':size+size//2})
''')
        self.assertLessEqual(result['bytes_read'],result['limit'])
        self.assertEqual(result['summary']['queue_errors'],1)
        self.assertIn({'component':'external','code':'scan_limit'},result['summary']['inspection_issues'])

    def test_unsafe_mutex_is_not_repaired_or_treated_as_contention(self):
        for kind in ('symlink','hardlink','fifo','marker','permissions'):
            with self.subTest(kind=kind):
                result,_=self.native(r'''
target=write('external-deliveries-fixture.json',{'deliveries':{}});lock=data/(target.name+'.lock')
victim=write('victim',{});before=victim.read_bytes();kind=KIND
if kind=='symlink':lock.symlink_to(victim)
elif kind=='hardlink':os.link(victim,lock)
elif kind=='fifo':os.mkfifo(lock,0o640)
else:
    lock.write_bytes(b'incorrect marker' if kind=='marker' else b'SLS_JSON_V1\n')
    lock.chmod(0o666 if kind=='permissions' else 0o640)
before_mode=lock.lstat().st_mode;value=summary()
emit({'summary':value,'unchanged':victim.read_bytes()==before and lock.lstat().st_mode==before_mode})
'''.replace('KIND',repr(kind)))
                self.assertTrue(result['unchanged'])
                self.assertEqual(result['summary']['queue_errors'],1)
                self.assertIn({'component':'external','code':'unsafe'},result['summary']['inspection_issues'])

    def test_forwarding_inspection_failure_keeps_distinct_current_fault_flags(self):
        result,_=self.native(r'''
write('mass-notifications.config',{'control_api':{'audit_syslog':'1'}})
for name in ('control-api-audit-forwarding.json','security-audit-forwarding.json'):(data/name).write_text('{broken')
emit(summary())
''')
        self.assertEqual(result['queue_errors'],0)
        self.assertTrue(result['audit_forwarding_active'])
        self.assertEqual(result['audit_forwarding_error'],'audit_forwarding_health_unavailable')
        self.assertTrue(result['security_audit_forwarding_active'])
        self.assertEqual(result['security_audit_forwarding_error'],'audit_health_unavailable')
        self.assertIn({'component':'control_audit','code':'invalid'},result['inspection_issues'])
        self.assertIn({'component':'security_audit','code':'invalid'},result['inspection_issues'])

    def test_real_audit_failures_and_successful_recovery_preserve_history(self):
        result,_=self.native(r'''
write('mass-notifications.config',{'control_api':{'audit_syslog':'1'}})
for security in (False,True):
    for forwarding in (False,True):
        assert storage.record_audit_health(data,'audit_fixture_failure',forwarding=forwarding,security=security)
failed=summary()
for security in (False,True):
    for forwarding in (False,True):
        assert storage.record_audit_health(data,forwarding=forwarding,security=security)
emit({'failed':failed,'recovered':summary()})
''')
        for prefix,active in [('audit_','fault_active'),('audit_forwarding_','active'),('security_audit_','fault_active'),('security_audit_forwarding_','active')]:
            self.assertTrue(result['failed'][prefix+active])
            self.assertFalse(result['recovered'][prefix+active])
            self.assertEqual(result['recovered'][prefix+'failed_records'],1)
        self.assertEqual(result['failed']['inspection_issues'],[])
        self.assertEqual(result['recovered']['inspection_issues'],[])

    def test_repeated_faults_have_bounded_sanitized_diagnostics(self):
        result,log=self.native(r'''
for index in range(70):(data/('external-deliveries-secret-'+str(index)+'.json')).write_text('{private-body')
emit(summary())
''')
        self.assertEqual(result['queue_errors'],70)
        self.assertEqual(result['inspection_issues'],[{'component':'external','code':'invalid'}])
        self.assertEqual(log.count('Storage inspection external: invalid.'),1)
        self.assertNotIn('secret-',log)
        self.assertNotIn('private-body',log)

    def test_native_summary_to_notification_reports_corruption_without_replaying_mail(self):
        result,_=self.native(r'''
import datetime
import sls_system_notifications as notifications
write('mass-notifications.config',{'enabled':'0','generated_media_cache_mib':64,'generated_media_min_free_mib':64})
worker={'ok':True,'checked_at':datetime.datetime.fromtimestamp(now,datetime.timezone.utc).isoformat()}
config={'system_notification_emails':'fixture@example.invalid'};calls=[]
def sender(*args,**kwargs):calls.append(args);return True
state=data/'private-email-state.json'
healthy=notifications.collect_health_faults(worker,summary(),now=now)
first=notifications.process_faults(config,healthy,state,sender=sender,now=now)
target=data/'external-deliveries-fixture.json';target.write_text('{corrupt-private-queue')
faults=notifications.collect_health_faults(worker,summary(),now=now)
second=notifications.process_faults(config,faults,state,sender=sender,now=now)
third=notifications.process_faults(config,faults,state,sender=sender,now=now+60)
emit({'healthy':first,'healthy_faults':healthy,'corrupt':second,'repeat':third,'calls':len(calls),
      'safe_body':all('corrupt-private-queue' not in args[2] for args in calls)})
''')
        self.assertEqual(result['healthy'],{'sent':0,'active':0},result['healthy_faults'])
        self.assertEqual(result['corrupt'],{'sent':1,'active':1})
        self.assertEqual(result['repeat'],{'sent':0,'active':1})
        self.assertEqual(result['calls'],1)
        self.assertTrue(result['safe_body'])


if __name__=='__main__':unittest.main()
