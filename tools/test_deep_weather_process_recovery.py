#!/usr/bin/python3
"""Real retry journal/process leases; every transport is an inert private marker."""
from datetime import datetime, timezone
import importlib.util
import json
import multiprocessing
import os
from pathlib import Path
import signal
import sys
import tempfile
import unittest
from unittest import mock

if os.environ.get('SLS_TEST_NAMESPACE') != 'entered':
    raise SystemExit('Run only through the isolated test wrapper.')
sys.dont_write_bytecode = True
RUNTIME = Path(__file__).resolve().parents[1]/'slsmassnotifyserver/bin/sls_mass_notify'
sys.path.insert(0,str(RUNTIME))
spec=importlib.util.spec_from_file_location('deep_weather_process',RUNTIME/'sls_notification_destinations.py')
weather=importlib.util.module_from_spec(spec);spec.loader.exec_module(weather)


def worker(directory,settings,clock,label,started=None,release=None):
    root=Path(directory)
    def email(*args):
        line=json.dumps({'worker':label,'subject':args[1],'recipients':args[-1]},sort_keys=True).encode()+b'\n'
        descriptor=os.open(root/'effects.jsonl',os.O_CREAT|os.O_WRONLY|os.O_APPEND,0o600)
        try:
            if os.write(descriptor,line)!=len(line):raise RuntimeError('private effect marker short write')
            os.fsync(descriptor)
        finally:os.close(descriptor)
        if started is not None:started.set()
        if release is not None and not release.wait(8):raise RuntimeError('private worker barrier timed out')
        return True
    with mock.patch.object(weather.time,'time',return_value=clock):
        result=weather.retry_external_deliveries(root/'external-deliveries-north.json',settings,'nws',live=True,
            email_sender=email,webhook_dispatcher=lambda *args,**kwargs:[])
    (root/('result-'+label+'.json')).write_text(json.dumps(result))


class WeatherProcessRecovery(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory(prefix='sls-weather-process-recovery-');self.addCleanup(self.temp.cleanup)
        self.root=Path(self.temp.name);self.context=multiprocessing.get_context('fork');self.children=[]
        self.addCleanup(self.stop_children)
        self.path=self.root/'external-deliveries-north.json'
        self.settings={'enabled':'1','discord_webhooks':[],'generic_webhooks':[],'nws_zones':[
            {'id':'north','name':'North','zone':'TXC491','email_recipients':['private@example.invalid'],
             'discord_webhook_ids':[],'generic_webhook_ids':[],'quiet_hours_enabled':'0','quiet_critical_events':[]}]}
        self.feature={'id':'private-alert','properties':{'event':'Heat Advisory','status':'Actual','messageType':'Alert',
            'expires':datetime.fromtimestamp(3000,timezone.utc).isoformat()}}
        self.validity=weather.weather_source_validity('nws','north',feature=self.feature,
            chain_key='Heat Advisory|private-alert',zone='TXC491',observed_at=1000)
        self.observe(True)

    def stop_children(self):
        for child in self.children:
            if child.is_alive():child.kill()
            child.join(timeout=2)
            if child.is_alive():raise AssertionError('private recovery fixture left child alive')

    def observe(self,active,clock=1100):
        path=self.root/'weather-delivery.json'
        path.write_text(json.dumps({'snapshots':{'north':{'zone':'TXC491','observed_at':clock,
            'active':{self.validity['chain_key']:self.feature}if active else{}}}}));path.chmod(0o640)

    def queue(self,correlation='first'):
        return weather.queue_external_delivery(self.path,self.settings,correlation,correlation,'Private synthetic recovery evidence',
            event='Heat Advisory',source='nws',email_recipients='private@example.invalid',now=1000,source_validity=self.validity)

    def start(self,label,clock=1100,started=None,release=None):
        child=self.context.Process(target=worker,args=(str(self.root),self.settings,clock,label,started,release))
        child.start();self.children.append(child);return child

    def finish(self,child,code=0):
        child.join(timeout=5);self.assertFalse(child.is_alive(),'isolated retry worker exceeded bound');self.assertEqual(child.exitcode,code)

    def effects(self):
        path=self.root/'effects.jsonl';return[json.loads(line)for line in path.read_text().splitlines()]if path.exists()else[]

    def state(self,key):return json.loads(self.path.read_text())['deliveries'][key]

    def block_first(self):
        started=self.context.Event();release=self.context.Event();child=self.start('original',started=started,release=release)
        self.assertTrue(started.wait(3),'original fake transport did not cross durable intent boundary')
        return child,release

    def test_six_concurrent_workers_do_not_replay_an_active_effect(self):
        key=self.queue();first,release=self.block_first()
        token=self.state(key)['worker_claim'];self.assertTrue(self.state(key)['email_inflight'])
        contenders=[self.start('contender-'+str(i))for i in range(6)]
        for child in contenders:self.finish(child)
        self.assertEqual(len(self.effects()),1);self.assertEqual(self.state(key)['worker_claim'],token)
        release.set();self.finish(first)
        self.assertEqual(self.state(key)['destination_receipts']['email:email']['status'],'accepted')
        self.finish(self.start('after-complete'));self.assertEqual(len(self.effects()),1)

    def test_unrelated_record_progresses_while_first_transport_is_blocked(self):
        first_key=self.queue('first');first,release=self.block_first();second_key=self.queue('second')
        other=self.start('independent');self.finish(other)
        self.assertEqual({row['subject']for row in self.effects()},{'first','second'})
        self.assertTrue(self.state(first_key)['email_inflight']);self.assertTrue(self.state(second_key)['completed_at'])
        release.set();self.finish(first)
        self.assertEqual(len(self.effects()),2)

    def test_sigkill_and_clock_rollback_keep_uncertain_effect_unreplayable(self):
        key=self.queue();first,release=self.block_first()
        os.kill(first.pid,signal.SIGKILL);self.finish(first,-signal.SIGKILL)
        original=self.state(key);self.assertTrue(original['email_inflight']);self.assertFalse(original.get('email_uncertain'))
        self.finish(self.start('rollback',clock=1000));self.assertEqual(len(self.effects()),1)
        self.assertEqual(self.state(key)['worker_claim'],original['worker_claim'])
        self.observe(True,clock=1221)
        self.finish(self.start('recover',clock=1221))
        recovered=self.state(key);self.assertFalse(recovered['email_inflight']);self.assertFalse(recovered['email_pending'])
        self.assertEqual(recovered['email_uncertain']['status'],'uncertain')
        self.assertEqual(recovered['terminal_status'],'uncertain');self.assertEqual(len(self.effects()),1)
        self.finish(self.start('after-recovery',clock=1222));self.assertEqual(len(self.effects()),1)

    def test_fully_accepted_effect_survives_source_cancellation_and_reappearance(self):
        key=self.queue();first,release=self.block_first();self.observe(False)
        release.set();self.finish(first)
        record=self.state(key);self.assertEqual(record['destination_receipts']['email:email']['status'],'accepted')
        # The one original channel already crossed the acceptance boundary;
        # cancellation cannot undo it and no later unsent channel exists.
        self.assertEqual(record['terminal_status'],'complete');self.assertEqual(len(self.effects()),1)
        self.observe(True,clock=1101);self.finish(self.start('source-returned',clock=1101))
        self.assertEqual(len(self.effects()),1);self.assertEqual(self.state(key)['terminal_status'],'complete')


if __name__=='__main__':unittest.main()
