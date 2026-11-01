#!/usr/bin/python3
"""Current/frozen NWS phone authority; pure synthetic queue/group snapshots."""
from contextlib import contextmanager
import importlib.util
import os
from pathlib import Path
import sys
import unittest
from unittest import mock

if os.environ.get('SLS_TEST_NAMESPACE')!='entered':raise SystemExit('Use the isolated wrapper.')
sys.dont_write_bytecode=True
RUNTIME=Path(__file__).resolve().parents[1]/'slsmassnotifyserver/bin/sls_mass_notify'
sys.path.insert(0,str(RUNTIME))
spec=importlib.util.spec_from_file_location('deep_nws_current_phone',RUNTIME/'sls_weather_queue.py')
queue=importlib.util.module_from_spec(spec);spec.loader.exec_module(queue)


class CurrentPhone(unittest.TestCase):
    def check(self,current,recipient,original=None,quiet=False):
        job={'state':'running','service':'nws','group_id':'north','deadline_at':2000,
            'payload':{'zone':'TXC491','feature':{'properties':{'event':'Heat Advisory'}},
                'routing_snapshot':{'phones':['1001'] if original is None else original}}}
        @contextmanager
        def state(*args,**kwargs):yield {'jobs':{'synthetic':job}}
        row=['north','North','TXC491',','.join(current),'','', '0','21:00','06:00','','']
        with mock.patch.object(queue,'state_lock',side_effect=state),\
             mock.patch.object(queue,'valid_nws',return_value=True),\
             mock.patch.object(queue,'groups',return_value={'north':row}),\
             mock.patch.object(queue.time,'time',return_value=1100):
            return queue.check_job('synthetic',phone_recipient=recipient)

    def test_original_phone_still_selected_is_permitted(self):
        self.assertTrue(self.check(['1001'],'1001'))
    def test_removed_original_phone_cannot_use_valid_source_to_submit(self):
        self.assertFalse(self.check(['1002'],'1001'))
    def test_new_phone_cannot_expand_original_audience(self):
        self.assertFalse(self.check(['1001','1002'],'1002'))
    def test_one_removed_phone_does_not_cancel_an_independently_allowed_phone(self):
        self.assertTrue(self.check(['1002'],'1002',original=['1001','1002']))
    def test_legacy_numeric_original_identity_preserves_existing_dispatch_normalization(self):
        self.assertTrue(self.check(['1001'],'1001',original=[1001]))
    def test_malformed_or_missing_original_phone_binding_fails_closed(self):
        for recipient,original in [('1001',[]),('1001','1001'),('1/../x',['1001']),('', ['1001']), (True,['1001'])]:
            with self.subTest(recipient=recipient,original=original):
                self.assertFalse(self.check(['1001'],recipient,original=original))


if __name__=='__main__':unittest.main()
