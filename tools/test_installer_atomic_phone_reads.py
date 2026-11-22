#!/usr/bin/python3
"""Regression for normal atomic publication while an unlocked reader opens."""
import importlib.util
import os
from pathlib import Path
import unittest
from unittest import mock
ROOT=Path(__file__).resolve().parents[1]
spec=importlib.util.spec_from_file_location('phone_read_fixture',ROOT/'tools/test_phone_admission.py')
fixture=importlib.util.module_from_spec(spec);spec.loader.exec_module(fixture)
phone=fixture.phone
class AtomicPhoneReads(unittest.TestCase):
    def setUp(self):
        self.fixture=fixture.PhoneAdmissionTests();self.fixture.setUp();self.addCleanup(self.fixture.tearDown)
    def read_during_publication(self,kind):
        store=self.fixture.store;real_open=phone.os.open;armed=True;committed=[]
        def interleaved_open(path,flags,*args,**kwargs):
            nonlocal armed
            fd=real_open(path,flags,*args,**kwargs)
            if path=='phone-admission.json' and armed:
                armed=False
                current=self.fixture.contents()
                token=store.admit(self.fixture.targets,25,{'complete':True,'started_tick':self.fixture.now,
                    'generation':current['collector']['generation'],'boot_id':store.boot_id,'channels':[]},service='manual')
                committed.append(token)
                self.assertEqual(os.fstat(fd).st_nlink,0)
            return fd
        with mock.patch.object(phone.os,'open',side_effect=interleaved_open):
            try:
                value=store._ledger_revision() if kind=='revision' else phone.read_private_json('phone-admission.json',self.fixture.root)
            except phone.PhoneAdmissionError as error:
                self.fail('A normal atomic ledger publication must not interrupt a reader: '+str(error))
        self.assertEqual(len(committed),1)
        if kind=='revision': self.assertEqual(value[1],(self.fixture.root/'phone-admission.json').stat().st_ino)
        else: self.assertIn(committed[0],value['batches'])
    def test_revision_reader_reopens_after_normal_publication(self):
        self.read_during_publication('revision')
    def test_json_reader_reopens_after_normal_publication(self):
        self.read_during_publication('json')
    def test_current_hardlinked_ledger_remains_rejected(self):
        path=self.fixture.root/'phone-admission.json';other=self.fixture.root/'untrusted-link';os.link(path,other)
        for reader in (self.fixture.store._ledger_revision,lambda:phone.read_private_json(path.name,self.fixture.root)):
            with self.assertRaisesRegex(phone.PhoneAdmissionError,'phone_config_unsafe'):reader()
        self.assertTrue(other.exists())
if __name__=='__main__':unittest.main()
