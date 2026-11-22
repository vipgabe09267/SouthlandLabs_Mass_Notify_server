#!/usr/bin/python3
"""Isolated cache-crash and retained-publisher bootstrap regressions."""
import importlib.util
import io
import json
import os
from pathlib import Path
import re
import select
import shutil
import signal
import subprocess
import sys
import tarfile
import unittest

if os.environ.get('SLS_TEST_NAMESPACE') != 'entered':
    raise RuntimeError('Run only through tools/run_isolated_tests.sh')
ROOT=Path(__file__).resolve().parents[1]
BIN=ROOT/'slsmassnotifyserver/bin/sls_mass_notify'


def module(path, name):
    spec=importlib.util.spec_from_file_location(name,path)
    value=importlib.util.module_from_spec(spec);spec.loader.exec_module(value)
    return value


BOOTSTRAP_FIXTURE=module(ROOT/'tools/test_verified_bootstrap.py','v020_bootstrap_fixture')
STOCK_FIXTURE=module(ROOT/'tools/test_upgrade_trust.py','v020_cache_fixture')


class RetainedVerifierBootstrap(unittest.TestCase):
    def setUp(self):
        self.fixture=BOOTSTRAP_FIXTURE.VerifiedBootstrap(methodName='runTest')
        self.fixture.setUp();self.addCleanup(self.fixture.tearDown)
        f=self.fixture
        helpers=f.path/'retained-helpers';helpers.mkdir(mode=0o700)
        public=(f.path/'publisher.pem').read_bytes()
        contents={'module.xml':b'<module><rawname>slsmassnotifyserver</rawname><version>0.1.9-beta</version></module>'}
        for name in ('sls_release_trust.py','sls_module_trust.py'):
            body=(BIN/name).read_bytes()
            if name=='sls_module_trust.py':
                body,count=re.subn(rb'^PUBLIC_KEY = .*$',lambda unused:b'PUBLIC_KEY = '+repr(public).encode(),body,flags=re.M)
                self.assertEqual(count,1)
            (helpers/name).write_bytes(body);(helpers/name).chmod(0o600)
            contents['bin/sls_mass_notify/'+name]=body
        self.trust=module(helpers/'sls_module_trust.py','v020_retained_module_trust')
        self.publisher=module(helpers/'sls_release_trust.py','v020_retained_publisher')
        archive=f.path/'slsmassnotifyserver-0.1.9-beta.tgz'
        with tarfile.open(archive,'w:gz') as output:
            for name,body in contents.items():
                entry=tarfile.TarInfo('slsmassnotifyserver/'+name);entry.size=len(body);entry.mode=0o644
                output.addfile(entry,io.BytesIO(body))
        archive.chmod(0o600)
        f.manifest.update(tag='release-0.1.9-beta',package_sha256=self.trust.digest(archive.read_bytes()))
        f.sign()
        self.store=f.path/'trust'
        self.trust.enroll_sls(self.store,archive,f.path/'release-manifest.json',f.path/'release-manifest.sig')
        self.approved,self.generation=self.trust.load(self.store,'slsmassnotifyserver')
        self.missing=f.path/'removed-runtime'
        self.script=f.path/'retained-bootstrap.sh'
        self.script.write_text((ROOT/'tools/install_bootstrap.sh').read_text()
            .replace('/var/lib/sls-mass-notify-trust',str(self.store))
            .replace('/usr/local/bin/sls_mass_notify',str(self.missing)))
        self.before=(self.store/'slsmassnotifyserver.active.json').read_bytes()

    def verify(self):
        f=self.fixture
        return subprocess.run(['/bin/bash','-c',
            'source "$1"; bootstrap_verify "$2" 0.1.9-beta release-0.1.9-beta 1',
            'fixture',str(self.script),str(f.path)],capture_output=True,text=True,timeout=15)

    def assert_preserved(self):
        self.assertFalse(self.missing.exists())
        self.assertFalse(self.fixture.marker.exists())
        self.assertEqual((self.store/'slsmassnotifyserver.active.json').read_bytes(),self.before)

    def test_removed_runtime_uses_exact_retained_publisher_source_without_reenrollment(self):
        result=self.verify()
        self.assertEqual(result.returncode,0,result.stderr)
        self.assert_preserved()

    def test_retained_verifier_still_enforces_initialized_policy_revocation(self):
        store=self.publisher.TrustStore(self.store,(self.fixture.path/'publisher.pem').read_bytes())
        store.initialize()
        healthy=self.verify();self.assertEqual(healthy.returncode,0,healthy.stderr)
        state,initialized=store.load();self.assertTrue(initialized)
        state['policy']['keys'][0]['revoked_at']=self.fixture.manifest['signing']['issued_at']
        store.state.write_bytes(self.publisher.canonical(state))
        result=self.verify();self.assertNotEqual(result.returncode,0)
        self.assert_preserved()

    def test_changed_retained_verifier_is_refused_instead_of_adopting_its_live_hash(self):
        path=self.generation/'module/bin/sls_mass_notify/sls_release_trust.py'
        path.write_bytes(path.read_bytes()+b'\nraise RuntimeError("must never execute changed verifier")\n')
        result=self.verify();self.assertNotEqual(result.returncode,0)
        self.assertNotIn('must never execute changed verifier',result.stderr)
        self.assert_preserved()

    def test_wrong_retained_inventory_digest_is_refused(self):
        inventory=self.generation/'inventory.json';inventory.write_bytes(inventory.read_bytes()+b'\n')
        result=self.verify();self.assertNotEqual(result.returncode,0)
        self.assert_preserved()


CACHE_CHILD=r'''
import importlib.util,os,signal,sys
from pathlib import Path
helper,workspace,root,signer,keyhash=sys.argv[1:]
spec=importlib.util.spec_from_file_location('v020_cache_child',helper)
upgrade=importlib.util.module_from_spec(spec);spec.loader.exec_module(upgrade)
upgrade.UPSTREAM_SIGNER=signer;upgrade.UPSTREAM_KEY_SHA256=keyhash
real=upgrade.TRUST.os.replace
def boundary(source,target,*args,**kwargs):
    if str(target)=='dashboard-17.0.6.tgz.gpg':
        print('cache-ready',flush=True);os.kill(os.getpid(),signal.SIGSTOP)
    return real(source,target,*args,**kwargs)
upgrade.TRUST.os.replace=boundary
upgrade.cache_stock_packages(Path(workspace),Path(root))
'''


class AuthenticatedCacheRetry(unittest.TestCase):
    @classmethod
    def setUpClass(cls):STOCK_FIXTURE.UpgradeTrustTests.setUpClass()

    @classmethod
    def tearDownClass(cls):STOCK_FIXTURE.UpgradeTrustTests.tearDownClass()

    def setUp(self):
        self.fixture=STOCK_FIXTURE.UpgradeTrustTests(methodName='runTest')
        self.fixture.setUp();self.addCleanup(self.fixture.doCleanups)
        f=self.fixture;self.upgrade=f.upgrade;self.store=f.args.trust_root
        self.cache=self.store/'stock-packages'
        self.upgrade.TRUST.prepare_root(self.store);self.upgrade.TRUST.prepare_root(self.cache)
        for path in f.offline.glob('*.tgz.gpg'):
            self.upgrade.TRUST.atomic(self.cache/path.name,path.read_bytes())
        self.original={p.name:p.read_bytes() for p in self.cache.iterdir()}
        self.pending=f.root/'pending';self.pending.mkdir(mode=0o700)
        contents={**f.stock['dashboard'],'module.xml':b'<module><rawname>dashboard</rawname><version>17.0.6</version></module>'}
        plain=self.pending/'dashboard.tgz';STOCK_FIXTURE.package(plain,'dashboard',contents)
        self.signed=self.pending/'dashboard-17.0.6.tgz.gpg'
        subprocess.run(f.gpg_command+['--output',str(self.signed),'--sign',str(plain)],check=True,capture_output=True,timeout=20)

    def test_own_killed_cache_publication_retries_only_with_matching_authenticated_pending_source(self):
        f=self.fixture
        child=subprocess.Popen([sys.executable,'-I','-c',CACHE_CHILD,
            str(f.helpers/'sls_upgrade_trust.py'),str(self.pending),str(self.store),
            self.upgrade.UPSTREAM_SIGNER,self.upgrade.UPSTREAM_KEY_SHA256],
            stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True)
        try:
            self.assertTrue(select.select([child.stdout],[],[],12)[0])
            self.assertEqual(child.stdout.readline(),'cache-ready\n')
            child.kill();child.communicate(timeout=5);self.assertEqual(child.returncode,-signal.SIGKILL)
            orphan,=list(self.cache.glob('.new-*'))
            body=self.signed.read_bytes();self.assertEqual(orphan.read_bytes(),body)
            empty=f.root/'empty';empty.mkdir(mode=0o700)
            with self.assertRaises((RuntimeError,OSError)):
                self.upgrade.cache_stock_packages(empty,self.store)
            self.assertTrue(orphan.exists())
            self.upgrade.cache_stock_packages(self.pending,self.store)
            self.assertEqual((self.cache/self.signed.name).read_bytes(),body)
            self.assertEqual(list(self.cache.glob('.new-*')),[])
            evidence=[p for p in self.store.rglob('*') if p.is_file() and p.parent!=self.cache and p.read_bytes()==body]
            self.assertTrue(evidence,'interrupted publication bytes were discarded instead of retained privately')
            for name,original in self.original.items():self.assertEqual((self.cache/name).read_bytes(),original)
        finally:
            if child.poll() is None:child.kill();child.communicate(timeout=5)

    def test_unknown_atomic_temporary_is_preserved_and_refused(self):
        orphan=self.cache/('.new-'+'a'*24);orphan.write_bytes(b'unknown unreviewed bytes');orphan.chmod(0o600)
        with self.assertRaises((RuntimeError,OSError)):
            self.upgrade.cache_stock_packages(self.pending,self.store)
        self.assertEqual(orphan.read_bytes(),b'unknown unreviewed bytes')
        for name,original in self.original.items():self.assertEqual((self.cache/name).read_bytes(),original)


if __name__=='__main__':unittest.main()
