#!/usr/bin/python3
"""Disposable real A/B signatures across bootstrap, staging and retained review."""
import argparse
import base64
import copy
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import tempfile
import time
import unittest
from unittest.mock import patch
import tarfile

for label,kind in [('MOUNT','mnt'),('NET','net'),('PID','pid')]:
    if (os.geteuid()!=0 or os.environ.get('SLS_TEST_NAMESPACE')!='entered'
            or os.environ.get('SLS_TEST_PARENT_'+label+'_NS') in (None,'',os.readlink('/proc/self/ns/'+kind))):
        raise SystemExit('Fresh root-private namespaces required; no trust helpers ran.')

ROOT=Path(__file__).resolve().parents[1]
BIN=ROOT/'slsmassnotifyserver/bin/sls_mass_notify'


class PublisherAuthorityContinuity(unittest.TestCase):
    def setUp(self):
        temporary=tempfile.TemporaryDirectory(prefix='sls-publisher-continuity-',dir='/run')
        self.addCleanup(temporary.cleanup);self.root=Path(temporary.name);self.now=int(time.time())
        self.keys=[]
        for number in range(2):
            private=self.root/('private-'+str(number))
            subprocess.run(['/usr/bin/openssl','genpkey','-algorithm','Ed25519','-out',str(private)],check=True,capture_output=True)
            public=subprocess.check_output(['/usr/bin/openssl','pkey','-in',str(private),'-pubout'])
            self.keys.append((private,public))
        self.helpers=self.root/'helpers';self.helpers.mkdir(mode=0o700)
        for name in ('sls_module_trust','sls_release_trust','sls_upgrade_trust','sls_installer_recovery'):
            body=(BIN/(name+'.py')).read_bytes()
            if name=='sls_module_trust':
                body,count=re.subn(rb'^PUBLIC_KEY = .*$',lambda unused:b'PUBLIC_KEY = '+repr(self.keys[0][1]).encode(),body,flags=re.M)
                self.assertEqual(count,1)
            (self.helpers/(name+'.py')).write_bytes(body)
            (self.helpers/(name+'.py')).chmod(0o600)
        self.publisher=self.load('sls_release_trust');self.module=self.load('sls_module_trust');self.upgrade=self.load('sls_upgrade_trust')
        self.directory=self.root/'live-trust';self.store=self.publisher.TrustStore(self.directory,self.keys[0][1])
        self.web=self.root/'web';self.web.mkdir(mode=0o700);self.upgrade.WEB=self.web

    def load(self,name):
        spec=importlib.util.spec_from_file_location('continuity_'+name,self.helpers/(name+'.py'))
        value=importlib.util.module_from_spec(spec);spec.loader.exec_module(value);return value

    def sign(self,body,number):
        plain=self.root/'body';signature=self.root/'signature';plain.write_bytes(body)
        subprocess.run(['/usr/bin/openssl','pkeyutl','-sign','-rawin','-inkey',str(self.keys[number][0]),'-in',str(plain),'-out',str(signature)],check=True,capture_output=True)
        return signature.read_bytes()

    def overlap(self):
        self.store.initialize()
        policy={'schema':1,'sequence':1,'keys':[self.publisher.key_entry(public) for private,public in self.keys]}
        self.transition(policy,(0,1))

    def transition(self,policy,numbers):
        body=self.publisher.canonical(policy)
        self.store.import_transition({'schema':1,'policy':policy,'proofs':[
            {'key_id':self.publisher.key_entry(self.keys[number][1])['id'],'signature':base64.b64encode(self.sign(body,number)).decode()}
            for number in numbers]},now=self.now)

    def release(self,number=0,version='0.2.0-beta',expires_at=None,include_helpers=False):
        assets=self.root/('assets-'+str(len(list(self.root.glob('assets-*')))));assets.mkdir(mode=0o700)
        contents={'module.xml':('<module><rawname>slsmassnotifyserver</rawname><version>'+version+'</version></module>').encode()}
        if include_helpers:
            contents.update({'bin/sls_mass_notify/'+path.name:path.read_bytes() for path in self.helpers.iterdir()})
        archive=assets/('slsmassnotifyserver-'+version+'.tgz')
        with tarfile.open(archive,'w:gz') as handle:
            for name,body in contents.items():
                entry=tarfile.TarInfo('slsmassnotifyserver/'+name);entry.size=len(body);entry.mode=0o644
                handle.addfile(entry,io.BytesIO(body))
        installer=assets/'install_release.sh';installer.write_bytes(b'#!/bin/bash\n# Inert fixture; verification never executes this installer.\n')
        manifest={'schema':1,'version':version,'tag':'v'+version,'package':archive.name,
            'package_sha256':hashlib.sha256(archive.read_bytes()).hexdigest(),'installer_sha256':hashlib.sha256(installer.read_bytes()).hexdigest(),
            'signing':{'key_id':self.publisher.key_entry(self.keys[number][1])['id'],'issued_at':self.now-3600,
                       'expires_at':self.now+3600 if expires_at is None else expires_at}}
        (assets/'release-manifest.json').write_bytes(self.publisher.canonical(manifest))
        (assets/'release-manifest.sig').write_bytes(self.sign(self.publisher.canonical(manifest),number))
        (assets/'publisher.pem').write_bytes(self.keys[0][1])
        for path in assets.iterdir():path.chmod(0o600)
        return archive,assets/'release-manifest.json',assets/'release-manifest.sig'

    def bootstrap(self,release,existing=True):
        source=(ROOT/'tools/install_bootstrap.sh').read_text().replace('/var/lib/sls-mass-notify-trust',str(self.directory)).replace('/usr/local/bin/sls_mass_notify',str(self.helpers))
        fixture=self.root/'bootstrap.sh';fixture.write_text(source)
        version=json.loads(release[1].read_bytes())['version']
        return subprocess.run(['/bin/bash','-c','source "$1"; bootstrap_verify "$2" "$3" "v$3" "$4"','fixture',str(fixture),str(release[0].parent),version,'1' if existing else '0'],capture_output=True,text=True,timeout=15)

    def args(self,release):
        return argparse.Namespace(workspace=self.root/'workspace',archive=release[0],manifest=release[1],signature=release[2],trust_root=self.directory)

    def prepare_through_sls(self,release):
        class NativeStageReached(Exception):pass
        real_identity=self.upgrade.identity
        def identity(web,module):
            if module=='dashboard':raise NativeStageReached()
            return real_identity(web,module)
        with patch.object(self.upgrade,'identity',side_effect=identity),self.assertRaises(NativeStageReached):
            self.upgrade.prepare(self.args(release))

    def test_bootstrap_obeys_actual_root_reviewed_overlap(self):
        self.overlap();release=self.release(1)
        self.publisher.authenticate_manifest(release[1].read_bytes(),release[2].read_bytes(),anchor=self.keys[0][1],directory=self.directory)
        before={path.name:path.read_bytes() for path in self.directory.iterdir() if path.is_file()}
        result=self.bootstrap(release)
        self.assertEqual(result.returncode,0,result.stderr)
        self.assertEqual({path.name:path.read_bytes() for path in self.directory.iterdir() if path.is_file()},before)

    def test_fresh_bootstrap_still_requires_pinned_A(self):
        self.assertEqual(self.bootstrap(self.release(0),existing=False).returncode,0)
        self.assertNotEqual(self.bootstrap(self.release(1),existing=False).returncode,0)

    def test_prepare_candidate_registry_uses_existing_authority(self):
        self.overlap();self.prepare_through_sls(self.release(1))
        self.assertFalse((self.root/'workspace/registry/publisher-trust.json').exists())
        self.assertFalse((self.root/'workspace/registry/release-trust.initialized').exists())

    def test_prepare_prior_registry_uses_same_current_authority(self):
        self.overlap();prior=self.release(1,'0.1.9-beta')
        self.module.enroll_sls(self.directory,*prior)
        data,generation=self.module.load(self.directory,'slsmassnotifyserver')
        target=self.web/'admin/modules/slsmassnotifyserver';target.parent.mkdir(parents=True)
        shutil.copytree(generation/'module',target)
        (self.directory/'slsmassnotifyserver.active.json').unlink()
        with patch.dict(os.environ,{'SLS_MASS_NOTIFY_PREVIOUS_'+key:str(path) for key,path in zip(('TGZ','MANIFEST','MANIFEST_SIGNATURE'),prior)}):
            self.prepare_through_sls(self.release(1))
        self.assertTrue((self.root/'workspace/previous-registry/slsmassnotifyserver.active.json').exists())

    def test_staging_registry_policy_never_becomes_candidate_authority(self):
        self.overlap();state,_=self.store.load()
        workspace=self.root/'workspace';workspace.mkdir(mode=0o700)
        staging=self.publisher.TrustStore(workspace/'registry',self.keys[0][1]);staging.initialize()
        staging.state.write_bytes(self.publisher.canonical(state));staging.state.chmod(0o600)
        # Only the throwaway staging tree now has B. Actual authority keeps A.
        state['policy']['keys']=state['policy']['keys'][:1]
        self.store.state.write_bytes(self.publisher.canonical(state));self.store.state.chmod(0o600)
        with self.assertRaises(self.upgrade.TRUST.TrustError):self.upgrade.prepare(self.args(self.release(1)))
        self.assertFalse((workspace/'registry/slsmassnotifyserver.active.json').exists())

    def test_legacy_approved_installation_uses_A_and_refuses_changed_inventory(self):
        release=self.release(0);self.module.enroll_sls(self.directory,*release)
        self.assertFalse(self.store.marker.exists())
        self.assertEqual(self.bootstrap(release).returncode,0)
        self.assertNotEqual(self.bootstrap(self.release(1)).returncode,0)
        _,generation=self.module.load(self.directory,'slsmassnotifyserver')
        (generation/'inventory.json').write_bytes(b'{}')
        self.assertNotEqual(self.bootstrap(release).returncode,0)

    def test_revoked_keys_and_incomplete_policy_never_bootstrap(self):
        self.overlap()
        for number in (0,1):
            with self.subTest(number=number):
                state,_=self.store.load();original=self.store.state.read_bytes()
                state['policy']['keys'][number]['revoked_at']=self.now-1
                state['retired_ids'].append(state['policy']['keys'][number]['id'])
                self.store.state.write_bytes(self.publisher.canonical(state));self.store.state.chmod(0o600)
                self.assertNotEqual(self.bootstrap(self.release(number)).returncode,0)
                self.store.state.write_bytes(original)
        self.store.state.unlink()
        self.assertNotEqual(self.bootstrap(self.release(0)).returncode,0)

    def test_retained_verifier_keeps_overlap_but_changed_source_refuses(self):
        self.overlap();release=self.release(1,include_helpers=True)
        self.module.enroll_sls(self.directory,*release)
        data,generation=self.module.load(self.directory,'slsmassnotifyserver')
        (self.helpers/'sls_release_trust.py').unlink()
        self.assertEqual(self.bootstrap(release).returncode,0)
        retained=generation/'module/bin/sls_mass_notify/sls_release_trust.py'
        retained.write_bytes(retained.read_bytes()+b'\n# changed retained evidence\n')
        self.assertNotEqual(self.bootstrap(release).returncode,0)

    def expired_generation(self):
        self.overlap();release=self.release(1,expires_at=self.now-60)
        with patch('time.time',return_value=self.now-120):self.module.enroll_sls(self.directory,*release)
        return release,self.module.load(self.directory,'slsmassnotifyserver')[1]

    def approve_retained(self):
        review=self.upgrade.review_retained(self.directory,now=self.now)
        self.upgrade.review_retained(self.directory,approval=review['challenge'],operator='Fixture operator',
                                    reason='Reviewed byte-exact retained release for upgrade continuity.',now=self.now)
        return review

    def test_expired_retained_release_requires_explicit_bounded_review(self):
        release,generation=self.expired_generation()
        with self.assertRaises(ValueError):self.upgrade.authenticated_generation(self.directory)
        with self.assertRaises((ValueError,self.upgrade.UpgradeError,OSError)):
            self.upgrade.authenticated_generation(self.directory,retained=True,now=self.now)
        review=self.upgrade.review_retained(self.directory,now=self.now)
        self.assertRegex(review['challenge'],r'^[a-f0-9]{64}$')
        receipt=self.directory/'retained-release-approval.json';self.assertFalse(receipt.exists())
        self.approve_retained()
        self.assertEqual(receipt.stat().st_mode&0o777,0o600)
        approved=json.loads(receipt.read_bytes())
        self.assertLessEqual(approved['expires_at']-approved['issued_at'],7*86400)
        self.assertEqual(approved['evidence']['generation'],generation.name)
        data,contents=self.upgrade.authenticated_generation(self.directory,retained=True,now=self.now)
        self.assertEqual(data['source']['archive_sha256'],hashlib.sha256(release[0].read_bytes()).hexdigest())
        self.assertIn('module.xml',contents)
        # Neither candidate enrollment nor the ordinary authenticator uses the exception.
        with self.assertRaises(self.module.TrustError):self.module.enroll_sls(self.root/'candidate',*release,authority_directory=self.directory)
        with self.assertRaises(ValueError):self.publisher.authenticate_manifest(release[1].read_bytes(),release[2].read_bytes(),anchor=self.keys[0][1],directory=self.directory,now=self.now)

    def test_prepare_uses_reviewed_expired_prior_but_candidate_expiry_stays_strict(self):
        prior,generation=self.expired_generation()
        target=self.web/'admin/modules/slsmassnotifyserver';target.parent.mkdir(parents=True)
        shutil.copytree(generation/'module',target)
        candidate=self.release(1)
        with self.assertRaises(OSError):self.upgrade.prepare(self.args(candidate))
        self.approve_retained();self.prepare_through_sls(candidate)
        with self.assertRaises(self.upgrade.TRUST.TrustError):self.upgrade.prepare(self.args(prior))

    def test_review_is_root_only_and_full_source_changes_never_get_receipts(self):
        release,generation=self.expired_generation();review=self.upgrade.review_retained(self.directory,now=self.now)
        with patch.object(os,'geteuid',return_value=999),self.assertRaises(self.upgrade.UpgradeError):
            self.upgrade.review_retained(self.directory,now=self.now)
        source=generation/'module/module.xml';source.write_bytes(source.read_bytes()+b'changed')
        with self.assertRaises((self.upgrade.UpgradeError,self.module.TrustError,ValueError)):
            self.upgrade.review_retained(self.directory,approval=review['challenge'],operator='Root',reason='Reviewed retained source before mutation.',now=self.now)
        self.assertFalse((self.directory/'retained-release-approval.json').exists())

    def test_review_refuses_legacy_missing_expiration_with_fixed_error(self):
        release=self.release(0);manifest=json.loads(release[1].read_bytes());manifest['signing']=None
        body=self.publisher.canonical(manifest);release[1].write_bytes(body);release[2].write_bytes(self.sign(body,0))
        # Legacy uninitialized approval preserves its original contract; it has
        # no expired metadata which this new reviewed exception can authorize.
        self.module.enroll_sls(self.directory,*release)
        with self.assertRaisesRegex(self.upgrade.UpgradeError,'expired signed release metadata'):
            self.upgrade.review_retained(self.directory,now=self.now)
        self.assertFalse((self.directory/'retained-release-approval.json').exists())

    def test_changed_manifest_and_policy_invalidate_review_challenge(self):
        release,generation=self.expired_generation();review=self.upgrade.review_retained(self.directory,now=self.now)
        manifest=json.loads((generation/'release-manifest.json').read_bytes());manifest['signing']['expires_at']-=1
        body=self.publisher.canonical(manifest)
        (generation/'release-manifest.json').write_bytes(body);(generation/'release-manifest.sig').write_bytes(self.sign(body,1))
        with self.assertRaises(self.upgrade.UpgradeError):
            self.upgrade.review_retained(self.directory,approval=review['challenge'],operator='Root',reason='Old review must not authorize changed evidence.',now=self.now)
        changed=self.upgrade.review_retained(self.directory,now=self.now);self.assertNotEqual(review['challenge'],changed['challenge'])
        policy=copy.deepcopy(self.store.load()[0]['policy']);policy['sequence']+=1;self.transition(policy,(1,))
        with self.assertRaises(self.upgrade.UpgradeError):
            self.upgrade.review_retained(self.directory,approval=changed['challenge'],operator='Root',reason='Old review must not authorize changed policy.',now=self.now)

    def test_receipt_cannot_override_revocation_key_expiry_or_policy_changes(self):
        release,generation=self.expired_generation();self.approve_retained()
        original=self.store.state.read_bytes()
        for mutation in ('revoked','expired','sequence'):
            with self.subTest(mutation=mutation):
                state=json.loads(original)
                if mutation=='revoked':state['policy']['keys'][1]['revoked_at']=self.now;state['retired_ids'].append(state['policy']['keys'][1]['id'])
                elif mutation=='expired':state['policy']['keys'][1]['expires_at']=self.now
                else:state['policy']['sequence']+=1
                self.store.state.write_bytes(self.publisher.canonical(state));self.store.state.chmod(0o600)
                with self.assertRaises((ValueError,self.upgrade.UpgradeError)):
                    self.upgrade.authenticated_generation(self.directory,retained=True,now=self.now)
                self.store.state.write_bytes(original)

    def test_retained_receipt_expiry_clock_and_changed_fields_fail_closed(self):
        release,generation=self.expired_generation();self.approve_retained()
        path=self.directory/'retained-release-approval.json';original=path.read_bytes();good=json.loads(original)
        for key,value in [('issued_at',True),('issued_at',self.now+1),('issued_at',0),('expires_at',self.now),
                          ('expires_at',self.now+7*86400+1),('challenge','a'*64),('operator',''),('reason','short'),('schema',True)]:
            with self.subTest(key=key,value=value):
                bad=copy.deepcopy(good);bad[key]=value;path.write_bytes(self.publisher.canonical(bad))
                with self.assertRaises((ValueError,self.upgrade.UpgradeError)):
                    self.upgrade.authenticated_generation(self.directory,retained=True,now=self.now)
        path.write_bytes(original)
        for checked in (self.now-1,self.now+7*86400):
            with self.subTest(checked=checked),self.assertRaises((ValueError,self.upgrade.UpgradeError)):
                self.upgrade.authenticated_generation(self.directory,retained=True,now=checked)
        path.chmod(0o644)
        with self.assertRaises((ValueError,self.upgrade.UpgradeError)):
            self.upgrade.authenticated_generation(self.directory,retained=True,now=self.now)

    def test_receipt_binds_exact_active_generation_and_protected_bytes(self):
        release,generation=self.expired_generation();self.approve_retained()
        source=generation/'module/module.xml';original=source.read_bytes();source.write_bytes(original+b'changed')
        with self.assertRaises((ValueError,self.upgrade.UpgradeError,self.module.TrustError)):
            self.upgrade.authenticated_generation(self.directory,retained=True,now=self.now)
        source.write_bytes(original)
        next_release=self.release(1,'0.1.8-beta',expires_at=self.now-60)
        with patch('time.time',return_value=self.now-120):self.module.enroll_sls(self.directory,*next_release)
        with self.assertRaises((ValueError,self.upgrade.UpgradeError)):
            self.upgrade.authenticated_generation(self.directory,retained=True,now=self.now)

    def test_review_cli_requires_separate_challenge_and_bounded_metadata(self):
        release,generation=self.expired_generation()
        command=['/usr/bin/python3','-I',str(self.helpers/'sls_upgrade_trust.py'),'--workspace',str(self.root/'unused-workspace'),
                 '--trust-root',str(self.directory),'--coordination-lock',str(self.root/'private-coordination.lock')]
        result=subprocess.run(command+['--review-retained'],capture_output=True,text=True,timeout=15)
        self.assertEqual(result.returncode,0,result.stderr);review=json.loads(result.stdout)
        self.assertFalse((self.directory/'retained-release-approval.json').exists())
        refused=subprocess.run(command+['--approve-retained',review['challenge']],capture_output=True,text=True,timeout=15)
        self.assertNotEqual(refused.returncode,0)
        approved=subprocess.run(command+['--approve-retained',review['challenge'],'--operator','Fixture root','--reason','Independent review of byte-exact retained release.'],capture_output=True,text=True,timeout=15)
        self.assertEqual(approved.returncode,0,approved.stderr)
        self.assertTrue((self.directory/'retained-release-approval.json').exists())

    def first_upgrade_inspection_registry(self):
        """Exercise real inspector preparation/cleanup over already signed fixtures.

        Resource admission and fixture download/extraction replace host discovery
        and network. The inspector, protected bootstrap copying, authenticated
        prepare, expired-prior refusal, and scratch cleanup execute unchanged.
        """
        self.overlap()
        prior=self.release(1,'0.1.9-beta',expires_at=self.now-60)
        with patch('time.time',return_value=self.now-120):self.module.enroll_sls(self.directory,*prior)
        _,old_generation=self.module.load(self.directory,'slsmassnotifyserver')
        installed=self.web/'admin/modules/slsmassnotifyserver';installed.parent.mkdir(parents=True)
        shutil.copytree(old_generation/'module',installed)
        framework=self.web/'admin/modules/framework';framework.mkdir()
        (framework/'module.xml').write_bytes(b'<module><rawname>framework</rawname><version>17.0.33</version></module>')
        freepbx=self.root/'freepbx.conf';freepbx.write_bytes(b'private fixture only')
        for name in ('sls_privileged_install','sls_install_transaction','sls_install_idle','sls_install_guard',
                     'sls_audio_state','sls_config_crypto','sls_legacy_permissions'):
            path=self.helpers/(name+'.py');path.write_bytes((BIN/path.name).read_bytes());path.chmod(0o600)
        key=self.helpers/'freepbx-mirror-signing.pub';key.write_bytes((BIN/key.name).read_bytes());key.chmod(0o600)
        helper=self.helpers/'sls_upgrade_trust.py'
        original=helper.read_text();self.assertIn("WEB = Path('/var/www/html')",original)
        helper.write_text(original.replace("WEB = Path('/var/www/html')",'WEB = Path('+repr(str(self.web))+')'))
        candidate=self.release(1,include_helpers=True)
        self.publisher.authenticate_manifest(candidate[1].read_bytes(),candidate[2].read_bytes(),
                                             anchor=self.keys[0][1],directory=self.directory)
        self.assertEqual(json.loads(candidate[1].read_bytes())['package_sha256'],self.module.digest(candidate[0].read_bytes()))
        scratch=self.root/'inspection-scratch';scratch.mkdir(mode=0o700)
        installer=self.root/'inspection-installer.sh'
        installer.write_text((ROOT/'tools/install_release.sh').read_text()
            .replace('/etc/freepbx.conf',str(freepbx)).replace('/var/www/html',str(self.web)))
        state=self.root/'inspection-result';log=self.root/'inspection-output'
        command=r'''
source "$1"
bootstrap_resource_capacity() { printf '{}\n'; }
select_install_temp_root() { INSTALL_TEMP_ROOT="$SLS_FIXTURE_SCRATCH"; }
validate_installer_memory_profile() { return 0; }
download_tgz() {
  DOWNLOAD_DIR="$SLS_FIXTURE_SCRATCH/download";mkdir -m700 "$DOWNLOAD_DIR"
  cp -- "$SLS_FIXTURE_ARCHIVE" "$DOWNLOAD_DIR/package.tgz"
  cp -- "$SLS_FIXTURE_MANIFEST" "$DOWNLOAD_DIR/release-manifest.json"
  cp -- "$SLS_FIXTURE_SIGNATURE" "$DOWNLOAD_DIR/release-manifest.sig"
  TGZ="$DOWNLOAD_DIR/package.tgz"
}
# Inputs were independently authenticated by the trusted fixture verifier.
# Real prepare authenticates them again against the current live policy.
verify_tgz() { return 0; }
stage_module_directory() {
  STAGING_DIR="$SLS_FIXTURE_SCRATCH/staging";mkdir -m700 "$STAGING_DIR"
  /usr/bin/tar -xzf "$TGZ" -C "$STAGING_DIR"
}
TRUST_ROOT="$SLS_FIXTURE_TRUST"
if inspect_installation; then inspected=0;else inspected=$?;fi
printf '%s\n' "$inspected" "$UPGRADE_TRUST_DIR" >"$SLS_FIXTURE_RESULT"
'''
        environment=dict(os.environ,SLS_FIXTURE_SCRATCH=str(scratch),SLS_FIXTURE_ARCHIVE=str(candidate[0]),
            SLS_FIXTURE_MANIFEST=str(candidate[1]),SLS_FIXTURE_SIGNATURE=str(candidate[2]),
            SLS_FIXTURE_TRUST=str(self.directory),SLS_FIXTURE_RESULT=str(state))
        result=subprocess.run(['/bin/bash','-c',command,'fixture',str(installer)],env=environment,
                              capture_output=True,text=True,timeout=20)
        log.write_text(result.stdout+result.stderr)
        self.assertEqual(result.returncode,0,log.read_text())
        outcome,workspace=state.read_text().splitlines()
        self.assertNotEqual(outcome,'0','An expired old generation was accepted without explicit review')
        self.assertIn('Inspection failed',log.read_text())
        inspection_logs=list(scratch.glob('sls-mass-notify-inspection.*.log'))
        self.assertEqual(len(inspection_logs),1)
        self.assertIn('retained-release-approval.json',inspection_logs[0].read_text(),
                      'The inspected candidate must reach the expired prior-generation approval boundary')
        self.assertFalse((scratch/'download').exists())
        self.assertFalse((scratch/'staging').exists())
        self.assertEqual(list(scratch.glob('sls-mass-notify-bootstrap.*')),[])
        workspace=Path(workspace)
        self.assertTrue(workspace.is_relative_to(scratch))
        self.assertEqual(workspace.stat().st_mode&0o777,0o700)
        self.assertTrue((workspace/'registry/slsmassnotifyserver.active.json').is_file())
        return workspace/'registry',installed,candidate

    def independently_verified_candidate_helper(self,registry):
        """Established trusted verifiers validate all code before any CLI import."""
        data,generation=self.module.load(registry,'slsmassnotifyserver')
        manifest=self.publisher.authenticate_manifest((generation/'release-manifest.json').read_bytes(),
            (generation/'release-manifest.sig').read_bytes(),anchor=self.keys[0][1],directory=self.directory)
        self.assertEqual(manifest['package_sha256'],data['source']['archive_sha256'])
        self.assertEqual(manifest['version'],data['version'])
        self.assertEqual(self.module.inventory_tree(generation/'module','slsmassnotifyserver'),set(data['files']))
        for name,entry in data['files'].items():
            body=self.module.read(generation/'module'/name,self.module.MAX_ARCHIVE,protected=True)
            if self.module.digest(body)!=entry['sha256']:
                raise self.module.TrustError('Candidate helper source changed before execution: '+name)
        return generation/'module/bin/sls_mass_notify/sls_upgrade_trust.py'

    def test_first_upgrade_can_review_with_retained_new_candidate_after_inspection_cleanup(self):
        registry,installed,candidate=self.first_upgrade_inspection_registry()
        self.assertFalse((installed/'bin/sls_mass_notify/sls_upgrade_trust.py').exists(),
                         'The old installed fixture must not supply the new review CLI')
        old_pointer=(self.directory/'slsmassnotifyserver.active.json').read_bytes()
        helper=self.independently_verified_candidate_helper(registry)
        command=['/usr/bin/python3','-I',str(helper),'--workspace',str(self.root/'unused-review-workspace'),
            '--trust-root',str(self.directory),'--coordination-lock',str(self.root/'private-review.lock')]
        reviewed=subprocess.run(command+['--review-retained'],capture_output=True,text=True,timeout=15)
        self.assertEqual(reviewed.returncode,0,reviewed.stderr);review=json.loads(reviewed.stdout)
        receipt=self.directory/'retained-release-approval.json';self.assertFalse(receipt.exists())
        approved=subprocess.run(command+['--approve-retained',review['challenge'],'--operator','Fixture administrator',
            '--reason','Independent review using the authenticated candidate before installation.'],capture_output=True,text=True,timeout=15)
        self.assertEqual(approved.returncode,0,approved.stderr)
        self.assertEqual(receipt.stat().st_mode&0o777,0o600)
        self.assertEqual((self.directory/'slsmassnotifyserver.active.json').read_bytes(),old_pointer)
        self.assertFalse((self.root/'unused-review-workspace').exists())
        self.assertIn(b'<version>0.1.9-beta</version>',(installed/'module.xml').read_bytes())
        self.assertEqual(self.module.inventory_tree(installed,'slsmassnotifyserver'),{'module.xml'})
        self.upgrade.authenticated_generation(self.directory,retained=True)

    def test_retained_candidate_cli_requires_live_authority_and_unchanged_source_before_execution(self):
        registry,installed,candidate=self.first_upgrade_inspection_registry()
        helper=self.independently_verified_candidate_helper(registry)
        for name in ('sls_upgrade_trust.py','sls_release_trust.py','sls_module_trust.py'):
            with self.subTest(name=name):
                path=helper.with_name(name);original=path.read_bytes()
                path.write_bytes(original+b'\nraise SystemExit("changed helper must never execute")\n')
                try:
                    with self.assertRaisesRegex(self.module.TrustError,'changed before execution'):
                        self.independently_verified_candidate_helper(registry)
                finally:path.write_bytes(original)
        # A policy planted in the staging registry must not overrule live
        # revocation, even though its candidate signature was valid earlier.
        staging=self.publisher.TrustStore(registry,self.keys[0][1]);staging.initialize()
        trusted,_=self.store.load();staging.state.write_bytes(self.publisher.canonical(trusted))
        trusted['policy']['keys'][1]['revoked_at']=self.now
        trusted['retired_ids'].append(trusted['policy']['keys'][1]['id'])
        self.store.state.write_bytes(self.publisher.canonical(trusted))
        with self.assertRaisesRegex(ValueError,'revoked'):
            self.independently_verified_candidate_helper(registry)
        self.assertFalse((self.directory/'retained-release-approval.json').exists())


if __name__=='__main__':unittest.main()
