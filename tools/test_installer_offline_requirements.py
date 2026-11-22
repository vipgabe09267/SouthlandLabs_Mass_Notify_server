#!/usr/bin/python3
"""Offline completeness uses the authenticated candidate and explicit target needs.

Real disposable Ed25519 signatures protect the synthetic archive. Wheel
resolution and upstream GPG are separate fixture boundaries; their authenticity
and resolver behavior have their own suites. This exercises real asset reads,
hashes, signed catalogue parsing and target completeness without live state.
"""
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import tarfile
import unittest
from unittest.mock import patch

ROOT=Path(__file__).resolve().parents[1]
spec=importlib.util.spec_from_file_location('offline_requirement_fixture',ROOT/'tools/test_installation_doctor.py')
fixture=importlib.util.module_from_spec(spec);spec.loader.exec_module(fixture)
BUNDLE=fixture.BUNDLE


class OfflineRequirements(unittest.TestCase):
    def setUp(self):
        self.fixture=fixture.OfflineBundle(methodName='runTest');self.fixture.setUp()
        self.addCleanup(self.fixture.doCleanups)
        self.root=self.fixture.directory
        self.optional=b'exact independently signed optional voice bytes'
        optional_config=b'{"audio":{"sample_rate":22050}}'
        self.optional_name='es_MX-ald-medium.onnx'
        self.base=b'exact base voice';wheel=b'inert wheel resolver boundary'
        digest=lambda body:hashlib.sha256(body).hexdigest()
        catalogue={'schema':1,'voices':[{'id':'es_MX-ald-medium','files':{
            self.optional_name:{'sha256':digest(self.optional),'size':len(self.optional),'url':'https://example.invalid/unused'},
            self.optional_name+'.json':{'sha256':digest(optional_config),'size':len(optional_config),'url':'https://example.invalid/unused'}}}]}
        self.contents={
            'module.xml':b'<module><rawname>slsmassnotifyserver</rawname><version>0.1.6-beta</version></module>',
            'bin/sls_mass_notify/piper-packaging.lock':b'fixture --hash=sha256:'+digest(wheel).encode(),
            'bin/sls_mass_notify/piper-requirements.lock':b'fixture --hash=sha256:'+digest(wheel).encode(),
            'bin/sls_mass_notify/piper-optional-voices.json':json.dumps(catalogue).encode(),
            'bin/sls_mass_notify_install_piper_voices.sh':('declare -A hashes=(\n["en_US-base.onnx"]="'+digest(self.base)+'"\n)\n').encode()}
        with tarfile.open(self.fixture.package,'w:gz') as archive:
            for name,body in self.contents.items():
                member=tarfile.TarInfo('slsmassnotifyserver/'+name);member.size=len(body);member.mode=0o644
                archive.addfile(member,io.BytesIO(body))
        self.fixture.sign()
        for name in ('assets/wheels','assets/voices','upstream'):
            (self.root/name).mkdir(parents=True,exist_ok=True)
        for name,body in {'assets/wheels/fixture-py3-none-any.whl':wheel,
                          'assets/voices/en_US-base.onnx':self.base,
                          'assets/voices/'+self.optional_name+'.json':optional_config,
                          'upstream/framework-17.0.33.tgz.gpg':b'independent upstream signature boundary',
                          'upstream/dashboard-17.0.5.tgz.gpg':b'independent upstream signature boundary'}.items():
            path=self.root/name;path.write_bytes(body);path.chmod(0o600)
        self.enterContext(patch.object(BUNDLE,'verify_wheel_resolution',return_value=None))
        self.enterContext(patch.object(BUNDLE,'verify_upstream',return_value=None))

    def test_selected_optional_voice_must_exist_before_bundle_is_accepted(self):
        with self.assertRaises((ValueError,OSError)):
            BUNDLE.validate(self.root,optional_voice_packs=['es_MX-ald-medium'])

    def test_selected_optional_voice_must_match_its_signed_size_and_hash(self):
        path=self.root/'assets/voices'/self.optional_name;path.write_bytes(b'changed voice');path.chmod(0o600)
        with self.assertRaises(ValueError):BUNDLE.validate(self.root,optional_voice_packs=['es_MX-ald-medium'])
        path.write_bytes(self.optional)
        result=BUNDLE.validate(self.root,optional_voice_packs=['es_MX-ald-medium'])
        self.assertEqual(result['optional_voice_packs'],['es_MX-ald-medium'])
        self.assertEqual(result['optional_voice_file_count'],2)

    def test_unknown_optional_selection_does_not_fall_back_to_base_voices(self):
        with self.assertRaises(ValueError):BUNDLE.validate(self.root,optional_voice_packs=['unknown-voice'])

    def test_empty_upstream_cannot_claim_signature_or_target_completeness(self):
        for path in (self.root/'upstream').iterdir():path.unlink()
        with self.assertRaises(ValueError):BUNDLE.validate(self.root)

    def test_requested_target_versions_require_the_exact_signed_package_names(self):
        with self.assertRaises(ValueError):
            BUNDLE.validate(self.root,required_upstream_versions={'framework':'17.0.33.2','dashboard':'17.0.5'})
        result=BUNDLE.validate(self.root,required_upstream_versions={'framework':'17.0.33','dashboard':'17.0.5'})
        self.assertEqual(result['target_upstream_versions_verified'],{'framework':'17.0.33','dashboard':'17.0.5'})


if __name__=='__main__':unittest.main()
