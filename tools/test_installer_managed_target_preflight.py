#!/usr/bin/python3
"""Fixed integration targets must be writable with preservable ownership first."""
import json
import os
from pathlib import Path
import pwd
import subprocess
import tempfile
import unittest
ROOT=Path(__file__).resolve().parents[1]
class ManagedTargetPreflight(unittest.TestCase):
    def test_root_owned_static_target_is_refused_without_staging_or_other_mutation(self):
        account=pwd.getpwnam('asterisk')
        with tempfile.TemporaryDirectory(dir='/run',prefix='sls-integration-target-preflight-') as name:
            root=Path(name);root.chmod(0o755)
            for relative in ('etc/asterisk','web/admin/views','web/admin/modules/dashboard/sections','web/admin/modules/dashboard/views/sections'):
                (root/relative).mkdir(parents=True,exist_ok=True)
            for folder in root.rglob('*'):
                if folder.is_dir():os.chown(folder,0,account.pw_gid);folder.chmod(0o775)
            target=root/'etc/asterisk/extensions_custom.conf';target.write_bytes(b'; retained native administrator configuration\n');os.chown(target,0,account.pw_gid);target.chmod(0o664)
            source=(ROOT/'slsmassnotifyserver/Slsmassnotifyserver.class.php').read_text()
            source=source.replace('__DIR__',repr(str(ROOT/'slsmassnotifyserver'))).replace('/etc/asterisk/',str(root/'etc/asterisk')+'/').replace('/var/www/html/',str(root/'web')+'/')
            copied=root/'module.php';copied.write_text(source);copied.chmod(0o644)
            runner=root/'preflight.php';runner.write_text('''<?php
interface BMO {}
require $argv[1];
$account=posix_getpwnam('asterisk');
if(!posix_setgid($account['gid'])||!posix_setuid($account['uid'])){throw new RuntimeException('Private UID transition failed');}
$module=(new ReflectionClass(FreePBX\\modules\\Slsmassnotifyserver::class))->newInstanceWithoutConstructor();
try{$module->preflightManagedIntegrationTargets();echo json_encode(['rejected'=>false]);}
catch(Throwable $error){echo json_encode(['rejected'=>true,'message'=>$error->getMessage()]);}
''');runner.chmod(0o644)
            def inspect():
                result=subprocess.run(['/usr/bin/php',str(runner),str(copied)],capture_output=True,text=True,timeout=8)
                self.assertEqual(result.returncode,0,result.stderr);return json.loads(result.stdout)
            before={(str(p.relative_to(root)),p.lstat().st_ino,p.lstat().st_mode) for p in root.rglob('*')}
            rejected=inspect()
            self.assertTrue(rejected['rejected'])
            self.assertRegex(rejected.get('message','').lower(),'ownership|root-owned',
                             'Refuse the concrete ownership limitation before any integration mutation')
            self.assertEqual({(str(p.relative_to(root)),p.lstat().st_ino,p.lstat().st_mode) for p in root.rglob('*')},before)
            self.assertEqual(target.read_bytes(),b'; retained native administrator configuration\n')
            os.chown(target,account.pw_uid,account.pw_gid)
            self.assertFalse(inspect()['rejected'],'Service-owned supported static target should pass the same read-only preflight')
if __name__=='__main__':unittest.main()
