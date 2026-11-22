#!/usr/bin/python3
"""Qualify effective PHP on the PBX route, with inert native Apache config."""
import importlib.util
import grp
import json
import os
from pathlib import Path
import pwd
import shutil
import subprocess
import tempfile
import unittest

if os.environ.get('SLS_TEST_NAMESPACE') != 'entered':
    raise RuntimeError('Use tools/run_isolated_tests.sh')
ROOT = Path(__file__).resolve().parents[1]
SOURCE = (ROOT / 'tools/install_release.sh').read_text()
CODE = SOURCE.split("<<'PYPHPHANDLER'\n", 1)[1].split('\nPYPHPHANDLER', 1)[0]


class RouteProfiles(unittest.TestCase):
    def test_served_php_prerequisites_keep_healthy_held_packages(self):
        code = SOURCE.split('    local served_profile served_version served_package\n', 1)[1].split(
            '    /usr/bin/python3 -I -c ', 1)[0]
        script = '''set -eu
fixture_status=$1
SERVED_PHP_PROFILES=8.2:fpm
dpkg-query() {
  [ "$1" = '-W' ] && [ "$2" = '-f=${Status}' ] || return 99
  case "$3" in php8.2-cli|php8.2-common|php8.2-sqlite3|php8.2-curl|php8.2-xml|php8.2-mbstring) ;;
    *) return 99 ;; esac
  printf '%s' "$fixture_status"
}
add_missing_package() { printf '%s\\n' "$1"; }
check_served_packages() {
  local served_profile served_version served_package
''' + code + '\n}\ncheck_served_packages\n'
        expected = ['php8.2-'+name for name in ('cli', 'common', 'sqlite3', 'curl', 'xml', 'mbstring')]
        for status in ('install ok installed', 'hold ok installed', 'install reinstreq installed',
                'hold reinstreq installed', 'install ok half-configured', 'install ok unpacked',
                'deinstall ok installed', 'purge ok installed', 'install ok installed extra'):
            with self.subTest(status=status):
                result = subprocess.run(['/bin/bash', '-c', script, 'php-status-fixture', status],
                    capture_output=True, text=True, timeout=4)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(result.stdout.splitlines(), [] if status in (
                    'install ok installed', 'hold ok installed') else expected)

    def test_actual_runtime_marker_requires_both_service_uid_and_primary_group(self):
        account=pwd.getpwnam('asterisk')
        foreign=grp.getgrnam('www-data').gr_gid
        self.assertNotEqual(account.pw_gid,foreign)
        with tempfile.TemporaryDirectory(dir='/run',prefix='sls-php-marker-') as name:
            root=Path(name);root.chmod(0o755)
            for item in ('index.php','runtime-security.php'):
                target=root/item
                shutil.copyfile(ROOT/'slsmassnotifyserver/api/sls-mass-notify'/item,target)
                target.chmod(0o644)
            code="$_GET=['sls_installer_runtime'=>'1'];$_SERVER=['REQUEST_METHOD'=>'GET','REMOTE_ADDR'=>'127.0.0.1'];require $argv[1];"
            for group,expected in ((account.pw_gid,True),(foreign,False)):
                with self.subTest(group=group):
                    result=subprocess.run(['/usr/bin/php','-r',code,str(root/'index.php')],
                        user=account.pw_uid,group=group,extra_groups=[],capture_output=True,text=True,timeout=6)
                    self.assertEqual(result.returncode,0,result.stderr)
                    marker=json.loads(result.stdout)
                    self.assertEqual(marker['runtime_account_ok'],expected)
                    self.assertEqual('web_runtime_must_run_as_asterisk' in marker['missing'],not expected)

    def native(self, extra, pbx_extra='', observe_local=False, request_path='/api/sls-mass-notify/?resource=status'):
        with tempfile.TemporaryDirectory(dir='/run', prefix='sls-php-route-') as name:
            base = Path(name)
            config = base / 'apache2.conf'
            config.write_text('ServerRoot '+str(base)+'\nServerName audit.invalid\n'
                'ErrorLog /dev/null\nPidFile '+str(base/'pid')+'\n'
                'LoadModule mpm_prefork_module /usr/lib/apache2/modules/mod_mpm_prefork.so\n'
                'LoadModule php_module /usr/lib/apache2/modules/libphp8.2.so\n'
                'LoadModule proxy_module /usr/lib/apache2/modules/mod_proxy.so\n'
                'LoadModule proxy_fcgi_module /usr/lib/apache2/modules/mod_proxy_fcgi.so\n'
                'User asterisk\nGroup asterisk\nListen 8443\n'
                '<VirtualHost *:8443>\nServerName pbx.audit.invalid\nDocumentRoot /var/www/html\n'
                '<FilesMatch "\\.php$">\nSetHandler application/x-httpd-php\n</FilesMatch>\n'
                +pbx_extra+'</VirtualHost>\n'+extra)
            config.chmod(0o644)
            env={**os.environ, 'APACHE_CONFDIR':str(base), 'APACHE_ENVVARS':str(base/'none'),
                 'APACHE_RUN_DIR':str(base), 'APACHE_LOCK_DIR':str(base),
                 'APACHE_RUN_USER':'asterisk', 'APACHE_RUN_GROUP':'asterisk',
                 'APACHE_PID_FILE':str(base/'pid')}
            result=subprocess.run(['/usr/bin/python3','-I','-c',CODE],
                capture_output=True,text=True,timeout=15,env=env)
            if observe_local:
                discovery=subprocess.run(['/usr/sbin/apache2ctl','-t','-D','DUMP_VHOSTS','-D','DUMP_CONFIG',
                    '-C','LoadModule info_module /usr/lib/apache2/modules/mod_info.so'],
                    capture_output=True,text=True,timeout=10,env=env)
                self.assertEqual(discovery.returncode,0,discovery.stderr)
                before,marker,effective=discovery.stdout.partition('# In file:')
                self.assertTrue(marker,'The native route observation requires effective DUMP_CONFIG')
                probe=r'''namespace FreePBX\modules {
require dirname($argv[1],2).'/tools/fixtures/local_web_curl.php';
$GLOBALS['localWebCurlObserver']=static function($url,$options){$GLOBALS['requests'][]=$url;return '{}';};
}
namespace {require $argv[1];$GLOBALS['requests']=[];
try { iterator_to_array(\FreePBX\modules\SlsLocalWebProbe::responses('pbx.audit.invalid',
$argv[4],['Authorization: Bearer inert-scope-fixture'],1,$argv[2],$argv[3])); }
catch (\RuntimeException $error) {}
echo json_encode($GLOBALS['requests']);}
'''
                observed=subprocess.run(['/usr/bin/php','-r',probe,str(ROOT/'slsmassnotifyserver/LocalWebProbe.php'),before,effective,request_path],
                    capture_output=True,text=True,timeout=5)
                self.assertEqual(observed.returncode,0,observed.stderr)
                result.local_requests=json.loads(observed.stdout)
            self.assertFalse((base/'pid').exists())
            return result

    def test_native_same_vhost_unrelated_scopes_do_not_impose_their_handlers(self):
        cases={
            'directory':'<Directory /srv/unrelated>\nSetHandler "proxy:fcgi://192.0.2.1:9000"\n</Directory>\n',
            'location':'<Location /unrelated>\nSetHandler "proxy:fcgi://192.0.2.1:9000"\n</Location>\n',
            'files':'<FilesMatch "\\.(?:css|js)$">\nSetHandler "proxy:fcgi://192.0.2.1:9000"\n</FilesMatch>\n',
            'proxy':'ProxyPass /unrelated fcgi://192.0.2.1:9000\n',
        }
        for label,scope in cases.items():
            result=self.native('',pbx_extra=scope,observe_local=True)
            with self.subTest(scope=label,component='php_profile'):
                self.assertEqual(result.returncode,0,result.stderr)
                self.assertEqual(result.stdout.strip(),'8.2:apache2')
            with self.subTest(scope=label,component='local_request'):
                self.assertEqual(len(result.local_requests),2,'Unrelated scope blocked the independently qualified PBX request')

    def test_native_same_vhost_active_pbx_handlers_remain_refused(self):
        for scope in (
            '<Location /api/sls-mass-notify>\nSetHandler "proxy:fcgi://192.0.2.1:9000"\n</Location>\n',
            '<FilesMatch "\\.php$">\nSetHandler "proxy:fcgi://192.0.2.1:9000"\n</FilesMatch>\n',
            'ProxyPass /api/sls-mass-notify fcgi://192.0.2.1:9000\n',
        ):
            with self.subTest(scope=scope):
                result=self.native('',pbx_extra=scope,observe_local=True)
                self.assertNotEqual(result.returncode,0)
                self.assertIn('handler',result.stderr.lower())
                self.assertEqual(result.local_requests,[],'Active unsupported PBX handler received credentials')

    def test_static_selector_is_still_binding_for_an_actual_static_path_request(self):
        scope='<FilesMatch "\\.(?:css|js)$">\nSetHandler "proxy:fcgi://192.0.2.1:9000"\n</FilesMatch>\n'
        for path in ('/api/sls-mass-notify/private.css','/api/sls-mass-notify/private.css/following',
                     '/api/sls-mass-notify/private.css/following.php'):
            with self.subTest(path=path):
                result=self.native('',pbx_extra=scope,observe_local=True,request_path=path)
                self.assertEqual(result.returncode,0,result.stderr)
                self.assertEqual(result.local_requests,[],'A matching nonPHP handler received credentials for the actual requested filename or PATH_INFO prefix')

    def test_scoped_fpm_keeps_the_modphp_profile_for_other_pbx_routes(self):
        spec=importlib.util.spec_from_file_location('mixed_preparation',ROOT/'tools/test_installer_preparation.py')
        preparation=importlib.util.module_from_spec(spec);spec.loader.exec_module(preparation)
        for api in ('sls-mass-notify','sipnotify'):
            with self.subTest(api=api),tempfile.TemporaryDirectory(dir='/run',prefix='sls-mixed-php-') as name:
                handler='LoadModule php_module /usr/lib/apache2/modules/libphp8.2.so\nUser asterisk\nGroup asterisk\n'
                handler+='<FilesMatch "\\.php$">\nSetHandler application/x-httpd-php\n</FilesMatch>\n'
                handler+='<Location /api/'+api+'>\nSetHandler "proxy:unix:/run/php/php8.2-fpm.sock|fcgi://localhost"\n</Location>\n'
                result=preparation.Preparation().php_profile(Path(name),handler)
                self.assertEqual(result.returncode,0,result.stderr)
                self.assertEqual(result.stdout.splitlines(),['8.2:apache2','8.2:fpm'],
                    'A scoped API pool hid the Apache PHP profile still serving /admin and other PBX routes')
        for directive in ('User www-data\nGroup asterisk\n','User asterisk\nGroup www-data\n'):
            with self.subTest(principal=directive),tempfile.TemporaryDirectory(dir='/run',prefix='sls-mixed-principal-') as name:
                handler='LoadModule php_module /usr/lib/apache2/modules/libphp8.2.so\n'+directive
                handler+='<FilesMatch "\\.php$">\nSetHandler application/x-httpd-php\n</FilesMatch>\n'
                handler+='<Location /api/sls-mass-notify>\nSetHandler "proxy:unix:/run/php/php8.2-fpm.sock|fcgi://localhost"\n</Location>\n'
                result=preparation.Preparation().php_profile(Path(name),handler)
                self.assertNotEqual(result.returncode,0,'A safe API pool hid the foreign principal serving PBX mod_php')
                self.assertIn('asterisk',result.stderr)

    def test_proven_all_php_fpm_can_leave_an_unused_apache_module_unselected(self):
        spec=importlib.util.spec_from_file_location('blanket_preparation',ROOT/'tools/test_installer_preparation.py')
        preparation=importlib.util.module_from_spec(spec);spec.loader.exec_module(preparation)
        handler='LoadModule php_module /usr/lib/apache2/modules/libphp8.2.so\nUser www-data\nGroup www-data\n'
        handler+='<FilesMatch "\\.php$">\nSetHandler "proxy:unix:/run/php/php8.2-fpm.sock|fcgi://localhost"\n</FilesMatch>\n'
        with tempfile.TemporaryDirectory(dir='/run',prefix='sls-blanket-php-') as name:
            result=preparation.Preparation().php_profile(Path(name),handler)
            self.assertEqual(result.returncode,0,result.stderr)
            self.assertEqual(result.stdout.splitlines(),['8.2:fpm'])
            overlapping=handler+'<FilesMatch "\\.php$">\nSetHandler application/x-httpd-php\n</FilesMatch>\n'
            result=preparation.Preparation().php_profile(Path(name),overlapping)
            self.assertNotEqual(result.returncode,0,'Overlapping blanket FPM and explicit mod_php silently omitted a possible principal')
            self.assertIn('Apache mod_php must run as the asterisk',result.stderr)

    def test_overlapping_php_handlers_qualify_apache_and_every_local_pool(self):
        spec=importlib.util.spec_from_file_location('overlap_preparation',ROOT/'tools/test_installer_preparation.py')
        preparation=importlib.util.module_from_spec(spec)
        spec.loader.exec_module(preparation)
        handler=('LoadModule php_module /usr/lib/apache2/modules/libphp8.2.so\nUser asterisk\nGroup asterisk\n'
                 '<FilesMatch ".+\\.ph(?:ar|p|tml)$">\nSetHandler application/x-httpd-php\n</FilesMatch>\n'
                 '<FilesMatch "\\.php$">\nSetHandler "proxy:unix:/run/php/php8.2-fpm.sock|fcgi://localhost"\n</FilesMatch>\n'
                 '<Location /api/sipnotify>\nSetHandler "proxy:unix:/run/php/desktop.sock|fcgi://localhost"\n</Location>\n')
        pool='[desktop]\nuser=asterisk\ngroup=asterisk\nlisten=/run/php/desktop.sock\n'
        cases=[
            (handler,pool,None),
            (handler.replace('Group asterisk','Group www-data'),pool,'asterisk primary group'),
            (handler,pool.replace('user=asterisk','user=www-data'),'must run as asterisk'),
            (handler,pool.replace('group=asterisk','group=www-data'),'asterisk primary group'),
            (handler,pool+'php_admin_value[disable_functions]=proc_open\n','disables required functions'),
            (handler.replace('unix:/run/php/desktop.sock|fcgi://localhost','fcgi://192.0.2.1:9000'),pool,'unidentified or remote'),
        ]
        for apache,pool_text,error in cases:
            with self.subTest(expected_error=error),tempfile.TemporaryDirectory(dir='/run',prefix='sls-php-overlap-') as name:
                result=preparation.Preparation().php_profile(Path(name),apache,extra_pools={'desktop.conf':pool_text})
                if error:
                    self.assertNotEqual(result.returncode,0)
                    self.assertIn(error,result.stderr)
                else:
                    self.assertEqual(result.returncode,0,result.stderr)
                    self.assertEqual(result.stdout.splitlines(),['8.2:apache2','8.2:fpm'])

    def test_inactive_remote_handler_does_not_reject_actual_modphp_route(self):
        result=self.native('<IfDefine SLS_NOT_DEFINED>\n'
            'SetHandler "proxy:fcgi://192.0.2.1:9000"\n</IfDefine>\n')
        self.assertEqual(result.returncode,0,result.stderr)
        self.assertEqual(result.stdout.strip(),'8.2:apache2')

    def test_unrelated_vhost_handler_does_not_impose_its_pool_on_the_pbx(self):
        result=self.native('<VirtualHost *:8080>\nServerName unrelated.audit.invalid\n'
            'DocumentRoot /srv/unrelated\n<FilesMatch "\\.php$">\n'
            'SetHandler "proxy:fcgi://192.0.2.1:9000"\n</FilesMatch>\n</VirtualHost>\n')
        self.assertEqual(result.returncode,0,result.stderr)
        self.assertEqual(result.stdout.strip(),'8.2:apache2')

    def test_active_unknown_handler_on_a_pbx_vhost_remains_refused(self):
        result=self.native('<VirtualHost *:8444>\nServerName second-pbx.audit.invalid\n'
            'DocumentRoot /var/www/html\n<FilesMatch "\\.php$">\n'
            'SetHandler "proxy:fcgi://192.0.2.1:9000"\n</FilesMatch>\n</VirtualHost>\n')
        self.assertNotEqual(result.returncode,0)
        self.assertIn('handler',result.stderr.lower())

    def test_fpm_foreign_primary_group_is_refused_before_activation(self):
        spec=importlib.util.spec_from_file_location('route_preparation',ROOT/'tools/test_installer_preparation.py')
        preparation=importlib.util.module_from_spec(spec);spec.loader.exec_module(preparation)
        with tempfile.TemporaryDirectory(dir='/run',prefix='sls-php-group-') as name:
            root=Path(name)
            handler='SetHandler "proxy:unix:/run/php/php8.2-fpm.sock|fcgi://localhost"\n'
            result=preparation.Preparation().php_profile(root,handler,extra_pool='group = www-data\n')
            self.assertNotEqual(result.returncode,0)
            self.assertIn('group',result.stderr.lower())


if __name__=='__main__': unittest.main()
