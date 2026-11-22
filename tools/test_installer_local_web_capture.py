#!/usr/bin/python3
"""Root inspection passes bounded nonsecret route authority to the web UID."""
import ast
import http.server
import json
import os
from pathlib import Path
import pwd
import shutil
import socket
import subprocess
import tarfile
import tempfile
import threading
import unittest

if os.environ.get('SLS_TEST_NAMESPACE')!='entered': raise RuntimeError('Use the isolated wrapper')
ROOT=Path(__file__).resolve().parents[1]


class RootRouteCapture(unittest.TestCase):
    def test_rewrite_conditions_preserve_route_scope_without_passing_secrets(self):
        installer=(ROOT/'tools/install_release.sh').read_text()
        block=installer.split('capture_local_web_probe_authority() {',1)[1].split('\n}\n',1)[0]
        sanitizer=block.split("| /usr/bin/python3 -I -c '\n",1)[1].split("\n')\"",1)[0]
        exclusion='!^/(api/(sipnotify|sls-mass-notify)|sls_mass_notify)(/|$)'
        raw=('# In file: /audit/apache.conf\n'
             'RewriteCond %{HTTP:Authorization} hidden-secret [OR]\n'
             f'RewriteCond %{{REQUEST_URI}} {exclusion}\n'
             'RewriteRule ^ https://hidden-endpoint.invalid/path [R=308,L,NE]\n'
             'RewriteCond %{REQUEST_URI} !^/public/\n'
             'AllowOverride None\n'
             'RewriteRule ^ https://hidden-endpoint.invalid/ [R=302,L]\n'
             'RewriteCond %{LA-U:REQUEST_FILENAME} -U [OR]\n'
             'RewriteCond %{REQUEST_URI} -F\n'
             'RewriteCond %{HTTP_HOST} ^pbx[.]example$ [NC]\n')
        result=subprocess.run(['/usr/bin/python3','-I','-c',sanitizer],input=raw,
                              capture_output=True,text=True,timeout=5,check=True)
        self.assertEqual(json.loads(result.stdout)['config'].splitlines(),[
            'RewriteCond UNKNOWN UNKNOWN [OR]', f'RewriteCond %{{REQUEST_URI}} {exclusion}',
            'RewriteRule ^ UNQUALIFIED_REMOTE_HANDLER [R=308,L,NE]',
            'RewriteCond %{REQUEST_URI} !^/public/', 'SLSRewriteBoundary reset',
            'RewriteRule ^ UNQUALIFIED_REMOTE_HANDLER [R=302,L]',
            'RewriteCond UNKNOWN UNKNOWN [UNKNOWN]', 'RewriteCond UNKNOWN UNKNOWN [UNKNOWN]',
            'RewriteCond UNKNOWN UNKNOWN [NC]'])

    def test_normal_installer_uses_current_carrier_on_ipv4(self):
        self.check_carrier('127.0.0.1', recovery=False)

    def test_corrected_recovery_uses_current_carrier_on_ipv6(self):
        self.check_carrier('::1', recovery=True)

    def check_carrier(self, address, recovery):
        # Run the normal installer function and actual PHP/libcurl as asterisk.
        # Both the private network namespace and the ephemeral listener are local.
        self.assertEqual(os.environ['SLS_TEST_NAMESPACE'], 'entered')
        self.assertNotEqual(os.readlink('/proc/self/ns/net'), os.environ['SLS_TEST_PARENT_NET_NS'])
        calls = []
        class Handler(http.server.BaseHTTPRequestHandler):
            def do_GET(self):
                calls.append((self.path, self.headers['Host']))
                self.send_response(200); self.end_headers(); self.wfile.write(b'fixture\x00media')
            def log_message(self, *args):
                pass
        class LocalServer(http.server.ThreadingHTTPServer):
            address_family = socket.AF_INET6 if ':' in address else socket.AF_INET

        server = LocalServer((address, 0), Handler)
        self.addCleanup(server.server_close)
        with tempfile.TemporaryDirectory(dir='/run', prefix='sls-carrier-route-') as name:
            root = Path(name); root.chmod(0o755)
            worker = threading.Thread(target=server.serve_forever, daemon=True); worker.start()
            self.addCleanup(worker.join, 2); self.addCleanup(server.shutdown)
            carrier = root/'carrier'; carrier.mkdir(mode=0o700)
            (carrier/'bootstrap').mkdir(mode=0o700)
            probe = ROOT/'slsmassnotifyserver/LocalWebProbe.php'
            with tarfile.open(carrier/'package.tgz', 'w:gz') as archive:
                archive.add(probe, arcname='slsmassnotifyserver/LocalWebProbe.php')
            (carrier/'package.tgz').chmod(0o600)
            config = root/'settings.json'; config.write_text('{"public_pbx_host":"pbx.fixture.invalid"}'); config.chmod(0o644)
            crypto = root/'crypto.php'; shutil.copyfile(ROOT/'slsmassnotifyserver/api/sls-mass-notify/config-crypto.php', crypto); crypto.chmod(0o644)
            installer = root/'installer.sh'
            installer.write_text((ROOT/'tools/install_release.sh').read_text().replace(
                '/usr/local/bin/sls_mass_notify/sls_config_crypto.php', str(crypto)).replace(
                '/var/lib/asterisk/SLS_Mass_Notifications_Plugin/mass-notifications.config',str(config)).replace(
                '/var/www/html/admin/modules/slsmassnotifyserver/LocalWebProbe.php',str(root/'absent-legacy-helper.php')))
            private = root/'private'; private.mkdir(mode=0o700)
            output=private/'response'; port=str(server.server_port); host='pbx.fixture.invalid'
            binding = ('[' + address + ']' if ':' in address else address) + ':' + port
            inventory=binding+' '+host+' (/fixture/native.conf:1)'
            base='Listen '+binding+'\n<VirtualHost '+binding+'>\nServerName '+host+'\nDocumentRoot /var/www/html\n'
            shell=r'''source "$1"
INSTALL_BOOTSTRAP_DIR="$2/carrier/bootstrap"
if [ "$5" = recovery ]; then
  RECOVERY_PROGRAM_DIR="$INSTALL_BOOTSTRAP_DIR"
  INSTALL_BOOTSTRAP_DIR="$2/absent-obsolete/bootstrap"
fi
LOG_FILE="$2/installer.log"
capture_local_web_probe_authority() { SLS_LOCAL_WEB_VHOST_DUMP="$vhosts"; SLS_LOCAL_WEB_CONFIG_DUMP="$configuration"; }
curl() { return 1; }
local_web_probe "$3" "$4" '^200$'
'''
            def run(path, directives=''):
                output.unlink(missing_ok=True)
                return subprocess.run(['/bin/bash','-c',shell,'fixture',str(installer),str(root),path,str(output),
                                       'recovery' if recovery else 'normal'],
                    env={**os.environ,'vhosts':inventory,'configuration':base+directives+'</VirtualHost>\n'},
                    capture_output=True,text=True,timeout=12)
            media='/sls_mass_notify/installer-render-check-425.png'
            result=run(media)
            self.assertEqual((result.returncode,result.stdout),(0,'200\n'),result.stderr)
            self.assertEqual(output.read_bytes(),b'fixture\x00media')
            self.assertEqual(calls,[(media,host+':'+port)])
            # A scoped native alias must refuse this exact media path while the API remains usable.
            override='Alias /sls_mass_notify /srv/other-fixture\n'
            result=run(media,override)
            self.assertNotEqual(result.returncode,0); self.assertEqual(result.stdout,'000\n')
            self.assertEqual(len(calls),1)
            api='/api/sls-mass-notify/?sls_installer_runtime=1'
            result=run(api,override)
            self.assertEqual((result.returncode,result.stdout),(0,'200\n'),result.stderr)
            self.assertEqual(calls[-1],(api,host+':'+port))
            (carrier/'package.tgz').write_bytes(b'not the approved carrier')
            result=run(api)
            self.assertNotEqual(result.returncode,0); self.assertEqual(result.stdout,'000\n')
            self.assertEqual(len(calls),2)

    def unnamed_routes(self, vhosts=None, config=None, host=None):
        fixture=json.loads((ROOT/'tools/fixtures/freepbx17-manual-unnamed-apache-route.json').read_text())
        tree=ast.parse((ROOT/'slsmassnotifyserver/bin/sls_mass_notify/sls_privileged_install.py').read_text())
        apache=next(ast.literal_eval(node.value) for node in tree.body
                    if isinstance(node,ast.Assign) and any(isinstance(target,ast.Name) and target.id=='APACHE'
                                                         for target in node.targets))
        php=r'''
require $argv[1];
$input=json_decode(stream_get_contents(STDIN),true,32,JSON_THROW_ON_ERROR);
echo json_encode([
    'api'=>\FreePBX\modules\SlsLocalWebProbe::targets($input['host'],$input['vhosts'],$input['config']),
    'media'=>\FreePBX\modules\SlsLocalWebProbe::targets($input['host'],$input['vhosts'],$input['config'],$input['path'])
],JSON_THROW_ON_ERROR);
'''
        result=subprocess.run(['/usr/bin/php','-r',php,str(ROOT/'slsmassnotifyserver/LocalWebProbe.php')],
            input=json.dumps({'host':fixture['public_host'] if host is None else host, 'path':fixture['media_path'],
                              'vhosts':fixture['vhosts'] if vhosts is None else vhosts,
                              'config':(fixture['config'] if config is None else config)+'\n'+apache}),
            capture_output=True,text=True,timeout=5,check=True)
        self.assertEqual(result.stderr,'')
        return json.loads(result.stdout)

    def test_sole_unnamed_native_vhost_accepts_saved_machine_hostname(self):
        # Regression: requiring an inferred ServerName rejected the ordinary
        # manual install although its only vhost serves every valid Host.
        result=self.unnamed_routes()
        for kind in ('api','media'):
            with self.subTest(kind=kind):
                self.assertEqual(len(result[kind]),2,'The sole native unnamed PBX vhost must authorize both loopback families')
                self.assertEqual({row['connect_url'] for row in result[kind]},
                                 {'http://127.0.0.1:80','http://[::1]:80'})
                self.assertTrue(all(row['host']=='manual-pbx.audit.invalid' and row['route_authorized']
                                    for row in result[kind]),'The configured Host must remain intact')

    def test_unnamed_admission_requires_unique_native_authority_and_no_explicit_name(self):
        unnamed='<VirtualHost *:80>\nDocumentRoot /var/www/html\n</VirtualHost>\n'
        named=unnamed.replace('DocumentRoot','ServerName named.audit.invalid\nDocumentRoot')
        cases=[
            ('explicit_server_name','*:80 named.audit.invalid (/audit/pbx.conf:1)','Listen 80\n'+named),
            ('explicit_alias','*:80 127.0.1.1 (/audit/pbx.conf:1)',
             'Listen 80\n'+unnamed.replace('DocumentRoot','ServerAlias alias.audit.invalid\nDocumentRoot')),
            ('inherited_name','*:80 named.audit.invalid (/audit/pbx.conf:1)',
             'ServerName named.audit.invalid\nListen 80\n'+unnamed),
            ('unclassified_explicit_name','*:80 pbx_host.audit.invalid (/audit/pbx.conf:1)',
             'Listen 80\n'+unnamed.replace('DocumentRoot','ServerName pbx_host.audit.invalid\nDocumentRoot')),
            ('unclassified_explicit_alias','*:80 127.0.1.1 (/audit/pbx.conf:1)',
             'Listen 80\n'+unnamed.replace('DocumentRoot','ServerAlias pbx_alias.audit.invalid\nDocumentRoot')),
            ('unclassified_inherited_name','*:80 pbx_host.audit.invalid (/audit/pbx.conf:1)',
             'ServerName pbx_host.audit.invalid\nListen 80\n'+unnamed),
            ('missing_native_inventory','','Listen 80\n'+unnamed),
            ('multiple_config_vhosts','*:80 127.0.1.1 (/audit/pbx.conf:1)',
             'Listen 80\n'+unnamed+'<VirtualHost *:80>\nDocumentRoot /var/www/decoy\n</VirtualHost>\n'),
            ('multiple_native_vhosts','*:80 is a NameVirtualHost\n port 80 namevhost 127.0.1.1 (/audit/one.conf:1)\n'
             ' port 80 namevhost 127.0.1.1 (/audit/two.conf:1)','Listen 80\n'+unnamed),
            ('unparsed_more_specific_native','*:80 127.0.1.1 (/audit/pbx.conf:1)\n'
             '127.0.0.1:80 decoy.audit.invalid (/audit/decoy.conf:1)','Listen 127.0.0.1:80\n'+unnamed),
            ('unparsed_native_wildcard_port','*:80 127.0.1.1 (/audit/pbx.conf:1)\n'
             '127.0.0.1:* decoy.audit.invalid (/audit/decoy.conf:1)','Listen 127.0.0.1:80\n'+unnamed),
            ('more_specific_decoy','*:80 127.0.1.1 (/audit/pbx.conf:1)\n'
             '127.0.0.1:80 decoy.audit.invalid (/audit/decoy.conf:1)',
             'Listen 127.0.0.1:80\n'+unnamed+'<VirtualHost 127.0.0.1:80>\nServerName decoy.audit.invalid\nDocumentRoot /var/www/decoy\n</VirtualHost>\n'),
            ('wildcard_port_decoy','*:80 127.0.1.1 (/audit/pbx.conf:1)\n'
             '127.0.0.1:* decoy.audit.invalid (/audit/decoy.conf:1)',
             'Listen 127.0.0.1:80\n'+unnamed+'<VirtualHost 127.0.0.1:*>\nDocumentRoot /var/www/decoy\n</VirtualHost>\n'),
            ('omitted_port_decoy','*:80 127.0.1.1 (/audit/pbx.conf:1)\n'
             '127.0.0.1:* decoy.audit.invalid (/audit/decoy.conf:1)',
             'Listen 127.0.0.1:80\n'+unnamed+'<VirtualHost 127.0.0.1>\nDocumentRoot /var/www/decoy\n</VirtualHost>\n'),
            ('wrong_root','*:80 127.0.1.1 (/audit/pbx.conf:1)',
             'Listen 80\n'+unnamed.replace('/var/www/html','/var/www/decoy')),
            ('remote_handler','*:80 127.0.1.1 (/audit/pbx.conf:1)',
             'Listen 80\n'+unnamed.replace('DocumentRoot','SetHandler proxy:fcgi://remote.audit.invalid:9000\nDocumentRoot')),
        ]
        for label,vhosts,config in cases:
            with self.subTest(case=label):
                self.assertEqual(self.unnamed_routes(vhosts,config),{'api':[],'media':[]})

    def test_sanitization_cannot_hide_an_unclassified_competing_native_vhost(self):
        config='Listen 127.0.0.1:80\n<VirtualHost *:80>\nDocumentRoot /var/www/html\n</VirtualHost>\n'
        raw=('VirtualHost configuration:\n*:80 127.0.1.1 (/audit/pbx.conf:1)\n'
             '127.0.0.1:* decoy.audit.invalid (/audit/decoy.conf:1)\n# In file: /audit/apache.conf\n'+config)
        installer=(ROOT/'tools/install_release.sh').read_text()
        block=installer.split('capture_local_web_probe_authority() {',1)[1].split('\n}\n',1)[0]
        sanitizer=block.split("| /usr/bin/python3 -I -c '\n",1)[1].split("\n')\"",1)[0]
        result=subprocess.run(['/usr/bin/python3','-I','-c',sanitizer],input=raw,
                              capture_output=True,text=True,timeout=5,check=True)
        authority=json.loads(result.stdout)
        self.assertEqual(self.unnamed_routes(authority['vhosts'],authority['config']),{'api':[],'media':[]},
                         'Root sanitization must retain the fact that native binding authority is incomplete')

    def test_named_route_cannot_ignore_unclassified_more_specific_binding(self):
        named='<VirtualHost *:80>\nServerName manual-pbx.audit.invalid\nDocumentRoot /var/www/html\n</VirtualHost>\n'
        native='*:80 manual-pbx.audit.invalid (/audit/pbx.conf:1)\n127.0.0.1:* decoy.audit.invalid (/audit/decoy.conf:1)'
        for config in ('Listen 127.0.0.1:80\n'+named,
                       'Listen 127.0.0.1:80\n'+named+'<VirtualHost 127.0.0.1:*>\nDocumentRoot /var/www/decoy\n</VirtualHost>\n'):
            with self.subTest(config=config):
                self.assertEqual(self.unnamed_routes(native,config),{'api':[],'media':[]},
                                 'A named wildcard must not authorize credentials for an unclassified exact-address vhost')

    def test_inferred_name_cannot_bypass_sole_unnamed_vhost_proof(self):
        native='*:80 is a NameVirtualHost\n port 80 namevhost 127.0.1.1 (/audit/one.conf:1)\n port 80 namevhost 127.0.1.1 (/audit/two.conf:1)'
        unnamed='<VirtualHost *:80>\nDocumentRoot /var/www/html\n</VirtualHost>\n'
        for config in ('Listen 80\n'+unnamed,'Listen 80\n'+unnamed+unnamed,
                       'Listen 80\n'+unnamed.replace('DocumentRoot','ServerAlias pbx_alias.audit.invalid\nDocumentRoot'),
                       'ServerName 127.0.1.1\nListen 80\n'+unnamed,
                       'ServerName pbx_host.audit.invalid\nListen 80\n'+unnamed):
            with self.subTest(config=config):
                self.assertEqual(self.unnamed_routes(native,config,host='127.0.1.1'),{'api':[],'media':[]},
                                 'Matching an inferred name cannot skip native/config multiplicity checks')

    def test_matching_inherited_name_retains_single_route_authority(self):
        native='*:80 manual-pbx.audit.invalid (/audit/pbx.conf:1)'
        config='ServerName manual-pbx.audit.invalid\nListen 127.0.0.1:80\n<VirtualHost *:80>\nDocumentRoot /var/www/html\n</VirtualHost>\n'
        result=self.unnamed_routes(native,config)
        for kind in ('api','media'):
            self.assertEqual(len(result[kind]),1)
            self.assertEqual(result[kind][0]['host'],'manual-pbx.audit.invalid')

    def test_named_and_main_routes_require_matching_native_binding_rank_and_count(self):
        named='<VirtualHost *:80>\nServerName manual-pbx.audit.invalid\nDocumentRoot /var/www/html\n</VirtualHost>\n'
        other='<VirtualHost *:80>\nServerName decoy.audit.invalid\nDocumentRoot /var/www/decoy\n</VirtualHost>\n'
        one='*:80 manual-pbx.audit.invalid (/audit/pbx.conf:1)'
        two='*:80 is a NameVirtualHost\n port 80 namevhost decoy.audit.invalid (/audit/one.conf:1)\n port 80 namevhost manual-pbx.audit.invalid (/audit/two.conf:1)'
        cases=[
            ('native_extra_vhost',two,'Listen 127.0.0.1:80\n'+named),
            ('config_extra_vhost',one,'Listen 127.0.0.1:80\n'+named+other),
            ('normalized_exact_address',one+'\n127.0.0.1:80 decoy.audit.invalid (/audit/decoy.conf:1)',
             'Listen 127.0.0.1:80\n'+named+other.replace('*:80','127.0.0.01:80')),
            ('main_omits_native_vhost','127.0.0.1:80 decoy.audit.invalid (/audit/decoy.conf:1)',
             'Listen 127.0.0.1:80\nServerName manual-pbx.audit.invalid\nDocumentRoot /var/www/html\n'),
        ]
        for label,native,config in cases:
            with self.subTest(case=label):
                self.assertEqual(self.unnamed_routes(native,config),{'api':[],'media':[]},
                                 'Hostname matching cannot replace native/config address precedence agreement')

    def test_main_server_retains_authority_when_no_native_vhost_owns_the_socket(self):
        result=self.unnamed_routes('', 'Listen 127.0.0.1:80\nServerName manual-pbx.audit.invalid\nDocumentRoot /var/www/html\n')
        self.assertEqual({kind:len(rows) for kind,rows in result.items()},{'api':1,'media':1})

    def test_actual_default_freepbx_dump_keeps_publisher_media_rewrite_route_authorized(self):
        fixture=json.loads((ROOT/'tools/fixtures/freepbx17-default-apache-media-route.json').read_text())
        tree=ast.parse((ROOT/'slsmassnotifyserver/bin/sls_mass_notify/sls_privileged_install.py').read_text())
        apache=next(ast.literal_eval(node.value) for node in tree.body
                    if isinstance(node,ast.Assign) and any(isinstance(target,ast.Name) and target.id=='APACHE'
                                                         for target in node.targets))
        # Reconstructed global SLL block, not a claim of observed pre-rollback
        # bytes. Both the stock native dump and publisher block stay unedited.
        raw=fixture['apache_dump']+'\n# In file: /etc/apache2/conf-enabled/sls-mass-notify.conf\n'+apache
        installer=(ROOT/'tools/install_release.sh').read_text()
        block=installer.split('capture_local_web_probe_authority() {',1)[1].split('\n}\n',1)[0]
        sanitizer=block.split("| /usr/bin/python3 -I -c '\n",1)[1].split("\n')\"",1)[0]
        observed=subprocess.run(['/usr/bin/python3','-I','-c',sanitizer],input=raw,
                                capture_output=True,text=True,timeout=5,check=True)
        authority=json.loads(observed.stdout)
        php=r'''
require $argv[1];
$input=json_decode(stream_get_contents(STDIN),true,32,JSON_THROW_ON_ERROR);
echo json_encode([
  'api'=>\FreePBX\modules\SlsLocalWebProbe::targets($input['host'],$input['vhosts'],$input['config']),
  'media'=>\FreePBX\modules\SlsLocalWebProbe::targets($input['host'],$input['vhosts'],$input['config'],$input['path'])
],JSON_THROW_ON_ERROR);
exit(0);
'''
        def inspect(config,path=fixture['media_path']):
            result=subprocess.run(['/usr/bin/php','-r',php,str(ROOT/'slsmassnotifyserver/LocalWebProbe.php')],
                input=json.dumps({**authority,'config':config,'host':fixture['public_host'],'path':path}),
                capture_output=True,text=True,timeout=5,check=True)
            return json.loads(result.stdout)
        source_block='<FilesMatch ".+\\.phps$">\nSetHandler application/x-httpd-php-source\n</FilesMatch>'
        self.assertIn(source_block,authority['config'],'The native Debian source-view handler must remain in this regression input')
        control=inspect(authority['config'].replace(source_block,''))
        self.assertTrue(control['api'] and control['media'],'Removing only the irrelevant native source-view block must isolate the authority failure')
        # A PHP-matching remote handler must still block both direct PHP APIs
        # and media that internally rewrites to the PHP policy handler.
        remote='<FilesMatch ".+\\.php$">\nSetHandler proxy:fcgi://remote.audit.invalid:9000\n</FilesMatch>'
        blocked=inspect(authority['config'].replace(source_block,remote))
        self.assertEqual(blocked,{'api':[],'media':[]})
        for path in ('/api/sls-mass-notify/index.phps','/api/sls-mass-notify/index.phps/extra','/unqualified-extensionless'):
            with self.subTest(path=path):
                matching=inspect(authority['config'],path)
                self.assertEqual(matching['media'],[],'Matching, PATH_INFO or unknown extensionless source-handler routes must never gain credential authority')
        for destination in ('/unreviewed-handler.php?file=$1 [END,QSA]',
                            'https://remote.audit.invalid/media [R,L]'):
            with self.subTest(destination=destination):
                unsafe=authority['config'].replace('/api/sls-mass-notify/media.php?file=$1 [END,QSA]',destination)
                altered=inspect(unsafe)
                self.assertTrue(altered['api'],'An unrelated generated-media override must not erase API route scope')
                self.assertEqual(altered['media'],[],'Only the exact publisher policy rewrite may authorize generated-media routes')
        routes=inspect(authority['config'])
        self.assertTrue(routes['api'],'The actual native baseline must first qualify the ordinary PBX API route')
        self.assertTrue(routes['media'],'The exact publisher media rewrite must retain local route authority on the default native PBX')
        self.assertTrue(all(row['route_authorized'] and row['host_matched'] for row in routes['media']))
        self.assertTrue(all(row['connect_url'].split('://',1)[1].split(':',1)[0] in ('127.0.0.1','[')
                            for row in routes['media']))

    def observe(self, override='', expected_targets=True):
        with tempfile.TemporaryDirectory(dir='/run',prefix='sls-route-capture-') as name:
            root=Path(name);root.chmod(0o755)
            include=root/'root-private.conf'
            include.write_text('Listen 18080\n<VirtualHost *:18080>\nServerName pbx.audit.invalid\n'
                'DocumentRoot /var/www/html\nSetEnv SLS_TEST_PRIVATE_VALUE inert-must-not-cross-boundary\n'+override+'</VirtualHost>\n')
            include.chmod(0o600)
            config=root/'apache2.conf'
            config.write_text('ServerRoot '+str(root)+'\nServerName audit.invalid\nErrorLog /dev/null\n'
                'PidFile '+str(root/'pid')+'\nLoadModule mpm_prefork_module /usr/lib/apache2/modules/mod_mpm_prefork.so\n'
                'LoadModule env_module /usr/lib/apache2/modules/mod_env.so\nUser asterisk\nGroup asterisk\nInclude '+str(include)+'\n')
            config.write_text(config.read_text().replace('LoadModule env_module ',
                'LoadModule alias_module /usr/lib/apache2/modules/mod_alias.so\n'
                'LoadModule proxy_module /usr/lib/apache2/modules/mod_proxy.so\nLoadModule env_module '))
            config.chmod(0o644)
            for relative in ('LocalWebProbe.php','api/sls-mass-notify/security.php'):
                target=root/'module'/relative;target.parent.mkdir(parents=True,exist_ok=True)
                shutil.copyfile(ROOT/'slsmassnotifyserver'/relative,target);target.chmod(0o644)
            for directory in (root/'module').rglob('*'):
                if directory.is_dir():directory.chmod(0o755)
            (root/'module').chmod(0o755)
            php=root/'capture.php'
            php.write_text('''<?php
require $argv[1];
$config=getenv('SLS_LOCAL_WEB_CONFIG_DUMP');$vhosts=getenv('SLS_LOCAL_WEB_VHOST_DUMP');
try{$targets=\\FreePBX\\modules\\SlsLocalWebProbe::targets('pbx.audit.invalid');}
catch(RuntimeException $error){$targets=[];}
echo json_encode(['uid'=>posix_geteuid(),'config'=>$config,'vhosts'=>$vhosts,'targets'=>$targets]);
''');php.chmod(0o644)
            shell='''source "$1"
LOG_FILE="$2/log"
capture_local_web_probe_authority
sls_as_asterisk /usr/bin/php "$2/capture.php" "$2/module/LocalWebProbe.php"
'''
            env={**os.environ,'APACHE_CONFDIR':str(root),'APACHE_ENVVARS':str(root/'none'),
                 'APACHE_RUN_DIR':str(root),'APACHE_LOCK_DIR':str(root),
                 'APACHE_RUN_USER':'asterisk','APACHE_RUN_GROUP':'asterisk','APACHE_PID_FILE':str(root/'pid')}
            result=subprocess.run(['/bin/bash','-c',shell,'fixture',str(ROOT/'tools/install_release.sh'),str(root)],
                capture_output=True,text=True,timeout=15,env=env)
            self.assertEqual(result.returncode,0,result.stderr)
            observed=json.loads(result.stdout)
            self.assertEqual(observed['uid'],pwd.getpwnam('asterisk').pw_uid)
            self.assertIn('DocumentRoot /var/www/html',observed['config'])
            self.assertNotIn('inert-must-not-cross-boundary',observed['config'])
            self.assertNotIn('SLS_TEST_PRIVATE_VALUE',observed['config'])
            self.assertNotIn('root-private.conf',observed['config'])
            self.assertNotIn('never-expose-proxy-credential',observed['config'])
            targets=observed['targets']
            self.assertEqual(bool(targets),expected_targets)
            self.assertTrue(all(t['host_matched'] for t in targets))
            self.assertTrue(all(':18080' in t['connect_url'] for t in targets))
            self.assertFalse((root/'pid').exists())

    def test_private_include_is_qualified_without_exposing_other_configuration(self):
        self.observe()

    def test_root_sanitizer_preserves_each_native_route_override_as_blocking(self):
        for directive in ('ScriptAlias /admin /srv/unrelated/\n',
                          'Redirect /admin https://unrelated.audit.invalid/\n',
                          'RedirectMatch "^/admin" https://unrelated.audit.invalid/\n'):
            with self.subTest(directive=directive.split()[0]):
                self.observe(directive,False)

    def test_sanitized_remote_override_keeps_its_literal_local_scope_without_credentials(self):
        self.observe('ProxyPass /unrelated http://user:never-expose-proxy-credential@unrelated.audit.invalid/\n',True)


if __name__=='__main__': unittest.main()
