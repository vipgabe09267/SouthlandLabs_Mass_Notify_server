#!/usr/bin/python3
"""Actual NWS callfile loop, private spool, inert current-source predicate."""
import os
from pathlib import Path
import shlex
import subprocess
import tempfile
import unittest

if os.environ.get('SLS_TEST_NAMESPACE')!='entered':
    raise SystemExit('Use the unchanged isolated test wrapper.')
ROOT=Path(__file__).resolve().parents[1]
SOURCE=ROOT/'slsmassnotifyserver/bin/sls_mass_notify_nws_poll.sh'


class NwsAudioBoundary(unittest.TestCase):
    def execute(self,cancel_after_first=False,removed=''):
        text=SOURCE.read_text()
        start=text.index('  for recipient in "${admitted_recipients[@]}"; do')
        end=text.index('\n}\n\nacquire_audio_delivery_slot()',start)
        loop=text[start:end]
        with tempfile.TemporaryDirectory(prefix='sls-nws-spool-boundary-') as name:
            root=Path(name);outgoing=root/'outgoing';outgoing.mkdir();staging=root/'staging';staging.mkdir()
            guard=root/'inert-cluster-guard.py';guard.write_text('raise SystemExit(0)\n')
            original='/usr/local/bin/sls_mass_notify/sls_cluster_guard.py'
            self.assertEqual(loop.count(original),1)
            loop=loop.replace(original,shlex.quote(str(guard)),1)
            script=root/'loop.sh'
            setup='''#!/bin/bash
set -u
SPOOL={outgoing}
SPOOL_TMP={staging}
LOG={log}
CONFIG_JSON_FILE={config}
cancelled={cancelled}
source_change={change}
removed={removed}
admitted_recipients=(1001 1002)
NWS_ALERT_RECIPIENTS=(1001 1002)
accepted_count=2
voicemail_copy_failed=0
phone_token=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
SLS_AUDIO_CONTEXT=sls-alert-audio
SLS_CALLERID_NAME=Fixture
SLS_CALLERID_NUM=SLS
sound_sequence=SLS_Mass_Notifications_Plugin/tts/fixture
call_wait_seconds=30
page_hold_seconds=5
queued=0
event=Fixture
alert_id=synthetic
queued_delivery_is_current() {{
 test ! -e "$cancelled" || return 1
 if [ "$#" -gt 0 ] && [ "$1" = "$removed" ]; then return 1; fi
 return 0
}}
report_fault() {{ printf '%s\\n' "private fault: $*" >> "$LOG"; }}
mv() {{
 command mv "$@" || return $?
 if [ "$source_change" = 1 ]; then : > "$cancelled"; fi
}}
fixture_queue() {{
 queued_delivery_is_current || return 1
'''.format(outgoing=shlex.quote(str(outgoing)),staging=shlex.quote(str(staging)),log=shlex.quote(str(root/'log')),
                config=shlex.quote(str(root/'config')),cancelled=shlex.quote(str(root/'cancelled')),
                change='1' if cancel_after_first else '0',removed=shlex.quote(removed))
            script.write_text(setup+loop+'\n}\nfixture_queue\ncode=$?\nprintf "status=%s queued=%s\\n" "$code" "$queued"\n')
            result=subprocess.run(['/bin/bash',str(script)],capture_output=True,text=True,timeout=5,
                env={'PATH':'/usr/sbin:/usr/bin:/sbin:/bin','LANG':'C.UTF-8'})
            self.assertEqual(result.returncode,0,result.stderr)
            self.assertEqual(result.stderr,'')
            files=[path.read_text() for path in outgoing.iterdir()]
            self.assertEqual(list(staging.iterdir()),[])
            return files,result.stdout

    def test_unchanged_source_queues_both_original_private_tickets(self):
        files,status=self.execute()
        self.assertEqual(len(files),2)
        self.assertIn('status=0 queued=2',status)

    def test_source_changed_after_first_enqueue_preserves_first_and_stops_second(self):
        files,status=self.execute(cancel_after_first=True)
        self.assertEqual(len(files),1,'Second NWS callfile queued after current-source predicate became false')
        self.assertIn('Local/1001@',files[0])
        self.assertIn('status=1 queued=1',status)

    def test_removed_first_phone_does_not_suppress_independently_allowed_later_phone(self):
        files,status=self.execute(removed='1001')
        self.assertEqual(len(files),1)
        self.assertIn('Local/1002@',files[0])
        self.assertIn('status=1 queued=1',status)


if __name__=='__main__':unittest.main()
