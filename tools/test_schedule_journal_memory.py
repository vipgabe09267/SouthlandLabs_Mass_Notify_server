#!/usr/bin/env python3
"""Load a valid retained schedule journal under a bounded PHP memory limit."""
import hashlib
import json
from pathlib import Path
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]


class ScheduleJournalMemory(unittest.TestCase):
    def test_actual_runtime_reader_under_64_mib(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory=Path(temporary);path=directory/'schedule.json'
            occurrences={}
            for index in range(17000):
                identity='occ_'+hashlib.sha256(str(index).encode()).hexdigest()[:20]
                occurrences[identity]={'occurrence_id':identity,'schedule_id':'private_schedule',
                    'schedule_name':'Private retained schedule','state':'success','message':'x'*180,
                    'run_at_utc':'2026-10-13T12:00:00Z','claimed_at':'2026-10-13T12:00:00Z',
                    'completed_at':'2026-10-13T12:00:01Z','updated_at':'2026-10-13T12:00:01Z','attempts':1}
            ledger=json.dumps({'version':1,'occurrences':occurrences,'worker':{}},separators=(',',':'))
            if path.write_text(ledger,encoding='utf-8') != len(ledger):
                self.fail('The retained-journal fixture was not written completely.')
            script=directory/'reader.php'
            source='''<?php
interface BMO {}
require '''+json.dumps(str(ROOT/'slsmassnotifyserver/Slsmassnotifyserver.class.php'))+''';
$reflection=new ReflectionClass(FreePBX\\modules\\Slsmassnotifyserver::class);$lines=file($reflection->getFileName());
$fixture='class Reader {const MAX_SCHEDULES=50;const MAX_SCHEDULE_OCCURRENCES=500;const NATIVE_BACKUP_MAX_LEDGER_BYTES=16777216;const SCHEDULE_STATE_JSON='.var_export($argv[1],true).';';
foreach(['loadScheduleExecutionStore','validateNativeScheduleLedger','readNativeBackupFile','parseScheduleUtcTimestamp']as$name){
    $method=$reflection->getMethod($name);$fixture.=implode('',array_slice($lines,$method->getStartLine()-1,$method->getEndLine()-$method->getStartLine()+1));
}
eval($fixture.' public function read(){return $this->loadScheduleExecutionStore(true);}}');unset($fixture,$lines);
$ledger=(new Reader)->read();echo json_encode(['count'=>count($ledger['occurrences']),'peak'=>memory_get_peak_usage(true)]);
'''
            if script.write_text(source,encoding='utf-8') != len(source):
                self.fail('The retained-journal reader fixture was not written completely.')
            environment={'PATH':'/usr/bin:/bin','LANG':'C','LC_ALL':'C'}
            result=subprocess.run(['/usr/bin/php','-d','memory_limit=64M',str(script),str(path)],
                                  capture_output=True,text=True,timeout=8,env=environment,cwd=directory)
            self.assertEqual(result.returncode,0,result.stderr)
            self.assertEqual(result.stderr,'')
            report=json.loads(result.stdout)
            print('Schedule reader at 64 MiB: '+json.dumps(report,sort_keys=True))
            self.assertEqual(report['count'],17000)
            self.assertLess(report['peak'],64*1048576)


class LargeJsonValidation(unittest.TestCase):
    def test_large_json_guards_with_optional_cache_builtin_disabled(self):
        padding=json.dumps('x'*1048576)
        cases=[
            ('valid','{"padding":'+padding+',"answer":17}',True),
            ('escaped duplicate','{"padding":'+padding+',"a":1,"\\u0061":2}',False),
            ('nested duplicate','{"padding":'+padding+',"nested":{"x":1,"x":2}}',False),
            ('nonfinite','{"padding":'+padding+',"number":1e999}',False),
            ('trailing syntax','{"padding":'+padding+'} trailing',False),
            ('depth','{"padding":'+padding+',"nested":'+'['*64+'0'+']'*64+'}',False),
            ('nonobject','['+padding+']',False),
        ]
        with tempfile.TemporaryDirectory() as temporary:
            directory=Path(temporary);script=directory/'parser.php';path=directory/'input.json'
            script.write_text('''<?php
require '''+json.dumps(str(ROOT/'slsmassnotifyserver/api/sls-mass-notify/security.php'))+''';
try {
    $value=\\SLS\\MassNotify\\ApiSecurity::jsonObject(file_get_contents($argv[1]));
    echo json_encode(['accepted'=>true,'answer'=>$value['answer']??null,'padding_bytes'=>strlen($value['padding']??''),'cache_builtin'=>function_exists('gc_mem_caches')]);
} catch (Throwable $error) { echo json_encode(['accepted'=>false,'error_class'=>get_class($error),'cache_builtin'=>function_exists('gc_mem_caches')]); }
''')
            for disabled in [False,True]:
                for name,raw,accepted in cases:
                    with self.subTest(builtin_disabled=disabled,case=name):
                        path.write_text(raw);before=hashlib.sha256(path.read_bytes()).hexdigest()
                        command=['/usr/bin/php','-d','memory_limit=64M']
                        if disabled:command+=['-d','disable_functions=gc_mem_caches']
                        result=subprocess.run(command+[str(script),str(path)],capture_output=True,text=True,timeout=8,
                                              env={'PATH':'/usr/bin:/bin','LANG':'C','LC_ALL':'C'},cwd=directory)
                        self.assertEqual(result.returncode,0,result.stderr);self.assertEqual(result.stderr,'')
                        report=json.loads(result.stdout);self.assertIs(report['accepted'],accepted)
                        self.assertIs(report['cache_builtin'],not disabled)
                        if accepted:self.assertEqual((report['answer'],report['padding_bytes']),(17,1048576))
                        self.assertEqual(hashlib.sha256(path.read_bytes()).hexdigest(),before)

    def test_large_retained_journal_refuses_invalid_state_without_rewriting_history(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory=Path(temporary);path=directory/'schedule.json';script=directory/'reader.php'
            records={}
            for index in range(17000):
                identity='occ_'+hashlib.sha256(str(index).encode()).hexdigest()[:20]
                records[identity]={'occurrence_id':identity,'schedule_id':'private_schedule',
                    'schedule_name':'Private retained schedule','state':'success','message':'x'*180,
                    'run_at_utc':'2026-10-13T12:00:00Z','claimed_at':'2026-10-13T12:00:00Z',
                    'completed_at':'2026-10-13T12:00:01Z','updated_at':'2026-10-13T12:00:01Z','attempts':1}
            last=next(reversed(records));records[last]['state']='unapproved_delivery_state'
            path.write_text(json.dumps({'version':1,'occurrences':records,'worker':{}},separators=(',',':')))
            before=hashlib.sha256(path.read_bytes()).hexdigest()
            source='''<?php
interface BMO {}
require '''+json.dumps(str(ROOT/'slsmassnotifyserver/Slsmassnotifyserver.class.php'))+''';
$reflection=new ReflectionClass(FreePBX\\modules\\Slsmassnotifyserver::class);$lines=file($reflection->getFileName());
$fixture='class Reader {const MAX_SCHEDULES=50;const MAX_SCHEDULE_OCCURRENCES=500;const NATIVE_BACKUP_MAX_LEDGER_BYTES=16777216;const SCHEDULE_STATE_JSON='.var_export($argv[1],true).';';
foreach(['loadScheduleExecutionStore','validateNativeScheduleLedger','readNativeBackupFile','parseScheduleUtcTimestamp']as$name){
    $method=$reflection->getMethod($name);$fixture.=implode('',array_slice($lines,$method->getStartLine()-1,$method->getEndLine()-$method->getStartLine()+1));
}
eval($fixture.' public function read(){return $this->loadScheduleExecutionStore(true);}}');unset($fixture,$lines);
try { (new Reader)->read();echo json_encode(['rejected'=>false]); }
catch (RuntimeException $error) {echo json_encode(['rejected'=>true,'reason'=>$error->getPrevious()?->getMessage()]);}
'''
            script.write_text(source)
            result=subprocess.run(['/usr/bin/php','-d','memory_limit=64M',str(script),str(path)],
                                  capture_output=True,text=True,timeout=8,env={'PATH':'/usr/bin:/bin','LANG':'C','LC_ALL':'C'},cwd=directory)
            self.assertEqual(result.returncode,0,result.stderr);self.assertEqual(result.stderr,'')
            report=json.loads(result.stdout);self.assertIs(report['rejected'],True)
            self.assertIn('invalid delivery state',report['reason'])
            self.assertEqual(hashlib.sha256(path.read_bytes()).hexdigest(),before)


if __name__=='__main__':
    unittest.main()
