#!/usr/bin/python3
"""Real private API projection with inert module readiness; no PBX bootstrap."""
import json
import os
from pathlib import Path
import sys
import unittest

if os.environ.get('SLS_TEST_NAMESPACE')!='entered':
    raise SystemExit('Use the unchanged isolated wrapper.')
sys.dont_write_bytecode=True
import test_api_security as fixtures

class ReadinessScopeBoundary(unittest.TestCase):
    def test_scope_union_keeps_restricted_readiness_projection(self):
        api=fixtures.ApiSecurityTests('test_strict_json_preserves_long_text_and_rejects_ambiguous_members')
        api.setUp();self.addCleanup(api.tearDown)
        principals={
            'restricted_read':api.issue(scopes=('read',)),
            'restricted_monitor':api.issue(scopes=('monitor',)),
            'restricted_combined':api.issue(scopes=('read','monitor')),
            'unrestricted_read':api.issue(scopes=('read',),unrestricted=True),
        }
        api.write_config(control_api={'enabled':True,'rate_limit_enabled':False,
            'credentials':[value['credential'] for value in principals.values()]})
        api.start_api()
        path=api.directory/'index.php';source=path.read_text()
        original="return ['success'=>true,'method'=>$name,'arguments'=>$arguments,'available_request_slots'=>$available];"
        self.assertEqual(source.count(original),1)
        # Real getDeploymentReadiness copies diagnostic details such as the
        # configured Piper executable/voice path. Do not substitute a private
        # acceptance report: that report has its own independent scope guard.
        replacement="return ['success'=>true,'method'=>$name,'available_request_slots'=>$available,'schema'=>'sls-deployment-readiness-v1','checks'=>[['id'=>'runtime_voice','code'=>'runtime_voice','state'=>'ok','reason_code'=>'healthy','label'=>'Piper voice','detail'=>'PRIVATE_SYNTHETIC_PATH /private/voice.onnx']]];"
        path.write_text(source.replace(original,replacement))
        failures=[]
        for name,issued in principals.items():
            status,body=api.request(issued['secret'],path='/?resource=readiness')
            private='PRIVATE_SYNTHETIC_PATH' in json.dumps(body)
            print('SLS_READINESS_SCOPE '+json.dumps({'case':name,'status':status,'private_detail':private,
                'check_fields':sorted(body.get('checks',[{}])[0])}),flush=True)
            if name=='restricted_read':self.assertEqual(status,403)
            elif name=='unrestricted_read':self.assertEqual(status,200);self.assertTrue(private)
            else:
                self.assertEqual(status,200)
                if private:failures.append(name)
        self.assertEqual(failures,[],'Restricted read+monitor must retain narrow monitor readiness projection')

if __name__=='__main__':unittest.main()
