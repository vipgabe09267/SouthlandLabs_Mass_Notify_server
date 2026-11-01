#!/usr/bin/python3
"""Private queued Lightning authority probes with inert local handoffs."""
import copy
import json
import os
from pathlib import Path
import sys
import tempfile
import time
import unittest
from unittest import mock

if os.environ.get('SLS_TEST_NAMESPACE')!='entered':
    raise SystemExit('Run only through the unchanged isolated test wrapper.')
sys.dont_write_bytecode=True
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'slsmassnotifyserver/bin/sls_mass_notify'))
import sls_mass_notify_xweather_poll as lightning
import sls_phone_admission as phone


class QueuedLightningBoundary(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory(prefix='sls-lightning-audio-boundary-');self.addCleanup(self.temp.cleanup)
        self.root=Path(self.temp.name);self.phone=[];self.visual=[];self.effects=[];self.clock=[1100]
        self.config={'enabled':'1','ami':{},'desktop_clients':[{'enabled':'1','username':'alice','client_id':'cli_'+'a'*24}],
            'xweather':{'enabled':'1','voicemail_enabled':'0','provider':'xweather',
                'groups':[{'id':'north','name':'North','enabled':'1','location':'30,-97','radius_miles':25,
                    'strike_type':'cloud_to_ground','extensions':['1001'],'desktop_clients':['alice'],
                    'email_recipients':[],'all_clear':'send','quiet_hours_enabled':'0'}]}}
        self.group=lightning.select_group(self.config['xweather'],'north')
        self.observation={'active':True,'cluster_started':1000,'last_observed_at':1100}
        self.state=self.root/'xweather-lightning-state-north.json';self.save_observation()
        self.record={'group_id':'north','configuration_identity':lightning.lightning_area_identity(self.config,self.group),
            'event_kind':'entry','cluster_started':1000,'observed_at':1100,'alert_id':'north_1100_entry',
            'event_name':'Lightning Radius Alert','severity':'Warning','state_label':'Inside radius','nearest_miles':3,
            'message':'Synthetic queued Lightning evidence','subject':'Synthetic Lightning fixture',
            'correlation_key':'north:entry:1000','routing_snapshot':{'phones':['1001'],'desktops':['alice'],
                'desktop_client_ids':{'alice':'cli_'+'a'*24},'emails':[],'webhooks':[],
                'webhook_fingerprints':{},'channels':{'voice_recipient_ids':[],'sms_recipient_ids':[],'fingerprints':{}}}}

    def save_observation(self):
        self.state.write_text(json.dumps(self.observation));self.state.chmod(0o640)

    def execute(self,change=None):
        def synthesize(*args,**kwargs):
            if change:change()
            return 'SLS_Mass_Notifications_Plugin/tts/synthetic'
        def phone(*args,**kwargs):self.phone.append(copy.deepcopy(args[0]));return 1,[]
        def visual(*args,**kwargs):self.visual.append(copy.deepcopy(args[1]))
        with mock.patch.object(lightning,'DATA_DIR',self.root),\
             mock.patch.object(lightning,'LEGACY_STATE_FILE',self.root/'legacy.json'),\
             mock.patch.object(lightning,'STATE_FILE_EXPLICIT',False),\
             mock.patch.object(lightning.time,'time',side_effect=lambda:self.clock[0]),\
             mock.patch.object(lightning,'load_config',side_effect=lambda:(self.config,self.config['xweather'])),\
             mock.patch.object(lightning,'generate_audio',side_effect=synthesize),\
             mock.patch.object(lightning,'submit_local_channels',side_effect=phone),\
             mock.patch.object(lightning,'send_visual',side_effect=visual),\
             mock.patch.object(lightning,'queue_external_delivery',return_value='synthetic'),\
             mock.patch.object(lightning,'append_event',side_effect=self.effects.append),\
             mock.patch.object(lightning,'record_xweather_outcome'):
            result=lightning.deliver_queued_event(self.record)
        print('SLS_LIGHTNING_BOUNDARY '+json.dumps({'test':self.id(),'desktop_publications':self.visual,
            'phone_handoffs':self.phone,'result':result}),flush=True)
        self.assertEqual(self.visual,[['alice']],'Previously published original Desktop work was repeated or erased')
        return result

    def test_unchanged_source_keeps_original_desktop_and_phone_handoffs(self):
        self.execute()
        self.assertEqual(self.phone,[['1001']])

    def test_source_cleared_during_synthesis_stops_later_phone_handoff(self):
        def cleared():self.observation['active']=False;self.save_observation()
        self.execute(cleared)
        self.assertEqual(self.phone,[],'Cleared Lightning source still authorized a later phone handoff')

    def test_area_disabled_during_synthesis_stops_later_phone_handoff(self):
        self.execute(lambda:self.config['xweather'].update(enabled='0'))
        self.assertEqual(self.phone,[],'Disabled Lightning source still authorized a later phone handoff')

    def test_phone_recipient_removed_during_synthesis_is_not_replaced_by_new_recipient(self):
        self.execute(lambda:self.config['xweather']['groups'][0].update(extensions=['1002']))
        self.assertEqual(self.phone,[])

    def test_new_phone_added_during_synthesis_does_not_expand_original_audience(self):
        self.execute(lambda:self.config['xweather']['groups'][0].update(extensions=['1001','1002']))
        self.assertEqual(self.phone,[['1001']])

    def test_legacy_numeric_extension_keeps_the_same_original_phone_identity(self):
        self.execute(lambda:self.config['xweather']['groups'][0].update(extensions=[1001]))
        self.assertEqual(self.phone,[['1001']])

    def test_source_superseded_during_synthesis_stops_later_phone_handoff(self):
        def superseded():self.observation['cluster_started']=2000;self.save_observation()
        self.execute(superseded)
        self.assertEqual(self.phone,[])

    def test_original_source_expiry_during_synthesis_stops_later_phone_handoff(self):
        def expired():
            self.clock[0]=4701
            self.observation['last_observed_at']=4701
            self.save_observation()
        self.execute(expired)
        self.assertEqual(self.phone,[])

    def test_quiet_boundary_during_synthesis_stops_later_phone_handoff(self):
        previous=os.environ.get('TZ');os.environ['TZ']='UTC';time.tzset()
        try:
            self.config['xweather']['groups'][0].update(quiet_hours_enabled='1',quiet_hours_start='00:19',quiet_hours_end='00:20')
            self.execute(lambda:self.clock.__setitem__(0,1141))
            self.assertEqual(self.phone,[])
        finally:
            if previous is None:os.environ.pop('TZ',None)
            else:os.environ['TZ']=previous
            time.tzset()

    def spool(self,change=None,targets=None,after_first=None,during_wait=None,during_fence=None):
        self.config['xweather']['voicemail_enabled']='1'
        targets=targets or ['1001']
        self.config['xweather']['groups'][0]['extensions']=list(targets)
        outgoing=self.root/'private-outgoing';outgoing.mkdir()
        temporary=self.root/'private-temporary';temporary.mkdir()
        original_mkstemp=tempfile.mkstemp;original_replace=os.replace;replacements=[]
        def admission(*args,**kwargs):
            if change:change()
            return {'targets':list(targets),'token':'a'*32,'voicemail_targets':[]}
        def replace(source,target,*args,**kwargs):
            result=original_replace(source,target,*args,**kwargs)
            if Path(target).parent==outgoing:
                replacements.append(str(target))
                if len(replacements)==1 and after_first:after_first()
            return result
        context={'event':'Lightning Radius Alert','severity':'Warning','event_id':'xweather-north_1100_entry',
            'source_validity':lightning.weather_source_validity('xweather','north',observed_at=1100,
                event_kind='entry',cluster_started=1000,configuration_identity=self.record['configuration_identity'])}
        with mock.patch.object(lightning,'DATA_DIR',self.root),\
             mock.patch.object(lightning,'LEGACY_STATE_FILE',self.root/'legacy.json'),\
             mock.patch.object(lightning,'STATE_FILE_EXPLICIT',False),\
             mock.patch.object(lightning.time,'time',side_effect=lambda:self.clock[0]),\
             mock.patch.object(lightning,'load_config',side_effect=lambda:(self.config,self.config['xweather'])),\
             mock.patch.object(lightning,'SPOOL_DIR',outgoing),\
             mock.patch.object(lightning,'wait_for_slot',side_effect=lambda *args:during_wait() if during_wait else None),\
             mock.patch.object(lightning,'audio_page_hold_seconds',return_value=1),\
             mock.patch.object(phone,'admit_internal',side_effect=admission),\
             mock.patch.object(lightning._cluster_guard,'fence_legacy',side_effect=lambda:during_fence() if during_fence else None),\
             mock.patch.object(lightning.os,'replace',side_effect=replace),\
             mock.patch.object(lightning.tempfile,'mkstemp',side_effect=lambda **kwargs:original_mkstemp(
                 prefix=kwargs['prefix'],suffix=kwargs['suffix'],dir=temporary,text=True)):
            lightning.configure_group_runtime(self.group)
            result=lightning.queue_audio(list(targets),'SLS_Mass_Notifications_Plugin/tts/synthetic',voicemail_context=context,
                source_context={**context,'phones':list(targets),'desktops':[],'desktop_client_ids':{}})
        files=list(outgoing.iterdir())
        print('SLS_LIGHTNING_SPOOL '+json.dumps({'test':self.id(),'queued':result[0],'private_spool_files':len(files)}),flush=True)
        return result,files

    def test_unchanged_source_positive_control_spools_exact_private_ticket(self):
        result,files=self.spool()
        self.assertEqual(result[0],1);self.assertEqual(len(files),1)
        self.assertIn('Account: slsphone_'+'a'*32,files[0].read_text())

    def test_source_cleared_during_capacity_admission_cannot_spool(self):
        def cleared():self.observation['active']=False;self.save_observation()
        result,files=self.spool(cleared)
        self.assertEqual(files,[],'New callfile moved to spool after source cleared during admission')
        self.assertEqual(result[0],0)

    def test_source_cleared_during_audio_wait_cannot_admit_or_spool(self):
        def cleared():self.observation['active']=False;self.save_observation()
        result,files=self.spool(during_wait=cleared)
        self.assertEqual(files,[]);self.assertEqual(result[0],0)

    def test_first_queued_ticket_survives_source_clear_while_second_is_suppressed(self):
        def cleared():self.observation['active']=False;self.save_observation()
        result,files=self.spool(targets=['1001','1002'],after_first=cleared)
        self.assertEqual(result[0],1);self.assertEqual(len(files),1)
        self.assertIn('Local/1001@',files[0].read_text())

    def test_source_cleared_at_last_fence_removes_staging_file_without_spooling(self):
        def cleared():self.observation['active']=False;self.save_observation()
        result,files=self.spool(during_fence=cleared)
        self.assertEqual(result[0],0);self.assertEqual(files,[])
        self.assertEqual(list((self.root/'private-temporary').iterdir()),[])

    def visual_delay(self,change=None,desktops=False,after_publication=None):
        calls=[]
        context={'event':'Lightning Radius Alert','severity':'Warning',
            'source_validity':lightning.weather_source_validity('xweather','north',observed_at=1100,
                event_kind='entry',cluster_started=1000,configuration_identity=self.record['configuration_identity']),
            'phones':['1001'],'desktops':['alice'] if desktops else [],
            'desktop_client_ids':{'alice':'cli_'+'a'*24} if desktops else {}}
        def transport(command,**kwargs):
            calls.append(command)
            self.assertIn('--lightning-source-context-stdin',command)
            self.assertEqual(json.loads(kwargs['input']),context)
            self.assertIs(kwargs.get('text'),True)
            if '--api-only' in command and after_publication:after_publication()
        with mock.patch.object(lightning,'DATA_DIR',self.root),\
             mock.patch.object(lightning.time,'time',side_effect=lambda:self.clock[0]),\
             mock.patch.object(lightning.time,'sleep',side_effect=lambda *args:change() if change else None),\
             mock.patch.object(lightning,'load_config',side_effect=lambda:(self.config,self.config['xweather'])),\
             mock.patch.object(lightning.subprocess,'run',side_effect=transport):
            try:lightning.send_visual(['1001'],['alice'] if desktops else [],'Synthetic visual',phone_delay_seconds=2,source_context=context)
            except RuntimeError:
                if change is None and after_publication is None:raise
        return calls

    def test_phone_visual_positive_control_keeps_handoff_after_delay(self):
        self.assertEqual(len(self.visual_delay()),1)

    def test_phone_visual_source_cleared_during_intentional_delay_is_not_submitted(self):
        def cleared():self.observation['active']=False;self.save_observation()
        self.assertEqual(self.visual_delay(cleared),[])

    def test_both_visual_positive_control_preserves_independent_handoffs(self):
        calls=self.visual_delay(desktops=True)
        self.assertEqual(len(calls),2)
        self.assertIn('--api-only',calls[0]);self.assertIn('--no-api',calls[1])

    def test_source_clear_during_desktop_publication_preserves_first_and_suppresses_later_phone_visual(self):
        def cleared():self.observation['active']=False;self.save_observation()
        calls=self.visual_delay(desktops=True,after_publication=cleared)
        self.assertEqual(len(calls),1);self.assertIn('--api-only',calls[0])

    def test_full_fleet_source_context_crosses_process_stdin_above_single_env_limit(self):
        names=['fleet'+'x'*38+str(index).zfill(4) for index in range(1000)]
        phones=['1000000000000000'+str(index).zfill(4) for index in range(1000)]
        bindings={name:'cli_'+format(index,'024x') for index,name in enumerate(names)}
        self.config['desktop_clients']=[{'username':name,'client_id':bindings[name],'enabled':'1'} for name in names]
        self.config['xweather']['groups'][0].update(extensions=phones,desktop_clients=names)
        context={'source_validity':lightning.weather_source_validity('xweather','north',observed_at=1100,
            event_kind='entry',cluster_started=1000,configuration_identity=self.record['configuration_identity']),
            'event':'Lightning Radius Alert','severity':'Warning','phones':phones,'desktops':names,
            'desktop_client_ids':bindings}
        encoded=json.dumps(context,separators=(',',':'),ensure_ascii=True,allow_nan=False)
        self.assertGreater(len(encoded),131072)
        output=self.root/'received.json';child=self.root/'inert-visual-child.py'
        child.write_text('import json,sys\nfrom pathlib import Path\nraw=sys.stdin.buffer.read(262145)\nvalue=json.loads(raw)\n'
            'Path('+repr(str(output))+').write_text(json.dumps({"bytes":len(raw),"desktops":len(value["desktops"])}))\n')
        with mock.patch.object(lightning,'DATA_DIR',self.root),\
             mock.patch.object(lightning.time,'time',side_effect=lambda:self.clock[0]),\
             mock.patch.object(lightning,'load_config',side_effect=lambda:(self.config,self.config['xweather'])),\
             mock.patch.object(lightning,'VISUAL_SCRIPT',child):
            lightning.send_visual([],names,'Synthetic full fleet',source_context=context)
        self.assertEqual(json.loads(output.read_text()),{'bytes':len(encoded),'desktops':1000})

    def test_oversized_source_context_cannot_launch_a_visual_child(self):
        context={'source_validity':{},'event':'x'*262144,'severity':'','phones':[],'desktops':[],
            'desktop_client_ids':{}}
        with mock.patch.object(lightning.subprocess,'run') as launch:
            with self.assertRaisesRegex(RuntimeError,'publication limit'):
                lightning.send_visual(['1001'],[],'Synthetic oversized context',source_context=context)
        launch.assert_not_called()


if __name__=='__main__':unittest.main()
