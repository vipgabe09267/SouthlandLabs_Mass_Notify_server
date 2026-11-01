#!/usr/bin/python3
"""Actual child sender + inert AMI/private journal; no real notification route."""
import configparser
from contextlib import ExitStack
import importlib.util
import io
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest import mock

if os.environ.get('SLS_TEST_NAMESPACE') != 'entered':
    raise SystemExit('Use the unchanged isolated test wrapper.')
sys.dont_write_bytecode=True
SOURCE=Path(__file__).resolve().parents[1]/'slsmassnotifyserver/bin/sls_mass_notify'
sys.path.insert(0,str(SOURCE))
import sls_mass_notify_xweather_poll as lightning
import sls_notification_destinations as destinations
spec=importlib.util.spec_from_file_location('sls_notify_child_observation',SOURCE/'sls_notify.py')
sender=importlib.util.module_from_spec(spec);spec.loader.exec_module(sender)

class ChildBoundary(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory(prefix='sls-lightning-child-');self.addCleanup(self.temp.cleanup)
        self.root=Path(self.temp.name);self.actions=[];self.clock=1100
        self.settings={'runtime_enabled':True,'xweather':{'enabled':'1','groups':[{
            'id':'north','name':'North','enabled':'1','location':'30,-97','radius_miles':25,
            'strike_type':'cloud_to_ground','extensions':['1001'],'desktop_clients':['alice'],
            'email_recipients':[],'quiet_hours_enabled':'0','all_clear':'send'}]}}
        self.settings['desktop_clients']=[{'enabled':True,'username':'alice','client_id':'cli_'+'a'*24}]
        group=lightning.select_group(self.settings['xweather'],'north')
        self.context={'source_validity':destinations.weather_source_validity('xweather','north',
            observed_at=1100,event_kind='entry',cluster_started=1000,
            configuration_identity=lightning.lightning_area_identity(self.settings,group)),
            'event':'Lightning Radius Alert','severity':'Warning','phones':['1001'],'desktops':['alice'],
            'desktop_client_ids':{'alice':'cli_'+'a'*24}}
        self.observation={'active':True,'cluster_started':1000,'last_observed_at':1100}
        self.path=self.root/'xweather-lightning-state-north.json';self.save()
        self.config=configparser.ConfigParser(interpolation=None)
        self.config.read_dict({'ami':{'host':'127.0.0.1','port':'5038','username':'synthetic','password':'synthetic'},
            'api':{'events_file':str(self.root/'events.jsonl')},
            'logging':{'log_file':str(self.root/'private.log')},
            'desktop':{'client_ids':json.dumps({'alice':'cli_'+'a'*24})}})

    def save(self):self.path.write_text(json.dumps(self.observation));self.path.chmod(0o640)
    def current(self):return destinations.validate_external_weather(self.context,self.settings,self.root,now=self.clock)[0]
    def clear(self):self.observation['active']=False;self.save()

    def execute(self,when=None,desktop=False,expected=None):
        self.assertEqual(self.current(),'eligible','Synthetic parent admission failed before child starts')
        owner=self
        class Ami:
            def __init__(self,*args,**kwargs):pass
            def __enter__(self):return self
            def __exit__(self,*args):pass
            def action(self,fields,complete_event=None):
                owner.actions.append(fields)
                if when=='after_first_action':owner.clear()
                if when=='ami_failure':raise OSError('Synthetic response lost after AMI action began')
                if when=='typed_ami_failure':raise sender.SubmissionSuppressed('Synthetic downstream error after action began')
                return {'Response':'Success','Message':'Synthetic accepted'},[]
        def render(*args,**kwargs):
            if when=='render':self.clear()
            if when=='enrollment_change':self.settings['desktop_clients'][0]['client_id']='cli_'+'b'*24
            if when=='phone_removed':self.settings['xweather']['groups'][0]['extensions']=[]
            return '<YealinkIPPhoneText><Text>Synthetic fixture</Text></YealinkIPPhoneText>'
        def inventory(*args,**kwargs):
            if when=='contact_lookup':self.clear()
            fmt='generic' if when=='payload_build' else 'yealink'
            return {value:{'format':fmt,'formats':[fmt],'contacts':[]} for value in self.context['phones']}
        def begin(*args,**kwargs):
            if when=='cluster_claim':self.clear()
            return {'id':'synthetic-consumed-claim'}
        def payload(*args,**kwargs):self.clear();return '<fixture/>'
        replace=sender.os.replace
        def replace_publication(source,target,*args,**kwargs):
            if Path(target)==self.root/'events.jsonl':raise OSError('Synthetic replacement outcome unconfirmed')
            return replace(source,target,*args,**kwargs)
        with ExitStack() as stack:
            stack.enter_context(mock.patch.object(lightning,'DATA_DIR',self.root))
            stack.enter_context(mock.patch.object(lightning,'load_config',return_value=(self.settings,self.settings['xweather'])))
            stack.enter_context(mock.patch.object(destinations.time,'time',return_value=self.clock))
            stack.enter_context(mock.patch.object(sender.socket,'create_connection',side_effect=AssertionError('Real sockets forbidden')))
            stack.enter_context(mock.patch.object(sender.subprocess,'run',side_effect=AssertionError('Real CLI forbidden')))
            stack.enter_context(mock.patch.object(sender,'AmiClient',Ami))
            stack.enter_context(mock.patch.object(sender,'build_announcement_image_xml',side_effect=render))
            stack.enter_context(mock.patch.object(sender,'render_announcement_image',return_value=''))
            stack.enter_context(mock.patch.object(sender,'get_registered_endpoint_info',side_effect=inventory))
            stack.enter_context(mock.patch.object(sender,'pjsip_notify_capabilities',return_value={'contact_uri_usable':True}))
            stack.enter_context(mock.patch.object(sender._cluster_guard,'begin',side_effect=begin))
            finish=stack.enter_context(mock.patch.object(sender._cluster_guard,'finish'))
            if when=='replace_failure':stack.enter_context(mock.patch.object(sender.os,'replace',side_effect=replace_publication))
            stack.enter_context(mock.patch.object(sender,'PHONE_VISUAL_STATE',self.root/'visual-state'))
            if when=='payload_build':stack.enter_context(mock.patch.object(sender,'build_phone_xml_for_format',side_effect=payload))
            phones=[] if desktop else self.context['phones']
            source_guard=sender.lightning_submission_guard(self.context,phones,['alice'] if desktop else [])
            try:
                sender.push_announcement(self.config,'Synthetic child boundary',phones,
                    print_results=False,api_publish=desktop,api_only=desktop,image=True,
                    desktop_targets=['alice'] if desktop else [],submission_guard=source_guard)
            except (RuntimeError,OSError):
                if when is None:raise
        journal=self.root/'events.jsonl'
        rows=journal.read_text().splitlines() if journal.exists() else []
        actual=len(rows) if desktop else len(self.actions)
        print('SLS_LIGHTNING_CHILD '+json.dumps({'case':self.id(),'source_after_preparation':self.current(),
            'private_journal_publications':len(rows),'recording_ami_actions':len(self.actions),
            'cluster_finishes':[call.kwargs for call in finish.call_args_list]}),flush=True)
        self.assertEqual(actual,(0 if when else 1) if expected is None else expected,
            'Child submitted after the original source cleared during reversible preparation')
        if when=='cluster_claim':
            self.assertFalse(finish.call_args.kwargs['uncertain'],'Proven final suppression was mislabeled as possible submission')
            self.assertEqual(finish.call_args.kwargs['category'],'submission_suppressed')
        for call in finish.call_args_list:self.assertEqual(call.args[0],{'id':'synthetic-consumed-claim'})
        if when in {'ami_failure','typed_ami_failure','replace_failure'}:
            self.assertTrue(finish.call_args.kwargs['uncertain'],'Actual downstream failure was incorrectly treated as a known refusal')

    def test_unchanged_phone_positive(self):self.execute()
    def test_source_clear_during_render_stops_actual_phone_submission(self):self.execute('render')
    def test_source_clear_during_contact_lookup_stops_actual_phone_submission(self):self.execute('contact_lookup')
    def test_unchanged_desktop_positive(self):self.execute(desktop=True)
    def test_source_clear_during_render_stops_actual_desktop_publication(self):self.execute('render',desktop=True)
    def test_source_clear_during_payload_render_stops_actual_phone_submission(self):self.execute('payload_build')
    def test_source_clear_during_cluster_claim_stops_actual_phone_submission(self):self.execute('cluster_claim')
    def test_source_clear_during_cluster_claim_stops_actual_desktop_publication(self):self.execute('cluster_claim',desktop=True)
    def test_reenrolled_desktop_does_not_receive_original_source(self):self.execute('enrollment_change',desktop=True)
    def test_removed_phone_does_not_receive_original_source(self):self.execute('phone_removed')
    def test_source_clear_after_first_actual_action_preserves_first_and_suppresses_second(self):
        self.context['phones']=['1001','1002'];self.settings['xweather']['groups'][0]['extensions']=['1001','1002']
        self.execute('after_first_action',expected=1)
    def test_actual_ami_failure_retains_uncertainty(self):self.execute('ami_failure',expected=1)
    def test_downstream_ami_error_cannot_impersonate_pre_submission_suppression(self):self.execute('typed_ami_failure',expected=1)
    def test_actual_journal_replace_failure_retains_uncertainty(self):self.execute('replace_failure',desktop=True,expected=0)

    def cli(self,raw,targets='1001',extra=(),desktop=False):
        wire=type('FixtureInput',(),{'buffer':io.BytesIO(raw)})()
        argv=['sls_notify.py','--announcement','Synthetic CLI evidence','--no-retry',
            '--lightning-source-context-stdin',*extra]
        argv+=['--api-only','--desktop-targets','alice'] if desktop else ['--no-api','--targets',targets]
        with mock.patch.object(sender.sys,'argv',argv),mock.patch.object(sender.sys,'stdin',wire),\
             mock.patch.object(sender.sys,'stdout',io.StringIO()),mock.patch.object(sender,'load_config',return_value=self.config),\
             mock.patch.object(sender,'setup_logging'),mock.patch.object(sender,'push_announcement') as push,\
             mock.patch.object(lightning,'DATA_DIR',self.root),\
             mock.patch.object(lightning,'load_config',return_value=(self.settings,self.settings['xweather'])),\
             mock.patch.object(destinations.time,'time',return_value=self.clock):
            status=sender.main()
            if push.called:self.assertTrue(push.call_args.kwargs['submission_guard']())
            return status,push.call_count

    def test_cli_positive_passes_bounded_context_to_real_guard(self):
        self.assertEqual(self.cli(json.dumps(self.context).encode()),(0,1))
    def test_cli_desktop_positive_passes_bounded_context_to_real_guard(self):
        self.assertEqual(self.cli(json.dumps(self.context).encode(),desktop=True),(0,1))

    def test_cli_duplicate_keys_are_rejected_before_delivery(self):
        raw=json.dumps(self.context)[:-1]+',"event":"duplicate"}'
        self.assertEqual(self.cli(raw.encode()),(1,0))

    def test_cli_oversized_context_rejected_before_delivery(self):
        self.assertEqual(self.cli(b'x'*262145),(1,0))

    def test_cli_foreign_requested_route_is_refused(self):
        self.assertEqual(self.cli(json.dumps(self.context).encode(),targets='1002'),(1,0))

    def test_cli_source_cannot_be_mixed_with_test_mode(self):
        with self.assertRaises(SystemExit) as caught:self.cli(json.dumps(self.context).encode(),extra=['--is-test'])
        self.assertEqual(caught.exception.code,2)

    def test_unknown_context_fields_are_refused(self):
        context=dict(self.context,configuration_path='/never/read/arbitrary/config')
        with self.assertRaises(ValueError):sender.lightning_submission_guard(context,['1001'],[])

    def test_scheduled_guard_remains_conjoined_with_explicit_authority(self):
        with self.assertRaises(RuntimeError):
            sender.push_announcement(self.config,'Synthetic conjunction',[],print_results=False,
                api_only=True,desktop_targets=['alice'],latest_start=253402300000,submission_guard=lambda:False)
        self.assertFalse((self.root/'events.jsonl').exists())
    def test_expired_scheduled_deadline_still_refuses_when_other_authority_allows(self):
        with self.assertRaises(sender.ScheduledStartExpired):
            sender.push_announcement(self.config,'Synthetic conjunction',[],print_results=False,
                api_only=True,desktop_targets=['alice'],latest_start=1,submission_guard=lambda:True)
        self.assertFalse((self.root/'events.jsonl').exists())

if __name__=='__main__':unittest.main()
