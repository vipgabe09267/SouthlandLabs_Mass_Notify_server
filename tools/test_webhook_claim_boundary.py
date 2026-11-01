#!/usr/bin/python3
"""Actual webhook handoff function, consumed fake claim, no sockets/providers."""
import importlib.util
import os
from pathlib import Path
import sys
import unittest
from unittest import mock
if os.environ.get('SLS_TEST_NAMESPACE')!='entered':raise SystemExit('Use isolated wrapper.')
sys.dont_write_bytecode=True
RUNTIME=Path(__file__).resolve().parents[1]/'slsmassnotifyserver/bin/sls_mass_notify'
sys.path.insert(0,str(RUNTIME))
spec=importlib.util.spec_from_file_location('webhook_claim_boundary',RUNTIME/'sls_notification_destinations.py');transport=importlib.util.module_from_spec(spec);spec.loader.exec_module(transport)

class WebhookClaimBoundary(unittest.TestCase):
 def probe(self,case):
  clock=[100.];allowed=[True];guards=[];calls=[];claims=[];finished=[];claim={'private_claim':'consumed'}
  class Guard:
   failure_code='authorization_changed'
   def __call__(self):
    guards.append(clock[0])
    # Trigger by the consumed coordination phase, never a guard-call ordinal.
    if case=='guard_wait_consumes_deadline'and claims:clock[0]+=6
    return allowed[0]
  class Sock:
   value=None
   def settimeout(self,value):self.value=value
  class Connection:
   def __init__(self,*args):self.sock=Sock()
   def connect(self):pass
   def close(self):pass
   def request(self,*args,**kwargs):
    calls.append({'at':clock[0],'method':args[0],'socket_timeout':self.sock.value})
    if case=='post_started_then_failed':raise OSError('inert uncertain transport')
   def getresponse(self):
    if case=='known_response_after_deadline':clock[0]+=6
    return type('Response',(),{'status':200,'getheader':lambda *args:''})()
  def begin(*args,**kwargs):
   claims.append(claim)
   if case in('authority_changes_during_claim','source_reader_fails_after_claim','suppression_receipt_fenced'):allowed[0]=False
   if case in('claim_consumes_deadline','guardless_claim_consumes_deadline'):clock[0]+=6
   if case=='short_claim_wait':clock[0]+=2
   return None if case=='legacy_no_cluster'else claim
  def finish(value,**kwargs):
   finished.append((value,kwargs))
   if case=='suppression_receipt_fenced':raise transport._cluster_guard.ClusterFenced('inert receipt timeout')
  if case=='authority_refused_before_claim':allowed[0]=False
  error=None;result=None
  guard=None if case=='guardless_claim_consumes_deadline'else Guard()
  if case=='source_reader_fails_after_claim':
   def source_reader():
    guards.append(clock[0])
    if not allowed[0]:raise OSError('inert source reader unavailable')
    return 'eligible',''
   guard=transport._WeatherSubmissionGuard(source_reader)
  with mock.patch.object(transport,'_validated_url',return_value=('private.example.test','/inert',['8.8.8.8'])),mock.patch.object(transport,'_PinnedHTTPSConnection',Connection),mock.patch.object(transport.time,'monotonic',side_effect=lambda:clock[0]),mock.patch.object(transport._cluster_guard,'begin',side_effect=begin),mock.patch.object(transport._cluster_guard,'finish',side_effect=finish):
   try:result=transport._request_once('https://private.example.test/inert','generic',{'timestamp':'2026-10-28T12:00:00Z','message':'Inert boundary'},timeout=5,idempotency_key='private-boundary',submission_guard=guard)
   except transport.DestinationError as caught:error=caught
  return {'clock':clock[0],'guards':guards,'calls':calls,'claims':claims,'finished':finished,'error':error,'result':result}
 def test_unchanged_authority_accepts_one_inert_request(self):
  r=self.probe('unchanged');self.assertIsNone(r['error']);self.assertEqual(len(r['calls']),1);self.assertEqual(r['result'],(200,''));self.assertEqual(r['finished'],[({'private_claim':'consumed'},{'uncertain':False,'category':'http_response_200'})])
 def known_refusal(self,case):
  r=self.probe(case)
  self.assertEqual(r['calls'],[],f'{case} still invoked inert POST: {r["calls"]}')
  self.assertIsInstance(r['error'],transport.DestinationError);self.assertFalse(r['error'].submission_possible)
  self.assertEqual(r['claims'],[{'private_claim':'consumed'}]);self.assertEqual(len(r['finished']),1)
  claim,receipt=r['finished'][0];self.assertEqual(claim,{'private_claim':'consumed'});self.assertFalse(receipt['uncertain']);self.assertEqual(receipt['category'],'submission_suppressed');self.assertLessEqual(receipt['timeout'],1)
 def test_authority_withdrawn_during_claim_refuses_post(self):self.known_refusal('authority_changes_during_claim')
 def test_claim_time_is_inside_original_request_deadline(self):self.known_refusal('claim_consumes_deadline')
 def test_final_readonly_guard_wait_cannot_extend_original_deadline(self):self.known_refusal('guard_wait_consumes_deadline')
 def test_original_deadline_without_optional_guard_is_preserved(self):self.known_refusal('guardless_claim_consumes_deadline')
 def test_actual_source_reader_failure_is_known_no_submit(self):self.known_refusal('source_reader_fails_after_claim')
 def test_fenced_suppression_receipt_preserves_known_no_submit(self):self.known_refusal('suppression_receipt_fenced')
 def test_socket_budget_is_refreshed_after_short_claim_wait(self):
  r=self.probe('short_claim_wait');self.assertEqual(r['result'],(200,''));self.assertEqual(r['calls'],[{'at':102.,'method':'POST','socket_timeout':3.}])
 def test_known_response_after_start_does_not_erase_acceptance(self):
  r=self.probe('known_response_after_deadline');self.assertEqual(r['result'],(200,''));self.assertEqual(len(r['calls']),1);self.assertFalse(r['finished'][0][1]['uncertain'])
 def test_actual_started_post_failure_remains_uncertain(self):
  r=self.probe('post_started_then_failed');self.assertEqual(len(r['calls']),1);self.assertTrue(r['error'].submission_possible);self.assertTrue(r['finished'][0][1]['uncertain'])
 def test_preclaim_refusal_consumes_no_claim(self):
  r=self.probe('authority_refused_before_claim');self.assertEqual(r['calls'],[]);self.assertEqual(r['claims'],[]);self.assertEqual(r['finished'],[]);self.assertFalse(r['error'].submission_possible)
 def test_existing_no_cluster_transport_still_accepts(self):
  r=self.probe('legacy_no_cluster');self.assertEqual(len(r['calls']),1);self.assertEqual(r['result'],(200,''))

if __name__=='__main__':unittest.main()
