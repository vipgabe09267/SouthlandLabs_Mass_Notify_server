'use strict';
const assert = require('node:assert/strict');
const fs = require('node:fs');
const vm = require('node:vm');
const path = require('node:path');
const fixtureTime = Date.now();
class FixtureDate extends Date { static now() { return fixtureTime; } }
const handlers = new Map(), stored = new Map(), displayed = [], opened = [];
let disappearOnMatch = '';
const receiptCalls = [], receiptPlans = new Map();
async function receiptFetch(url, options) {
  assert.equal(url, '/mass-notify/subscriber.php');
  const stage = new URLSearchParams(String(options.body)).get('stage');
  receiptCalls.push(stage);
  const plan = receiptPlans.get(stage) || [];
  const result = plan.length ? plan.shift() : 204;
  if (result instanceof Error) throw result;
  return new Response(null, {status: result});
}
const ledger = { async match(request) { if (request.url === disappearOnMatch) { disappearOnMatch = ''; stored.delete(request.url); return undefined; } return stored.get(request.url)?.clone(); }, async put(request, response) { stored.set(request.url, response.clone()); }, async keys() { return [...stored.keys()].map(url => new Request(url)); }, async delete(request) { return stored.delete(request.url); } };
const self = { location: { origin: 'https://pbx.example.test' }, addEventListener(type, handler) { handlers.set(type, handler); }, registration: { async showNotification(title, options) { displayed.push({ title, options }); } } };
vm.runInNewContext(fs.readFileSync(path.join(__dirname, '../slsmassnotifyserver/portal/subscriber-worker.js'), 'utf8'), { self, caches: { async open(name) { assert.equal(name, 'sls-browser-push-v1'); return ledger; } }, clients: { async openWindow(url) { opened.push(url); } }, Date: FixtureDate, Request, Response, URL, Number, URLSearchParams, AbortController, setTimeout, clearTimeout, fetch: receiptFetch });
const now = Math.floor(fixtureTime / 1000), event = { event_id: 'fixture_1', title: 'Fixture', message: 'Message', is_test: true, expires_at: now + 300 };
async function push(value) { let work; handlers.get('push')({ data: { json() { return value; } }, waitUntil(promise) { work = promise; } }); await work; }
(async () => {
  await push(event); await push(event); assert.equal(displayed.length, 1); assert.equal(displayed[0].title, 'SLL · TEST · Fixture');
  const proof = {subscriber_id:'sub_'+'a'.repeat(24),event_key:'b'.repeat(64),endpoint_id:'c'.repeat(64),token:'d'.repeat(64),expires_at:now+300};
  receiptPlans.set('received', [503, new Error('Synthetic receipt network failure'), 204]);
  receiptPlans.set('displayed', [400, 204]);
  await push({...event,event_id:'receipt-retry',browser_receipt:proof});
  assert.equal(receiptCalls.filter(stage=>stage==='received').length,3,'Transient receipt failures were not retried to success');
  assert.equal(receiptCalls.filter(stage=>stage==='displayed').length,1,'Permanent receipt rejection was retried');
  const show = self.registration.showNotification;
  let attempts = 0; const attemptTags = [];
  self.registration.showNotification = async (...args) => { attempts++; attemptTags.push(args[1]?.tag); if (attempts === 1) throw Error('Temporary display failure'); return show(...args); };
  const retry = { ...event, event_id: 'display-retry' };
  await assert.rejects(push(retry), /Temporary display failure/);
  assert(!stored.has('https://pbx.example.test/mass-notify/subscriber.php?event=display-retry'));
  await Promise.all([push(retry), push(retry)]);
  assert.equal(attempts, 2, JSON.stringify(attemptTags)); assert.equal(displayed.length, 3);
  self.registration.showNotification = show;
  for (const bad of [{ ...event, event_id: 'expired', expires_at: now - 1 }, { ...event, event_id: 'too-far', expires_at: now + 601 }, { ...event, event_id: '../path' }, { ...event, event_id: 'string-test', is_test: 'true' }, null]) await push(bad);
  assert.equal(displayed.length, 3);
  let closed = false, work; handlers.get('notificationclick')({ notification: { data: { expires_at: now + 300, event_id: 'fixture' }, close() { closed = true; } }, waitUntil(promise) { work = promise; } }); await work;
  assert(closed); assert.deepEqual(opened, ['/mass-notify/subscriber.php?event=fixture']);
  handlers.get('notificationclick')({ notification: { data: { expires_at: now - 1 }, close() {} }, waitUntil() { throw Error('Expired notification opened a page'); } });
  receiptPlans.set('clicked', [429, 204]);
  handlers.get('notificationclick')({ notification: { data: { expires_at: now + 300, event_id: 'receipt-retry', browser_receipt: proof }, close() {} }, waitUntil(promise) { work = promise; } }); await work;
  assert.equal(receiptCalls.filter(stage=>stage==='clicked').length,2,'Rate-limited click receipt was not retried');
  disappearOnMatch = 'https://pbx.example.test/mass-notify/subscriber.php?event=fixture_1';
  await push({ ...event, event_id: 'cleanup-race' });
  for (let i = 0; i < 105; i++) await push({ ...event, event_id: `bounded_${i}` }); assert(stored.size <= 100);
  assert(!handlers.has('fetch'), 'Subscriber worker must never intercept operator authentication or API requests');

  // An unavailable dedup write must prevent display rather than permit an
  // accepted display whose identity disappears on worker restart.
  function deliveryFixture() {
    const rows = new Map(), shown = []; let clock = fixtureTime;
    class WorkerDate extends Date { static now() { return clock; } }
    const options = {failPut:false,failDelete:false,afterDisplay:null,afterPut:null};
    const cache = {
      async match(request) { return rows.get(request.url)?.clone(); },
      async put(request,response) { if(options.failPut)throw Error('Synthetic quota failure'); rows.set(request.url,response.clone()); if(options.afterPut)await options.afterPut(); },
      async delete(request) { if(options.failDelete)throw Error('Synthetic delete failure'); return rows.delete(request.url); },
      async keys() { return [...rows.keys()].map(url=>new Request(url)); }
    };
    const source=fs.readFileSync(path.join(__dirname,'../slsmassnotifyserver/portal/subscriber-worker.js'),'utf8');
    const restart=()=>{
      const callbacks=new Map();
      const scope={location:{origin:'https://pbx.example.test'},addEventListener(type,handler){callbacks.set(type,handler);},
        registration:{async showNotification(title,parameters){shown.push({title,parameters});if(options.afterDisplay)await options.afterDisplay();}}};
      vm.runInNewContext(source,{self:scope,caches:{async open(name){assert.equal(name,'sls-browser-push-v1');return cache;}},clients:{async openWindow(){}},Date:WorkerDate,Request,Response,URL,Number,URLSearchParams,AbortController,setTimeout,clearTimeout,fetch:receiptFetch});
      return {async push(value){let promise;callbacks.get('push')({data:{json(){return value;}},waitUntil(work){promise=work;}});await promise;}};
    };
    return {rows,shown,options,restart,advance(milliseconds){clock+=milliseconds;}};
  }
  const blocked=deliveryFixture(),blockedWorker=blocked.restart();blocked.options.failPut=true;
  const claimFailure={...event,event_id:'claim-storage-failure'};
  await assert.rejects(blockedWorker.push(claimFailure),/Synthetic quota failure/);
  assert.equal(blocked.shown.length,0,'Unavailable durable claim permitted a display');
  blocked.options.failPut=false;await blockedWorker.push(claimFailure);assert.equal(blocked.shown.length,1);

  const restarting=deliveryFixture();let showEntered,releaseShow;
  const entered=new Promise(resolve=>showEntered=resolve),release=new Promise(resolve=>releaseShow=resolve);
  restarting.options.afterDisplay=async()=>{if(restarting.shown.length===1){showEntered();await release;}};
  const restartEvent={...event,event_id:'accepted-before-promise-resolution'};
  const first=restarting.restart().push(restartEvent);await entered;
  try{await restarting.restart().push(restartEvent);assert.equal(restarting.shown.length,1,'Fresh worker replayed an accepted or uncertain display');}
  finally{releaseShow();await first;}

  const afterward=deliveryFixture();afterward.options.afterDisplay=()=>{afterward.options.failPut=true;};
  const accepted={...event,event_id:'accepted-before-storage-outage'};
  await afterward.restart().push(accepted);await afterward.restart().push(accepted);
  assert.equal(afterward.shown.length,1,'Later storage failure reopened a displayed identity');

  const refused=deliveryFixture();refused.options.afterDisplay=()=>{throw Error('Explicit display rejection');};
  const refusedEvent={...event,event_id:'explicitly-rejected-display'};
  await assert.rejects(refused.restart().push(refusedEvent),/Explicit display rejection/);
  assert.equal(refused.rows.size,0,'Explicit rejection retained an otherwise removable claim');
  refused.options.afterDisplay=null;await refused.restart().push(refusedEvent);assert.equal(refused.shown.length,2);

  const undeletable=deliveryFixture();undeletable.options.afterDisplay=()=>{throw Error('Explicit display rejection');};undeletable.options.failDelete=true;
  const undeletableEvent={...event,event_id:'rejected-claim-removal-unavailable'};
  await assert.rejects(undeletable.restart().push(undeletableEvent),/Explicit display rejection/);
  assert.equal(undeletable.rows.size,1,'Failed claim removal lost conservative evidence');
  undeletable.options.afterDisplay=null;await undeletable.restart().push(undeletableEvent);assert.equal(undeletable.shown.length,1);

  const expiring=deliveryFixture();expiring.options.afterPut=()=>expiring.advance(2000);
  await expiring.restart().push({...event,event_id:'expired-during-cache-write',expires_at:now+1});
  assert.equal(expiring.shown.length,0,'Cache write extended the absolute display deadline');

  const legacy=deliveryFixture();legacy.rows.set('https://pbx.example.test/mass-notify/subscriber.php?event=legacy-consumed',new Response(String(now+300)));
  await legacy.restart().push({...event,event_id:'legacy-consumed'});assert.equal(legacy.shown.length,0,'Upgrade replayed a legacy consumed cache entry');
  console.log('Subscriber uncertainty: pre-display persistence, restarted workers, later storage outage, explicit rejection retry, failed claim removal, awaited expiry and legacy cache compatibility passed.');
  console.log('Subscriber worker: expiry, duplicate isolation, bounded receipt retry, explicit tests, bounded cache and fixed-origin navigation passed.');
})().catch(error => { console.error(error); process.exitCode = 1; });
