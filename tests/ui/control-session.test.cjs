const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const vm = require('node:vm');
const path = require('node:path');
const source = fs.readFileSync(path.join(__dirname, '../../management/control/web/app.js'), 'utf8');

function harness(fetch) {
  const context = vm.createContext({fetch, authVersion: 1, csrf: 'old', lang: 'en', json: JSON.stringify,
    t: key => key, signedIn: () => { context.exits++; }, exits: 0});
  vm.runInContext(source.slice(source.indexOf('async function request('), source.indexOf('function signedIn(')), context);
  return context;
}
test('old unauthorized responses do not destroy a newly authenticated session', async () => {
  let complete;
  const context = harness(() => new Promise(resolve => { complete = resolve; }));
  const pending = context.request('/control/session');
  context.authVersion++;
  complete({ok:false,status:401,json:async()=>({error:'expired'})});
  await assert.rejects(pending);
  assert.equal(context.exits, 0);
});
test('CSRF rejection refreshes session and retries once without signing out', async () => {
  const calls=[];
  const context = harness(async (url, options) => {
    calls.push([url, options]);
    if (calls.length === 1) return {ok:false,status:403,json:async()=>({code:'csrf_expired'})};
    return {ok:true,json:async()=>url === 'control/session' ? {csrf:'fresh'} : {result:'saved'}};
  });
  assert.equal((await context.request('/control/commit', {confirm:true})).result, 'saved');
  assert.equal(calls[2][1].headers['X-CSRF-Token'], 'fresh');
  assert.equal(context.exits, 0);
});
test('login errors do not invalidate another session', async () => {
  const context = harness(async () => ({ok:false,status:401,json:async()=>({error:'invalid_credentials'})}));
  await assert.rejects(context.request('/control/login', {password:'wrong'}));
  assert.equal(context.exits, 0);
});
