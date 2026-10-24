const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const vm = require('node:vm');
const path = require('node:path');
const source = fs.readFileSync(path.join(__dirname,'../../management/control/web/app.js'),'utf8');
const code = source.slice(source.indexOf('function requiresConfirmation('),source.indexOf('function field('));

test('ordinary creation and saving never require a second confirmation', () => {
  const scope=vm.createContext({});vm.runInContext(code,scope);
  for (const command of ['subscribercreate {"title":"New","enabled":false}','subcreate alice Name','add delete-user','set alice {"note":"delete"}','subset abc {"title":"New"}','subset abc {"enabled":true}','configsave {"log_level":"info"}','certjobcreate example {}','peerinvite','service start','backup']) assert.equal(scope.requiresConfirmation(command),false,command);
  for (const command of ['delete alice','subdelete abc','subrotate abc','subset abc {"enabled":false}','bulk delete alice','service stop','service restart','certservice restart','restore backup','inboundapply 1','peergrant node true','configsave {"sni":"example.test"}']) assert.equal(scope.requiresConfirmation(command),true,command);
});

test('creating a subscriber commits immediately without a success popup', async () => {
  const nodes=Object.fromEntries(['editor','notice','confirmation'].map(id=>[id,{open:false,textContent:'',close(){this.open=false},showModal(){throw Error('Unexpected confirmation')}}]));
  const calls=[],shown=[];
  const scope=vm.createContext({page:'subscriptions',$:id=>nodes[id],t:key=>key,render:async()=>{},showResult:value=>shown.push(value),request:async(path,data)=>{
    calls.push([path,data]);
    return path.endsWith('prepare')?{confirmation:'token',secret:true}:{result:{result:{url:'https://example.test/sub/test'}}};
  }});
  vm.runInContext(code,scope);
  await scope.operation('subscribercreate {"title":"New"}',true);
  assert.equal(calls.length,2);
  assert.equal(calls[1][0],'/control/commit');
  assert.equal(shown.length,0);
  assert.equal(nodes.notice.textContent,'');
});

test('created user appears from committed API response without refetching all lists', async () => {
  const renders=[],shown=[];
  const scope=vm.createContext({page:'users',usersView:{page:'users',data:{users:[{name:'old',enabled:true}],total:1},groups:[],subscriptions:[]},usersSearch:'old',usersPage:1,userFilter:'active',render:async snapshot=>renders.push(snapshot),showResult:value=>shown.push(value)});
  vm.runInContext(code,scope);
  await scope.finishMutation('usercreate {}',{result:{name:'new',enabled:true,note:'saved'}});
  assert.equal(renders[0].data.users.find(user=>user.name==='new').note,'saved');
  assert.equal(renders[0].data.total,2);
  assert.equal(scope.usersSearch,'');assert.equal(scope.userFilter,'all');
  assert.equal(shown.length,0);
});
