const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const vm = require('node:vm');
const source = fs.readFileSync(require('node:path').join(__dirname, '../../management/control/web/app.js'), 'utf8');
test('backup page only creates copies after an explicit button click', async () => {
  const start = source.indexOf("} else if (page === 'backups') {") + "} else if (page === 'backups') {".length;
  const body = source.slice(start, source.indexOf("} else if (page === 'security')", start));
  const buttons = [], mutations = [], reads = [];
  const context = {root:{}, async read(command){reads.push(command);return command === 'backups' ? {backups:[]} : []},
    table(){}, card(){return {append(...items){buttons.push(...items)}}}, actions(){return []},
    button(label, click){return {label, click}}, operation(command){mutations.push(command)}, quote:value=>JSON.stringify(value)};
  vm.createContext(context);
  await vm.runInContext('(async()=>{' + body + '})()', context);
  assert.deepEqual(mutations, []);
  assert.deepEqual(reads, ['backups','panelbackups','certbackups']);
  assert.equal(buttons.length, 3);
  for (const button of buttons) await button.click();
  assert.deepEqual(mutations, ['backup','panelbackup','certbackup']);
});
