const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const {spawnSync} = require('node:child_process');
const panelRoot = path.join(__dirname, '../../management/control/web');
const desktopRoot = path.join(__dirname, '../../client/windows/gui/web');
const localRoot = fs.existsSync(desktopRoot) ? desktopRoot : panelRoot;
const qr = require(path.join(localRoot, 'qrcode.js'));
qr.stringToBytes = text => Array.from(new TextEncoder().encode(text));

test('share renderer stays offline and clears its previous link', () => {
  const share = fs.readFileSync(path.join(localRoot,'share.js'),'utf8');
  assert.doesNotMatch(share,/fetch\(|XMLHttpRequest|https?:\/\//);
  assert.match(share,/margin = 4/);
  assert.match(share,/link\.value = ''/);
  assert.match(share,/textContent = title/);
});

test('panel and Windows share the same offline QR encoder and renderer', {skip: !fs.existsSync(panelRoot) || !fs.existsSync(desktopRoot)}, () => {
  for (const name of ['qrcode.js','share.js']) assert.deepEqual(fs.readFileSync(path.join(panelRoot,name)),fs.readFileSync(path.join(desktopRoot,name)));
});

test('offline QR encodes short, Unicode and long subscription links', () => {
  for (const url of ['https://vpn.example.test/sub/'+'a'.repeat(43),'https://例子.测试/sub/'+'b'.repeat(43),'https://vpn.example.test/'+'a'.repeat(1200)]) {
    const code=qr(0,'M'); code.addData(url,'Byte'); code.make();
    assert.ok(code.getModuleCount()>=21);
    assert.equal(code.isDark(0,0),true);
    assert.equal(code.isDark(1,1),false);
  }
});

test('JavaScript-generated QR decodes exactly with independent ZXing reader', {skip:!process.env.ZXING_CORE_JAR}, () => {
  const java=process.env.JAVA_HOME ? path.join(process.env.JAVA_HOME,'bin/java.exe') : 'java';
  for (const url of ['https://vpn.example.test/sub/'+'a'.repeat(43),'https://例子.测试/sub/'+'b'.repeat(43),'https://vpn.example.test/'+'a'.repeat(1200)]) {
    const code=qr(0,'M'); code.addData(url,'Byte'); code.make();
    const side=code.getModuleCount();
    const rows=Array.from({length:side+8},(_,y)=>Array.from({length:side+8},(_,x)=>y>=4&&x>=4&&y<side+4&&x<side+4&&code.isDark(y-4,x-4)?'1':'0').join(''));
    const result=spawnSync(java,['--class-path',process.env.ZXING_CORE_JAR,path.join(__dirname,'QrRoundTrip.java')],{input:Buffer.from(url).toString('base64')+'\n'+rows.join('\n'),encoding:'utf8'});
    assert.equal(result.status,0,result.stderr);
    assert.match(result.stdout,/QR round trip OK/);
  }
});
