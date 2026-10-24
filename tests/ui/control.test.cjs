const {test} = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const vm = require('node:vm');
const path = require('node:path');
const root = path.join(__dirname, '../../management/control/web');
const scope = {};
vm.runInNewContext(fs.readFileSync(path.join(root, 'forms.js'), 'utf8'), scope);
const forms = scope.ControlForms;

test('subscription editor rejects selected inbounds without a public client address', () => {
  const app = fs.readFileSync(path.join(root, 'app.js'), 'utf8');
  assert.match(app, /controls\.advertise\.required = true/);
  const guard = app.split('\n').find(line => line.includes("throw Error('inbound_public_address_required')"));
  assert.ok(guard);
  const check = (address, selected = true) => vm.runInNewContext(guard, {
    catalog: {inbounds: [{settings: {id: 'default', advertise_addr: address}}]},
    selected: new Set(selected ? ['default'] : []),
  });
  for (const address of [undefined, '', '   ']) assert.throws(() => check(address), /inbound_public_address_required/);
  assert.doesNotThrow(() => check('192.0.2.1:1026'));
  assert.doesNotThrow(() => check('', false));
});

test('panel pairing exposes pending approval and offline revocation honestly', () => {
  const app = fs.readFileSync(path.join(root, 'app.js'), 'utf8');
  assert.match(app, /data\?\.remote_notified === false \? t\('peer_revoked_offline'\)/);
  assert.match(app, /data\?\.pending === true \? t\('peer_pending_notice'\)/);
  assert.match(app, /peer\.role === 'primary'/);
  assert.match(app, /invite\.disabled = join\.disabled = !encrypted/);
});

test('remote inbound writes reuse the typed editor and require separate permissions', () => {
  const app = fs.readFileSync(path.join(root, 'app.js'), 'utf8');
  assert.match(app, /if \(remote && !catalog\.peer_inbounds_write\) throw Error\('peer_forbidden'\)/);
  assert.match(app, /peerexecute \$\{remote\} \$\{quote\(command\)\}/);
  assert.match(app, /peergrant \$\{peer\.id\} \$\{!peer\.inbounds_write\}/);
  assert.match(app, /peerretry \$\{id\} \$\{job\.id\}/);
});

test('remote catalog snapshots are synchronized explicitly and displayed as a compact table', () => {
  const app = fs.readFileSync(path.join(root, 'app.js'), 'utf8');
  assert.match(app, /operation\(`peersync \$\{peer\.id\}`\)/);
  assert.match(app, /await read\('remotecatalogs'\)/);
  assert.match(app, /table\(root, \['remote_panel', 'server_id', 'revision', 'inbounds'\]/);
});

test('subscription migration previews a plan and applies explicit selections only', () => {
  const app = fs.readFileSync(path.join(root, 'app.js'), 'utf8');
  assert.match(app, /async function migrateSubscriptions/);
  assert.match(app, /await read\('submigration'\)/);
  assert.match(app, /choose\.disabled = !item\.eligible/);
  assert.match(app, /submigrate \$\{plan\.revision\}/);
});

test('subscriber policy and session actions stay in the subscriber interface', () => {
  const app = fs.readFileSync(path.join(root, 'app.js'), 'utf8');
  assert.match(app, /controls\.ipLimit = field\(basic, 'subscriber_ip_limit'/);
  assert.match(app, /patch\.ip_limit = ControlForms\.integer\(controls\.ipLimit\.value, 10000\)/);
  assert.match(app, /subkick \$\{sub\.id\}/);
  assert.match(app, /subrekey \$\{sub\.id\}/);
});

test('inbound tuning editor exposes per-listener runtime fields with bounded inputs', () => {
  const app = fs.readFileSync(path.join(root, 'app.js'), 'utf8');
  assert.match(app, /ControlForms\.inboundTuning/);
  assert.match(app, /settings\.quic\.disable_pacer/);
  assert.match(app, /inboundForm\.requestSubmit/);
  assert.equal(forms.inboundTuning.quic.length, 5);
  assert.equal(forms.inboundTuning.yamux.length, 3);
  assert.equal(forms.inboundTuning.quic.find(([key]) => key === 'conn_receive_window_mb')[2], 1024);
  assert.equal(forms.inboundTuning.yamux.some(([key]) => key === 'max_connection_window_kb'), false);
});

test('quota editor uses a short decimal with a lossless byte round trip', () => {
  assert.equal(forms.quotaInput(107374182), '0.1');
  assert.equal(forms.quotaInput(1073741824), '1');
  assert.equal(forms.quotaInput(0), '0');
  for (const bytes of [1, 2, 107374182, 1073741823, 1073741825, 987654321, Number.MAX_SAFE_INTEGER]) {
    assert.equal(forms.quotaBytes(forms.quotaInput(bytes)), bytes);
  }
  for (const invalid of [-1, 0.1, NaN, Infinity, Number.MAX_SAFE_INTEGER + 1]) assert.throws(() => forms.quotaInput(invalid));
});

test('control fractional quotas are exact and invalid values never mean unlimited', () => {
  assert.equal(forms.quotaBytes('0.1'), 107374182);
  assert.equal(forms.quotaBytes('0,1'), 107374182);
  assert.equal(forms.quotaBytes('0'), 0);
  assert.equal(forms.quotaBytes('1.000000000931322574'), 1073741824);
  assert.equal(forms.quotaBytes('1.000000000931322575'), 1073741825);
  for (const value of ['NaN', 'Infinity', '-1', '', '1e3', '0.00000000001', '9999999999999999']) assert.throws(() => forms.quotaBytes(value));
});

test('control user edits preserve quota, expiry and other untouched fields', () => {
  const original = {total_limit: 107374182, expires_at: 1800000000, ip_limit: 2, enabled: true, note: 'old'};
  const values = {quota: String(original.total_limit / 1073741824), expires: forms.expiryInput(original.expires_at), ip_limit: '2', enabled: true, note: 'new'};
  const patch = forms.userPatch(original, values);
  assert.deepEqual(JSON.parse(JSON.stringify(patch)), {note: 'new'});
  const changed = forms.userPatch(original, {...values, quota: '0.1', expires: '', ip_limit: '0', enabled: false});
  assert.equal(changed.total_limit, 107374182);
  assert.equal(changed.expires_at, 0);
  assert.equal(changed.ip_limit, 0);
  assert.equal(changed.enabled, false);
});

test('control shared accounts cannot accidentally reset their underlying legacy quota', () => {
  const original = {subscription_id: 'a'.repeat(32), total_limit: 0, enabled: true};
  const patch = forms.userPatch(original, {quota: '0.1', expires: '', ip_limit: '0', enabled: true, note: ''});
  assert.equal(Object.hasOwn(patch, 'total_limit'), false);
});

test('control expiry and numeric fields reject invalid inputs', () => {
  assert.equal(forms.expiryTimestamp(''), 0);
  const date = 1800000000;
  assert.equal(forms.expiryTimestamp(forms.expiryInput(date)), date);
  for (const value of ['yesterday', 'not-a-date']) assert.throws(() => forms.expiryTimestamp(value));
  for (const value of ['', 'NaN', '-1', '1.5', '10001']) assert.throws(() => forms.integer(value, 10000));
});

function theme({saved = null, system = false, denied = false} = {}) {
  const attributes = new Map(), storage = new Map(saved ? [['atlant-control-theme', saved]] : []);
  const callbacks = {};
  const select = {value: '', addEventListener(name, fn) {callbacks[name] = fn;}};
  const media = {matches: system, addEventListener(name, fn) {callbacks.media = fn;}};
  vm.runInNewContext(fs.readFileSync(path.join(root, 'theme.js'), 'utf8'), {
    document: {readyState: 'complete', documentElement: {setAttribute(k, v) {attributes.set(k, v);}}, getElementById() {return select;}},
    matchMedia() {return media;},
    localStorage: {getItem(k) {if (denied) throw Error(); return storage.get(k);}, setItem(k, v) {if (denied) throw Error(); storage.set(k, v);}},
  });
  return {attributes, select, storage, choose(value) {callbacks.change({target: {value}});}, system(value) {media.matches = value; callbacks.media();}};
}

test('control defaults to dark and preserves explicit light preference with blocked storage', () => {
  const ui = theme({system: true});
  assert.equal(ui.attributes.get('data-theme'), 'dark');
  ui.choose('light'); ui.system(true);
  assert.equal(ui.attributes.get('data-theme'), 'light');
  assert.equal(ui.storage.get('atlant-control-theme'), 'light');
  assert.equal(theme({saved: 'light', system: true}).attributes.get('data-theme'), 'light');
  ui.choose('dark'); ui.system(false);
  assert.equal(ui.attributes.get('data-theme'), 'dark');
  ui.choose('system');
  assert.equal(ui.attributes.get('data-theme'), 'dark');
  assert.equal(theme({system: false}).attributes.get('data-theme'), 'dark');
  assert.equal(theme({saved: 'system', system: false}).attributes.get('data-theme'), 'dark');
  const blocked = theme({denied: true});
  assert.doesNotThrow(() => blocked.choose('dark'));
  assert.equal(blocked.attributes.get('data-theme'), 'dark');
});

test('control pages render typed views, not raw JSON configuration dumps', () => {
  const app = fs.readFileSync(path.join(root, 'app.js'), 'utf8');
  assert.equal(/function display\(/.test(app), false);
  assert.equal(/JSON\.stringify\(result/.test(app), false);
  assert.equal(app.includes('innerHTML'), false);
  assert.match(app, /ControlForms\.userPatch/);
  assert.match(app, /subattach \$\{id\}/);
});

test('VPN service page does not expose legacy global inbound settings or identity', () => {
  const app = fs.readFileSync(path.join(root, 'app.js'), 'utf8');
  const service = app.split("} else if (page === 'settings') {")[1].split("} else if (page === 'logs') {")[0];
  assert.match(service, /read\('service status'\)/);
  assert.match(service, /service_scope_notice/);
  assert.match(service, /inbound_settings_location/);
  assert.match(service, /page = 'inbounds'/);
  assert.doesNotMatch(service, /read\('config(?:info)?'\)|configset|configsave|server_pub_key|field\(/);
  assert.doesNotMatch(app, /page === 'settings'\) groupWorkspace/);
  const inbounds = app.split("} else if (page === 'inbounds') {")[1].split("} else if (page === 'users') {")[0];
  assert.match(inbounds, /spec\.listen/);
  assert.match(inbounds, /spec\.sni/);
  assert.match(inbounds, /record\.server_pub_key/);
});

test('native inbounds distinguish saved state and expose writes only with capabilities', () => {
  const app = fs.readFileSync(path.join(root, 'app.js'), 'utf8');
  assert.match(app, /read\('inbounds'\)/);
  assert.match(app, /catalog\.running \? catalog\.active/);
  assert.match(app, /inbounds_readonly/);
  assert.match(app, /if \(catalog\.editable\)/);
  assert.match(app, /if \(catalog\.can_apply && catalog\.revision !== catalog\.applied_revision\)/);
  assert.match(app, /pending_inbound_settings/);
  assert.match(app, /const settings = \{\.\.\.original/);
  assert.match(app, /\['overview', 'inbounds', 'subscriptions', 'nodes'\]\.map/);
  assert.match(app, /subscription-endpoint/);
});

test('narrow workspace constrains navigation without shrinking tab labels', () => {
  const css = fs.readFileSync(path.join(root, 'style.css'), 'utf8');
  assert.match(css, /body #workspace\{grid-template-columns:minmax\(0,1fr\)\}/);
  assert.match(css, /\.sidebar\{min-width:0\}/);
  assert.match(css, /\.sidebar nav>button\{flex:0 0 auto\}/);
});

test('subscribers use compact rows and one grouped editor instead of separate quota/account forms', () => {
  const app = fs.readFileSync(path.join(root, 'app.js'), 'utf8');
  const listing = app.split("} else if (page === 'subscriptions') {")[1].split("} else if (page === 'nodes') {")[0];
  const editor = app.split("async function editSubscription(id = '') {")[1].split('async function editLegacySubscription')[0];
  assert.match(listing, /subscriber-row/);
  assert.doesNotMatch(listing, /subscription-card|subquota|subcreate|accountChoices/);
  assert.match(editor, /subscribercreate/);
  assert.match(editor, /group\('quota'\)/);
  assert.match(editor, /group\('connections'\)/);
  assert.doesNotMatch(editor, /usersall|accountChoices/);
  assert.match(fs.readFileSync(path.join(root, 'style.css'), 'utf8'), /prefers-reduced-motion:reduce/);
});
