'use strict';
let savedLanguage = '';
try { savedLanguage = localStorage.getItem('atlant-control-language') || ''; } catch {}
let lang = savedLanguage || (navigator.language || 'en').slice(0, 2);
if (!['en', 'ru', 'zh'].includes(lang)) lang = 'en';
let languages = {}, csrf = '', page = 'overview', pending = '', renderVersion = 0;
let usersPage = 1;
let authVersion = 0, loggingIn = false, logTimer;
let usersSearch = '';
let userFilter = 'all';
const selectedUsers = new Set();
let editorSequence = 0;
let demonstration = false;
let usersView = null;
let pendingCommand = '';
const $ = id => document.getElementById(id);
const t = key => languages[lang]?.[key] || languages.en?.[key] || key;
const quote = value => "'" + String(value).replaceAll("'", "'\"'\"'") + "'";
const json = value => JSON.stringify(value);
const bytes = value => new Intl.NumberFormat(lang, {maximumFractionDigits: 2}).format(Number(value || 0) / 1073741824) + ' GiB';

function element(tag, text, className) {
  const node = document.createElement(tag);
  if (text !== undefined) node.textContent = text;
  if (className) node.className = className;
  return node;
}
function icon(key) {
  const paths = {overview: 'M3 13h7V3H3z M14 21h7V11h-7z M3 21h7v-4H3z M14 7h7V3h-7z', users: 'M16 21v-2a4 4 0 0 0-4-4H6a4 4 0 0 0-4 4v2 M16 3a4 4 0 0 1 0 8 M22 21v-2a4 4 0 0 0-3-3.87 M13 7a4 4 0 1 1-8 0a4 4 0 0 1 8 0', settings: 'M4 4h16v6H4z M4 14h16v6H4z M7 7h1 M7 17h1', groups: 'M20 12l-8 8L2 10V2h8z M7 7h.01', subscriptions: 'M6 3h12v18H6z M9 7h6 M9 11h6 M9 15h4', nodes: 'M3 3h7v7H3z M14 14h7v7h-7z M10 6h7v8 M6 10v7h8', panel_settings: 'M4 4h16v16H4z M4 9h16 M9 9v11', core_settings: 'M6 3v18 M18 3v18 M3 7h6 M15 16h6', appearance: 'M12 3a9 9 0 1 0 9 9a7 7 0 0 1-9-9', certificates: 'M12 2l8 4v6c0 5-8 10-8 10S4 17 4 12V6z', security: 'M6 11h12v10H6z M8 11V7a4 4 0 0 1 8 0v4', logs: 'M5 3h14v18H5z M8 7h8 M8 11h8 M8 15h5', backups: 'M3 16v5h18v-5 M12 3v13 M7 8l5-5 5 5'};
  const svg = document.createElementNS('http://www.w3.org/2000/svg', 'svg');
  paths.edit = 'M16 3l5 5 M3 21l5-1L21 7a2 2 0 0 0-5-5L3 15z';
  svg.setAttribute('viewBox', '0 0 24 24'); svg.setAttribute('aria-hidden', 'true');
  const path = document.createElementNS('http://www.w3.org/2000/svg', 'path'); path.setAttribute('d', paths[key] || paths.settings); svg.append(path); return svg;
}
function button(key, action, className) {
  const node = element('button', t(key), className);
  node.type = 'button';
  node.addEventListener('click', async () => {
    if (node.disabled) return;
    node.disabled = true;
    try { await guarded(action); } finally { node.disabled = false; }
  });
  return node;
}
async function guarded(action) {
  try { $('notice').textContent = ''; await action(); }
  catch (error) { $('notice').textContent = languages[lang]?.[error.message] || error.message; }
}
async function request(path, data, retry = true) {
  const version = authVersion;
  const response = await fetch(path.replace(/^\//, ''), {method: data ? 'POST' : 'GET', credentials: 'same-origin', cache: 'no-store', headers: data ? {'Content-Type': 'application/json', 'X-CSRF-Token': csrf} : {}, body: data ? json({...data, lang}) : undefined});
  const result = await response.json();
  if (!response.ok) {
    // A delayed response from an older session must not log out a fresh login.
    if (response.status === 401 && version === authVersion && path !== '/control/login') signedIn(false);
    if (response.status === 403 && result.code === 'csrf_expired' && retry && version === authVersion) {
      const session = await request('/control/session');
      if (version !== authVersion) throw Error(t('unauthorized'));
      csrf = session.csrf;
      // CSRF rejection happens before command execution, so this retry is safe.
      return request(path, data, false);
    }
    throw Error(result.error || t('failed'));
  }
  return result;
}
function signedIn(yes) {
  if (yes) document.body.setAttribute('data-authenticated', 'true'); else document.body.removeAttribute('data-authenticated');
  $('workspace').hidden = !yes;
  $('logout').hidden = !yes;
  $('login').hidden = yes;
  if (!yes) {
    clearTimeout(logTimer);
    authVersion++;
    csrf = ''; pending = ''; pendingCommand = ''; renderVersion++;
    usersView = null;
    $('content').replaceChildren(); $('result-body').textContent = '';
    for (const id of ['result', 'confirmation', 'editor']) if ($(id).open) $(id).close();
  }
}
function translate() {
  document.documentElement.lang = lang;
  $('language').value = lang;
  for (const node of document.querySelectorAll('[data-i18n]')) node.textContent = t(node.dataset.i18n);
  $('logout').textContent = t('logout');
  const item = key => {
    const node = button(key === 'users' ? 'legacy_accounts' : key === 'settings' ? 'service' : key, async () => { page = key; await render(); });
    node.prepend(icon(key));
    if (key === page) node.setAttribute('aria-current', 'page');
    return node;
  };
  const section = (title, entries) => {
    const details = element('details'), heading = element('summary'), content = element('div');
    heading.append(icon(title), document.createTextNode(t(title))); details.open = entries.includes(page);
    content.append(...entries.map(item)); details.append(heading, content); return details;
  };
  const logout = $('logout'); logout.classList.add('nav-bottom');
  $('navigation').replaceChildren(...['overview', 'inbounds', 'subscriptions', 'nodes'].map(item), section('panel_settings', ['appearance', 'logs', 'language', 'groups']), section('core_settings', ['settings', 'users', 'backups']), logout);
}
async function read(command) {
  try { return (await request('/control/prepare', {command})).result; }
  catch (error) {
    if (/HTTP 404/.test(error.message)) throw Error(t('core_feature_unavailable'));
    throw error;
  }
}
async function readOptional(command, fallback) {
  try { return await read(command); } catch (error) { return fallback; }
}
function showResult(result) {
  $('result-title').textContent = t('completed');
  const data = result?.result || result;
  if (data?.uncertain) $('result-title').textContent = t('peer_job_unknown');
  else if (data?.ok === false) $('result-title').textContent = t('failed');
  const link = data?.link || data?.url;
  const peerMessage = data?.uncertain ? `${t('peer_uncertain')}\n${data.request_id}` : data?.ok === false ? t(data.error || 'peer_operation_failed') : data?.remote_notified === false ? t('peer_revoked_offline') : data?.pending === true ? t('peer_pending_notice') : data?.connected === true ? t('peer_connected_notice') : data?.approved === true ? t('peer_approved_notice') : '';
  $('result-body').textContent = link || data?.token || peerMessage || (typeof data === 'string' ? data : data?.applied === false ? t('inbound_saved_pending') : data?.backup ? `${t('backup_created')}\n${data.backup}` : t('completed'));
  $('result').showModal();
}
function requiresConfirmation(command) {
  const [verb, subcommand] = command.trim().split(/\s+/, 2);
  const critical = new Set(['delete','disable','kick','reset','rekey','subdelete','subkick','subrotate','subrekey','submigrate','inbounddelete','inboundapply','nodedel','groupdelete','quotadisable','backupremove','restore','certrestore','panelrestore','certjobdelete','peerrevoke','peergrant','peerreject','peercancel','peerapprove','peerfinish','peerjoin','peerexecute','peerretry','peersync','panelset','tlsset','certlisten','certjobset']);
  if (critical.has(verb)) return true;
  if (['service','certservice'].includes(verb)) return ['stop','restart'].includes(subcommand);
  if (verb === 'bulk') return ['delete','disable','reset'].includes(subcommand);
  if (verb === 'reload') return true;
  if (['configset','configsave','set','subset','inboundset','quotaset'].includes(verb)) {
    try {
      const patch = JSON.parse(command.slice(command.indexOf('{')));
      if (patch.enabled === false) return true;
      if (['configset','configsave'].includes(verb)) return Object.keys(patch).some(key => key !== 'log_level');
    } catch { return true; }
  }
  return false;
}
async function finishMutation(command, result) {
  const data = result?.result || result;
  let snapshot = null;
  const verb = command.split(' ')[0];
  if (page === 'users' && usersView && ['usercreate','add','set'].includes(verb) && typeof data?.name === 'string' && typeof data.enabled === 'boolean') {
    const users = usersView.data.users.filter(user => user.name !== data.name).concat(data).sort((a,b) => a.name.localeCompare(b.name));
    snapshot = {...usersView, data:{...usersView.data, users, total:users.length}};
    if (['usercreate','add'].includes(verb)) {
      usersSearch = ''; userFilter = 'all'; usersPage = Math.floor(users.findIndex(user => user.name === data.name) / 10) + 1;
    }
  }
  await render(snapshot);
  // Ordinary saves are silent. Only errors, uncertain remote outcomes and
  // explicitly requested credentials need a result window.
  if (data?.ok === false || data?.uncertain || data?.link_cache_saved === false || ['peerinvite','peerjoin','peerfinish','quotaenroll','subrotate','subrekey','rekey'].includes(verb)) showResult(result);
}
async function operation(command, reveal = false) {
  const result = await request('/control/prepare', {command, reveal});
  if (result.confirmation) {
    if (!requiresConfirmation(command)) {
      const completed = await request('/control/commit', {confirmation: result.confirmation, confirm: true});
      if ($('editor').open) $('editor').close();
      await finishMutation(command, completed.result);
      return;
    }
    if ($('editor').open) $('editor').close();
    pending = result.confirmation; pendingCommand = command;
    $('operation-label').textContent = result.label_key ? `${t(result.label_key)} · ${result.target}` : languages[lang]?.[result.label] || result.label;
    $('confirmation').showModal();
  } else showResult(result.result);
}
function field(form, key, value = '', type = 'text', choices) {
  const label = element('label'); label.append(element('span', t(key)));
  const input = element(choices ? 'select' : 'input'); input.name = key;
  if (choices) for (const option of choices) { const node = element('option', option.label); node.value = option.value; input.append(node); }
  else input.type = type;
  if (type === 'checkbox') { input.checked = Boolean(value); label.className = 'check'; }
  else input.value = value;
  label.append(input); form.append(label); return input;
}
function form(card, build, submit, submitLabel = 'save') {
  const node = element('form'); const controls = build(node);
  const errorBox = element('p', '', 'form-error'); errorBox.setAttribute('role', 'alert'); node.append(errorBox);
  const save = element('button', t(submitLabel), 'primary'); node.append(save); card.append(node);
  node.addEventListener('submit', event => { event.preventDefault(); guarded(async () => {
    save.disabled = true;
    const footer = $('save-editor');
    const grouped = footer?.dataset.formTarget === node.id;
    if (grouped) footer.disabled = true;
    errorBox.textContent = '';
    try { await submit(controls); } catch (error) { errorBox.textContent = t(error.message); throw error; }
    finally { save.disabled = false; if (grouped) footer.disabled = false; }
  }); });
}
function card(root, title) { const node = element('section', undefined, 'card'); node.dataset.section = title; node.append(element('h2', t(title))); root.append(node); return node; }
const workspaceTabs = {};
function groupWorkspace(root, groups) {
  const cards = [...root.querySelectorAll(':scope > .card')];
  const tabs = element('div', undefined, 'workspace-tabs'); tabs.setAttribute('role', 'tablist');
  const panels = [];
  for (const [title, keys] of groups) {
    const panel = element('div', undefined, 'workspace-panel'); panel.setAttribute('role', 'tabpanel');
    const selected = button(title, () => select(title)); selected.setAttribute('role', 'tab');
    selected.id = `tab-${page}-${title}`; panel.id = `panel-${page}-${title}`;
    selected.addEventListener('keydown', event => {
      if (!['ArrowLeft', 'ArrowRight', 'Home', 'End'].includes(event.key)) return;
      event.preventDefault();
      const index = panels.findIndex(entry => entry.selected === selected);
      const next = event.key === 'Home' ? 0 : event.key === 'End' ? panels.length - 1 : (index + (event.key === 'ArrowRight' ? 1 : -1) + panels.length) % panels.length;
      select(panels[next].title); panels[next].selected.focus();
    });
    selected.setAttribute('aria-controls', panel.id); panel.setAttribute('aria-labelledby', selected.id);
    for (const node of cards) if (keys.includes(node.dataset.section)) panel.append(node);
    if (!panel.childElementCount) continue;
    tabs.append(selected); root.append(panel); panels.push({title, panel, selected});
  }
  function select(title) {
    workspaceTabs[page] = title;
    for (const entry of panels) { const active = entry.title === title; entry.panel.hidden = !active; entry.selected.setAttribute('aria-selected', String(active)); entry.selected.tabIndex = active ? 0 : -1; }
  }
  root.insertBefore(tabs, root.children[1] || null);
  select(panels.some(entry => entry.title === workspaceTabs[page]) ? workspaceTabs[page] : panels[0]?.title);
}
function detailList(values) {
  const list = element('dl', undefined, 'facts');
  for (const [key, value] of values) { list.append(element('dt', t(key)), element('dd', value ?? '—')); }
  return list;
}
function facts(root, title, values) { card(root, title).append(detailList(values)); }
function table(root, headings, rows) {
  const wrap = element('div', undefined, 'table-scroll'), node = element('table'), head = element('tr');
  for (const key of headings) head.append(element('th', t(key)));
  const thead = element('thead'); thead.append(head); node.append(thead);
  const body = element('tbody');
  if (!rows.length) { const row = element('tr'), cell = element('td', t('empty'), 'empty'); cell.colSpan = headings.length; row.append(cell); body.append(row); }
  for (const cells of rows) { const row = element('tr'); for (const cell of cells) { const td = element('td'); td.append(cell instanceof Node ? cell : document.createTextNode(String(cell ?? ''))); row.append(td); } body.append(row); }
  node.append(body); wrap.append(node); root.append(wrap);
}
function actions(items) { const node = element('div', undefined, 'actions'); for (const [key, command, reveal] of items) node.append(button(key, () => operation(command, reveal), key === 'delete' ? 'danger' : '')); return node; }
function accountChoices(records) { return records.map(user => ({label: user.name, value: user.name})); }
function expiry(value) { return value ? new Date(Number(value) * 1000).toLocaleString(lang) : t('unlimited'); }
function badge(enabled) { return element('span', t(enabled ? 'enabled' : 'disabled'), `badge ${enabled ? 'on' : ''}`); }
function trafficUsage(total, spent, reserved = 0, shared = false) {
  total = Number(total || 0); spent = Number(spent || 0); reserved = Number(reserved || 0);
  const usage = element('div', undefined, 'usage'), progress = element('progress');
  progress.max = total || 1; progress.value = total ? Math.min(total, spent) : 0;
  progress.setAttribute('aria-label', t(shared ? 'quota' : 'user_quota'));
  usage.append(element('div', `${bytes(spent)} / ${total ? bytes(total) : t('unlimited')}`), progress);
  if (total) usage.append(element('div', `${t('remaining')}: ${bytes(Math.max(0, total - spent))}`, 'muted'));
  if (shared) usage.append(element('div', `${t('shared')} · ${t('reserved')}: ${bytes(reserved)}`, 'muted'));
  return usage;
}
function editDialog(title) {
  $('save-editor').hidden = true; $('save-editor').onclick = null; delete $('save-editor').dataset.formTarget;
  $('editor-title').textContent = title;
  $('editor-body').replaceChildren();
  return $('editor-body');
}
async function editInbound(id = '', remote = '') {
  const catalog = await read(remote ? `peercatalog ${remote}` : 'inbounds');
  if (remote && !catalog.peer_inbounds_write) throw Error('peer_forbidden');
  if (!catalog.editable) throw Error('invalid');
  const original = id ? catalog.inbounds.find(record => record.settings.id === id)?.settings : {
    id: '', name: '', enabled: true, listen: '0.0.0.0:1026', advertise_addr: '',
    sni: '', transports: ['tcp', 'xhttp', 'quic'], wire_version: 7, xhttp_path: '/api/v1/sync', up_mbps: 0, down_mbps: 0,
  };
  if (!original) throw Error('invalid');
  const root = editDialog(t(id ? 'edit' : 'create'));
  root.append(element('p', t('inbound_key_notice'), 'editor-note'));
  form(root, node => {
    node.className = 'inbound-form';
    const identity = field(node, 'inbound_id', original.id); identity.disabled = Boolean(id);
    const controls = {identity, name: field(node, 'name', original.name),
      listen: field(node, 'listen', original.listen), advertise: field(node, 'advertise_addr', original.advertise_addr || ''),
      sni: field(node, 'sni', original.sni), path: field(node, 'xhttp_path', original.xhttp_path || '/api/v1/sync'),
      up: field(node, 'up_mbps', original.up_mbps || 0, 'number'), down: field(node, 'down_mbps', original.down_mbps || 0, 'number')};
    controls.advertise.required = true;
    const transports = element('fieldset', undefined, 'transport-options'); transports.append(element('legend', t('protocol'))); node.append(transports);
    controls.transports = ['tcp', 'xhttp', 'quic'].map(value => [value, field(transports, 'transport_' + value, original.transports.includes(value), 'checkbox')]);
    controls.enabled = field(node, 'enabled', original.enabled, 'checkbox');
    const advanced = element('details', undefined, 'editor-group inbound-tuning');
    advanced.append(element('summary', t('transport_tuning')), element('p', t('tuning_defaults'), 'muted')); node.append(advanced);
    const tuningGrid = element('div', undefined, 'tuning-grid'); advanced.append(tuningGrid);
    controls.tuning = {};
    for (const [section, fields] of Object.entries(ControlForms.inboundTuning)) {
      const group = element('fieldset', undefined, 'editor-group'); group.append(element('legend', t(section + '_tuning'))); tuningGrid.append(group);
      controls.tuning[section] = fields.map(([key, label, maximum]) => {
        const input = field(group, label, original[section]?.[key] || 0, 'number');
        input.min = '0'; input.max = String(maximum); input.step = '1'; return [key, input, maximum];
      });
      if (section === 'quic') controls.disablePacer = field(group, 'quic_disable_pacer', original.quic?.disable_pacer || false, 'checkbox');
      else if (original.yamux?.max_connection_window_kb) group.append(element('p', t('yamux_legacy_window_notice'), 'muted'));
    }
    return controls;
  }, inputs => {
    const settings = {...original, id: inputs.identity.value.trim(), name: inputs.name.value.trim(), enabled: inputs.enabled.checked,
      listen: inputs.listen.value.trim(), advertise_addr: inputs.advertise.value.trim(), sni: inputs.sni.value.trim(),
      xhttp_path: inputs.path.value, up_mbps: ControlForms.integer(inputs.up.value, 1000000), down_mbps: ControlForms.integer(inputs.down.value, 1000000),
      transports: inputs.transports.filter(([,input]) => input.checked).map(([value]) => value)};
    if (!settings.transports.length) throw Error('invalid');
    for (const [section, fields] of Object.entries(inputs.tuning)) {
      settings[section] = {...original[section]};
      for (const [key, input, maximum] of fields) settings[section][key] = ControlForms.integer(input.value, maximum);
    }
    settings.quic.disable_pacer = inputs.disablePacer.checked;
    if ((settings.quic.keep_alive_period_sec || 10) >= (settings.quic.max_idle_timeout_sec || 30) ||
        (settings.quic.conn_receive_window_mb || 64) < (settings.quic.stream_receive_window_mb || 32) ||
        (settings.yamux.max_stream_window_kb > 0 && settings.yamux.max_stream_window_kb < 256)) throw Error('invalid');
    const command = `${id ? 'inboundset' : 'inboundcreate'} ${catalog.revision} ${json(settings)}`;
    return operation(remote ? `peerexecute ${remote} ${quote(command)}` : command);
  });
  const inboundForm = root.querySelector('form'); inboundForm.id = `inbound-form-${++editorSequence}`;
  const footerSave = $('save-editor'); footerSave.hidden = false; footerSave.disabled = false; footerSave.dataset.formTarget = inboundForm.id;
  footerSave.onclick = () => inboundForm.requestSubmit();
  $('editor').showModal();
}
function tabs(root, keys) {
  const result = {}, buttons = {}, bar = element('div', undefined, 'tab-list'); bar.setAttribute('role', 'tablist');
  const sequence = ++editorSequence;
  const choose = key => {
    for (const value of keys) { result[value].hidden = value !== key; buttons[value].setAttribute('aria-selected', String(value === key)); buttons[value].tabIndex = value === key ? 0 : -1; }
  };
  keys.forEach((key, index) => {
    const panel = element('div', undefined, 'tab-panel'), tab = button(key, () => choose(key));
    panel.id = `editor-${sequence}-${key}`; panel.setAttribute('role', 'tabpanel'); panel.setAttribute('aria-labelledby', panel.id + '-tab');
    tab.id = panel.id + '-tab'; tab.setAttribute('role', 'tab'); tab.setAttribute('aria-controls', panel.id);
    tab.addEventListener('keydown', event => {
      if (!['ArrowLeft', 'ArrowRight', 'Home', 'End'].includes(event.key)) return;
      event.preventDefault();
      const next = event.key === 'Home' ? 0 : event.key === 'End' ? keys.length - 1 : (index + (event.key === 'ArrowRight' ? 1 : keys.length - 1)) % keys.length;
      choose(keys[next]); buttons[keys[next]].focus();
    });
    result[key] = panel; buttons[key] = tab; bar.append(tab);
  });
  root.append(bar, ...keys.map(key => result[key])); choose(keys[0]); return result;
}

async function migrateSubscriptions() {
  const plan = await read('submigration'), root = editDialog(t('migrate_subscriptions'));
  root.append(element('p', t('migration_notice'), 'editor-note'));
  const selected = new Set();
  for (const item of plan.items) {
    const group = element('fieldset', undefined, 'editor-group'); group.append(element('legend', item.title));
    const choose = field(group, 'migrate_subscription', false, 'checkbox'); choose.disabled = !item.eligible;
    choose.addEventListener('change', () => choose.checked ? selected.add(item.id) : selected.delete(item.id));
    group.append(detailList([['converted_profiles', item.converted_profiles], ['preserved_profiles', item.preserved_profiles]]));
    for (const reason of item.blockers) group.append(element('p', t(reason), 'editor-note'));
    root.append(group);
  }
  if (!plan.items.some(item => item.eligible)) root.append(element('p', t('migration_empty')));
  else root.append(button('apply_migration', () => {
    if (!selected.size || selected.size > 100) throw Error('invalid');
    return operation(`submigrate ${plan.revision} ${[...selected].join(' ')}`);
  }, 'primary'));
  $('editor').showModal();
}

async function joinPanel() {
  const root = editDialog(t('peerjoin'));
  root.append(element('p', t('pairing_notice'), 'editor-note'));
  form(root, node => ({link: field(node, 'pairing_link', '', 'password')}), controls => {
    return operation('peerjoin ' + quote(controls.link.value.trim()));
  }, 'peerjoin');
  $('editor').showModal();
}

async function peerCatalog(id) {
  const result = await read(`peercatalog ${id}`), root = editDialog(t('peercatalog'));
  root.append(element('p', id, 'editor-note'));
  if (result.peer_inbounds_write) {
    const controls = element('div', undefined, 'actions');
    if (result.editable) controls.append(button('create', () => editInbound('', id), 'primary'));
    if (result.can_apply && result.revision !== result.applied_revision) controls.append(button('apply_inbounds', () => operation(`peerexecute ${id} ${quote(`inboundapply ${result.revision}`)}`)));
    root.append(controls);
  }
  for (const record of result.inbounds || []) {
    const node = card(root, 'inbounds'), spec = record.settings;
    node.append(element('h3', spec.name), detailList([['inbound_id', spec.id], ['listen', spec.listen], ['advertise_addr', spec.advertise_addr], ['sni', spec.sni], ['protocol', (spec.transports || []).join(' / ')]]));
    if (result.peer_inbounds_write && result.editable) {
      const controls = element('div', undefined, 'actions');
      controls.append(button('edit', () => editInbound(spec.id, id)), button('delete', () => operation(`peerexecute ${id} ${quote(`inbounddelete ${result.revision} ${spec.id}`)}`), 'danger'));
      node.append(controls);
    }
  }
  $('editor').showModal();
}
async function peerJobs(id) {
  const result = await read(`peerjobs ${id}`), root = editDialog(t('peerjobs'));
  root.append(element('p', t('peer_uncertain'), 'editor-note'));
  table(root, ['inbound_id', 'status', 'settings'], result.jobs.map(job => [job.id, t('peer_job_' + job.state), job.state === 'done' ? '—' : button('peerretry', () => operation(`peerretry ${id} ${job.id}`))]));
  $('editor').showModal();
}
async function cachedCatalogs() {
  const result = await read('remotecatalogs'), root = editDialog(t('remotecatalogs'));
  table(root, ['remote_panel', 'server_id', 'revision', 'inbounds'], result.map(catalog => [catalog.peer_id, catalog.server_id, catalog.revision, (catalog.inbounds || []).map(record => record.settings.name).join(' · ') || '—']));
  if (!result.length) root.append(element('p', t('empty')));
  $('editor').showModal();
}
async function editUser(name) {
  const user = await read(`user ${quote(name)}`), root = editDialog(`${t('edit')}: ${name}`), sections = tabs(root, ['basic', 'credentials', 'links']);
  if (user.subscription_id) sections.basic.append(element('p', t('shared_quota_note'), 'editor-note'));
  form(sections.basic, node => {
    const controls = {enabled: field(node, 'enabled', user.enabled, 'checkbox'), expires: field(node, 'expires', ControlForms.expiryInput(user.expires_at), 'datetime-local'), ip: field(node, 'ip_limit', String(user.ip_limit || 0), 'number'), note: field(node, 'note', user.note || '')};
    controls.expires.step = '1';
    controls.ip.min = '0'; controls.ip.max = '10000'; controls.note.maxLength = 2048;
    return controls;
  }, controls => {
    const patch = ControlForms.userPatch(user, {enabled: controls.enabled.checked, expires: controls.expires.value, ip_limit: controls.ip.value, note: controls.note.value});
    if (!user.subscription_id && user.total_limit) patch.total_limit = 0;
    if (!Object.keys(patch).length) throw Error('no_changes');
    return operation(`set ${name} ${json(patch)}`);
  });
  sections.basic.append(actions([['reset_traffic', `reset ${quote(name)}`]]));
  facts(sections.credentials, 'account', [['name', user.name], ['subscription_id', user.subscription_id || '—']]);
  sections.credentials.append(actions([['rekey', `rekey ${quote(name)}`]]));
  sections.links.append(actions([['show_link', `link ${quote(name)}`, true]]));
  $('editor').showModal();
}
async function createUser() {
  const root = editDialog(t('create')), sections = tabs(root, ['basic']);
  form(sections.basic, node => ({name: field(node, 'name'), expires: field(node, 'expires', '', 'datetime-local'), ip: field(node, 'ip_limit', '0', 'number'), enabled: field(node, 'enabled', true, 'checkbox'), note: field(node, 'note')}), values => operation('usercreate ' + json({name: values.name.value.trim(), total_limit: 0, expires_at: ControlForms.expiryTimestamp(values.expires.value), ip_limit: ControlForms.integer(values.ip.value, 1000000), enabled: values.enabled.checked, note: values.note.value})));
  $('editor').showModal();
}
async function editGroup(id = '') {
  const [groups, accounts] = await Promise.all([readOptional('groups', []), read('usersall')]);
  const current = groups.find(group => group.id === id) || {name: '', note: '', users: []};
  const root = editDialog(id ? `${t('edit')}: ${current.name}` : t('create')), sections = tabs(root, ['basic', 'group_members']);
  sections.group_members.append(element('p', t('group_move_notice'), 'editor-note'));
  const members = element('div', undefined, 'member-list'), chosen = new Set(current.users);
  for (const user of accounts.users) {
    const label = element('label', undefined, 'check'), input = element('input'); input.type = 'checkbox'; input.checked = chosen.has(user.name);
    input.addEventListener('change', () => input.checked ? chosen.add(user.name) : chosen.delete(user.name));
    const other = groups.find(group => group.id !== id && group.users.includes(user.name));
    label.append(input, document.createTextNode(user.name + (other ? ` · ${other.name}` : ''))); members.append(label);
  }
  sections.group_members.append(members);
  form(sections.basic, node => ({name: field(node, 'name', current.name), note: field(node, 'note', current.note)}), values => operation(`${id ? 'groupset ' + id : 'groupcreate'} ${json({name: values.name.value.trim(), note: values.note.value, users: [...chosen], ...(id ? {revision: current.revision} : {})})}`));
  // The shared save action also remains available on the membership tab.
  sections.group_members.append(button('save', () => {
    const form = sections.basic.querySelector('form'); form.requestSubmit();
  }, 'primary'));
  $('editor').showModal();
}
async function editSubscription(id = '') {
  const [current, catalog] = await Promise.all([id ? read(`sub ${id}`) : Promise.resolve(null), readOptional('inbounds', {inbounds: [], unavailable: true})]);
  const sub = current || {title: '', enabled: true, expires_at: 0, update_hours: 1, total_limit: 0, inbound_refs: [], nodes: []};
  const root = editDialog(t(id ? 'edit_subscriber' : 'create_subscriber'));
  root.append(element('p', t('subscriber_form_notice'), 'editor-note'));
  const catalogAvailable = !catalog.unavailable;
  const selected = catalogAvailable ? new Set((sub.inbound_refs || []).filter(ref => ref.server_id === catalog.server_id).map(ref => ref.inbound_id)) : new Set();
  const foreign = catalogAvailable ? (sub.inbound_refs || []).filter(ref => ref.server_id !== catalog.server_id) : (sub.inbound_refs || []);
  form(root, node => {
    node.className = 'subscriber-form';
    const group = key => { const section = element('fieldset', undefined, 'editor-group'); section.append(element('legend', t(key))); node.append(section); return section; };
    const basic = group('basic'), quota = group('quota'), connections = group('connections');
    const controls = {title: field(basic, 'title', sub.title), enabled: field(basic, 'enabled', sub.enabled, 'checkbox'), expires: field(basic, 'expires', ControlForms.expiryInput(sub.expires_at), 'datetime-local')};
    controls.title.required = true; controls.title.maxLength = 256; controls.expires.step = '1';
    if (!id || sub.managed) {
      controls.ipLimit = field(basic, 'subscriber_ip_limit', sub.ip_limit || 0, 'number'); controls.ipLimit.min = '0'; controls.ipLimit.max = '10000';
      controls.note = field(basic, 'note', sub.note || ''); controls.note.maxLength = 4096;
    }
    controls.quota = field(quota, 'gib', ControlForms.quotaInput(Number(sub.total_limit || 0)));
    controls.quota.inputMode = 'decimal';
    quota.append(element('p', t('subscriber_quota_notice'), 'compact-note'));
    if (id && sub.total_limit === undefined) controls.shared = field(quota, 'shared', false, 'checkbox');
    connections.append(element('p', t('subscriber_connections_notice'), 'compact-note'));
    for (const record of catalog.inbounds || []) {
      const spec = record.settings, label = element('label', undefined, 'inbound-choice'), input = element('input');
      input.type = 'checkbox'; input.checked = selected.has(spec.id);
      input.addEventListener('change', () => input.checked ? selected.add(spec.id) : selected.delete(spec.id));
      const description = element('span'); description.append(element('strong', spec.name), element('small', `${spec.advertise_addr || spec.listen} · ${(spec.transports || []).map(value => value.toUpperCase()).join(' / ')}`));
      label.append(input, description, badge(spec.enabled)); connections.append(label);
    }
    if (!catalogAvailable) connections.append(element('p', t('core_feature_unavailable'), 'editor-note'));
    else if (!(catalog.inbounds || []).length) connections.append(element('p', t('empty'), 'muted'));
    for (const ref of foreign) connections.append(element('p', `${ref.server_id} · ${ref.inbound_id}`, 'muted'));
    if (sub.nodes?.length) connections.append(element('p', `${t('imported_profiles')}: ${sub.nodes.length}. ${t('imported_profiles_preserved')}`, 'compact-note'));
    const advanced = element('details', undefined, 'editor-group'); advanced.append(element('summary', t('advanced_settings'))); node.append(advanced);
    controls.hours = field(advanced, 'update_hours', sub.update_hours, 'number'); controls.hours.min = '1'; controls.hours.max = '168';
    controls.support = field(advanced, 'support_url', sub.support_url || '', 'url'); controls.announcement = field(advanced, 'announcement', sub.announcement || '');
    return controls;
  }, controls => {
    const refs = [...foreign, ...[...selected].map(inbound_id => ({server_id: catalog.server_id, inbound_id}))];
    if (!id && !refs.length) throw Error('select_inbound_first');
    if ((catalog.inbounds || []).some(record => selected.has(record.settings.id) && !record.settings.advertise_addr?.trim())) throw Error('inbound_public_address_required');
    const patch = {title: controls.title.value.trim(), enabled: controls.enabled.checked, expires_at: ControlForms.expiryTimestamp(controls.expires.value), update_hours: ControlForms.integer(controls.hours.value, 168), support_url: controls.support.value, announcement: controls.announcement.value, inbound_refs: refs};
    if (!patch.update_hours) throw Error('invalid');
    if (controls.ipLimit) { patch.ip_limit = ControlForms.integer(controls.ipLimit.value, 10000); patch.note = controls.note.value; }
    if (!controls.shared || controls.shared.checked) patch.total_limit = ControlForms.quotaBytes(controls.quota.value);
    else if (refs.length) throw Error('enable_quota_first');
    if (id) { patch.revision = sub.revision; return operation(`subset ${id} ${json(patch)}`); }
    return operation(`subscribercreate ${json(patch)}`, true);
  });
  const groupedForm = root.querySelector('form'); groupedForm.id = `subscriber-form-${++editorSequence}`;
  const footerSave = $('save-editor'); footerSave.hidden = false; footerSave.disabled = false; footerSave.dataset.formTarget = groupedForm.id;
  footerSave.onclick = () => groupedForm.requestSubmit();
  if (id) {
    const links = element('details', undefined, 'editor-group'); links.append(element('summary', t('links')), actions([['rotate_link', `subrotate ${id}`, true]])); root.append(links);
    if (!sub.managed) root.append(button('legacy_management', async () => { $('editor').close(); await editLegacySubscription(id); }));
  }
  $('editor').showModal();
}
async function showSubscriptionLink(id, title) {
  const result = await request('/control/prepare', {command: `subshare ${id}`, reveal: true});
  const show = url => AtlantShare.open(url, title, {qr:t('share_qr'),link:t('subscription_url'),copy:t('copy'),copied:t('copied'),close:t('cancel'),warning:t('share_warning'),tooLong:t('share_qr_failed')});
  if (result.result?.url) { show(result.result.url); return; }
  const root = editDialog(t('share_subscription'));
  root.append(element('p', t('share_missing'), 'editor-note'));
  form(root, node => {
    const url = field(node, 'subscription_url', '', 'url'); url.required = true; url.maxLength = 2048; return {url};
  }, async controls => {
    const prepared = await request('/control/prepare', {command:`subshareimport ${id} ${quote(controls.url.value.trim())}`,reveal:true});
    const committed = await request('/control/commit', {confirmation:prepared.confirmation,confirm:true});
    $('editor').close(); show(committed.result.result.url);
  });
  $('editor').showModal();
}
async function editLegacySubscription(id) {
  const [sub, all, config, bindings] = await Promise.all([read(`sub ${id}`), read('usersall'), read('config'), read('quotabindings')]);
  const root = editDialog(`${t('edit')}: ${sub.title}`), sections = tabs(root, ['basic', 'group_members', 'connections', 'links']);
  form(sections.basic, node => {
    const controls = {title: field(node, 'title', sub.title), enabled: field(node, 'enabled', sub.enabled, 'checkbox'), expires: field(node, 'expires', ControlForms.expiryInput(sub.expires_at), 'datetime-local'), hours: field(node, 'update_hours', sub.update_hours, 'number'), support: field(node, 'support_url', sub.support_url || '', 'url'), announcement: field(node, 'announcement', sub.announcement || ''), shared: field(node, 'shared', sub.total_limit !== undefined, 'checkbox'), quota: field(node, 'gib', ControlForms.quotaInput(Number(sub.total_limit || 0)))};
    controls.expires.step = '1'; controls.hours.min = '1'; controls.hours.max = '168';
    controls.shared.disabled = sub.total_limit !== undefined; controls.title.required = true;
    return controls;
  }, controls => {
    const patch = {revision: sub.revision, title: controls.title.value, enabled: controls.enabled.checked, expires_at: ControlForms.expiryTimestamp(controls.expires.value), update_hours: ControlForms.integer(controls.hours.value, 168), support_url: controls.support.value, announcement: controls.announcement.value};
    if (!patch.update_hours) throw Error('invalid');
    if (controls.shared.checked && (sub.total_limit === undefined || controls.quota.value !== String(Number(sub.total_limit) / 1073741824))) patch.total_limit = ControlForms.quotaBytes(controls.quota.value);
    return operation(`subset ${id} ${json(patch)}`);
  });
  sections.group_members.append(element('h2', t('account')));
  table(sections.group_members, ['name', 'status', 'settings'], all.users.filter(user => user.name === sub.user || user.subscription_id === id || bindings.some(binding => binding.user === user.name && binding.subscription === id)).map(user => [user.name, badge(user.enabled), button('edit', () => editUserFromSubscription(user.name))]));
  if (sub.total_limit === undefined) sections.group_members.append(element('p', t('enable_quota_first'), 'editor-note'));
  else {
    const endpoints = sub.nodes.map((node, index) => ({node, index: index + 1})).filter(entry => entry.node.server_pub_key === config.server_pub_key);
    const available = all.users.filter(user => !user.subscription_id && !bindings.some(binding => binding.user === user.name));
    sections.group_members.append(element('h2', t('attach_account')), element('p', t('attach_notice'), 'editor-note'));
    if (endpoints.length && available.length) form(sections.group_members, node => ({user: field(node, 'account', available[0].name, 'text', accountChoices(available)), endpoint: field(node, 'endpoint', String(endpoints[0].index), 'text', endpoints.map(entry => ({value: String(entry.index), label: `${entry.node.name} · ${entry.node.server}`})))}), controls => operation(`subattach ${id} ${controls.user.value} ${controls.endpoint.value}`), 'attach_account');
    else sections.group_members.append(element('p', t('empty'), 'muted'));
  }
  sections.connections.append(element('p', t('endpoint_notice'), 'editor-note'), button('create', () => editEndpoint(id), 'primary'));
  table(sections.connections, ['name', 'endpoint', 'account', 'settings'], sub.nodes.map((node, index) => [node.name, node.server, node.user || sub.user, endpointActions(id, index + 1, sub.revision)]));
  sections.links.append(actions([['rotate_link', `subrotate ${id}`, true]]));
  $('editor').showModal();
}
function endpointActions(id, index, revision) {
  const controls = actions([['delete', `nodedel ${id} ${index} ${revision}`]]);
  controls.prepend(button('edit', () => editEndpoint(id, index))); return controls;
}
async function editEndpoint(id, index = 0) {
  const [sub, config] = await Promise.all([read(`sub ${id}`), read('config')]);
  const current = index ? sub.nodes[index - 1] : {name: '', server: config.advertise_addr || '', sni: config.sni || '', server_pub_key: config.server_pub_key || '', user: '', wire_version: config.wire_version || 7};
  if (!current) throw Error('invalid');
  if ($('editor').open) $('editor').close();
  const root = editDialog(t(index ? 'edit_endpoint' : 'add_endpoint'));
  root.append(element('p', t('endpoint_notice'), 'editor-note'), element('p', t('endpoint_key_notice'), 'editor-note'));
  form(root, node => {
    const inputs = {name: field(node, 'name', current.name), server: field(node, 'endpoint', current.server), sni: field(node, 'sni', current.sni), pin: field(node, 'public_key', current.server_pub_key), user: field(node, 'account', current.user || ''), key: field(node, 'endpoint_key', '', 'password'), clear: field(node, 'clear_endpoint_key', false, 'checkbox'), wire: field(node, 'wire_version', String(current.wire_version), 'text', [7, 6, 4, 3, 2].map(version => ({value: String(version), label: String(version)})))};
    for (const key of ['name', 'server', 'sni', 'pin']) inputs[key].required = true;
    inputs.pin.pattern = '[a-fA-F0-9]{64}'; inputs.key.pattern = '[a-fA-F0-9]{64}'; inputs.key.autocomplete = 'off';
    inputs.name.maxLength = 256; inputs.sni.maxLength = 253; inputs.server.maxLength = 512;
    return inputs;
  }, inputs => {
    const patch = {revision: sub.revision, name: inputs.name.value.trim(), server: inputs.server.value.trim(), sni: inputs.sni.value.trim(), server_pub_key: inputs.pin.value.trim(), user: inputs.user.value.trim(), wire_version: ControlForms.integer(inputs.wire.value, 7)};
    if (inputs.key.value && inputs.clear.checked) throw Error('invalid');
    if (inputs.key.value) patch.pbk = inputs.key.value.trim();
    else if (inputs.clear.checked) patch.pbk = '';
    else if (!index && patch.server_pub_key !== config.server_pub_key) throw Error('remote_key_required');
    return operation(`${index ? `nodeset ${id} ${index}` : `nodeadd ${id}`} ${json(patch)}`);
  });
  root.append(button('back_to_subscription', async () => { $('editor').close(); await editSubscription(id); }));
  $('editor').showModal();
}
async function editUserFromSubscription(name) { $('editor').close(); await editUser(name); }
async function editQuotaNode(id = '') {
  const [nodes, subscriptions] = await Promise.all([read('quotanodes'), read('subscriptions')]);
  const current = (nodes || []).find(node => node.id === id) || {id: '', enabled: true, subscriptions: []};
  const root = editDialog(t(id ? 'edit' : 'enroll_node')), chosen = new Set(current.subscriptions);
  root.append(element('p', t('quota_node_notice'), 'editor-note'));
  form(root, node => {
    const fields = {id: field(node, 'node_id', current.id), enabled: field(node, 'enabled', current.enabled, 'checkbox')};
    fields.id.required = true; fields.id.pattern = '[A-Za-z0-9_-]{1,64}'; fields.id.disabled = Boolean(id);
    const members = element('fieldset', undefined, 'member-list'); members.append(element('legend', t('subscriptions')));
    for (const sub of subscriptions) {
      const label = element('label', undefined, 'check'), checkbox = element('input'); checkbox.type = 'checkbox'; checkbox.checked = chosen.has(sub.id);
      checkbox.addEventListener('change', () => checkbox.checked ? chosen.add(sub.id) : chosen.delete(sub.id));
      label.append(checkbox, document.createTextNode(sub.title)); members.append(label);
    }
    node.append(members); return fields;
  }, fields => {
    if (id) return operation(`quotaset ${id} ${json({enabled: fields.enabled.checked, subscriptions: [...chosen]})}`);
    if (!chosen.size) throw Error('invalid');
    return operation(`quotaenroll ${fields.id.value.trim()} ${[...chosen].join(' ')}`, true);
  });
  $('editor').showModal();
}
async function editCertificateJob(id = '') {
  const data = await read('certjobs');
  if (!data.manager_available) throw Error('certificate_helper_missing');
  const defaults = data.defaults || {};
  const job = id ? data.jobs.find(job => job.id === id) : {id: defaults.id || 'panel', tls: {mode: defaults.mode || 'acme-ip', host: defaults.host || '', email: defaults.email || '', accept_terms: defaults.accept_terms !== false, staging: defaults.staging === true}};
  if (!job) throw Error('certificate_missing');
  const root = editDialog(t(id ? 'edit' : 'create'));
  root.append(element('p', t('certificate_job_notice'), 'editor-note'));
  form(root, node => {
    const values = {id: field(node, 'certificate_job_id', job.id), mode: field(node, 'mode', job.tls.mode, 'text', [{value: 'acme-ip', label: t('tls_ip')}, {value: 'acme-domain', label: t('tls_domain')}]), host: field(node, 'host', job.tls.host), email: field(node, 'email', job.tls.email, 'email'), terms: field(node, 'accept_terms', job.tls.accept_terms, 'checkbox'), staging: field(node, 'staging', job.tls.staging, 'checkbox')};
    values.id.pattern = '[A-Za-z0-9_-]{1,64}'; values.id.required = true; values.id.disabled = Boolean(id);
    values.host.required = true; values.host.maxLength = 253; values.email.maxLength = 254;
    values.terms.required = true;
    if (!id) values.mode.addEventListener('change', () => {
      const automatic = values.mode.value === 'acme-ip' ? defaults.ip : defaults.domain;
      if (automatic) values.host.value = automatic;
    });
    return values;
  }, values => operation(`${id ? 'certjobset' : 'certjobcreate'} ${values.id.value.trim()} ${json({revision: data.revision, mode: values.mode.value, host: values.host.value.trim(), email: values.email.value.trim(), accept_terms: values.terms.checked, staging: values.staging.checked})}`));
  $('editor').showModal();
}
function logLines(root, value) {
  const rows = Array.isArray(value) ? value : Array.isArray(value?.logs) ? value.logs : String(value?.logs || value || '').split('\n');
  const list = root.querySelector('.log-lines') || element('ol', undefined, 'log-lines');
  const follow = list.scrollHeight - list.scrollTop - list.clientHeight < 48;
  list.replaceChildren();
  for (const row of rows.filter(row => row !== '').slice(-50)) {
    const text = typeof row === 'string' ? row : row.message || row.line || '—';
    list.append(element('li', text, /\b(ERR|ERROR|FATAL)\b/i.test(text) ? 'log-error' : /\bWARN\b/i.test(text) ? 'log-warning' : ''));
  }
  if (!list.children.length) list.append(element('li', t('log_empty'), 'muted'));
  if (!list.parentNode) {
    const window = card(root, 'logs'); window.classList.add('log-window');
    window.append(element('p', t('log_live'), 'log-live'), list);
    list.setAttribute('aria-label', t('logs')); list.tabIndex = 0;
  }
  root.querySelector('.log-live').textContent = `${t('log_live')} · ${new Date().toLocaleTimeString(lang)}`;
  if (follow) list.scrollTop = list.scrollHeight;
}

function scheduleLogs(version, root) {
  logTimer = setTimeout(async () => {
    if (version !== renderVersion || !csrf || page !== 'logs') return;
    try {
      if (!document.hidden) {
        const value = await read('logs 50');
        if (version !== renderVersion || !csrf) return;
        logLines(root, value); $('notice').textContent = '';
      }
    } catch (error) { if (version === renderVersion && csrf) $('notice').textContent = error.message; }
    if (version === renderVersion && csrf) scheduleLogs(version, root);
  }, 3000);
}

async function editPanelSettings() {
  const data = await read('panelsettings'), jobs = await read('certjobs'), current = data.settings;
  const settings = current.tls || {}, mode = settings.mode?.startsWith('acme-') ? 'agent' : (settings.cert_file || current.cert_file) ? 'manual' : 'loopback-http';
  const root = editDialog(t('panel_address'));
  root.append(element('p', t('panel_tls_automatic'), 'editor-note'));
  root.append(element('p', t('panel_saved_notice'), 'editor-note'));
  form(root, node => {
    const modes = [{value: 'manual', label: t('tls_manual')}, {value: 'loopback-http', label: t('loopback_http')}];
    if (jobs.jobs.length) modes.splice(1, 0, {value: 'agent', label: t('tls_agent')});
    const values = {
      listen: field(node, 'listen', current.listen), port: field(node, 'port', current.port, 'number'), origin: field(node, 'public_url', current.origin),
      mode: field(node, 'mode', mode, 'text', modes),
      certificate: field(node, 'cert_file', settings.cert_file || current.cert_file || ''), key: field(node, 'key_file', settings.key_file || current.key_file || ''),
      job: field(node, 'certificate_job_id', current.certificate_agent?.job_id || jobs.jobs[0]?.id || '', 'text', jobs.jobs.map(job => ({value: job.id, label: `${job.id} · ${job.tls.host}${job.tls.staging ? ' · ' + t('staging') : ''}`}))),
    };
    for (const key of ['listen', 'origin', 'port']) values[key].required = true;
    values.port.min = '1'; values.port.max = '65535';
    const update = () => {
      for (const key of ['certificate', 'key']) { values[key].closest('label').hidden = values.mode.value !== 'manual'; values[key].required = values.mode.value === 'manual'; }
      values.job.closest('label').hidden = values.mode.value !== 'agent'; values.job.required = values.mode.value === 'agent';
    };
    values.mode.addEventListener('change', update); update();
    return values;
  }, values => {
    const patch = {listen: values.listen.value.trim(), port: ControlForms.integer(values.port.value), origin: values.origin.value.trim(), mode: values.mode.value, revision: data.revision};
    if (patch.mode === 'manual') { patch.cert_file = values.certificate.value.trim(); patch.key_file = values.key.value.trim(); }
    if (patch.mode === 'agent') patch.job_id = values.job.value;
    return operation('panelset ' + json(patch));
  });
  $('editor').showModal();
}

async function render(snapshot = null) {
  clearTimeout(logTimer);
  const version = ++renderVersion;
  translate();
  const root = element('div'), heading = element('div', undefined, 'page-top');
  const title = element('div', undefined, 'page-title');
  title.append(element('span', t('network_management'), 'eyebrow'), element('h1', t(page === 'users' ? 'legacy_accounts' : page === 'settings' ? 'service' : page)));
  if (['inbounds', 'subscriptions'].includes(page)) title.append(element('p', t(page + '_description')));
  heading.append(title);
  if (page === 'users') heading.append(button('create', createUser, 'primary'));
  if (page === 'groups') heading.append(button('create', () => editGroup(), 'primary'));
  if (page === 'subscriptions') heading.append(button('create_subscriber', () => editSubscription(), 'primary'));
  root.append(heading);
  if (page === 'overview') {
    const [status, online] = await Promise.all([read('status'), read('online')]);
    const metrics = element('div', undefined, 'metrics');
    for (const [key, value] of [['users', status.total_users ?? status.users ?? 0], ['connections', status.active_connections || 0], ['upload', bytes(status.total_up_bytes)], ['download', bytes(status.total_down_bytes)], ['upload_speed', `${Number(status.current_up_bps || 0).toLocaleString(lang)} B/s`], ['download_speed', `${Number(status.current_down_bps || 0).toLocaleString(lang)} B/s`]]) {
      const item = element('div', undefined, 'metric'); item.append(element('span', t(key)), element('strong', String(value))); metrics.append(item);
    }
    root.append(metrics);
    facts(root, 'status', [['version', status.version || '—'], ['protocol', status.protocol || 'Atlant'], ['uptime', status.uptime_str || `${status.uptime_sec || 0} s`], ['listen', status.server_addr || '—'], ['sni', status.sni || '—'], ['memory', `${Number(status.memory_alloc_mb || 0).toLocaleString(lang)} MB`]]);
    const sessions = Array.isArray(online) ? online : online.sessions || online.connections || [];
    const groupedSessions = new Map();
    for (const item of sessions) {
      const name = item.user || item.name || '—', remote = item.remote_addr || item.remote || '—', protocol = item.transport || item.protocol || '—';
      const key = json([name, remote, protocol]), since = item.started_at || item.connected_at || '';
      const group = groupedSessions.get(key) || {name, remote, protocol, count: 0, since};
      group.count++; if (since && (!group.since || since < group.since)) group.since = since;
      groupedSessions.set(key, group);
    }
    table(card(root, 'online'), ['account', 'remote', 'protocol', 'connections', 'since'], [...groupedSessions.values()].map(item => [item.name, item.remote, item.protocol, item.count, item.since ? new Date(item.since).toLocaleString(lang) : '—']));
    card(root, 'status').append(button('refresh', render));
  } else if (page === 'inbounds') {
    let catalog = null;
    try { catalog = await read('inbounds'); } catch (error) { catalog = null; }
    if (!catalog) {
      card(root, 'inbounds').append(element('p', t('core_feature_unavailable'), 'editor-note'));
    } else {
    const summary = card(root, 'status');
    summary.classList.add('connection-toolbar');
    const revisions = element('div', undefined, 'revision-pills');
    revisions.append(element('span', `${t('saved_revision')}: ${catalog.revision}`, 'badge'), element('span', `${t('applied_revision')}: ${catalog.applied_revision}`, 'badge on'));
    const help = element('details', undefined, 'toolbar-help'); help.append(element('summary', t('settings')), element('p', t(catalog.editable ? 'inbounds_apply_notice' : 'inbounds_readonly'), 'editor-note'));
    summary.append(revisions, help);
    const controls = element('div', undefined, 'actions'); controls.append(button('refresh', render));
    if (catalog.editable) controls.append(button('create', () => editInbound(), 'primary'));
    if (catalog.can_apply && catalog.revision !== catalog.applied_revision) controls.append(button('apply_inbounds', () => operation(`inboundapply ${catalog.revision}`)));
    summary.append(controls);
    const list = element('div', undefined, 'connection-list'); card(root, 'inbounds').append(list);
    const active = new Set(catalog.running ? catalog.active || [] : []);
    for (const record of catalog.inbounds || []) {
      const spec = record.settings, item = element('details', undefined, 'connection-row');
      const top = element('summary', undefined, 'connection-summary');
      const pendingSettings = catalog.revision !== catalog.applied_revision;
      top.append(element('span', spec.name || spec.id, 'connection-name'), element('code', spec.advertise_addr || spec.listen), element('span', t(active.has(spec.id) ? pendingSettings ? 'listener_previous' : 'listener_running' : 'listener_stopped'), `badge ${active.has(spec.id) ? 'on' : ''}`));
      const transports = element('div', undefined, 'transport-list');
      for (const transport of spec.transports || []) transports.append(element('span', transport.toUpperCase(), 'transport-tag'));
      top.append(transports);
      const details = element('div', undefined, 'connection-body');
      details.append(detailList([['listen', spec.listen], ['sni', spec.sni], ['version', `wire ${spec.wire_version}`], ['status', t(spec.enabled ? 'enabled' : 'disabled')], ['endpoint', spec.id], ['server_pub_key', record.server_pub_key], ['xhttp_path', spec.xhttp_path || '—']]));
      if (pendingSettings) details.append(element('p', t('pending_inbound_settings'), 'editor-note'));
      item.append(top, details); list.append(item);
      if (catalog.editable) {
        const controls = actions([['delete', `inbounddelete ${catalog.revision} ${spec.id}`]]);
        controls.prepend(button('edit', () => editInbound(spec.id))); details.append(controls);
      }
    }
    if (!list.childElementCount) list.append(element('p', t('empty'), 'empty'));
    }
  } else if (page === 'users') {
    const [data, groups, subscriptions] = snapshot?.page === 'users' ? [snapshot.data,snapshot.groups,snapshot.subscriptions] : await Promise.all([read('usersall'), readOptional('groups', []), read('subscriptions')]);
    if (version === renderVersion && csrf) usersView = {page:'users',data,groups,subscriptions};
    for (const name of selectedUsers) if (!data.users.some(user => user.name === name)) selectedUsers.delete(name);
    const quotaFor = user => subscriptions.find(sub => sub.id === user.subscription_id)?.global_quota;
    const matches = user => {
      const shared = quotaFor(user), total = Number(shared?.total_limit ?? 0), spent = shared ? Number(shared.upload) + Number(shared.download) : Number(user.up_bytes || 0) + Number(user.down_bytes || 0);
      const exhausted = total > 0 && spent >= total;
      return userFilter === 'all' || userFilter === 'connected' && user.online || userFilter === 'disabled' && !user.enabled || userFilter === 'exhausted' && exhausted || userFilter === 'active' && user.enabled && !exhausted && (!user.expires_at || user.expires_at * 1000 > Date.now());
    };
    const filtered = data.users.filter(user => matches(user) && (user.name + ' ' + (user.note || '')).toLowerCase().includes(usersSearch.toLowerCase()));
    usersPage = Math.max(1, Math.min(usersPage, Math.ceil(filtered.length / 10)));
    const filters = element('div', undefined, 'toolbar');
    for (const key of ['all', 'connected', 'active', 'exhausted', 'disabled']) filters.append(button(key, async () => { userFilter = key; usersPage = 1; await render(); }, `filter-chip ${key === userFilter ? 'active' : ''}`));
    root.append(filters);
    const searchBar = element('div', undefined, 'toolbar'), search = element('input'); search.type = 'search'; search.placeholder = t('search'); search.value = usersSearch;
    const searchButton = button('search', async () => {
      usersSearch = search.value.trim(); usersPage = 1; await render();
    }); searchBar.append(search, searchButton); root.append(searchBar);
    search.addEventListener('keydown', event => { if (event.key === 'Enter') { event.preventDefault(); searchButton.click(); } });
    const list = card(root, 'clients'), current = filtered.slice((usersPage - 1) * 10, usersPage * 10);
    const bulk = element('div', undefined, 'toolbar'), selected = element('span', `${t('bulk_actions')}: ${selectedUsers.size}`, 'muted'); bulk.append(selected);
    for (const [label, command] of [['enable', 'enable'], ['disable', 'disable'], ['reset_traffic', 'reset'], ['delete', 'delete']]) {
      const action = button(label, () => {
        if (!selectedUsers.size || selectedUsers.size > 100) throw Error('invalid');
        return operation(`bulk ${command} ${[...selectedUsers].map(quote).join(' ')}`);
      }, command === 'delete' ? 'danger' : '');
      action.disabled = !selectedUsers.size; bulk.append(action);
    }
    bulk.append(button('clear_selection', async () => { selectedUsers.clear(); await render(); })); list.append(bulk);
    renderUserRows(list, current, groups, subscriptions);
    const paging = element('div', undefined, 'actions');
    const previous = button('previous', async () => { usersPage--; await render(); }); previous.disabled = usersPage <= 1;
    const next = button('next', async () => { usersPage++; await render(); }); next.disabled = usersPage * 10 >= filtered.length;
    paging.append(previous, element('span', String(usersPage)), next); root.append(paging);
  } else if (page === 'groups') {
    let groups = null;
    try { groups = await read('groups'); } catch (error) { groups = null; }
    if (!groups) {
      card(root, 'groups').append(element('p', t('core_feature_unavailable'), 'editor-note'));
    } else {
    card(root, 'groups').append(element('p', t('group_notice'), 'editor-note'));
    table(card(root, 'groups'), ['name', 'clients', 'upload', 'download', 'used', 'settings'], groups.map(group => {
      const controls = actions([['delete', `groupdelete ${group.id}`]]); controls.prepend(button('edit', () => editGroup(group.id)));
      return [group.name, String(group.users.length), bytes(group.up_bytes), bytes(group.down_bytes), bytes(Number(group.up_bytes || 0) + Number(group.down_bytes || 0)), controls];
    }));
    }
  } else if (page === 'subscriptions') {
    const [records, catalog] = await Promise.all([read('subscriptions'), readOptional('inbounds', {inbounds: [], unavailable: true})]);
    const toolbar = element('div', undefined, 'toolbar'), search = element('input'); search.type = 'search'; search.placeholder = t('search'); search.setAttribute('aria-label', t('search'));
    toolbar.append(search, element('span', `${t('subscriptions')}: ${records.length}`, 'muted')); root.append(toolbar);
    toolbar.append(button('migrate_subscriptions', migrateSubscriptions));
    const subscriptions = element('div', undefined, 'subscriber-table'); subscriptions.setAttribute('role', 'table'); subscriptions.setAttribute('aria-label', t('subscriptions')); root.append(subscriptions);
    const head = element('div', undefined, 'subscriber-main subscriber-head'); head.setAttribute('role', 'row');
    for (const key of ['title', 'status', 'quota', 'expires', 'settings']) { const cell = element('div', t(key)); cell.setAttribute('role', 'columnheader'); head.append(cell); } subscriptions.append(head);
    const searchable = [];
    for (const sub of records) {
      const item = element('section', undefined, 'subscriber-row'), row = element('div', undefined, 'subscriber-main'); item.setAttribute('role', 'rowgroup'); row.setAttribute('role', 'row');
      const cell = (className, content) => { const value = element('div', undefined, className); value.setAttribute('role', 'cell'); value.append(content); row.append(value); return value; };
      const count = (sub.nodes || []).length + (sub.inbound_refs || []).length;
      const name = button('connections', () => { const open = detail.hidden; detail.hidden = !open; name.setAttribute('aria-expanded', String(open)); }, 'subscriber-expand');
      name.replaceChildren(element('strong', sub.title), element('small', `${t('connections')}: ${count}`)); name.setAttribute('aria-expanded', 'false'); name.title = sub.title;
      cell('subscriber-name', name); cell('subscriber-status', badge(sub.enabled));
      const q = sub.global_quota, usage = element('div', undefined, 'subscriber-usage');
      if (q) {
        const spent = Number(q.upload) + Number(q.download), total = Number(q.total_limit), progress = element('progress'); progress.max = total || 1; progress.value = total ? Math.min(total, spent) : 0; progress.setAttribute('aria-label', t('quota'));
        usage.append(element('span', `${bytes(spent)} / ${total ? bytes(total) : t('unlimited')}`), progress);
        if (total) usage.append(element('small', `${t('remaining')}: ${bytes(Math.max(0, total - spent))}`));
      } else usage.textContent = '—';
      cell('subscriber-traffic', usage); cell('subscriber-expiry', element('span', expiry(sub.expires_at)));
      const controls = element('div', undefined, 'actions'), edit = button('edit', () => editSubscription(sub.id));
      const share = button('share_subscription', () => showSubscriptionLink(sub.id, sub.title), 'share-subscription-button');
      share.title = t('share_subscription'); share.setAttribute('aria-label', share.title); share.textContent = 'QR';
      edit.setAttribute('aria-label', t('edit')); edit.title = t('edit'); edit.replaceChildren(icon('edit')); controls.append(share, edit);
      const menu = element('details', undefined, 'row-menu'), menuTitle = element('summary', '⋯'); menuTitle.setAttribute('aria-label', t('settings'));
      const options = actions([[sub.enabled ? 'disable' : 'enable', `subset ${sub.id} ${json({enabled: !sub.enabled})}`]]);
      if (sub.managed) {
        options.append(button('disconnect', () => operation(`subkick ${sub.id}`)));
        options.append(button('rekey', () => operation(`subrekey ${sub.id}`), 'danger'));
      }
      if (!sub.managed && sub.total_limit === undefined) options.append(button('delete', () => operation(`subdelete ${sub.id}`), 'danger'));
      menu.append(menuTitle, options); controls.append(menu); cell('subscriber-actions', controls);
      const detail = element('div', undefined, 'subscriber-details'); detail.hidden = true;
      for (const node of sub.nodes || []) {
        const row = element('div', undefined, 'subscription-endpoint');
        row.append(element('strong', node.name || node.server), element('code', node.server)); detail.append(row);
      }
      for (const ref of sub.inbound_refs || []) {
        const spec = ref.server_id === catalog.server_id ? catalog.inbounds.find(record => record.settings.id === ref.inbound_id)?.settings : null;
        const entry = element('div', undefined, 'subscription-endpoint'); entry.append(element('strong', spec?.name || ref.inbound_id), element('code', spec?.advertise_addr || spec?.listen || ref.server_id)); detail.append(entry);
      }
      if (q) detail.append(element('small', `${t('reserved')}: ${bytes(q.reserved)}`, 'muted'));
      if (sub.managed) detail.append(element('small', `${t('subscriber_ip_limit')}: ${sub.ip_limit || t('unlimited')}`, 'muted'));
      if (sub.note) detail.append(element('p', sub.note, 'muted'));
      item.append(row, detail); subscriptions.append(item); searchable.push([item, sub.title.toLocaleLowerCase(lang)]);
    }
    if (!records.length) subscriptions.append(element('p', t('empty'), 'empty'));
    search.addEventListener('input', () => { const query = search.value.trim().toLocaleLowerCase(lang); for (const [item, title] of searchable) item.hidden = !title.includes(query); });
  } else if (page === 'nodes') {
    const peerState = await read('peers'), pairing = card(root, 'panel_connections');
    pairing.append(element('p', t('pairing_notice')), detailList([['panel_id', peerState.panel_id], ['public_url', peerState.origin]]));
    const encrypted = peerState.origin.startsWith('https://');
    const invite = button('peerinvite', () => operation('peerinvite', true)), join = button('peerjoin', joinPanel, 'primary');
    invite.disabled = join.disabled = !encrypted;
    const connect = element('div', undefined, 'actions'); connect.append(invite, join, button('remotecatalogs', cachedCatalogs)); pairing.append(connect);
    if (!encrypted) pairing.append(element('p', t('peer_https_required'), 'editor-note'));
    table(pairing, ['remote_panel', 'public_url', 'role', 'status', 'settings'], peerState.peers.map(peer => {
      const controls = element('div', undefined, 'actions');
      if (peer.state !== 'revoked') {
        if (peer.role === 'primary') controls.append(button('peercatalog', () => peerCatalog(peer.id)));
        if (peer.role === 'primary') controls.append(button('peerjobs', () => peerJobs(peer.id)));
        if (peer.role === 'primary') controls.append(button('peersync', () => operation(`peersync ${peer.id}`)));
        if (peer.role === 'follower') controls.append(button(peer.inbounds_write ? 'peer_deny_writes' : 'peer_allow_writes', () => operation(`peergrant ${peer.id} ${!peer.inbounds_write}`)));
        controls.append(button('peerrevoke', () => operation(`peerrevoke ${peer.id}`), 'danger'));
      }
      return [peer.id, peer.origin, t('peer_role_' + peer.role), t('peer_state_' + peer.state), controls];
    }));
    if (peerState.incoming.length) table(card(root, 'incoming_pairings'), ['remote_panel','public_url','settings'], peerState.incoming.map(claim =>
      [claim.remote, claim.origin, actions([['peerapprove',`peerapprove ${claim.id}`],['peerreject',`peerreject ${claim.id}`]])]));
    if (peerState.outgoing.length) table(card(root, 'outgoing_pairings'), ['remote_panel','public_url','settings'], peerState.outgoing.map(claim =>
      [claim.remote, claim.origin, actions([['peerfinish',`peerfinish ${claim.id}`],['peercancel',`peercancel ${claim.id}`]])]));
    const [nodes, bindings] = await Promise.all([read('quotanodes'), read('quotabindings')]);
    const section = card(root, 'quota_nodes'); section.append(element('p', t('quota_node_notice')), button('enroll_node', () => editQuotaNode(), 'primary'));
    table(section, ['node_id', 'status', 'subscriptions', 'settings'], nodes.map(node => {
      const controls = actions([['disable', `quotadisable ${node.id}`]]); controls.prepend(button('edit', () => editQuotaNode(node.id)));
      return [node.id, badge(node.enabled), (node.subscriptions || []).join(', '), controls];
    }));
    table(card(root, 'account'), ['account', 'subscription_id'], bindings.map(binding => [binding.user, binding.subscription]));
  } else if (page === 'certificates') {
    const panel = await request('/control/certificate');
    facts(root, 'panel_certificates', [['public_url', panel.origin || '—'], ['mode', panel.mode], ['host', panel.host || '—'], ['certificate_expiry', panel.expires_at ? new Date(panel.expires_at * 1000).toLocaleString(lang) : '—'], ['error', panel.error || '—']]);
    const savedPanel = await read('panelsettings'), panelSection = card(root, 'panel_address');
    panelSection.append(element('p', t('panel_saved_notice')), button('edit', editPanelSettings, 'primary'));
    panelSection.append(detailList([['listen', savedPanel.settings.listen], ['port', savedPanel.settings.port], ['public_url', savedPanel.settings.origin]]));
    const panelBackups = await read('panelbackups');
    table(card(root, 'panel_backups'), ['name', 'settings'], panelBackups.map(name => [name, actions([['restore', `panelrestore ${quote(name)} ${savedPanel.revision}`], ['delete', `backupremove panel ${quote(name)}`]])]));
    const jobs = await read('certjobs'), jobSection = card(root, 'certificate_jobs');
    jobSection.append(element('p', t('certificate_job_notice')));
    if (jobs.manager_available) jobSection.append(button('create', () => editCertificateJob(), 'primary'));
    else jobSection.append(element('p', t('certificate_helper_optional'), 'editor-note'));
    const certificateService = card(root, 'certificate_service');
    certificateService.append(element('p', t('challenge_proxy_notice'), 'editor-note'));
    if (jobs.manager_available) form(certificateService, node => ({listen: field(node, 'challenge_listener', jobs.challenge_listen || ':80')}), inputs => operation(`certlisten ${quote(inputs.listen.value.trim())} ${jobs.revision}`));
    try {
      const service = await read('certservice status');
      certificateService.append(detailList([['status', service.active], ['state', service.state]]), actions([['start_service', 'certservice start'], ['stop', 'certservice stop'], ['restart', 'certservice restart']]));
    } catch (error) { certificateService.append(element('p', t('certificate_service_optional'), 'editor-note')); }
    table(jobSection, ['certificate_job_id', 'host', 'mode', 'certificate_expiry', 'error', 'settings'], jobs.jobs.map(job => {
      const controls = jobs.manager_available ? actions([['stop_renewal', `certjobdelete ${job.id} ${jobs.revision}`]]) : element('span', '—');
      if (jobs.manager_available) controls.prepend(button('edit', () => editCertificateJob(job.id)));
      return [job.id, job.tls.host, t(job.tls.mode === 'acme-ip' ? 'tls_ip' : 'tls_domain'), job.status?.not_after ? new Date(job.status.not_after).toLocaleString(lang) : '—', job.status?.error || '—', controls];
    }));
    const certificateBackups = card(root, 'certificate_backups');
    certificateBackups.append(element('p', t('certificate_backup_notice')));
    const savedCertificates = await read('certbackups');
    table(certificateBackups, ['name', 'settings'], savedCertificates.map(saved => [saved.name, actions([...(jobs.manager_available ? [['restore', `certrestore ${quote(saved.name)} ${jobs.revision}`]] : []), ['delete', `backupremove certificate ${quote(saved.name)}`]])]));
    let current;
    try { current = await read('tls'); }
    catch (error) { card(root, 'subscription_certificates').append(element('p', error.message)); if (version === renderVersion && csrf) $('content').replaceChildren(root); return; }
    const options = current.tls || {};
    const status = current.status || {};
    facts(root, 'status', [['status', t(status.listening ? 'enabled' : 'disabled')], ['mode', status.mode || options.mode], ['certificate_expiry', status.not_after ? new Date(status.not_after).toLocaleString(lang) : '—'], ['renew_before', status.renew_before ? new Date(status.renew_before).toLocaleString(lang) : '—'], ['error', status.error || '—']]);
    const section = card(root, 'subscription_certificates'); section.append(element('p', t('tls_notice')), element('p', t('restart_notice')));
    form(section, node => {
      const advanced = element('details');
      advanced.append(element('summary', t('advanced_settings')));
      const automaticNote = element('p', t('automatic_filled'), 'editor-note');
      const inputs = {
        enabled: field(node, 'enable', current.enabled, 'checkbox'),
        listen: field(node, 'listen', current.listen || ':443'),
        public_url: field(node, 'public_url', current.public_url || ''),
        mode: field(node, 'mode', options.mode || 'manual', 'text', ['manual', 'acme-ip', 'acme-domain'].map(value => ({value, label: t({manual: 'tls_manual', 'acme-ip': 'tls_ip', 'acme-domain': 'tls_domain'}[value])}))),
        cert_file: field(node, 'cert_file', options.cert_file || ''),
        key_file: field(node, 'key_file', options.key_file || ''),
      };
      node.append(automaticNote, advanced);
      inputs.host = field(advanced, 'host', options.host || '');
      inputs.cache_dir = field(advanced, 'cache_dir', options.cache_dir || '/var/lib/atlant/subscription-acme');
      inputs.email = field(advanced, 'email', options.email || '', 'email');
      inputs.accept_terms = field(advanced, 'accept_terms', options.accept_terms, 'checkbox');
      inputs.staging = field(advanced, 'staging', options.staging, 'checkbox');
      const automatic = () => inputs.mode.value === 'acme-ip' ? (jobs.defaults?.ip || jobs.defaults?.host || '') : inputs.mode.value === 'acme-domain' ? (jobs.defaults?.domain || jobs.defaults?.host || '') : '';
      const updateMode = () => {
        const manual = inputs.mode.value === 'manual';
        for (const key of ['cert_file', 'key_file']) inputs[key].closest('label').hidden = !manual;
        automaticNote.hidden = manual;
        advanced.hidden = manual;
        if (!manual) {
          if (!inputs.host.value.trim() && automatic()) inputs.host.value = automatic();
          if (!inputs.cache_dir.value.trim()) inputs.cache_dir.value = '/var/lib/atlant/subscription-acme';
          if (!inputs.public_url.value.trim() && inputs.host.value.trim()) {
            const port = (inputs.listen.value.trim().split(':').pop() || '').trim();
            inputs.public_url.value = `https://${inputs.host.value.trim()}${port && port !== '443' ? ':' + port : ''}`;
          }
        }
      };
      inputs.mode.addEventListener('change', updateMode); updateMode();
      return inputs;
    }, inputs => {
      const tls = {challenge_listen: ':80'};
      for (const key of ['mode', 'host', 'cert_file', 'key_file', 'cache_dir', 'email']) tls[key] = inputs[key].value.trim();
      tls.accept_terms = inputs.accept_terms.checked; tls.staging = inputs.staging.checked;
      return operation('tlsset ' + json({enabled: inputs.enabled.checked, listen: inputs.listen.value.trim(), public_url: inputs.public_url.value.trim(), tls}));
    });
  } else if (page === 'settings') {
    const service = card(root, 'service');
    try {
      const status = await read('service status');
      service.append(detailList([['status', t('service_status_' + status.active)], ['process_id', String(status.pid || '—')]]));
    } catch (error) { service.append(element('p', error.message, 'form-error')); }
    service.append(element('p', t('service_scope_notice'), 'editor-note'));
    service.append(actions([['start_service', 'service start'], ['stop', 'service stop'], ['restart', 'service restart']]));
    service.append(button('refresh', render));
    const connections = card(root, 'inbounds');
    connections.append(element('p', t('inbound_settings_location'), 'editor-note'));
    connections.append(button('inbounds', async () => { page = 'inbounds'; await render(); }, 'primary'));
  } else if (page === 'logs') {
    const info = await read('configinfo'), settings = card(root, 'log_level');
    settings.append(element('p', t('log_level_notice'), 'editor-note'));
    if (info.verified) form(settings, node => ({level: field(node, 'log_level', info.log_level || 'error', 'text', ['debug','info','warn','error','none'].map(value => ({value,label:t('log_'+value)})))}), values => operation('configsave '+json({log_level:values.level.value})));
    logLines(root, await read('logs 50'));
  } else if (page === 'backups') {
    const backups = await read('backups');
    table(card(root, 'backups'), ['backup_file', 'settings'], (backups.backups || []).map(name => [name, actions([['restore', `restore ${quote(name)}`], ['delete', `backupremove data ${quote(name)}`]])]));
    card(root, 'create').append(button('backup_data_create', () => operation('backup')), button('backup_panel_create', () => operation('panelbackup')), button('backup_certificate_create', () => operation('certbackup')));
    const panelBackups = await read('panelbackups'), certificateBackups = await read('certbackups');
    table(card(root, 'panel_backups'), ['backup_file', 'settings'], panelBackups.map(name => [name, actions([['restore', `panelrestore ${quote(name)}`], ['delete', `backupremove panel ${quote(name)}`]])]));
    table(card(root, 'certificate_backups'), ['backup_file', 'settings'], certificateBackups.map(item => [item.name, actions([['restore', `certrestore ${quote(item.name)}`], ['delete', `backupremove certificate ${quote(item.name)}`]])]));
  } else if (page === 'security') {
    card(root, 'security').append(element('p', t('password_cli_only')), element('code', 'sudo atlant panelpassword'));
  } else if (page === 'appearance') {
    const section = card(root, 'appearance'), theme = field(section, 'appearance', $('theme').value, 'text', ['dark', 'light'].map(value => ({value, label: t('theme_' + value)})));
    theme.addEventListener('change', () => { $('theme').value = theme.value; $('theme').dispatchEvent(new Event('change')); });
    section.append(element('p', t('appearance_notice'), 'editor-note'));
  } else if (page === 'language') {
    const control = field(card(root, 'language'), 'language', lang, 'text', [{value:'en',label:'English'},{value:'ru',label:'Русский'},{value:'zh',label:'简体中文'}]);
    control.addEventListener('change', () => { $('language').value=control.value; $('language').dispatchEvent(new Event('change')); });
  }
  if (page === 'certificates') groupWorkspace(root, [
    ['panel_certificates', ['panel_certificates', 'panel_address']],
    ['subscription_certificates', ['status', 'subscription_certificates']],
    ['certificate_jobs', ['certificate_jobs', 'certificate_service']],
    ['backups', ['panel_backups', 'certificate_backups']]
  ]);
  if (page === 'nodes') groupWorkspace(root, [['panel_connections', ['panel_connections', 'incoming_pairings', 'outgoing_pairings']], ['quota_nodes', ['quota_nodes', 'account']]]);
  if (version === renderVersion && csrf) {
    $('content').replaceChildren(root);
    if (page === 'logs') scheduleLogs(version, root);
  }
}

function renderUserRows(section, users, groups = [], subscriptions = []) {
  for (const old of section.querySelectorAll('.table-scroll')) old.remove();
  const select = element('input'); select.type = 'checkbox'; select.setAttribute('aria-label', t('select_all')); select.checked = users.length > 0 && users.every(user => selectedUsers.has(user.name));
  select.addEventListener('change', () => guarded(async () => { for (const user of users) select.checked ? selectedUsers.add(user.name) : selectedUsers.delete(user.name); await render(); }));
  const headings = ['name', 'status', 'connected', 'groups', 'user_quota', 'used', 'expires', 'settings'];
  table(section, ['select_all', ...headings], users.map(user => {
    const controls = actions([[user.enabled ? 'disable' : 'enable', `${user.enabled ? 'disable' : 'enable'} ${quote(user.name)}`], ['disconnect', `kick ${quote(user.name)}`], ['delete', `delete ${quote(user.name)}`]]);
    controls.prepend(button('edit', () => editUser(user.name)));
    const selected = element('input'); selected.type = 'checkbox'; selected.checked = selectedUsers.has(user.name); selected.setAttribute('aria-label', `${t('account')}: ${user.name}`);
    selected.addEventListener('change', () => guarded(async () => { selected.checked ? selectedUsers.add(user.name) : selectedUsers.delete(user.name); await render(); }));
    const group = groups.find(group => group.users.includes(user.name));
    const shared = subscriptions.find(sub => sub.id === user.subscription_id)?.global_quota;
    const quota = shared ? trafficUsage(shared.total_limit, Number(shared.upload) + Number(shared.download), shared.reserved, true) : user.subscription_id ? t('shared') : element('span', bytes(Number(user.up_bytes || 0) + Number(user.down_bytes || 0)));
    return [selected, user.name, badge(user.enabled), element('span', t(user.online ? 'connected' : 'offline'), 'muted'), group?.name || '—', quota, bytes(Number(user.up_bytes || 0) + Number(user.down_bytes || 0)), expiry(user.expires_at), controls];
  }));
  section.querySelector('th').replaceChildren(select);
}

$('login-form').addEventListener('submit', event => { event.preventDefault(); guarded(async () => {
  if (loggingIn) return;
  loggingIn = true; authVersion++;
  const submit = $('login-form').querySelector('button'); submit.disabled = true;
  try {
    const credential = typeof PasswordCredential === 'function' ? new PasswordCredential($('login-form')) : null;
    const result = await request('/control/login', {username: $('username').value, password: $('password').value});
    csrf = result.csrf; demonstration = result.demo === true;
    // Offer the browser's own password manager; never persist passwords ourselves.
    if (credential && navigator.credentials?.store) { try { navigator.credentials.store(credential).catch(() => {}); } catch {} }
    $('password').value = ''; signedIn(true); await render();
  } finally { loggingIn = false; submit.disabled = false; }
}); });
$('language').addEventListener('change', () => guarded(async () => { lang = $('language').value; try { localStorage.setItem('atlant-control-language', lang); } catch {} translate(); if (csrf) await render(); }));
$('logout').addEventListener('click', () => guarded(async () => { await request('/control/logout', {}); signedIn(false); }));
$('commit').addEventListener('click', () => guarded(async () => {
  const token = pending, command = pendingCommand; pending = ''; pendingCommand = ''; $('confirmation').close();
  const result = await request('/control/commit', {confirmation: token, confirm: true});
  await finishMutation(command, result.result);
}));
$('cancel-confirmation').addEventListener('click', () => { pending = ''; pendingCommand = ''; $('confirmation').close(); });
$('close-result').addEventListener('click', () => { $('result-body').textContent = ''; $('result').close(); });
$('result').addEventListener('close', () => { $('result-body').textContent = ''; });
$('close-editor').addEventListener('click', () => $('editor').close());
$('show-password').addEventListener('change', event => { $('password').type = event.target.checked ? 'text' : 'password'; });
guarded(async () => {
  languages = await request('/control/languages'); translate();
  const version = authVersion;
  if (loggingIn || csrf) return;
  try { const session = await request('/control/session'); if (version !== authVersion) return; csrf = session.csrf; demonstration = session.demo === true; signedIn(true); await render(); }
  catch { if (version === authVersion) signedIn(false); }
});

// Keep an actively used page alive, without extending the absolute eight-hour limit.
let lastActivity = Date.now();
for (const event of ['pointerdown', 'keydown']) document.addEventListener(event, () => { lastActivity = Date.now(); }, {passive:true});
setInterval(() => {
  if (csrf && !document.hidden && Date.now() - lastActivity < 300000) guarded(() => request('/control/session'));
}, 300000);
