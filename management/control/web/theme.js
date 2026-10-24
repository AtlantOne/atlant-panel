'use strict';
(() => {
  const key = 'atlant-control-theme';
  let preference = 'dark';
  try { preference = localStorage.getItem(key) || 'dark'; } catch {}
  if (!['light', 'dark'].includes(preference)) preference = 'dark';
  const media = matchMedia('(prefers-color-scheme: dark)');
  function apply() {
    const dark = preference === 'dark' || (preference === 'system' && media.matches);
    document.documentElement.setAttribute('data-theme', dark ? 'dark' : 'light');
    const select = document.getElementById('theme');
    if (select) select.value = preference;
  }
  function connect() {
    apply();
    document.getElementById('theme')?.addEventListener('change', event => {
      preference = ['light', 'dark'].includes(event.target.value) ? event.target.value : 'dark';
      try { localStorage.setItem(key, preference); } catch {}
      apply();
    });
  }
  apply();
  media.addEventListener('change', () => { if (preference === 'system') apply(); });
  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', connect);
  else connect();
})();
