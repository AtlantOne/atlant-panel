/* Local QR rendering. No subscription URL is sent to a third-party service. */
(function () {
  'use strict';
  function open(url, title, labels = {}) {
    if (typeof url !== 'string' || !url || url.length > 2048) throw Error(labels.invalid || 'Invalid subscription URL');
    const previous = document.getElementById('subscription-share');
    if (previous) previous.remove();
    const dialog = document.createElement('dialog'); dialog.id = 'subscription-share'; dialog.className = 'subscription-share';
    const heading = document.createElement('h2'); heading.textContent = title || labels.title || 'Subscription';
    const canvas = document.createElement('canvas'); canvas.className = 'share-qr'; canvas.setAttribute('role', 'img'); canvas.setAttribute('aria-label', labels.qr || 'Subscription QR code');
    const link = document.createElement('textarea'); link.readOnly = true; link.value = url; link.rows = 3; link.setAttribute('aria-label', labels.link || 'Subscription URL');
    const warning = document.createElement('p'); warning.textContent = labels.warning || 'This link grants VPN access. Share it only with people you trust.';
    const actions = document.createElement('div'); actions.className = 'actions';
    const copy = document.createElement('button'); copy.type = 'button'; copy.textContent = labels.copy || 'Copy link';
    copy.addEventListener('click', async () => {
      try { await navigator.clipboard.writeText(url); copy.textContent = labels.copied || 'Copied'; }
      catch { link.focus(); link.select(); copy.textContent = labels.select || 'Select and copy the link'; }
    });
    const close = document.createElement('button'); close.type = 'button'; close.textContent = labels.close || 'Close'; close.addEventListener('click', () => dialog.close());
    actions.append(copy, close); dialog.append(heading, canvas, link, warning, actions);
    dialog.addEventListener('close', () => { link.value = ''; dialog.remove(); });
    try {
      qrcode.stringToBytes = text => Array.from(new TextEncoder().encode(text));
      const code = qrcode(0, 'M'); code.addData(url, 'Byte'); code.make();
      const size = code.getModuleCount(), margin = 4, scale = 6;
      canvas.width = canvas.height = (size + margin * 2) * scale;
      const context = canvas.getContext('2d'); context.fillStyle = '#ffffff'; context.fillRect(0, 0, canvas.width, canvas.height); context.fillStyle = '#000000';
      for (let y = 0; y < size; y++) for (let x = 0; x < size; x++) if (code.isDark(y, x)) context.fillRect((x + margin) * scale, (y + margin) * scale, scale, scale);
    } catch { canvas.hidden = true; warning.textContent = labels.tooLong || 'Cannot generate QR. Copy the link instead.'; }
    document.body.append(dialog); dialog.showModal();
  }
  globalThis.AtlantShare = {open};
})();
