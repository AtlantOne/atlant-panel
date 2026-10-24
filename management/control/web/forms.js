'use strict';
globalThis.ControlForms = Object.freeze({
  inboundTuning: Object.freeze({
    quic: [ ['max_idle_timeout_sec','quic_idle',86400], ['keep_alive_period_sec','quic_keepalive',3600],
      ['stream_receive_window_mb','quic_stream_window',256], ['conn_receive_window_mb','quic_conn_window',1024],
      ['socket_buffer_size_mb','quic_socket_buffer',64] ],
    yamux: [ ['max_stream_window_kb','yamux_stream_window',262144], ['keep_alive_period_sec','yamux_keepalive',3600],
      ['write_timeout_sec','yamux_write_timeout',3600] ],
  }),
  quotaInput(value) {
    if (!Number.isSafeInteger(value) || value < 0) throw Error('invalid_quota');
    const bytes = BigInt(value), gib = 1073741824n;
    for (let digits = 0; digits <= 10; digits++) {
      const scale = 10n ** BigInt(digits);
      const candidate = (bytes * scale + gib - 1n) / gib;
      if (candidate * gib / scale !== bytes) continue;
      if (!digits) return String(candidate);
      return `${candidate / scale}.${String(candidate % scale).padStart(digits, '0')}`;
    }
    throw Error('invalid_quota');
  },
  quotaBytes(value) {
    const text = String(value).trim().replace(',', '.');
    if (!/^\d+(?:\.\d{1,18})?$/.test(text)) throw Error('invalid_quota');
    const [whole, fraction = ''] = text.split('.');
    const scale = 10n ** BigInt(fraction.length);
    const numerator = BigInt(whole) * scale + BigInt(fraction || '0');
    const result = numerator * 1073741824n / scale;
    if ((numerator > 0n && result === 0n) || result > BigInt(Number.MAX_SAFE_INTEGER)) throw Error('invalid_quota');
    return Number(result);
  },
  integer(value, maximum = Number.MAX_SAFE_INTEGER) {
    if (!/^\d+$/.test(String(value))) throw Error('invalid');
    const result = Number(value);
    if (!Number.isSafeInteger(result) || result < 0 || result > maximum) throw Error('invalid');
    return result;
  },
  expiryInput(value) {
    if (!value) return '';
    const date = new Date(Number(value) * 1000);
    if (Number.isNaN(date.getTime())) throw Error('invalid');
    date.setMinutes(date.getMinutes() - date.getTimezoneOffset());
    return date.toISOString().slice(0, 19);
  },
  expiryTimestamp(value) {
    if (!value) return 0;
    const result = new Date(value).getTime() / 1000;
    if (!Number.isSafeInteger(result) || result < 0) throw Error('invalid');
    return result;
  },
  userPatch(original, values) {
    const patch = {};
    if (values.ip_limit !== String(original.ip_limit || 0)) patch.ip_limit = this.integer(values.ip_limit, 10000);
    if (values.note !== (original.note || '')) patch.note = values.note;
    if (values.enabled !== Boolean(original.enabled)) patch.enabled = values.enabled;
    if (values.expires !== this.expiryInput(original.expires_at)) patch.expires_at = this.expiryTimestamp(values.expires);
    if (!original.subscription_id && values.quota !== undefined && values.quota !== String(Number(original.total_limit || 0) / 1073741824)) patch.total_limit = this.quotaBytes(values.quota);
    return patch;
  },
});
