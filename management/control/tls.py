"""Validate a panel certificate before publishing a new TLS context."""
import os
import datetime as dt
import json
import ipaddress
import base64
import re
from pathlib import Path
import ssl
import threading
import time
from urllib.parse import urlsplit


def validated_context(host, certificate, key):
    for path in {Path(certificate), Path(key)}:
        info = path.stat()
        if not path.is_file() or not 0 < info.st_size <= 1024 * 1024:
            raise ValueError('Certificate/key file is missing or too large')
    if os.name == 'posix' and Path(key).stat().st_mode & 0o007:
        raise ValueError('Private key must not be world-readable')
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    def no_password_prompt():
        raise ValueError('Encrypted private keys require external decryption; interactive prompts are disabled')
    context.load_cert_chain(certificate, key, password=no_password_prompt)

    # Use the TLS implementation itself to check SAN, validity and the key
    # pair. This in-memory handshake makes no connection to a remote service.
    # The supplied certificate bundle is the trust anchor for this local
    # validation; this is not a claim of public browser/CA trust.
    verifier = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    verifier.minimum_version = ssl.TLSVersion.TLSv1_2
    verifier.verify_flags |= ssl.VERIFY_X509_PARTIAL_CHAIN
    verifier.load_verify_locations(cafile=certificate)
    incoming, outgoing, peer_in, peer_out = (ssl.MemoryBIO() for _ in range(4))
    server = context.wrap_bio(incoming, outgoing, server_side=True)
    client = verifier.wrap_bio(peer_in, peer_out, server_hostname=host)
    done = [False, False]
    for _ in range(32):
        for index, connection in enumerate((client, server)):
            if not done[index]:
                try:
                    connection.do_handshake()
                    done[index] = True
                except ssl.SSLWantReadError:
                    pass
        for source, destination in ((outgoing, peer_in), (peer_out, incoming)):
            data = source.read()
            if data:
                destination.write(data)
        if all(done):
            peer = client.getpeercert()
            return context, {'host': host, 'not_before': peer['notBefore'],
                             'not_after': peer['notAfter'],
                             'expires_at': ssl.cert_time_to_seconds(peer['notAfter'])}
    raise ValueError('Certificate validation handshake did not complete')


class CertificateReloader:
    """A failed or non-atomic rotation leaves the last valid context intact."""
    def __init__(self, host, certificate, key, mode='manual', agent=None, bundle_context=None):
        self.host, self.certificate, self.key = host, certificate, key
        self.mode, self.agent = mode, agent
        self.bundle_context = bundle_context
        self.lock = threading.Lock()
        if bundle_context:
            check_bundle_context(certificate, bundle_context)
        self.context, self.details = validated_context(host, certificate, key)
        self.last_error, self.last_check = '', time.time()

    def reload(self, publish):
        try:
            if self.bundle_context:
                check_bundle_context(self.certificate, self.bundle_context)
            context, details = validated_context(self.host, self.certificate, self.key)
        except (OSError, ValueError, ssl.SSLError):
            with self.lock:
                self.last_check, self.last_error = time.time(), 'Certificate rotation rejected; previous certificate retained'
            return False
        # Each handshake receives one complete immutable context. Existing TLS
        # connections retain the old one and are not interrupted by rotation.
        with self.lock:
            publish(context)
            self.context, self.details = context, details
            self.last_check, self.last_error = time.time(), ''
        return True

    def status(self):
        with self.lock:
            result = dict(self.details, mode=self.mode, error=self.last_error,
                          last_check=self.last_check, expired=time.time() >= self.details['expires_at'])
        if self.agent:
            issuer = agent_status(self.agent['state_dir'], self.agent['job_id'], self.host)
            result['issuer'] = issuer
            if issuer.get('error'):
                result['error'] = result['error'] or issuer['error']
        return result

    def watch(self, stopped, publish, interval=30):
        while not stopped.wait(interval):
            self.reload(publish)


def agent_status(state_dir, job_id, host):
    try:
        path = Path(state_dir) / 'status.json'
        if not path.is_file() or path.stat().st_size > 128 * 1024:
            raise ValueError()
        report = json.loads(path.read_text(encoding='utf-8'))
        if report.get('version') != 1:
            raise ValueError()
        stamp = dt.datetime.fromisoformat(report['updated_at'].replace('Z', '+00:00'))
        if stamp.tzinfo is None:
            raise ValueError()
        updated = stamp.timestamp()
        if not 0 <= time.time() - updated <= 180:
            return {'error': 'Certificate agent status is stale; renewal is not confirmed'}
        daemon = report['jobs'].get('agent', {})
        if daemon.get('phase') != 'running' or daemon.get('listening') is not True:
            return {'error': daemon.get('error') or 'Certificate agent is not running'}
        job = report['jobs'][job_id]
        if job.get('host', '').lower() != host.lower():
            raise ValueError()
        result = {key: job[key] for key in ('host', 'mode', 'last_attempt', 'error', 'not_after', 'renew_before', 'next_attempt', 'phase') if key in job}
        if daemon.get('configuration_error'):
            result['error'] = daemon['configuration_error']
        return result
    except (OSError, ValueError, KeyError, TypeError, AttributeError):
        return {'error': 'Certificate agent status unavailable; renewal is not confirmed'}


def from_panel_settings(panel):
    if not isinstance(panel, dict):
        raise ValueError('Invalid panel settings')
    options = panel.get('tls', {})
    if not isinstance(options, dict):
        raise ValueError('Invalid panel TLS settings')
    mode = options.get('mode', 'manual')
    if not isinstance(mode, str):
        raise ValueError('Invalid panel TLS mode')
    host = urlsplit(panel.get('origin', '')).hostname
    if mode == 'manual':
        certificate = options.get('cert_file') or panel.get('cert_file')
        key = options.get('key_file') or panel.get('key_file')
        if not certificate and not key:
            return None
        if not isinstance(certificate, str) or not isinstance(key, str) or not host:
            raise ValueError('Panel HTTPS origin and certificate/key paths required')
        return CertificateReloader(host, certificate, key)
    if mode not in {'acme-ip', 'acme-domain'} or options.get('accept_terms') is not True:
        raise ValueError('Explicit ACME mode and certificate authority terms acceptance required')
    identity = options.get('host', '')
    if not host or not isinstance(identity, str) or identity.lower() != host.lower():
        raise ValueError('Panel certificate identity must match its HTTPS origin')
    try:
        address = ipaddress.ip_address(host)
    except ValueError:
        address = None
    if mode == 'acme-ip' and (address is None or not address.is_global) or mode == 'acme-domain' and (address is not None or '.' not in host):
        raise ValueError('Panel certificate mode does not match its hostname/IP')
    if not isinstance(options.get('cache_dir'), str):
        raise ValueError('Certificate cache directory required')
    cache = Path(options['cache_dir'])
    agent = panel['certificate_agent']
    if not isinstance(agent, dict) or not isinstance(agent.get('state_dir'), str) or not isinstance(agent.get('job_id'), str):
        raise ValueError('Invalid certificate agent settings')
    if not cache.is_absolute() or not Path(agent['state_dir']).is_absolute() or not re.fullmatch(r'[A-Za-z0-9_-]{1,64}', agent['job_id']):
        raise ValueError('Absolute certificate cache/agent state and job ID required')
    bundle = cache / 'subscription.pem'  # Shared engine preserves this filename for migration compatibility.
    expected = {'Host': host.lower(), 'Mode': mode, 'Directory': 'https://acme-staging-v02.api.letsencrypt.org/directory' if options.get('staging') else 'https://acme-v02.api.letsencrypt.org/directory'}
    return CertificateReloader(host, bundle, bundle, mode=mode, agent=agent, bundle_context=expected)


def check_bundle_context(path, expected):
    bundle = Path(path)
    if not bundle.is_file() or bundle.stat().st_size > 1024 * 1024:
        raise ValueError('Certificate issuance must complete before enabling panel HTTPS')
    match = re.search(r'-----BEGIN ATLANT CERTIFICATE CONTEXT-----\s+([A-Za-z0-9+/=\s]+)-----END ATLANT CERTIFICATE CONTEXT-----', bundle.read_text(encoding='ascii'))
    if not match or json.loads(base64.b64decode(re.sub(r'\s+', '', match[1]), validate=True)) != expected:
        raise ValueError('Certificate cache does not match the selected CA/profile or identity')
