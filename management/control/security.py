"""Password authentication and bounded, revocable in-memory panel sessions."""
import hashlib
import hmac
import re
import secrets
import threading
import time


def password_record(password, username='admin'):
    if not isinstance(username, str) or not re.fullmatch(r'[A-Za-z0-9_.@-]{1,64}', username):
        raise ValueError('Login must contain 1–64 ASCII letters, digits or _.@-')
    if not isinstance(password, str) or not 12 <= len(password) <= 256:
        raise ValueError('Password must contain 12–256 characters')
    salt = secrets.token_bytes(32)
    digest = hashlib.scrypt(password.encode(), salt=salt, n=16384, r=8, p=1, dklen=32)
    return {'version': 1, 'username': username, 'salt': salt.hex(), 'digest': digest.hex()}


def verify_password(record, password):
    if not isinstance(password, str) or len(password) > 256:
        return False
    try:
        if record['version'] != 1:
            return False
        salt, expected = bytes.fromhex(record['salt']), bytes.fromhex(record['digest'])
        if len(salt) != 32 or len(expected) != 32:
            return False
        actual = hashlib.scrypt(password.encode(), salt=salt, n=16384, r=8, p=1, dklen=32)
        return hmac.compare_digest(actual, expected)
    except (ValueError, TypeError, KeyError, UnicodeError):
        return False


class Authentication:
    def __init__(self, record, clock=time.monotonic):
        self.record, self.clock = record, clock
        self.lock = threading.Lock()
        self.hash_slots = threading.BoundedSemaphore(4)
        self.sessions, self.attempts = {}, {}
        self.global_attempts = []

    @staticmethod
    def digest(token):
        return hashlib.sha256(token.encode()).hexdigest()

    def allow_attempt(self, address):
        now = self.clock()
        with self.lock:
            self.global_attempts = [stamp for stamp in self.global_attempts if stamp > now - 60]
            self.attempts = {ip: stamps for ip, stamps in self.attempts.items() if stamps[-1] > now - 60}
            stamps = [stamp for stamp in self.attempts.get(address, []) if stamp > now - 60]
            if len(stamps) >= 5 or len(self.global_attempts) >= 20 or (address not in self.attempts and len(self.attempts) >= 1024):
                return False
            self.attempts[address] = stamps + [now]
            self.global_attempts.append(now)
        return True

    def login(self, address, password, username='admin'):
        if not self.allow_attempt(address):
            return None, 'rate_limited'
        if not self.hash_slots.acquire(blocking=False):
            return None, 'rate_limited'
        try:
            record = self.record
            # Hash even for unknown logins; keep one generic error and the same
            # attempt limits rather than exposing whether an account exists.
            valid = verify_password(record, password)
            expected = record.get('username', 'admin')
            valid = (isinstance(username, str) and len(username) <= 64 and
                     hmac.compare_digest(username.encode('utf-8', errors='replace'), expected.encode())) and valid
        finally:
            self.hash_slots.release()
        if not valid:
            return None, 'unauthorized'
        token, csrf = secrets.token_urlsafe(32), secrets.token_urlsafe(32)
        with self.lock:
            # A password rotation concurrent with hashing revokes this login too.
            if self.record is not record:
                return None, 'unauthorized'
            now = self.clock()
            self._prune(now)
            if len(self.sessions) >= 16:
                oldest = min(self.sessions, key=lambda key: self.sessions[key]['seen'])
                del self.sessions[oldest]
            self.sessions[self.digest(token)] = {'created': now, 'seen': now, 'csrf': csrf}
        return (token, csrf), None

    def change_password(self, address, session, current, replacement, persist):
        if not self.allow_attempt(address):
            raise OverflowError('Too many password attempts')
        if not self.hash_slots.acquire(blocking=False):
            raise OverflowError('Too many password attempts')
        try:
            record = self.record
            if not verify_password(record, current):
                raise PermissionError('Current password is incorrect')
            changed = password_record(replacement, record.get('username', 'admin'))
            with self.lock:
                self._prune(self.clock())
                if session not in self.sessions or self.record is not record:
                    raise PermissionError('Session expired during password change')
                # Persist first. If writing fails, old credentials and sessions
                # remain valid rather than publishing a non-durable password.
                persist(changed)
                self.record = changed
                self.sessions.clear()
        finally:
            self.hash_slots.release()

    def _prune(self, now):
        self.sessions = {key: value for key, value in self.sessions.items()
                         if now - value['seen'] < 1800 and now - value['created'] < 8 * 3600}

    def authenticate(self, token, csrf=None):
        if not isinstance(token, str) or not 32 <= len(token) <= 128:
            return None
        now = self.clock()
        with self.lock:
            self._prune(now)
            key = self.digest(token)
            session = self.sessions.get(key)
            if session is None or (csrf is not None and (not isinstance(csrf, str) or not hmac.compare_digest(csrf, session['csrf']))):
                return None
            session['seen'] = now
            return {'id': key, 'csrf': session['csrf']}

    def logout(self, token):
        with self.lock:
            self.sessions.pop(self.digest(token), None)


class Operations:
    """The browser and CLI invoke the same Manager, not separate write paths."""
    def __init__(self, manager, clock=time.monotonic):
        self.manager, self.clock = manager, clock
        self.lock, self.execute_lock = threading.Lock(), threading.Lock()
        self.pending = {}

    def prepare(self, session, command, reveal=False):
        if not isinstance(command, str) or not 0 < len(command) <= 8192 or '\x00' in command:
            raise ValueError('Invalid command')
        with self.execute_lock:
            action = self.manager.prepare(command)
            if action['secret'] and reveal is not True:
                raise PermissionError('Explicit secret disclosure required')
        if not action['write']:
            # Reads must not hold the mutation queue while waiting for the core.
            return {'result': self.manager.execute(action), 'secret': action['secret']}
        now = self.clock()
        token = secrets.token_urlsafe(32)
        with self.lock:
            self.pending = {key: value for key, value in self.pending.items() if value['expires'] > now}
            if len(self.pending) >= 128 or sum(value['session'] == session for value in self.pending.values()) >= 8:
                raise OverflowError('Too many pending operations')
            self.pending[token] = {'action': action, 'session': session, 'expires': now + 90}
        return {'confirmation': token, 'label': action['label'], 'secret': action['secret'], 'label_key': action.get('label_key'), 'target': action.get('target')}

    def commit(self, session, token):
        if not isinstance(token, str) or len(token) > 128:
            raise ValueError('Invalid confirmation')
        with self.lock:
            pending = self.pending.get(token)
            if pending is None or pending['expires'] <= self.clock() or pending['session'] != session:
                raise PermissionError('Confirmation missing, expired or belongs to another session')
            del self.pending[token]
        # A consumed confirmation cannot replay a destructive operation, even
        # when the API response is lost. Review fresh state before another try.
        with self.execute_lock:
            return {'result': self.manager.execute(pending['action']), 'secret': pending['action']['secret']}

    def revoke_confirmations(self):
        with self.lock:
            self.pending.clear()
