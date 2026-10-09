#!/usr/bin/env python3
import json
import os
import secrets
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from collections import defaultdict, deque
from http import cookies
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

ROOT = Path(__file__).resolve().parent
HOST = '0.0.0.0'
PORT = int(os.environ.get('PORT', '8001'))
API_BASE = 'https://api.monkeytype.com'
COOKIE_NAME = 'monkeystats_session'
SESSION_SECONDS = 8 * 3600
CACHE_SECONDS = 180
REQUEST_BYTES_MAX = 4096
IS_RENDER = bool(os.environ.get('RENDER_EXTERNAL_URL') or os.environ.get('RENDER'))

sessions = {}
caches = {}
login_attempts = defaultdict(deque)
lock = threading.RLock()


def api_request(key, path, params=None):
    if params:
        path += '?' + urllib.parse.urlencode(params)
    request = urllib.request.Request(
        API_BASE + path,
        headers={'Authorization': 'ApeKey ' + key,
                 'User-Agent': 'MonkeyStatsDashboard/3.0',
                 'Accept': 'application/json'},
    )
    try:
        with urllib.request.urlopen(request, timeout=18) as response:
            payload = json.load(response)
        if isinstance(payload, dict):
            return payload.get('data'), None
        return payload, None
    except urllib.error.HTTPError as exc:
        try:
            payload = json.loads(exc.read().decode('utf-8'))
            message = payload.get('message') or payload.get('error') or str(exc.reason)
        except (ValueError, UnicodeError):
            message = str(exc.reason)
        return None, 'HTTP ' + str(exc.code) + ': ' + str(message)
    except (urllib.error.URLError, TimeoutError):
        return None, 'Monkeytype is temporarily unreachable'
    except Exception:
        return None, 'Unexpected Monkeytype response'


def prune():
    now = time.time()
    with lock:
        for token in list(sessions):
            if sessions[token]['expires'] <= now:
                sessions.pop(token, None)
                caches.pop(token, None)
        for address in list(login_attempts):
            q = login_attempts[address]
            while q and now - q[0] > 900:
                q.popleft()
            if not q:
                login_attempts.pop(address, None)


def current_session(token):
    with lock:
        info = sessions.get(token)
        if info and info['expires'] > time.time():
            return info
        sessions.pop(token, None)
        caches.pop(token, None)
        return None


def cached_request(token, key, name, path, params=None):
    now = time.time()
    with lock:
        entry = caches.get(token, {}).get(name)
        if entry and now - entry['saved'] < CACHE_SECONDS:
            return entry['data'], None
    data, error = api_request(key, path, params)
    if error is None:
        with lock:
            if token in sessions:
                caches.setdefault(token, {})[name] = {'saved': time.time(), 'data': data}
    return data, error


def build_dashboard(token, key):
    data = {}
    errors = {}
    for name, path, params in (
        ('stats', '/users/stats', None),
        ('results', '/results', {'limit': 250, 'offset': 0}),
        ('last', '/results/last', None),
    ):
        data[name], error = cached_request(token, key, name, path, params)
        if error:
            errors[name] = error
    last = data.get('last')
    results = data.get('results')
    username = last.get('name') if isinstance(last, dict) else None
    if not username and isinstance(results, list):
        username = next((v['name'] for v in results if isinstance(v, dict) and v.get('name')), None)
    profile = None
    if username:
        path = '/users/' + urllib.parse.quote(str(username), safe='') + '/profile'
        profile, error = cached_request(token, key, 'profile', path)
        if error:
            errors['profile'] = error
    personal_bests = profile.get('personalBests') if isinstance(profile, dict) else None
    if not isinstance(personal_bests, dict):
        personal_bests = {'time': {}, 'words': {}}
        for mode, targets in (('time', ('15', '30', '60', '120')),
                              ('words', ('10', '25', '50', '100'))):
            for target in targets:
                name = 'pb_' + mode + '_' + target
                pb, error = cached_request(token, key, name,
                                           '/users/personalBests',
                                           {'mode': mode, 'mode2': target})
                if error:
                    errors.setdefault('personalBests', error)
                elif pb is not None:
                    personal_bests[mode][target] = pb
    data.update(profile=profile, username=username, personalBests=personal_bests,
                errors=errors, updatedAt=int(time.time() * 1000))
    return data


class Handler(BaseHTTPRequestHandler):
    def send_bytes(self, body, mime, status=200, cookie=None):
        self.send_response(status)
        for name, value in (
            ('Content-Type', mime), ('Content-Length', str(len(body))),
            ('Cache-Control', 'no-store'), ('X-Content-Type-Options', 'nosniff'),
            ('Referrer-Policy', 'no-referrer'), ('X-Frame-Options', 'DENY'),
            ('Content-Security-Policy', "default-src 'self'; script-src 'self' 'unsafe-inline'; "
             "style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self'; "
             "frame-ancestors 'none'; object-src 'none'; base-uri 'none'; form-action 'self'"),
        ):
            self.send_header(name, value)
        if cookie:
            self.send_header('Set-Cookie', cookie)
        self.end_headers()
        self.wfile.write(body)

    def send_json(self, obj, status=200, cookie=None):
        self.send_bytes(json.dumps(obj).encode('utf-8'),
                        'application/json; charset=utf-8', status, cookie)

    def token(self):
        try:
            jar = cookies.SimpleCookie()
            jar.load(self.headers.get('Cookie', ''))
            item = jar.get(COOKIE_NAME)
            return item.value if item else ''
        except cookies.CookieError:
            return ''

    def cookie(self, value, delete=False):
        jar = cookies.SimpleCookie()
        jar[COOKIE_NAME] = value
        jar[COOKIE_NAME]['path'] = '/'
        jar[COOKIE_NAME]['httponly'] = True
        jar[COOKIE_NAME]['samesite'] = 'Strict'
        jar[COOKIE_NAME]['max-age'] = 0 if delete else SESSION_SECONDS
        if IS_RENDER:
            jar[COOKIE_NAME]['secure'] = True
        return jar.output(header='').strip()

    def valid_origin(self):
        origin = self.headers.get('Origin', '')
        host = self.headers.get('Host', '')
        try:
            parts = urllib.parse.urlsplit(origin)
            return (parts.scheme in ('http', 'https') and
                    parts.netloc.lower() == host.lower() and not parts.path and
                    not parts.query and not parts.fragment)
        except ValueError:
            return False

    def do_GET(self):
        path = urllib.parse.urlsplit(self.path).path
        if path == '/health':
            self.send_json({'ok': True})
            return
        if path in ('/', '/index.html'):
            self.send_bytes((ROOT / 'index.html').read_bytes(), 'text/html; charset=utf-8')
            return
        if path == '/favicon.ico':
            self.send_bytes(b'', 'image/x-icon', 204)
            return
        if path in ('/api/session', '/api/dashboard', '/api/stats'):
            token = self.token()
            session = current_session(token)
            if not session:
                self.send_json({'authenticated': False, 'error': 'Login required'}, 401)
                return
            if path == '/api/session':
                self.send_json({'authenticated': True})
            elif path == '/api/dashboard':
                try:
                    self.send_json(build_dashboard(token, session['key']))
                except Exception:
                    self.send_json({'error': 'Dashboard temporarily unavailable'}, 502)
            else:
                result, error = cached_request(token, session['key'], 'stats', '/users/stats')
                self.send_json({'error': error} if error else {'data': result},
                               502 if error else 200)
            return
        self.send_json({'error': 'Not found'}, 404)

    def do_POST(self):
        path = urllib.parse.urlsplit(self.path).path
        if path not in ('/api/login', '/api/logout'):
            self.send_json({'error': 'Not found'}, 404)
            return
        if not self.valid_origin():
            self.send_json({'error': 'Invalid request origin'}, 403)
            return
        if path == '/api/logout':
            token = self.token()
            with lock:
                sessions.pop(token, None)
                caches.pop(token, None)
            self.send_json({'success': True}, cookie=self.cookie('', True))
            return
        prune()
        address = self.client_address[0]
        if IS_RENDER:
            # Render's reverse proxy sets the original client IP.
            address = self.headers.get('X-Forwarded-For', address).split(',')[0].strip()[:100]
        with lock:
            attempts = login_attempts[address]
            now = time.time()
            while attempts and now - attempts[0] > 900:
                attempts.popleft()
            if len(attempts) >= 8:
                self.send_json({'error': 'Too many attempts. Try again in 15 minutes.'}, 429)
                return
            attempts.append(now)
        try:
            size = int(self.headers.get('Content-Length', '0'))
            if not (0 < size <= REQUEST_BYTES_MAX):
                raise ValueError('Bad request size')
            payload = json.loads(self.rfile.read(size).decode('utf-8'))
            key = payload.get('apeKey') if isinstance(payload, dict) else None
            if not isinstance(key, str):
                raise ValueError('Missing key')
            key = key.strip()
            if not (8 <= len(key) <= 1024) or any(c.isspace() for c in key):
                raise ValueError('Bad key format')
        except (ValueError, UnicodeError):
            self.send_json({'error': 'Enter a valid Ape Key'}, 400)
            return
        _, error = api_request(key, '/users/stats')
        if error:
            self.send_json({'error': error}, 401)
            return
        old = self.token()
        token = secrets.token_urlsafe(40)
        with lock:
            sessions.pop(old, None)
            caches.pop(old, None)
            sessions[token] = {'key': key, 'expires': time.time() + SESSION_SECONDS}
        self.send_json({'success': True}, cookie=self.cookie(token))

    def log_message(self, format_string, *args):
        # Never print submitted key material or session cookies.
        print(self.command, urllib.parse.urlsplit(self.path).path, flush=True)


if __name__ == '__main__':
    print('MonkeyStats running on port', PORT, flush=True)
    server = ThreadingHTTPServer((HOST, PORT), Handler)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
