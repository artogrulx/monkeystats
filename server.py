
#!/usr/bin/env python3
import os
import json
import time
import threading
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer


ROOT = Path(__file__).resolve().parent
KEY_FILE = ROOT / "key.MAMAMA"
API_BASE = "https://api.monkeytype.com"
HOST = "0.0.0.0"
PORT = int(os.environ.get("PORT", "8001"))

CACHE_SECONDS = 90
cache = {}
cache_lock = threading.Lock()


def get_key():
    if not KEY_FILE.is_file():
        raise RuntimeError("key.MAMAMA was not found")

    key = KEY_FILE.read_text(encoding="utf-8").strip()

    if not key:
        raise RuntimeError("key.MAMAMA is empty")

    return key


def request_monkeytype(path, parameters=None):
    if parameters:
        path += "?" + urllib.parse.urlencode(parameters)

    request = urllib.request.Request(
        API_BASE + path,
        headers={
            "Authorization": "ApeKey " + get_key(),
            "User-Agent": "MonkeytypeLocalDashboard/1.0",
            "Accept": "application/json"
        },
        method="GET"
    )

    try:
        with urllib.request.urlopen(request, timeout=15) as response:
            payload = json.loads(response.read().decode("utf-8"))

        if isinstance(payload, dict):
            return payload.get("data"), None

        return payload, None

    except urllib.error.HTTPError as error:
        try:
            payload = json.loads(error.read().decode("utf-8"))
            message = payload.get("message", error.reason)
        except (ValueError, UnicodeDecodeError):
            message = error.reason

        return None, "HTTP " + str(error.code) + ": " + str(message)

    except urllib.error.URLError as error:
        return None, "Connection error: " + str(error.reason)

    except Exception as error:
        return None, str(error)


def cached_request(name, path, parameters=None, refresh=False):
    now = time.time()

    with cache_lock:
        entry = cache.get(name)

        if entry and not refresh and now - entry["saved"] < CACHE_SECONDS:
            return entry["data"], entry["error"]

    data, error = request_monkeytype(path, parameters)

    if error is None:
        with cache_lock:
            cache[name] = {
                "saved": time.time(),
                "data": data,
                "error": None
            }

    return data, error


def dashboard_data(refresh=False):
    stats, stats_error = cached_request(
        "stats", "/users/stats", refresh=refresh
    )

    results, results_error = cached_request(
        "results", "/results",
        {"limit": 250, "offset": 0},
        refresh=refresh
    )

    last, last_error = cached_request(
        "last", "/results/last", refresh=refresh
    )

    profile = None
    profile_error = None

    username = None

    if isinstance(last, dict):
        username = last.get("name")

    if not username and isinstance(results, list):
        for result in results:
            if isinstance(result, dict) and result.get("name"):
                username = result["name"]
                break

    if username:
        encoded_name = urllib.parse.quote(str(username), safe="")

        profile, profile_error = cached_request(
            "profile_" + username,
            "/users/" + encoded_name + "/profile",
            refresh=refresh
        )

    personal_bests = None
    personal_bests_error = None

    if isinstance(profile, dict):
        personal_bests = profile.get("personalBests")

    if personal_bests is None:
        personal_bests = {"time": {}, "words": {}}
        pb_errors = []

        for mode, targets in (
            ("time", ("15", "30", "60", "120")),
            ("words", ("10", "25", "50", "100"))
        ):
            for target in targets:
                data, error = cached_request(
                    "pb_" + mode + "_" + target,
                    "/users/personalBests",
                    {"mode": mode, "mode2": target},
                    refresh=refresh
                )

                if error:
                    pb_errors.append(error)
                elif data is not None:
                    personal_bests[mode][target] = data

        if pb_errors:
            personal_bests_error = pb_errors[0]

    errors = {}

    for name, error in (
        ("stats", stats_error),
        ("results", results_error),
        ("last", last_error),
        ("profile", profile_error),
        ("personalBests", personal_bests_error)
    ):
        if error:
            errors[name] = error

    return {
        "stats": stats,
        "results": results,
        "last": last,
        "profile": profile,
        "personalBests": personal_bests,
        "username": username,
        "errors": errors,
        "updatedAt": int(time.time() * 1000)
    }


class Handler(BaseHTTPRequestHandler):

    def send_json(self, payload, status=200):
        data = json.dumps(payload).encode("utf-8")

        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self):
        parsed = urllib.parse.urlparse(self.path)
        path = parsed.path

        if path == "/api/dashboard":
            query = urllib.parse.parse_qs(parsed.query)
            refresh = query.get("refresh", ["0"])[0] == "1"

            try:
                self.send_json(dashboard_data(refresh))
            except Exception as error:
                self.send_json({"error": str(error)}, 500)

            return

        if path == "/api/stats":
            data, error = cached_request("stats", "/users/stats")

            if error:
                self.send_json({"error": error}, 502)
            else:
                self.send_json({"data": data})

            return

        if path in ("/", "/index.html"):
            file_path = ROOT / "index.html"

            if not file_path.is_file():
                self.send_json({"error": "index.html is missing"}, 404)
                return

            content = file_path.read_bytes()

            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(content)))
            self.send_header("Cache-Control", "no-store")
            self.send_header(
                "Content-Security-Policy",
                "default-src 'self'; style-src 'self' 'unsafe-inline'; "
                "script-src 'self' 'unsafe-inline'; "
                "connect-src 'self'; img-src 'self' data:; "
                "object-src 'none'; base-uri 'none'"
            )
            self.end_headers()
            self.wfile.write(content)
            return

        self.send_json({"error": "Not found"}, 404)

    def log_message(self, format_string, *args):
        print(
            "[" + self.log_date_time_string() + "] "
            + format_string % args
        )


if __name__ == "__main__":
    print("Monkeytype Dashboard")
    print("Directory:", ROOT)
    print("URL: http://127.0.0.1:" + str(PORT))

    if not KEY_FILE.is_file():
        print("WARNING: key.MAMAMA was not found")

    server = ThreadingHTTPServer((HOST, PORT), Handler)

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nStopping server")
    finally:
        server.server_close()

