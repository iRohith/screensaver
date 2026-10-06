"""ScreenSaver — authenticated screenshot capture webserver.

Minimal-footprint Flask service: one admin (creds in .env) may capture the
screen via Pillow into folders under data/, issue time-boxed OTPs, and
stop/restart the server. Guests (any username + valid OTP) get read-only
gallery access. Self-detaches into a background process with no window on
Windows or Linux, manages its own ngrok tunnel, and enforces a singleton
via server.pid (deleting the pidfile kills the process immediately).

Only stdlib + flask + PIL + dotenv are used.
"""

from __future__ import annotations

import datetime as _dt
import hmac
import json
import os
import secrets
import subprocess
import sys
import threading
import time
from pathlib import Path

from dotenv import dotenv_values
from flask import Flask, Response, jsonify, request, send_from_directory, session
from werkzeug.serving import make_server

# ---------------------------------------------------------------- config

BASE_DIR = Path(__file__).resolve().parent
DATA_DIR = BASE_DIR / "data"
ENV_FILE = BASE_DIR / ".env"
PID_FILE = BASE_DIR / "server.pid"

_env = dotenv_values(ENV_FILE)  # .env is only ever read through dotenv
ADMIN_USERNAME = (_env.get("ADMIN_USERNAME") or "admin").strip()
ADMIN_PASSWORD = _env.get("ADMIN_PASSWORD") or "changeme"
SECRET_KEY = _env.get("SECRET_KEY") or secrets.token_hex(32)
PORT = int(_env.get("PORT") or 5000)
NGROK_DOMAIN = (_env.get("NGROK_DOMAIN") or "").strip()
NGROK_HOSTNAME = NGROK_DOMAIN.split("//")[-1].strip("/") if NGROK_DOMAIN else ""
# With a tunnel configured the app must only be reachable through it.
HOST = "127.0.0.1" if NGROK_HOSTNAME else (_env.get("HOST") or "127.0.0.1")

DEFAULT_OTP_HOURS = 3.0
OTP_MIN_HOURS, OTP_MAX_HOURS = 0.25, 24.0
ALLOWED_EXTENSIONS = {".png", ".jpg", ".jpeg", ".gif", ".bmp", ".webp"}

DATA_DIR.mkdir(exist_ok=True)
LOG_FILE = DATA_DIR / "screensaver.log"  # all server output lands here

# ---------------------------------------------------------------- state

app = Flask(__name__, static_folder=None, template_folder=None)
app.config.update(
    SECRET_KEY=SECRET_KEY,
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    MAX_CONTENT_LENGTH=64 * 1024,  # all requests are tiny JSON
)

_server = None                 # werkzeug server, kept so request threads can shut it down
_ngrok_proc = None             # subprocess.Popen of ngrok
_capture_lock = threading.Lock()
_shutdown = threading.Event()
_restarting = threading.Event()
_restart_ready = threading.Event()  # set by the child once it owns the port
_otp = None                    # {"code": str, "expires_at": float, "hours": float}
_state_lock = threading.Lock()
_fail_attempts: dict[str, list[float]] = {}

HTML_PATH = BASE_DIR / "index.html"
OTP_FILE = DATA_DIR / ".otp.json"  # persisted so an OTP survives server restart

# ---------------------------------------------------------------- helpers


def _is_live_pid(pid: int) -> bool:
    """True if a process with this pid exists and belongs to us."""
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    except OSError:
        return False
    return True


def _pid_alive_in_file() -> int | None:
    """Return the pid stored in server.pid if that process is alive."""
    try:
        pid = int(PID_FILE.read_text().strip())
    except (OSError, ValueError):
        return None
    return pid if _is_live_pid(pid) else None


def _write_pid() -> None:
    PID_FILE.write_text(str(os.getpid()))


def _remove_pid() -> None:
    try:
        PID_FILE.unlink()
    except OSError:
        pass


def pidfile_guard() -> None:
    """Kill-switch thread: if server.pid stops naming us, die immediately."""
    my_pid = os.getpid()
    while not _shutdown.is_set():
        time.sleep(0.5)  # sleep first: lets _shutdown be set before we read
        if _shutdown.is_set():
            break
        try:
            recorded = int(PID_FILE.read_text().strip())
        except (OSError, ValueError):
            recorded = -1
        if recorded != my_pid:
            os._exit(1)


def _sanitize_folder_name(name: str) -> str | None:
    """Return a safe folder name or None if invalid."""
    name = (name or "").strip()
    if not name or len(name) > 64:
        return None
    if name in (".", "..") or name.startswith("."):
        return None
    if any(c in name for c in "\\/:*?\"<>|") or any(ord(c) < 32 for c in name):
        return None
    return name


def _folder_path(folder: str) -> Path | None:
    """Resolve a client-supplied folder name under DATA_DIR, or None."""
    safe = _sanitize_folder_name(folder or "")
    if safe is None:
        return None
    path = (DATA_DIR / safe).resolve()
    if path.parent != DATA_DIR.resolve():  # no traversal
        return None
    return path


def _login_limited() -> bool:
    """Per-IP failed-login limiter: 8 tries / 60 s."""
    now = time.time()
    window = _fail_attempts.setdefault(request.remote_addr or "", [])
    window[:] = [t for t in window if now - t < 60]
    return len(window) >= 8


def _record_login_failure() -> None:
    _fail_attempts.setdefault(request.remote_addr or "", []).append(time.time())


def _require_admin() -> Response | None:
    if "role" not in session:
        return jsonify(error="unauthorized"), 401
    if session.get("role") != "admin":
        return jsonify(error="admin only"), 403
    return None


def _require_auth() -> Response | None:
    if "role" not in session:
        return jsonify(error="unauthorized"), 401
    return None


def _load_otp() -> None:
    """Restore the active OTP from disk, if any.

    Called once at startup so an OTP survives a server restart. An expired
    entry is dropped (it is useless and would otherwise linger forever).
    """
    global _otp
    try:
        raw = json.loads(OTP_FILE.read_text())
    except (OSError, ValueError, json.JSONDecodeError):
        return
    if not isinstance(raw, dict):
        return
    try:
        code = str(raw.get("code") or "")
        expires_at = float(raw.get("expires_at") or 0)
        hours = float(raw.get("hours") or 0)
    except (TypeError, ValueError):
        return
    if not code or expires_at <= time.time() or hours <= 0:
        _remove_otp_file()
        return
    with _state_lock:
        _otp = {"code": code, "expires_at": expires_at, "hours": hours}


def _save_otp() -> None:
    """Persist the active OTP to disk (best effort; never raises)."""
    try:
        DATA_DIR.mkdir(parents=True, exist_ok=True)
        OTP_FILE.write_text(json.dumps(_otp))
    except OSError:
        pass


def _remove_otp_file() -> None:
    try:
        OTP_FILE.unlink()
    except OSError:
        pass


def _otp_valid(code: str) -> bool:
    with _state_lock:
        return bool(_otp) and _otp["code"] == code and time.time() < _otp["expires_at"]


def _otp_payload() -> dict | None:
    global _otp
    with _state_lock:
        if not _otp:
            return None
        remaining = max(0, _otp["expires_at"] - time.time())
        if remaining <= 0:
            _otp = None
            _remove_otp_file()
            return None
        return {
            "code": _otp["code"],
            "expires_at": _otp["expires_at"],
            "remaining_seconds": remaining,
            "hours": _otp["hours"],
        }


def _set_otp(hours: float) -> dict:
    hours = OTP_MIN_HOURS if hours < OTP_MIN_HOURS else (OTP_MAX_HOURS if hours > OTP_MAX_HOURS else hours)
    with _state_lock:
        global _otp
        _otp = {
            "code": f"{secrets.randbelow(1_000_000):06d}",
            "expires_at": time.time() + hours * 3600,
            "hours": hours,
        }
        _save_otp()
        remaining = max(0, _otp["expires_at"] - time.time())
        return {
            "code": _otp["code"],
            "expires_at": _otp["expires_at"],
            "remaining_seconds": remaining,
            "hours": _otp["hours"],
        }


# ---------------------------------------------------------------- middleware


@app.before_request
def _host_allowlist() -> Response | None:
    """When a tunnel is configured, serve only via ngrok or localhost."""
    if NGROK_HOSTNAME:
        host = (request.host or "").split(":")[0].lower()
        if host not in (NGROK_HOSTNAME, "localhost", "127.0.0.1", "::1"):
            return jsonify(error="forbidden"), 403
    return None


# ---------------------------------------------------------------- routes


@app.get("/")
def index() -> Response:
    return Response(HTML_PATH.read_bytes(), mimetype="text/html")


@app.post("/api/login")
def login():
    if _login_limited():
        return jsonify(error="too many attempts, wait a minute"), 429
    data = request.get_json(silent=True) or {}
    username = str(data.get("username") or "").strip()
    if data.get("mode") == "admin":
        if (
            hmac.compare_digest(username, ADMIN_USERNAME)
            and hmac.compare_digest(str(data.get("password") or ""), ADMIN_PASSWORD)
        ):
            session.clear()
            session["role"] = "admin"
            session["username"] = username
            return jsonify(role="admin")
        _record_login_failure()
        return jsonify(error="invalid credentials"), 401
    # guest: any username + valid, unexpired OTP
    if 1 <= len(username) <= 32 and _otp_valid(str(data.get("otp") or "").strip()):
        session.clear()
        session["role"] = "guest"
        session["username"] = username
        return jsonify(role="guest")
    _record_login_failure()
    return jsonify(error="invalid username or OTP"), 401


@app.post("/api/logout")
def logout():
    session.clear()
    return jsonify(ok=True)


@app.get("/api/me")
def me():
    err = _require_auth()
    if err:
        return err
    return jsonify(role=session["role"], username=session.get("username", ""), otp=bool(_otp_payload()))


# ---- folders


@app.get("/api/folders")
def list_folders():
    err = _require_auth()
    if err:
        return err
    folders = sorted(
        p.name for p in DATA_DIR.iterdir()
        if p.is_dir() and not p.name.startswith(".")
    )
    return jsonify(folders=folders)


@app.post("/api/folders")
def create_folder():
    err = _require_admin()
    if err:
        return err
    data = request.get_json(silent=True) or {}
    name = _sanitize_folder_name(str(data.get("name") or ""))
    if name is None:
        return jsonify(error="invalid folder name"), 400
    path = DATA_DIR / name
    try:
        path.mkdir(exist_ok=True)
    except OSError as exc:
        return jsonify(error=str(exc)), 500
    return jsonify(folder=name)


# ---- gallery (both roles, read-only)


@app.get("/api/gallery")
def gallery():
    err = _require_auth()
    if err:
        return err
    folder = str(request.args.get("folder") or "")
    if folder:
        path = _folder_path(folder)
        if path is None or not path.is_dir():
            return jsonify(error="folder not found"), 404
        root = path
    else:
        root = DATA_DIR
    items = []
    try:
        for p in sorted(root.iterdir()):
            if p.name.startswith("."):
                continue
            if p.is_dir():
                items.append({"type": "folder", "name": p.name})
            elif p.is_file() and p.suffix.lower() in ALLOWED_EXTENSIONS:
                items.append({"type": "image", "name": p.name, "size": p.stat().st_size})
    except OSError as exc:
        return jsonify(error=str(exc)), 500
    return jsonify(folder=folder, items=items)


@app.delete("/api/media/<path:subpath>")
def delete_media(subpath: str):
    """Admin-only: delete a single image from its folder."""
    err = _require_admin()
    if err:
        return err
    parts = [seg for seg in subpath.split("/") if seg]
    if len(parts) != 2:
        return jsonify(error="not found"), 404
    folder, filename = parts
    base = _folder_path(folder)
    if base is None or not base.is_dir():
        return jsonify(error="not found"), 404
    if Path(filename).suffix.lower() not in ALLOWED_EXTENSIONS or Path(filename).name != filename:
        return jsonify(error="not found"), 404
    target = (base / filename).resolve()
    if target.parent != base.resolve() or not target.is_file():
        return jsonify(error="not found"), 404
    try:
        target.unlink()
    except OSError as exc:
        return jsonify(error=str(exc)), 500
    return jsonify(ok=True, deleted=target.name, folder=folder)


@app.get("/api/preview")
def preview():
    """Serve the latest refresh preview (data/.tmp_*.png), admin only."""
    err = _require_admin()
    if err:
        return err
    try:
        files = sorted(DATA_DIR.glob(".tmp_*.png"))
    except OSError:
        files = []
    if not files:
        return jsonify(error="no preview yet"), 404
    resp = send_from_directory(DATA_DIR, files[-1].name)
    resp.headers["Cache-Control"] = "no-store, max-age=0"
    resp.headers["X-Content-Type-Options"] = "nosniff"
    return resp


@app.get("/api/media/<path:subpath>")
def media(subpath: str):
    err = _require_auth()
    if err:
        return err
    # subpath is "<folder>/<file>" — files are only served out of a named
    # subfolder. Serving straight out of data/ would expose the hidden
    # refresh previews (.tmp_*.png) and the persisted OTP (.otp.json).
    parts = [seg for seg in subpath.split("/") if seg]
    if len(parts) != 2:
        return jsonify(error="not found"), 404
    folder, filename = parts
    base = _folder_path(folder)
    if base is None or not base.is_dir():
        return jsonify(error="not found"), 404
    if Path(filename).suffix.lower() not in ALLOWED_EXTENSIONS or Path(filename).name != filename:
        return jsonify(error="not found"), 404
    target = (base / filename).resolve()
    if target.parent != base.resolve():
        return jsonify(error="not found"), 404
    resp = send_from_directory(base, filename)
    resp.headers["Cache-Control"] = "no-store, max-age=0"
    resp.headers["X-Content-Type-Options"] = "nosniff"
    return resp


# ---- capture (admin only)


@app.post("/api/capture")
def capture():
    err = _require_admin()
    if err:
        return err
    data = request.get_json(silent=True) or {}
    path = _folder_path(str(data.get("folder") or ""))
    if path is None:
        return jsonify(error="invalid folder"), 400
    if not path.is_dir():
        return jsonify(error="folder not found"), 404
    if not _capture_lock.acquire(blocking=False):
        return jsonify(error="capture already in progress"), 409
    try:
        from PIL import ImageGrab  # imported late: keeps import cost off the request path

        stamp = _dt.datetime.now().strftime("%Y%m%d_%H%M%S_%f")
        target = path / f"{stamp}.png"
        try:
            img = ImageGrab.grab()
        except Exception as exc:  # Wayland, no display, etc.
            return jsonify(error=f"capture failed: {exc}"), 400
        img.save(target, "PNG")
        return jsonify(saved=target.name, folder=path.name)
    finally:
        _capture_lock.release()


@app.post("/api/refresh")
def refresh():
    """Grab the screen into data/ (no folder) as a throwaway preview.

    Useful for a live look at the screen without committing the capture to a
    folder. The image is a temp file, not part of any gallery folder. Each
    call replaces the previous preview so previews cannot pile up.
    """
    err = _require_admin()
    if err:
        return err
    if not _capture_lock.acquire(blocking=False):
        return jsonify(error="capture already in progress"), 409
    try:
        from PIL import ImageGrab

        stamp = _dt.datetime.now().strftime("%Y%m%d_%H%M%S_%f")
        target = DATA_DIR / f".tmp_{stamp}.png"
        # drop any previous preview so there is at most one at a time
        for old in DATA_DIR.glob(".tmp_*.png"):
            try:
                old.unlink()
            except OSError:
                pass
        try:
            img = ImageGrab.grab()
        except Exception as exc:  # Wayland, no display, etc.
            return jsonify(error=f"capture failed: {exc}"), 400
        img.save(target, "PNG")
        return jsonify(saved=target.name, tmp=True)
    finally:
        _capture_lock.release()


# ---- otp (admin only)


@app.get("/api/otp")
def get_otp():
    err = _require_admin()
    if err:
        return err
    payload = _otp_payload()
    if payload is None:
        return jsonify(otp=None)
    return jsonify(otp=payload)


@app.post("/api/otp")
def create_otp():
    err = _require_admin()
    if err:
        return err
    data = request.get_json(silent=True) or {}
    try:
        hours = float(data.get("hours") or DEFAULT_OTP_HOURS)
    except (TypeError, ValueError):
        return jsonify(error="invalid hours"), 400
    _set_otp(hours)
    return jsonify(otp=_otp_payload())


@app.post("/api/otp/adjust")
def adjust_otp():
    err = _require_admin()
    if err:
        return err
    data = request.get_json(silent=True) or {}
    try:
        delta = float(data.get("delta_hours"))
    except (TypeError, ValueError):
        return jsonify(error="invalid delta"), 400
    with _state_lock:
        if not _otp:
            return jsonify(error="no active OTP"), 404
        new_expiry = _otp["expires_at"] + delta * 3600
        if new_expiry <= time.time():
            return jsonify(error="OTP would already be expired"), 400
        _otp["expires_at"] = new_expiry
        _otp["hours"] = max(OTP_MIN_HOURS, (_otp["hours"] or DEFAULT_OTP_HOURS) + delta)
        _save_otp()
        remaining = max(0, _otp["expires_at"] - time.time())
        payload = {
            "code": _otp["code"],
            "expires_at": _otp["expires_at"],
            "remaining_seconds": remaining,
            "hours": _otp["hours"],
        }
    return jsonify(otp=payload)


@app.post("/api/otp/regenerate")
def regenerate_otp():
    err = _require_admin()
    if err:
        return err
    with _state_lock:
        hours = _otp["hours"] if _otp else DEFAULT_OTP_HOURS
    _set_otp(hours)  # replaces the code; the old one is instantly invalid
    return jsonify(otp=_otp_payload())


# ---- server control (admin only)


@app.get("/api/server-url")
def server_url():
    err = _require_admin()
    if err:
        return err
    return jsonify(url=_public_url())


def _terminate_ngrok() -> None:
    global _ngrok_proc
    if _ngrok_proc is not None:
        try:
            _ngrok_proc.terminate()
            _ngrok_proc.wait(timeout=5)
        except Exception:
            try:
                _ngrok_proc.kill()
            except Exception:
                pass
        _ngrok_proc = None


@app.post("/api/stop")
def stop_server():
    err = _require_admin()
    if err:
        return err

    def _do_stop():
        time.sleep(0.2)  # let the response flush
        # Signal the guard first so it cannot race the pidfile removal.
        _shutdown.set()
        time.sleep(0.6)  # let the guard observe _shutdown and exit
        _terminate_ngrok()
        _remove_pid()
        if _server is not None:
            _server.shutdown()
        os._exit(0)

    threading.Thread(target=_do_stop, daemon=True).start()
    return jsonify(ok=True, message="stopping")


@app.post("/api/restart")
def restart_server():
    err = _require_admin()
    if err:
        return err

    def _do_restart():
        time.sleep(0.2)
        _shutdown.set()
        time.sleep(0.6)  # let the guard observe _shutdown and exit
        _terminate_ngrok()
        # Release the singleton slot BEFORE spawning so the child's
        # startup check passes; the child's bind-retry absorbs the port race.
        _remove_pid()
        _restarting.set()
        _restart_ready.clear()
        _spawn_detached()
        # Release the port FIRST so the child's bind-retry loop can win it.
        if _server is not None:
            _server.shutdown()
        # Then wait for the child to actually bind before we exit.
        _restart_ready.wait(timeout=20)
        os._exit(0)

    threading.Thread(target=_do_restart, daemon=True).start()
    return jsonify(ok=True, message="restarting")


# ---------------------------------------------------------------- ngrok


def _start_ngrok() -> None:
    """Start the tunnel; on any failure fall back to localhost-only."""
    global _ngrok_proc
    if not NGROK_DOMAIN:
        return
    try:
        _ngrok_proc = subprocess.Popen(
            ["ngrok", "http", str(PORT), "--url", NGROK_DOMAIN],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            # ngrok is a console app: on Windows it spawns a window unless
            # we hide it. Pure Python, no shell, cross-platform.
            **_hide_kwargs(),
        )
    except (OSError, ValueError):
        _ngrok_proc = None
        print("[screensaver] ngrok not available — serving on localhost only", flush=True)
        return
    # wait for the tunnel to come up; give up quietly (host allowlist then
    # still applies, and the UI shows the localhost URL)
    import urllib.request

    for _ in range(20):
        if _ngrok_proc.poll() is not None:
            _ngrok_proc = None
            print("[screensaver] ngrok failed to start — serving on localhost only", flush=True)
            return
        try:
            with urllib.request.urlopen("http://127.0.0.1:4040/api/tunnels", timeout=1) as resp:
                tunnels = json.loads(resp.read()).get("tunnels", [])
                if tunnels:
                    return
        except Exception:
            pass
        time.sleep(0.5)


def _public_url() -> str:
    return _tunnel_url() or f"http://{HOST}:{PORT}"


def _tunnel_url() -> str:
    """Read the public ngrok URL from the local API, or "" if not up yet."""
    import urllib.request

    try:
        with urllib.request.urlopen("http://127.0.0.1:4040/api/tunnels", timeout=1) as resp:
            for t in json.loads(resp.read()).get("tunnels", []):
                if t.get("proto") == "https":
                    return t["public_url"]
    except Exception:
        pass
    return ""


# ---------------------------------------------------------------- runtime


def _hide_kwargs() -> dict:
    """subprocess kwargs that hide a child's console window.

    Windows: DETACHED_PROCESS | CREATE_NO_WINDOW. POSIX: the child is
    already detached via start_new_session, so nothing extra is needed.
    """
    if sys.platform != "win32":
        return {}
    return {"creationflags": 0x00000008 | 0x08000000}


def _spawn_detached() -> None:
    """Relaunch this script as a windowless, fully detached process.

    Pure Python, cross-platform. On Windows we use pythonw with
    DETACHED_PROCESS | CREATE_NO_WINDOW; on POSIX we double-fork
    through an intermediate Python process so the grandchild is
    reparented to init and survives this process exiting.
    """
    env = dict(os.environ, SCREENSAVER_DETACHED="1")
    target = str(BASE_DIR / "server.py")
    # The child owns no console: stdout/stderr go to the log file so we
    # never have a stray terminal, and every diagnostic is preserved.
    try:
        log_fp = open(LOG_FILE, "a", buffering=1)
    except OSError:
        log_fp = open(os.devnull, "w")
    if sys.platform == "win32":
        executable = sys.executable.replace("python.exe", "pythonw.exe")
        if not Path(executable).exists():
            executable = sys.executable
        subprocess.Popen(
            [executable, target], env=env,
            stdout=log_fp, stderr=log_fp, stdin=open(os.devnull, "r"),
            # DETACHED_PROCESS | CREATE_NO_WINDOW — the old 0x00000200
            # was CREATE_NEW_PROCESS_GROUP, which left a console open.
            creationflags=0x00000008 | 0x08000000)
    else:
        # Intermediate process: spawns the real child, then exits
        # immediately. The grandchild is orphaned to init and is
        # unaffected when this process later exits.
        subprocess.Popen(
            [sys.executable, "-c",
             "import subprocess, sys, os\n"
             f"subprocess.Popen([sys.executable, {target!r}], env=os.environ,\n"
             f"                 stdout=open({str(LOG_FILE)!r}, 'a'), stderr=subprocess.STDOUT,\n"
             "                 stdin=open(os.devnull, 'r'), start_new_session=True)\n"],
            env=env,
            stdout=log_fp, stderr=log_fp, stdin=open(os.devnull, "r"),
            start_new_session=True)


def _detach_self() -> None:
    """Relaunch ourselves as a windowless background process, then exit."""
    _spawn_detached()


def _redirect_log() -> None:
    """Send all stdout/stderr to data/screensaver.log.

    The detached child owns no console, so every print/exception goes to
    this file. The parent (the console you launched from) is unaffected.
    """
    try:
        _log_fp = open(LOG_FILE, "a", buffering=1)
    except OSError:
        return
    sys.stdout = _log_fp
    sys.stderr = _log_fp


def main() -> None:
    if os.environ.get("SCREENSAVER_DETACHED") != "1":
        # Parent role: spawn the detached child and exit immediately.
        # The child owns the port and the pidfile; the parent never binds.
        _spawn_detached()
        for _ in range(30):
            try:
                import urllib.request

                with urllib.request.urlopen(f"http://{HOST}:{PORT}/api/me", timeout=1):
                    pass
            except Exception:
                time.sleep(0.5)
                continue
            break
        url = _public_url()
        print(f"[screensaver] running in background — {url}", flush=True)
        if NGROK_DOMAIN:
            # The child owns the tunnel, so poll the ngrok local API
            # directly for the real public URL (up to 10 s).
            for _ in range(20):
                u = _tunnel_url()
                if u:
                    print(f"[screensaver] tunnel ready — {u}", flush=True)
                    break
                time.sleep(0.5)
        return

    # singleton: refuse if another instance is alive, take over a stale pid
    _redirect_log()
    existing = _pid_alive_in_file()
    if existing is not None and existing != os.getpid():
        print(f"[screensaver] already running (pid {existing})", flush=True)
        sys.exit(1)
    _write_pid()

    if (ADMIN_USERNAME, ADMIN_PASSWORD) == ("admin", "changeme"):
        print("[screensaver] WARNING: default admin credentials — set ADMIN_USERNAME/ADMIN_PASSWORD in .env", flush=True)

    threading.Thread(target=pidfile_guard, daemon=True).start()

    # startup retry loop (absorbs restart races on port and pidfile)
    deadline = time.time() + 15
    while True:
        try:
            global _server
            _server = make_server(HOST, PORT, app, threaded=True)
            _restart_ready.set()  # we own the port — the parent may exit now
            break
        except OSError:
            if time.time() > deadline:
                print(f"[screensaver] cannot bind {HOST}:{PORT}", flush=True)
                _remove_pid()
                sys.exit(1)
            time.sleep(0.5)

    _start_ngrok()
    _load_otp()
    if _otp:
        print(f"[screensaver] OTP { _otp['code'] } restored (expires in ~{int((_otp['expires_at'] - time.time()) / 3600)}h)", flush=True)
    tu = _tunnel_url()
    if tu:
        print(f"[screensaver] tunnel ready — {tu}", flush=True)
    print(f"[screensaver] ready — {_public_url()}", flush=True)
    try:
        _server.serve_forever(poll_interval=0.5)
    finally:
        if not _restarting.is_set():
            _terminate_ngrok()
            _remove_pid()


if __name__ == "__main__":
    main()
