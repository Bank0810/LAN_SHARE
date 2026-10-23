from pathlib import Path
import os
import secrets
import sqlite3
import time
from contextlib import contextmanager
from functools import wraps

from flask import (
    Flask, render_template, request, redirect, url_for, flash,
    send_from_directory, abort, jsonify, session,
)
from werkzeug.utils import secure_filename

app = Flask(__name__)
app.secret_key = os.environ.get("LANSHARE_SECRET")
if not app.secret_key:
    raise RuntimeError("กรุณาตั้งค่า LANSHARE_SECRET ก่อนเริ่มระบบ")

LAN_PIN = os.environ.get("LANSHARE_PIN")
if not LAN_PIN:
    raise RuntimeError("กรุณาตั้งค่า LANSHARE_PIN ก่อนเริ่มระบบ")

app.config["MAX_CONTENT_LENGTH"] = 2 * 1024 * 1024 * 1024
app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"

BASE_DIR = Path(__file__).resolve().parent
STORAGE_DIR = BASE_DIR / "storage"
STORAGE_DIR.mkdir(exist_ok=True)
DB_PATH = BASE_DIR / "lanshare.db"
ONLINE_TIMEOUT_SECONDS = 45


@contextmanager
def db_connect():
    conn = sqlite3.connect(DB_PATH, timeout=10)
    conn.row_factory = sqlite3.Row
    try:
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


def init_db():
    with db_connect() as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS user_sessions (
                session_id TEXT PRIMARY KEY,
                device_name TEXT NOT NULL,
                ip_address TEXT NOT NULL,
                user_agent TEXT NOT NULL,
                login_at REAL NOT NULL,
                last_seen REAL NOT NULL,
                logout_at REAL
            )
        """)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS activity_log (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp REAL NOT NULL,
                device_name TEXT NOT NULL,
                ip_address TEXT NOT NULL,
                action TEXT NOT NULL,
                detail TEXT NOT NULL
            )
        """)
        conn.execute("CREATE INDEX IF NOT EXISTS idx_activity_timestamp ON activity_log(timestamp DESC)")


def client_ip():
    # Use the direct peer address; do not trust forwarded headers on an unconfigured proxy.
    return request.remote_addr or "unknown"


def current_device_name():
    return session.get("device_name", "Unknown device")


def log_activity(action, detail, device_name=None, ip_address=None):
    with db_connect() as conn:
        conn.execute(
            "INSERT INTO activity_log(timestamp, device_name, ip_address, action, detail) VALUES (?, ?, ?, ?, ?)",
            (time.time(), device_name or current_device_name(), ip_address or client_ip(), action, detail),
        )


def format_size(size):
    units = ["B", "KB", "MB", "GB", "TB"]
    value = float(size)
    for unit in units:
        if value < 1024 or unit == "TB":
            return f"{value:.1f} {unit}"
        value /= 1024
    return f"{value:.1f} TB"


def get_files():
    files = []
    for path in STORAGE_DIR.iterdir():
        if path.is_file():
            stat = path.stat()
            files.append({
                "name": path.name,
                "size": format_size(stat.st_size),
                "modified": stat.st_mtime,
            })
    return sorted(files, key=lambda item: item["modified"], reverse=True)


def login_required(view):
    @wraps(view)
    def wrapped_view(*args, **kwargs):
        if not session.get("authenticated"):
            if request.path.startswith("/api/") or request.headers.get("X-Requested-With") == "XMLHttpRequest":
                return jsonify({"success": False, "message": "กรุณาเข้าสู่ระบบใหม่"}), 401
            return redirect(url_for("login"))
        return view(*args, **kwargs)
    return wrapped_view


@app.route("/login", methods=["GET", "POST"])
def login():
    if session.get("authenticated"):
        return redirect(url_for("home"))

    if request.method == "POST":
        pin = request.form.get("pin", "")
        device_name = request.form.get("device_name", "").strip()[:40]
        if not device_name:
            device_name = "Unnamed device"

        if secrets.compare_digest(pin, LAN_PIN):
            session.clear()
            session_id = secrets.token_hex(24)
            now = time.time()
            ip = client_ip()
            user_agent = request.user_agent.string[:500]
            session["authenticated"] = True
            session["session_id"] = session_id
            session["device_name"] = device_name

            with db_connect() as conn:
                conn.execute(
                    "INSERT INTO user_sessions(session_id, device_name, ip_address, user_agent, login_at, last_seen, logout_at) VALUES (?, ?, ?, ?, ?, ?, NULL)",
                    (session_id, device_name, ip, user_agent, now, now),
                )
                conn.execute(
                    "INSERT INTO activity_log(timestamp, device_name, ip_address, action, detail) VALUES (?, ?, ?, ?, ?)",
                    (now, device_name, ip, "login", "เข้าสู่ระบบสำเร็จ"),
                )
            return redirect(url_for("home"))

        flash("PIN ไม่ถูกต้อง")

    return render_template("login.html")


@app.route("/logout", methods=["POST"])
@login_required
def logout():
    session_id = session.get("session_id")
    now = time.time()
    device_name = current_device_name()
    ip = client_ip()
    if session_id:
        with db_connect() as conn:
            conn.execute("UPDATE user_sessions SET logout_at = ?, last_seen = ? WHERE session_id = ?", (now, now, session_id))
            conn.execute(
                "INSERT INTO activity_log(timestamp, device_name, ip_address, action, detail) VALUES (?, ?, ?, ?, ?)",
                (now, device_name, ip, "logout", "ออกจากระบบ"),
            )
    session.clear()
    return redirect(url_for("login"))


@app.route("/")
@login_required
def home():
    return render_template("index.html", files=get_files(), device_name=current_device_name())


@app.route("/api/heartbeat", methods=["POST"])
@login_required
def heartbeat():
    session_id = session.get("session_id")
    if not session_id:
        return jsonify({"success": False, "message": "กรุณาเข้าสู่ระบบใหม่"}), 401
    with db_connect() as conn:
        conn.execute(
            "UPDATE user_sessions SET last_seen = ?, ip_address = ?, user_agent = ? WHERE session_id = ? AND logout_at IS NULL",
            (time.time(), client_ip(), request.user_agent.string[:500], session_id),
        )
    return jsonify({"success": True})


@app.route("/api/status")
@login_required
def api_status():
    now = time.time()
    with db_connect() as conn:
        online_rows = conn.execute(
            "SELECT device_name, ip_address, user_agent, login_at, last_seen FROM user_sessions "
            "WHERE logout_at IS NULL AND last_seen >= ? ORDER BY login_at DESC",
            (now - ONLINE_TIMEOUT_SECONDS,),
        ).fetchall()
        log_rows = conn.execute(
            "SELECT timestamp, device_name, ip_address, action, detail FROM activity_log ORDER BY id DESC LIMIT 40"
        ).fetchall()

    online = [{
        "device_name": row["device_name"],
        "ip_address": row["ip_address"],
        "user_agent": row["user_agent"],
        "login_at": row["login_at"],
        "last_seen": row["last_seen"],
        "is_me": row["device_name"] == current_device_name() and row["ip_address"] == client_ip(),
    } for row in online_rows]
    activity = [dict(row) for row in log_rows]
    return jsonify({"files": get_files(), "online_users": online, "activity": activity, "server_time": now})


@app.route("/upload", methods=["POST"])
@login_required
def upload_file():
    is_ajax = request.headers.get("X-Requested-With") == "XMLHttpRequest"

    def respond(message, success, status=200):
        if is_ajax:
            return jsonify({"success": success, "message": message}), status
        flash(message)
        return redirect(url_for("home"))

    uploaded = request.files.get("file")
    if uploaded is None or not uploaded.filename:
        return respond("กรุณาเลือกไฟล์ก่อนอัปโหลด", False, 400)

    filename = secure_filename(uploaded.filename)
    if not filename:
        return respond("ชื่อไฟล์ไม่ถูกต้อง", False, 400)

    destination = STORAGE_DIR / filename
    stem, suffix = destination.stem, destination.suffix
    counter = 1
    while destination.exists():
        destination = STORAGE_DIR / f"{stem}_{counter}{suffix}"
        counter += 1

    try:
        uploaded.save(destination)
    except OSError:
        app.logger.exception("Failed to save uploaded file")
        return respond("บันทึกไฟล์ไม่สำเร็จ กรุณาตรวจสอบพื้นที่ดิสก์", False, 500)

    log_activity("upload", f"อัปโหลดไฟล์ {destination.name}")
    return respond(f"อัปโหลด {destination.name} สำเร็จ", True)


@app.route("/download/<path:filename>")
@login_required
def download_file(filename):
    safe_name = secure_filename(filename)
    if not safe_name or safe_name != filename:
        abort(404)
    path = STORAGE_DIR / safe_name
    if not path.is_file():
        abort(404)
    log_activity("download", f"ดาวน์โหลดไฟล์ {safe_name}")
    return send_from_directory(str(STORAGE_DIR), safe_name, as_attachment=True)


@app.route("/delete/<path:filename>", methods=["POST"])
@login_required
def delete_file(filename):
    safe_name = secure_filename(filename)
    if not safe_name or safe_name != filename:
        abort(404)
    path = STORAGE_DIR / safe_name
    if not path.is_file():
        if request.headers.get("X-Requested-With") == "XMLHttpRequest":
            return jsonify({"success": False, "message": "ไม่พบไฟล์นี้"}), 404
        abort(404)

    path.unlink()
    log_activity("delete", f"ลบไฟล์ {safe_name}")
    message = f"ลบ {safe_name} สำเร็จ"
    if request.headers.get("X-Requested-With") == "XMLHttpRequest":
        return jsonify({"success": True, "message": message})
    flash(message)
    return redirect(url_for("home"))


@app.errorhandler(413)
def file_too_large(error):
    if request.headers.get("X-Requested-With") == "XMLHttpRequest":
        return jsonify({"success": False, "message": "ไฟล์ใหญ่เกินขนาดที่ระบบอนุญาต"}), 413
    flash("ไฟล์ใหญ่เกินขนาดที่ระบบอนุญาต")
    return redirect(url_for("home")), 303


init_db()

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=False)
