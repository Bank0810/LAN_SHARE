
from pathlib import Path


import os
import secrets
from functools import wraps
from werkzeug.utils import secure_filename

from flask import (
    Flask,
    render_template,
    request,
    redirect,
    url_for,
    flash,
    send_from_directory,
    abort,
    jsonify,
    session,
)

app = Flask(__name__)

app.secret_key = os.environ.get("LANSHARE_SECRET")
if not app.secret_key:
    raise RuntimeError("กรุณาตั้งค่า LANSHARE_SECRET ก่อนเริ่มระบบ")

LAN_PIN = os.environ.get("LANSHARE_PIN")
if not LAN_PIN:
    raise RuntimeError("กรุณาตั้งค่า LANSHARE_PIN ก่อนเริ่มระบบ")

app.config["MAX_CONTENT_LENGTH"] = 2 * 1024 * 1024 * 1024

BASE_DIR = Path(__file__).resolve().parent
STORAGE_DIR = BASE_DIR / "storage"
STORAGE_DIR.mkdir(exist_ok=True)


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
            files.append({
                "name": path.name,
                "size": format_size(path.stat().st_size),
                "modified": path.stat().st_mtime,
            })

    return sorted(files, key=lambda item: item["modified"], reverse=True)

def login_required(view):
    @wraps(view)
    def wrapped_view(*args, **kwargs):
        if not session.get("authenticated"):
            return redirect(url_for("login"))
        return view(*args, **kwargs)
    return wrapped_view


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        pin = request.form.get("pin", "")

        if secrets.compare_digest(pin, LAN_PIN):
            session.clear()
            session["authenticated"] = True
            return redirect(url_for("home"))

        flash("PIN ไม่ถูกต้อง")

    return render_template("login.html")


@app.route("/logout", methods=["POST"])
def logout():
    session.clear()
    return redirect(url_for("login"))

@app.route("/")
@login_required
def home():
    return render_template("index.html", files=get_files())





@app.route("/upload", methods=["POST"])
def upload_file():
    is_ajax = (
        request.headers.get("X-Requested-With")
        == "XMLHttpRequest"
    )

    def respond(message, success, status=200):
        if is_ajax:
            return jsonify({
                "success": success,
                "message": message,
            }), status

        flash(message)
        return redirect(url_for("home"))

    uploaded = request.files.get("file")

    if uploaded is None or not uploaded.filename:
        return respond("กรุณาเลือกไฟล์ก่อนอัปโหลด", False, 400)

    filename = secure_filename(uploaded.filename)

    if not filename:
        return respond("ชื่อไฟล์ไม่ถูกต้อง", False, 400)

    destination = STORAGE_DIR / filename
    stem = destination.stem
    suffix = destination.suffix
    counter = 1

    while destination.exists():
        destination = STORAGE_DIR / f"{stem}_{counter}{suffix}"
        counter += 1

    try:
        uploaded.save(destination)
    except OSError:
        app.logger.exception("Failed to save uploaded file")
        return respond("บันทึกไฟล์ไม่สำเร็จ กรุณาตรวจสอบพื้นที่ดิสก์", False, 500)

    return respond(f"อัปโหลด {destination.name} สำเร็จ", True)


@app.route("/download/<path:filename>")
def download_file(filename):
    safe_name = secure_filename(filename)

    if not safe_name or safe_name != filename:
        abort(404)

    path = STORAGE_DIR / safe_name

    if not path.is_file():
        abort(404)

    return send_from_directory(
        str(STORAGE_DIR),
        safe_name,
        as_attachment=True,
    )


@app.route("/delete/<path:filename>", methods=["POST"])
def delete_file(filename):
    safe_name = secure_filename(filename)

    if not safe_name or safe_name != filename:
        abort(404)

    path = STORAGE_DIR / safe_name

    if not path.is_file():
        abort(404)

    path.unlink()
    flash(f"ลบ {safe_name} สำเร็จ")
    return redirect(url_for("home"))


@app.errorhandler(413)
def file_too_large(error):
    flash("ไฟล์ใหญ่เกินขนาดที่ระบบอนุญาต")
    return redirect(url_for("home")), 303


if __name__ == "__main__":
    app.run(
        host="0.0.0.0",
        port=5000,
        debug=False,
    )
