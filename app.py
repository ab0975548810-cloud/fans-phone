from flask import Flask, render_template, jsonify, request, session, send_file
import sqlite3
import os
import shutil
import threading
import time
import secrets
import json
import calendar
import urllib.request
import urllib.error
import hmac
from urllib.parse import urlparse
from datetime import datetime, timedelta
from functools import wraps
from zoneinfo import ZoneInfo
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
TW_TZ = ZoneInfo("Asia/Taipei")
DB_NAME = "pos.db"
APP_VERSION = "1.5.4"
UPDATE_MANIFEST_URL = "https://raw.githubusercontent.com/ab0975548810-cloud/fans-phone/main/version.json"


def get_db_dir():
    cloud_data_path = "/data"
    if os.path.exists(cloud_data_path) and os.path.isdir(cloud_data_path):
        return cloud_data_path
    return os.path.abspath(os.path.dirname(__file__))


def load_or_create_secret_key():
    env_key = os.environ.get("SECRET_KEY")
    if env_key:
        return env_key
    base_dir = get_db_dir()
    os.makedirs(base_dir, exist_ok=True)
    key_path = os.path.join(base_dir, ".pos_secret_key")
    if os.path.exists(key_path):
        with open(key_path, "r", encoding="utf-8") as f:
            key = f.read().strip()
            if key:
                return key
    key = secrets.token_hex(32)
    with open(key_path, "w", encoding="utf-8") as f:
        f.write(key)
    return key


app.secret_key = load_or_create_secret_key()
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=os.environ.get("SESSION_COOKIE_SECURE", "1") != "0",
    PERMANENT_SESSION_LIFETIME=timedelta(hours=12),
    SESSION_REFRESH_EACH_REQUEST=True,
)


@app.after_request
def add_header(response):
    response.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, max-age=0"
    response.headers["Pragma"] = "no-cache"
    response.headers["Expires"] = "-1"
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "SAMEORIGIN"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    response.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; "
        "script-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; "
        "style-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net https://fonts.googleapis.com; "
        "font-src 'self' https://fonts.gstatic.com data:; "
        "img-src 'self' data: blob:; connect-src 'self'; "
        "frame-ancestors 'self'; base-uri 'self'; form-action 'self'"
    )
    if request.is_secure or request.headers.get("X-Forwarded-Proto", "").lower() == "https":
        response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
    return response


def now_tw():
    return datetime.now(TW_TZ)


def today_tw():
    return now_tw().strftime("%Y-%m-%d")


def get_db_connection():
    db_dir = get_db_dir()
    os.makedirs(db_dir, exist_ok=True)
    db_path = os.path.join(db_dir, DB_NAME)
    conn = sqlite3.connect(db_path, timeout=15)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    conn.execute("PRAGMA busy_timeout = 15000")
    return conn


def get_setting(cursor, key, default=""):
    row = cursor.execute("SELECT value FROM settings WHERE key=?", (key,)).fetchone()
    return row["value"] if row else default


def set_setting(cursor, key, value):
    cursor.execute(
        "INSERT INTO settings (key, value) VALUES (?, ?) ON CONFLICT(key) DO UPDATE SET value=excluded.value",
        (key, str(value)),
    )


def setup_completed(cursor):
    return get_setting(cursor, "setup_completed", "0") == "1"


LOGIN_MAX_ATTEMPTS = 5
LOGIN_LOCK_SECONDS = 15 * 60
LOGIN_RESET_SECONDS = 30 * 60


def ensure_csrf_token():
    token = session.get("csrf_token")
    if not token:
        token = secrets.token_urlsafe(32)
        session["csrf_token"] = token
    return token


def _client_ip():
    forwarded = str(request.headers.get("X-Forwarded-For", "")).split(",")[0].strip()
    return forwarded or request.remote_addr or "unknown"


def _login_keys(partner_name):
    name = str(partner_name or "").strip().casefold() or "unknown"
    return (f"account:{name}", f"ip:{_client_ip()}")


def _login_lock_remaining(cursor, partner_name):
    now = int(time.time())
    remaining = 0
    for key in _login_keys(partner_name):
        row = cursor.execute("SELECT locked_until FROM login_security WHERE login_key=?", (key,)).fetchone()
        if row:
            remaining = max(remaining, int(row["locked_until"] or 0) - now)
    return max(0, remaining)


def _record_login_failure(cursor, partner_name):
    now = int(time.time())
    highest = 0
    locked = False
    for key in _login_keys(partner_name):
        row = cursor.execute("SELECT fail_count, locked_until, updated_at FROM login_security WHERE login_key=?", (key,)).fetchone()
        if row and int(row["locked_until"] or 0) > now:
            highest = max(highest, int(row["fail_count"] or LOGIN_MAX_ATTEMPTS))
            locked = True
            continue
        count = int(row["fail_count"] or 0) if row else 0
        updated = int(row["updated_at"] or 0) if row else 0
        if not updated or now - updated > LOGIN_RESET_SECONDS:
            count = 0
        count += 1
        locked_until = now + LOGIN_LOCK_SECONDS if count >= LOGIN_MAX_ATTEMPTS else 0
        cursor.execute(
            "INSERT INTO login_security (login_key, fail_count, locked_until, updated_at) VALUES (?, ?, ?, ?) "
            "ON CONFLICT(login_key) DO UPDATE SET fail_count=excluded.fail_count, locked_until=excluded.locked_until, updated_at=excluded.updated_at",
            (key, count, locked_until, now),
        )
        highest = max(highest, count)
        locked = locked or bool(locked_until)
    return highest, locked


def _clear_login_failures(cursor, partner_name):
    for key in _login_keys(partner_name):
        cursor.execute("DELETE FROM login_security WHERE login_key=?", (key,))


def _recently_reauthed():
    return int(session.get("reauth_until", 0) or 0) >= int(time.time())


def require_recent_reauth(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not session.get("partner_id"):
            return jsonify({"message": "⛔ 登入已失效，請重新登入"}), 401
        if not _recently_reauthed():
            return jsonify({"message": "此操作需要再次驗證目前使用者 PIN", "code": "reauth_required"}), 403
        return f(*args, **kwargs)
    return decorated_function


@app.before_request
def enforce_request_security():
    if request.method not in {"POST", "PUT", "PATCH", "DELETE"}:
        return None
    origin = request.headers.get("Origin")
    if origin:
        try:
            origin_host = urlparse(origin).netloc
        except Exception:
            origin_host = ""
        if origin_host and origin_host != request.host:
            return jsonify({"message": "⛔ 跨站請求已阻擋"}), 403
    if session.get("partner_id") and request.path not in {"/api/auth/login", "/api/setup"}:
        expected = str(session.get("csrf_token") or "")
        supplied = str(request.headers.get("X-CSRF-Token") or "")
        if not expected or not supplied or not hmac.compare_digest(expected, supplied):
            return jsonify({"message": "⛔ 安全驗證失敗，請重新整理後再試", "code": "csrf_failed"}), 403
    return None


def require_auth(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not session.get("partner_id"):
            return jsonify({"message": "⛔ 登入已失效，請重新登入"}), 401
        return f(*args, **kwargs)
    return decorated_function


def current_actor():
    return (session.get("partner_name") or "未知").strip() or "未知"


def log_action(cursor, action, detail=""):
    cursor.execute(
        "INSERT INTO audit_logs (created_at, partner_name, action, detail) VALUES (?, ?, ?, ?)",
        (now_tw().strftime("%Y-%m-%d %H:%M:%S"), current_actor(), str(action), str(detail or "")),
    )


def _is_cash_payment(name):
    text = str(name or "").strip().lower()
    return "現金" in text or text == "cash" or text.startswith("cash ")


def _business_day_row(cursor, date_str):
    return cursor.execute("SELECT * FROM business_days WHERE date=?", (date_str,)).fetchone()


def _day_write_guard(cursor, date_str, require_open_today=False):
    row = _business_day_row(cursor, date_str)
    if row and row["status"] == "closed":
        return f"{date_str} 已完成關帳；如需修改請先到『開／關班』重新開帳"
    if require_open_today and date_str == today_tw() and not row:
        return "今天尚未開班，請先到『開／關班』輸入備用金並開始營業"
    return None


def _expense_cash_total(row):
    if not row:
        return 0.0
    total = 0.0
    for amount_key, source_key in [
        ("rent_base", "rent_base_source"),
        ("cleaning", "cleaning_source"),
        ("electricity", "electricity_source"),
        ("other", "other_source"),
    ]:
        try:
            if str(row[source_key] or "").lower() == "cash":
                total += float(row[amount_key] or 0)
        except (KeyError, IndexError):
            pass
    return total


def _compute_day_summary(cursor, date_str, opening_cash=None):
    summary = cursor.execute(
        "SELECT COALESCE(SUM(total_revenue),0) AS revenue, COALESCE(SUM(total_cost),0) AS cost, COUNT(*) AS orders_count FROM orders WHERE date=? AND is_void=0",
        (date_str,),
    ).fetchone()
    payment_rows = cursor.execute(
        "SELECT payment_method AS name, COALESCE(SUM(total_revenue),0) AS total FROM orders WHERE date=? AND is_void=0 GROUP BY payment_method ORDER BY payment_method",
        (date_str,),
    ).fetchall()
    payments = {r["name"]: float(r["total"] or 0) for r in payment_rows}
    cash_sales = sum(amount for name, amount in payments.items() if _is_cash_payment(name))
    expense_row = cursor.execute("SELECT * FROM rent WHERE date=?", (date_str,)).fetchone()
    expenses = float(expense_row["amount"] or 0) if expense_row else 0.0
    cash_expenses = _expense_cash_total(expense_row)
    day_row = _business_day_row(cursor, date_str)
    if opening_cash is None:
        opening_cash = float(day_row["opening_cash"] or 0) if day_row else 0.0
    revenue = float(summary["revenue"] or 0)
    cost = float(summary["cost"] or 0)
    expected_cash = float(opening_cash or 0) + cash_sales - cash_expenses
    partner_names = {r["partner_name"] for r in cursor.execute(
        "SELECT DISTINCT partner_name FROM audit_logs WHERE created_at LIKE ? AND partner_name!=''",
        (f"{date_str}%",),
    ).fetchall()}
    partner_names.update(r["partner_name"] for r in cursor.execute(
        "SELECT DISTINCT partner_name FROM orders WHERE date=? AND partner_name!=''",
        (date_str,),
    ).fetchall())
    return {
        "date": date_str,
        "revenue": revenue,
        "cost": cost,
        "expenses": expenses,
        "net_profit": revenue - cost - expenses,
        "orders_count": int(summary["orders_count"] or 0),
        "payments": payments,
        "cash_sales": cash_sales,
        "cash_expenses": cash_expenses,
        "opening_cash": float(opening_cash or 0),
        "expected_cash": expected_cash,
        "partners": sorted(partner_names),
    }


def init_db():
    conn = get_db_connection()
    try:
        cursor = conn.cursor()
        cursor.execute("CREATE TABLE IF NOT EXISTS settings (key TEXT PRIMARY KEY, value TEXT NOT NULL)")
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS products (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL,
                cost REAL NOT NULL DEFAULT 0,
                price REAL NOT NULL DEFAULT 0,
                stock INTEGER NOT NULL DEFAULT 0,
                threshold INTEGER NOT NULL DEFAULT 10,
                track_stock INTEGER NOT NULL DEFAULT 1,
                price_mode TEXT NOT NULL DEFAULT 'fixed'
            )
        """)
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS payment_methods (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL UNIQUE
            )
        """)
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS rent (
                date TEXT PRIMARY KEY,
                amount REAL NOT NULL DEFAULT 0,
                rent_base REAL DEFAULT 0,
                cleaning REAL DEFAULT 0,
                electricity REAL DEFAULT 0,
                other REAL DEFAULT 0,
                rent_base_source TEXT NOT NULL DEFAULT 'owner',
                cleaning_source TEXT NOT NULL DEFAULT 'owner',
                electricity_source TEXT NOT NULL DEFAULT 'owner',
                other_source TEXT NOT NULL DEFAULT 'owner'
            )
        """)
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS orders (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                date TEXT NOT NULL,
                created_at TEXT NOT NULL,
                payment_method TEXT NOT NULL,
                total_revenue REAL NOT NULL DEFAULT 0,
                total_cost REAL NOT NULL DEFAULT 0,
                partner_name TEXT DEFAULT '',
                is_void INTEGER NOT NULL DEFAULT 0,
                voided_at TEXT DEFAULT NULL,
                voided_by TEXT DEFAULT NULL,
                edited_at TEXT DEFAULT NULL,
                edited_by TEXT DEFAULT NULL,
                edit_count INTEGER NOT NULL DEFAULT 0
            )
        """)
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS order_items (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                order_id INTEGER NOT NULL,
                product_id INTEGER NOT NULL,
                name TEXT NOT NULL,
                quantity INTEGER NOT NULL,
                price_at_sale REAL NOT NULL,
                cost_at_sale REAL NOT NULL,
                variant_id INTEGER DEFAULT NULL,
                track_stock_at_sale INTEGER NOT NULL DEFAULT 1,
                FOREIGN KEY(order_id) REFERENCES orders(id) ON DELETE CASCADE
            )
        """)
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS product_variants (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                product_id INTEGER NOT NULL,
                name TEXT NOT NULL,
                stock INTEGER NOT NULL DEFAULT 0,
                threshold INTEGER NOT NULL DEFAULT 5,
                FOREIGN KEY(product_id) REFERENCES products(id) ON DELETE CASCADE
            )
        """)
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS partners (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL UNIQUE,
                password_hash TEXT NOT NULL
            )
        """)
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS audit_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                created_at TEXT NOT NULL,
                partner_name TEXT NOT NULL,
                action TEXT NOT NULL,
                detail TEXT DEFAULT ''
            )
        """)
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS login_security (
                login_key TEXT PRIMARY KEY,
                fail_count INTEGER NOT NULL DEFAULT 0,
                locked_until INTEGER NOT NULL DEFAULT 0,
                updated_at INTEGER NOT NULL DEFAULT 0
            )
        """)
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS business_days (
                date TEXT PRIMARY KEY,
                status TEXT NOT NULL DEFAULT 'open',
                opening_cash REAL NOT NULL DEFAULT 0,
                opened_at TEXT DEFAULT NULL,
                opened_by TEXT DEFAULT NULL,
                closed_at TEXT DEFAULT NULL,
                closed_by TEXT DEFAULT NULL,
                counted_cash REAL DEFAULT NULL,
                expected_cash REAL DEFAULT NULL,
                cash_difference REAL DEFAULT NULL,
                difference_note TEXT DEFAULT '',
                closing_note TEXT DEFAULT '',
                cash_sales REAL NOT NULL DEFAULT 0,
                cash_expenses REAL NOT NULL DEFAULT 0,
                revenue REAL NOT NULL DEFAULT 0,
                cost REAL NOT NULL DEFAULT 0,
                expenses REAL NOT NULL DEFAULT 0,
                net_profit REAL NOT NULL DEFAULT 0,
                payment_summary TEXT DEFAULT '{}',
                reopened_at TEXT DEFAULT NULL,
                reopened_by TEXT DEFAULT NULL,
                reopen_reason TEXT DEFAULT '',
                reopen_count INTEGER NOT NULL DEFAULT 0
            )
        """)
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS report_targets (
                period TEXT PRIMARY KEY,
                target_amount REAL NOT NULL DEFAULT 0,
                updated_at TEXT DEFAULT NULL,
                updated_by TEXT DEFAULT NULL
            )
        """)
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS stocktake_sessions (
                batch_no TEXT PRIMARY KEY,
                created_at TEXT NOT NULL,
                partner_name TEXT NOT NULL,
                note TEXT DEFAULT ''
            )
        """)
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS stocktake_items (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                batch_no TEXT NOT NULL,
                product_id INTEGER NOT NULL,
                variant_id INTEGER DEFAULT NULL,
                product_name TEXT NOT NULL,
                expected_stock INTEGER NOT NULL DEFAULT 0,
                actual_stock INTEGER NOT NULL DEFAULT 0,
                difference INTEGER NOT NULL DEFAULT 0,
                FOREIGN KEY(batch_no) REFERENCES stocktake_sessions(batch_no) ON DELETE CASCADE
            )
        """)
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS restock_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                batch_no TEXT DEFAULT '',
                date TEXT NOT NULL,
                partner_name TEXT NOT NULL,
                product_id INTEGER DEFAULT NULL,
                variant_id INTEGER DEFAULT NULL,
                product_name TEXT NOT NULL,
                quantity INTEGER NOT NULL,
                cost REAL NOT NULL DEFAULT 0,
                is_deleted INTEGER DEFAULT 0,
                voided_at TEXT DEFAULT NULL,
                voided_by TEXT DEFAULT NULL,
                restored_at TEXT DEFAULT NULL,
                restored_by TEXT DEFAULT NULL,
                edited_at TEXT DEFAULT NULL,
                edited_by TEXT DEFAULT NULL
            )
        """)

        # 兼容舊資料庫欄位；母版新建 DB 時不會用到，但可避免誤放舊 DB 直接炸掉。
        product_cols = {r[1] for r in cursor.execute("PRAGMA table_info(products)").fetchall()}
        if "track_stock" not in product_cols:
            cursor.execute("ALTER TABLE products ADD COLUMN track_stock INTEGER NOT NULL DEFAULT 1")
        if "price_mode" not in product_cols:
            cursor.execute("ALTER TABLE products ADD COLUMN price_mode TEXT NOT NULL DEFAULT 'fixed'")

        rent_cols = {r[1] for r in cursor.execute("PRAGMA table_info(rent)").fetchall()}
        for col, ddl in {
            "rent_base_source": "ALTER TABLE rent ADD COLUMN rent_base_source TEXT NOT NULL DEFAULT 'owner'",
            "cleaning_source": "ALTER TABLE rent ADD COLUMN cleaning_source TEXT NOT NULL DEFAULT 'owner'",
            "electricity_source": "ALTER TABLE rent ADD COLUMN electricity_source TEXT NOT NULL DEFAULT 'owner'",
            "other_source": "ALTER TABLE rent ADD COLUMN other_source TEXT NOT NULL DEFAULT 'owner'",
        }.items():
            if col not in rent_cols:
                cursor.execute(ddl)

        order_cols = {r[1] for r in cursor.execute("PRAGMA table_info(orders)").fetchall()}
        if "created_at" not in order_cols:
            cursor.execute("ALTER TABLE orders ADD COLUMN created_at TEXT NOT NULL DEFAULT ''")
            cursor.execute("UPDATE orders SET created_at=date WHERE created_at='' OR created_at IS NULL")
        if "is_void" not in order_cols:
            cursor.execute("ALTER TABLE orders ADD COLUMN is_void INTEGER NOT NULL DEFAULT 0")
        if "voided_at" not in order_cols:
            cursor.execute("ALTER TABLE orders ADD COLUMN voided_at TEXT DEFAULT NULL")
        if "voided_by" not in order_cols:
            cursor.execute("ALTER TABLE orders ADD COLUMN voided_by TEXT DEFAULT NULL")
        if "edited_at" not in order_cols:
            cursor.execute("ALTER TABLE orders ADD COLUMN edited_at TEXT DEFAULT NULL")
        if "edited_by" not in order_cols:
            cursor.execute("ALTER TABLE orders ADD COLUMN edited_by TEXT DEFAULT NULL")
        if "edit_count" not in order_cols:
            cursor.execute("ALTER TABLE orders ADD COLUMN edit_count INTEGER NOT NULL DEFAULT 0")

        business_cols = {r[1] for r in cursor.execute("PRAGMA table_info(business_days)").fetchall()}
        if "closing_note" not in business_cols:
            cursor.execute("ALTER TABLE business_days ADD COLUMN closing_note TEXT DEFAULT ''")

        restock_cols = {r[1] for r in cursor.execute("PRAGMA table_info(restock_logs)").fetchall()}
        for col, ddl in {
            "voided_at": "ALTER TABLE restock_logs ADD COLUMN voided_at TEXT DEFAULT NULL",
            "voided_by": "ALTER TABLE restock_logs ADD COLUMN voided_by TEXT DEFAULT NULL",
            "restored_at": "ALTER TABLE restock_logs ADD COLUMN restored_at TEXT DEFAULT NULL",
            "restored_by": "ALTER TABLE restock_logs ADD COLUMN restored_by TEXT DEFAULT NULL",
            "edited_at": "ALTER TABLE restock_logs ADD COLUMN edited_at TEXT DEFAULT NULL",
            "edited_by": "ALTER TABLE restock_logs ADD COLUMN edited_by TEXT DEFAULT NULL",
        }.items():
            if col not in restock_cols:
                cursor.execute(ddl)

        item_cols = {r[1] for r in cursor.execute("PRAGMA table_info(order_items)").fetchall()}
        if "track_stock_at_sale" not in item_cols:
            cursor.execute("ALTER TABLE order_items ADD COLUMN track_stock_at_sale INTEGER NOT NULL DEFAULT 1")

        partner_cols = {r[1] for r in cursor.execute("PRAGMA table_info(partners)").fetchall()}
        if "password_hash" not in partner_cols:
            cursor.execute("ALTER TABLE partners ADD COLUMN password_hash TEXT DEFAULT ''")
            if "password" in partner_cols:
                old_rows = cursor.execute("SELECT id, password FROM partners").fetchall()
                for row in old_rows:
                    if row["password"]:
                        cursor.execute(
                            "UPDATE partners SET password_hash=? WHERE id=?",
                            (generate_password_hash(row["password"]), row["id"]),
                        )

        if cursor.execute("SELECT COUNT(*) FROM products").fetchone()[0] == 0:
            default_products = [
                ("iPhone (滿版)玻璃貼系列", 1, "fixed"),
                ("iPhone (霧面)玻璃貼系列", 1, "fixed"),
                ("iPhone (防窺)玻璃貼系列", 1, "fixed"),
                ("iPhone (抗藍光)玻璃貼系列", 1, "fixed"),
                ("iPhone (14以下)單鏡頭貼系列", 1, "fixed"),
                ("iPhone (14以上)單鏡頭貼系列", 1, "fixed"),
                ("iPhone (片)鏡頭貼系列", 1, "fixed"),
                ("Android (滿版)玻璃貼系列", 1, "fixed"),
                ("Android (邊膠)玻璃貼系列", 1, "fixed"),
                ("Android (果凍)玻璃貼系列", 1, "fixed"),
                ("iPad 鋼化膜系列", 1, "fixed"),
                ("全系列(半版)玻璃貼系列", 1, "fixed"),
                ("電競防窺玻璃貼系列", 1, "fixed"),
                ("全透玻璃貼系列", 1, "fixed"),
                ("羽毛玻璃貼系列", 1, "fixed"),
                ("手機殼系列", 1, "fixed"),
                ("旋轉殼系列", 1, "fixed"),
                ("其他／臨時商品", 0, "custom"),
            ]
            cursor.executemany(
                "INSERT INTO products (name, cost, price, stock, threshold, track_stock, price_mode) VALUES (?, 0, 0, 0, 10, ?, ?)",
                default_products,
            )

        if cursor.execute("SELECT COUNT(*) FROM payment_methods").fetchone()[0] == 0:
            cursor.executemany(
                "INSERT INTO payment_methods (name) VALUES (?)",
                [("現金結帳",), ("LINE PAY",), ("轉帳",)],
            )

        if not get_setting(cursor, "store_name", ""):
            set_setting(cursor, "store_name", "我的配件 POS")
        if not get_setting(cursor, "report_title", ""):
            set_setting(cursor, "report_title", "營業報表總覽")
        if not get_setting(cursor, "setup_completed", ""):
            set_setting(cursor, "setup_completed", "0")

        conn.commit()
    finally:
        conn.close()


init_db()


def _backup_database_to(dst_path):
    """使用 SQLite Online Backup API 產生一致性備份，避免直接複製寫入中的 DB。"""
    src_path = os.path.join(get_db_dir(), DB_NAME)
    if not os.path.exists(src_path):
        return False
    src_conn = sqlite3.connect(src_path, timeout=15)
    dst_conn = sqlite3.connect(dst_path, timeout=15)
    try:
        src_conn.backup(dst_conn)
        dst_conn.commit()
        return True
    finally:
        dst_conn.close()
        src_conn.close()


def _cleanup_old_backups(backup_dir):
    try:
        hourly = sorted(
            [os.path.join(backup_dir, n) for n in os.listdir(backup_dir) if n.startswith("pos_") and n.endswith(".db")],
            key=os.path.getmtime, reverse=True,
        )
        # 保留最近 168 份小時備份（約 7 天）。
        for old in hourly[168:]:
            try:
                os.remove(old)
            except OSError:
                pass
        daily = sorted(
            [os.path.join(backup_dir, n) for n in os.listdir(backup_dir) if n.startswith("daily_") and n.endswith(".db")],
            key=os.path.getmtime, reverse=True,
        )
        # 每日備份保留最近 90 天。
        for old in daily[90:]:
            try:
                os.remove(old)
            except OSError:
                pass
        manual = sorted(
            [os.path.join(backup_dir, n) for n in os.listdir(backup_dir) if n.startswith("manual_") and n.endswith(".db")],
            key=os.path.getmtime, reverse=True,
        )
        # 手動備份保留最近 20 份，避免長期堆積。
        for old in manual[20:]:
            try:
                os.remove(old)
            except OSError:
                pass
    except Exception as e:
        print("清理備份失敗:", e)


def _make_backup():
    base_dir = get_db_dir()
    backup_dir = os.path.join(base_dir, "POS_Backup")
    os.makedirs(backup_dir, exist_ok=True)
    src = os.path.join(base_dir, DB_NAME)
    if not os.path.exists(src):
        return None
    now = now_tw()
    hourly = os.path.join(backup_dir, f"pos_{now.strftime('%Y-%m-%d_%H%M')}.db")
    _backup_database_to(hourly)
    # daily_YYYY-MM-DD.db 每小時更新一次，所以當天最後狀態會留在每日備份。
    daily = os.path.join(backup_dir, f"daily_{now.strftime('%Y-%m-%d')}.db")
    _backup_database_to(daily)
    _cleanup_old_backups(backup_dir)
    return hourly


def _make_manual_backup():
    backup_dir = os.path.join(get_db_dir(), "POS_Backup")
    os.makedirs(backup_dir, exist_ok=True)
    now = now_tw()
    path = os.path.join(backup_dir, f"manual_{now.strftime('%Y-%m-%d_%H%M%S')}.db")
    if not _backup_database_to(path):
        return None
    _cleanup_old_backups(backup_dir)
    return path


def _backup_status_payload():
    base_dir = get_db_dir()
    backup_dir = os.path.join(base_dir, "POS_Backup")
    db_path = os.path.join(base_dir, DB_NAME)
    os.makedirs(backup_dir, exist_ok=True)
    names = os.listdir(backup_dir) if os.path.isdir(backup_dir) else []
    hourly = [os.path.join(backup_dir, n) for n in names if n.startswith("pos_") and n.endswith(".db")]
    daily = [os.path.join(backup_dir, n) for n in names if n.startswith("daily_") and n.endswith(".db")]
    manual = [os.path.join(backup_dir, n) for n in names if n.startswith("manual_") and n.endswith(".db")]
    all_backups = hourly + daily + manual
    latest = max(all_backups, key=os.path.getmtime) if all_backups else None
    return {
        "version": APP_VERSION,
        "storage": base_dir,
        "persistent_storage": os.path.abspath(base_dir) == "/data",
        "db_size": os.path.getsize(db_path) if os.path.exists(db_path) else 0,
        "backup_dir": backup_dir,
        "hourly_count": len(hourly),
        "daily_count": len(daily),
        "manual_count": len(manual),
        "latest_backup": datetime.fromtimestamp(os.path.getmtime(latest), TW_TZ).strftime("%Y-%m-%d %H:%M:%S") if latest else None,
    }


def start_auto_backup():
    # 啟動先留一份，再每小時備份。
    try:
        _make_backup()
    except Exception as e:
        print("備份失敗:", e)
    while True:
        time.sleep(3600)
        try:
            _make_backup()
        except Exception as e:
            print("備份失敗:", e)


threading.Thread(target=start_auto_backup, daemon=True).start()


@app.route("/api/setup/status", methods=["GET"])
def setup_status():
    conn = get_db_connection()
    try:
        cursor = conn.cursor()
        return jsonify({
            "setup_completed": setup_completed(cursor),
            "store_name": get_setting(cursor, "store_name", "我的配件 POS"),
        })
    finally:
        conn.close()


@app.route("/api/setup", methods=["POST"])
def setup_store():
    data = request.get_json() or {}
    store_name = str(data.get("store_name", "")).strip()
    partner_name = str(data.get("partner_name", "")).strip()
    partner_pin = str(data.get("partner_pin", "")).strip()
    if not store_name or not partner_name or len(partner_pin) < 6:
        return jsonify({"message": "店名與第一位使用者必填，個人 PIN 至少 6 碼"}), 400

    conn = get_db_connection()
    try:
        cursor = conn.cursor()
        if setup_completed(cursor):
            return jsonify({"message": "系統已完成初始化"}), 409
        set_setting(cursor, "store_name", store_name)
        set_setting(cursor, "report_title", "營業報表總覽")
        set_setting(cursor, "setup_completed", "1")
        cursor.execute(
            "INSERT INTO partners (name, password_hash) VALUES (?, ?)",
            (partner_name, generate_password_hash(partner_pin)),
        )
        partner_id = cursor.lastrowid
        session.clear()
        session["partner_id"] = partner_id
        session["partner_name"] = partner_name
        log_action(cursor, "首次設定", f"建立店家：{store_name}")
        conn.commit()
        return jsonify({"status": "success", "partner": partner_name, "store_name": store_name})
    except sqlite3.IntegrityError:
        conn.rollback()
        return jsonify({"message": "使用者名稱已存在"}), 400
    finally:
        conn.close()


@app.route("/api/auth/status", methods=["GET"])
def auth_status():
    logged_in = bool(session.get("partner_id"))
    csrf_token = ""
    if logged_in:
        session.permanent = True
        csrf_token = ensure_csrf_token()
    return jsonify({"logged_in": logged_in, "partner": session.get("partner_name", ""), "csrf_token": csrf_token})


@app.route("/api/auth/login", methods=["POST"])
def auth_login():
    data = request.get_json() or {}
    partner_name = str(data.get("partner_name", "")).strip()
    pwd = str(data.get("password", "")).strip()
    if not partner_name or not pwd:
        return jsonify({"message": "請選擇使用者並輸入 PIN"}), 400
    conn = get_db_connection()
    try:
        cursor = conn.cursor()
        if not setup_completed(cursor):
            return jsonify({"message": "請先完成首次設定"}), 409
        remaining = _login_lock_remaining(cursor, partner_name)
        if remaining > 0:
            minutes = max(1, (remaining + 59) // 60)
            return jsonify({"message": f"登入嘗試過多，請約 {minutes} 分鐘後再試", "retry_after": remaining}), 429
        user = cursor.execute("SELECT id, name, password_hash FROM partners WHERE name=?", (partner_name,)).fetchone()
        if user and user["password_hash"] and check_password_hash(user["password_hash"], pwd):
            _clear_login_failures(cursor, partner_name)
            session.clear()
            session["partner_id"] = user["id"]
            session["partner_name"] = user["name"]
            session.permanent = True
            csrf_token = ensure_csrf_token()
            log_action(cursor, "登入", "登入 POS")
            conn.commit()
            return jsonify({"status": "success", "partner": user["name"], "csrf_token": csrf_token})
        fail_count, locked = _record_login_failure(cursor, partner_name)
        attempts_left = max(0, LOGIN_MAX_ATTEMPTS - fail_count)
        cursor.execute("INSERT INTO audit_logs (created_at, partner_name, action, detail) VALUES (?, ?, ?, ?)", (now_tw().strftime("%Y-%m-%d %H:%M:%S"), partner_name or "未知", "登入失敗", "已觸發暫時鎖定" if locked else f"PIN 錯誤；剩餘嘗試 {attempts_left} 次"))
        conn.commit()
        if locked:
            return jsonify({"status": "error", "message": "PIN 連續錯誤過多，已暫停登入 15 分鐘", "retry_after": LOGIN_LOCK_SECONDS}), 429
        return jsonify({"status": "error", "message": f"PIN 錯誤，還可嘗試 {attempts_left} 次"}), 401
    finally:
        conn.close()


@app.route("/api/auth/reauth", methods=["POST"])
@require_auth
def auth_reauth():
    data = request.get_json() or {}
    pin = str(data.get("password", "")).strip()
    conn = get_db_connection()
    try:
        cursor = conn.cursor()
        partner_name = str(session.get("partner_name") or "")
        remaining = _login_lock_remaining(cursor, partner_name)
        if remaining > 0:
            return jsonify({"message": "目前帳號暫時鎖定，請稍後再試", "retry_after": remaining}), 429
        user = cursor.execute("SELECT password_hash FROM partners WHERE id=?", (session.get("partner_id"),)).fetchone()
        if user and pin and check_password_hash(user["password_hash"], pin):
            _clear_login_failures(cursor, partner_name)
            session["reauth_until"] = int(time.time()) + 300
            log_action(cursor, "安全驗證", "敏感操作二次驗證成功")
            conn.commit()
            return jsonify({"status": "success", "valid_for": 300})
        fail_count, locked = _record_login_failure(cursor, partner_name)
        log_action(cursor, "安全驗證失敗", "二次驗證 PIN 錯誤")
        conn.commit()
        if locked:
            return jsonify({"message": "PIN 連續錯誤過多，已暫停驗證 15 分鐘"}), 429
        return jsonify({"message": f"PIN 錯誤，還可嘗試 {max(0, LOGIN_MAX_ATTEMPTS-fail_count)} 次"}), 401
    finally:
        conn.close()


@app.route("/api/auth/logout", methods=["POST"])
def auth_logout():
    if session.get("partner_id"):
        conn = get_db_connection()
        try:
            cursor = conn.cursor()
            log_action(cursor, "登出", "登出 POS")
            conn.commit()
        finally:
            conn.close()
    session.clear()
    return jsonify({"status": "success"})


@app.route("/api/settings", methods=["GET", "POST"])
@require_auth
def settings_api():
    conn = get_db_connection()
    try:
        cursor = conn.cursor()
        if request.method == "GET":
            return jsonify({
                "store_name": get_setting(cursor, "store_name", "我的配件 POS"),
                "report_title": get_setting(cursor, "report_title", "營業報表總覽"),
            })
        data = request.get_json() or {}
        store_name = str(data.get("store_name", "")).strip()
        report_title = str(data.get("report_title", "")).strip()
        if store_name:
            set_setting(cursor, "store_name", store_name)
        if report_title:
            set_setting(cursor, "report_title", report_title)
        log_action(cursor, "系統設定", f"店名：{store_name or get_setting(cursor, 'store_name', '')}；報表：{report_title or get_setting(cursor, 'report_title', '')}")
        conn.commit()
        return jsonify({"status": "success"})
    finally:
        conn.close()


def _version_tuple(version):
    parts = []
    for part in str(version or "0").strip().lstrip("vV").split("."):
        digits = "".join(ch for ch in part if ch.isdigit())
        parts.append(int(digits or 0))
    while len(parts) < 3:
        parts.append(0)
    return tuple(parts[:3])


def _check_update_payload():
    req = urllib.request.Request(
        UPDATE_MANIFEST_URL,
        headers={"User-Agent": f"fans-phone-pos/{APP_VERSION}", "Cache-Control": "no-cache"},
    )
    try:
        with urllib.request.urlopen(req, timeout=5) as resp:
            manifest = json.loads(resp.read().decode("utf-8"))
        latest = str(manifest.get("version") or "").strip().lstrip("vV")
        if not latest:
            raise ValueError("版本資訊缺少 version")
        return {
            "current_version": APP_VERSION,
            "latest_version": latest,
            "update_available": _version_tuple(latest) > _version_tuple(APP_VERSION),
            "release_notes": str(manifest.get("release_notes") or "").strip(),
            "checked_at": now_tw().strftime("%Y-%m-%d %H:%M:%S"),
        }
    except Exception as e:
        return {
            "current_version": APP_VERSION,
            "latest_version": None,
            "update_available": False,
            "release_notes": "",
            "checked_at": now_tw().strftime("%Y-%m-%d %H:%M:%S"),
            "error": f"無法取得最新版本資訊：{e}",
        }


@app.route("/api/system/status", methods=["GET"])
@require_auth
def system_status_api():
    return jsonify(_backup_status_payload())




@app.route("/api/system/update_check", methods=["GET"])
@require_auth
def system_update_check_api():
    payload = _check_update_payload()
    if payload.get("error"):
        return jsonify(payload), 503
    return jsonify(payload)
@app.route("/api/system/backup", methods=["POST"])
@require_auth
def system_backup_api():
    path = _make_manual_backup()
    if not path:
        return jsonify({"message": "找不到資料庫，無法備份"}), 404
    conn = get_db_connection()
    try:
        cursor = conn.cursor()
        log_action(cursor, "手動備份", os.path.basename(path))
        conn.commit()
    finally:
        conn.close()
    payload = _backup_status_payload()
    payload.update({"status": "success", "file": os.path.basename(path)})
    return jsonify(payload)


@app.route("/api/system/backup/download", methods=["GET"])
@require_auth
@require_recent_reauth
def system_backup_download_api():
    path = _make_manual_backup()
    if not path:
        return jsonify({"message": "找不到資料庫，無法下載"}), 404
    download_name = f"POS_backup_{now_tw().strftime('%Y-%m-%d_%H%M%S')}.db"
    return send_file(path, as_attachment=True, download_name=download_name, mimetype="application/octet-stream")


@app.route("/api/payment_methods", methods=["GET", "POST", "DELETE"])
@require_auth
def payment_methods_api():
    conn = get_db_connection()
    try:
        cursor = conn.cursor()
        if request.method == "GET":
            rows = cursor.execute("SELECT id, name FROM payment_methods ORDER BY id ASC").fetchall()
            return jsonify([dict(r) for r in rows])
        if request.method == "POST":
            name = str((request.get_json() or {}).get("name", "")).strip()
            if not name:
                return jsonify({"message": "付款方式不可空白"}), 400
            try:
                cursor.execute("INSERT INTO payment_methods (name) VALUES (?)", (name,))
                log_action(cursor, "新增付款方式", name)
                conn.commit()
                return jsonify({"status": "success"})
            except sqlite3.IntegrityError:
                return jsonify({"message": "付款方式已存在"}), 400
        method_id = request.args.get("id")
        if cursor.execute("SELECT COUNT(*) FROM payment_methods").fetchone()[0] <= 1:
            return jsonify({"message": "至少保留一種付款方式"}), 400
        old = cursor.execute("SELECT name FROM payment_methods WHERE id=?", (method_id,)).fetchone()
        cursor.execute("DELETE FROM payment_methods WHERE id=?", (method_id,))
        log_action(cursor, "刪除付款方式", old["name"] if old else str(method_id))
        conn.commit()
        return jsonify({"status": "success"})
    finally:
        conn.close()


@app.route("/api/partners", methods=["GET", "POST", "DELETE"])
def handle_partners():
    conn = get_db_connection()
    try:
        cursor = conn.cursor()
        if request.method == "GET":
            rows = cursor.execute("SELECT id, name FROM partners ORDER BY id ASC").fetchall()
            return jsonify([dict(r) for r in rows])

        if not session.get("partner_id"):
            return jsonify({"message": "請先登入"}), 401

        if request.method == "POST":
            if not _recently_reauthed():
                return jsonify({"message": "人員資料異動前需要再次輸入目前使用者 PIN", "code": "reauth_required"}), 403

            data = request.get_json() or {}
            pid = data.get("id")
            name = str(data.get("name", "")).strip()
            pin = str(data.get("password", "")).strip()
            if not name:
                return jsonify({"message": "使用者名稱不可空白"}), 400

            try:
                if pid:
                    try:
                        pid_int = int(pid)
                    except (TypeError, ValueError):
                        return jsonify({"message": "使用者編號錯誤"}), 400
                    target = cursor.execute("SELECT id, name FROM partners WHERE id=?", (pid_int,)).fetchone()
                    if not target:
                        return jsonify({"message": "找不到此使用者"}), 404
                    is_self = int(session.get("partner_id")) == pid_int

                    # 身分 PIN 只能本人修改。不能先重設別人的 PIN 再冒用該帳號。
                    if pin and not is_self:
                        log_action(cursor, "阻擋 PIN 修改", f"嘗試修改其他使用者 PIN：{target['name']}")
                        conn.commit()
                        return jsonify({"message": "⛔ 不能修改其他使用者的 PIN；PIN 只能由本人登入後修改", "code": "target_pin_forbidden"}), 403

                    if pin:
                        if len(pin) < 6:
                            return jsonify({"message": "PIN 至少 6 碼"}), 400
                        cursor.execute(
                            "UPDATE partners SET name=?, password_hash=? WHERE id=?",
                            (name, generate_password_hash(pin), pid_int),
                        )
                    else:
                        cursor.execute("UPDATE partners SET name=? WHERE id=?", (name, pid_int))

                    if is_self:
                        session["partner_name"] = name
                    log_action(cursor, "使用者管理", f"編輯：{target['name']} → {name}" + ("；本人修改 PIN" if pin else ""))
                else:
                    if len(pin) < 6:
                        return jsonify({"message": "新增使用者時 PIN 至少 6 碼"}), 400
                    cursor.execute(
                        "INSERT INTO partners (name, password_hash) VALUES (?, ?)",
                        (name, generate_password_hash(pin)),
                    )
                    log_action(cursor, "使用者管理", f"新增：{name}")

                conn.commit()
                return jsonify({"status": "success"})
            except sqlite3.IntegrityError:
                conn.rollback()
                return jsonify({"message": "使用者名稱已存在"}), 400

        if not _recently_reauthed():
            return jsonify({"message": "刪除使用者前需要再次輸入目前使用者 PIN", "code": "reauth_required"}), 403
        pid = request.args.get("id")
        try:
            pid_int = int(pid)
        except (TypeError, ValueError):
            return jsonify({"message": "使用者編號錯誤"}), 400
        if pid_int == int(session.get("partner_id")):
            return jsonify({"message": "不能刪除目前正在登入的帳號；請先由其他使用者登入再操作"}), 400
        if cursor.execute("SELECT COUNT(*) FROM partners").fetchone()[0] <= 1:
            return jsonify({"message": "至少保留一位使用者"}), 400
        old = cursor.execute("SELECT name FROM partners WHERE id=?", (pid_int,)).fetchone()
        if not old:
            return jsonify({"message": "找不到此使用者"}), 404
        cursor.execute("DELETE FROM partners WHERE id=?", (pid_int,))
        log_action(cursor, "刪除使用者", old["name"])
        conn.commit()
        return jsonify({"status": "success"})
    finally:
        conn.close()


def recalc_product_stock(cursor, product_id):
    row = cursor.execute(
        "SELECT COUNT(*) AS c, COALESCE(SUM(stock), 0) AS total FROM product_variants WHERE product_id=?",
        (product_id,),
    ).fetchone()
    if row["c"] > 0:
        cursor.execute("UPDATE products SET stock=? WHERE id=?", (row["total"], product_id))


@app.route("/api/products", methods=["GET", "POST", "DELETE"])
@require_auth
def handle_products():
    conn = get_db_connection()
    try:
        cursor = conn.cursor()
        if request.method == "GET":
            products = cursor.execute("SELECT * FROM products ORDER BY id ASC").fetchall()
            result = []
            for p in products:
                d = dict(p)
                d["track_stock"] = bool(d.get("track_stock", 1))
                d["variants"] = [dict(v) for v in cursor.execute(
                    "SELECT id, name, stock, threshold FROM product_variants WHERE product_id=? ORDER BY id ASC",
                    (p["id"],),
                ).fetchall()]
                result.append(d)
            return jsonify(result)
        data = request.get_json() or {}
        name = str(data.get("name", "")).strip()
        if not name:
            return jsonify({"message": "商品名稱不可空白"}), 400
        try:
            cost = max(0, float(data.get("cost", 0) or 0))
            price = max(0, float(data.get("price", 0) or 0))
            stock = max(0, int(float(data.get("stock", 0) or 0)))
            threshold = max(0, int(float(data.get("threshold", 10) or 0)))
        except (TypeError, ValueError):
            return jsonify({"message": "成本、售價、庫存與安全線格式錯誤"}), 400
        track_stock = 1 if data.get("track_stock", True) in (True, 1, "1", "true", "True") else 0
        price_mode = "custom" if data.get("price_mode") == "custom" else "fixed"
        if not track_stock:
            stock = 0
            threshold = 0

        if request.method == "POST":
            if data.get("id"):
                cursor.execute(
                    "UPDATE products SET name=?, cost=?, price=?, stock=?, threshold=?, track_stock=?, price_mode=? WHERE id=?",
                    (name, cost, price, stock, threshold, track_stock, price_mode, data["id"]),
                )
                if not track_stock:
                    cursor.execute("DELETE FROM product_variants WHERE product_id=?", (data["id"],))
            else:
                cursor.execute(
                    "INSERT INTO products (name, cost, price, stock, threshold, track_stock, price_mode) VALUES (?, ?, ?, ?, ?, ?, ?)",
                    (name, cost, price, stock, threshold, track_stock, price_mode),
                )
            log_action(cursor, "商品設定", f"{'編輯' if data.get('id') else '新增'}：{name}")
            conn.commit()
            return jsonify({"status": "success"})

        pid = request.args.get("id")
        used = cursor.execute("SELECT 1 FROM order_items WHERE product_id=? LIMIT 1", (pid,)).fetchone()
        restocked = cursor.execute("SELECT 1 FROM restock_logs WHERE product_id=? LIMIT 1", (pid,)).fetchone()
        if used or restocked:
            return jsonify({"message": "此商品已有歷史單據或進貨紀錄，為保留資料完整性不可永久刪除；可改名或停用庫存追蹤。"}), 409
        old = cursor.execute("SELECT name FROM products WHERE id=?", (pid,)).fetchone()
        cursor.execute("DELETE FROM product_variants WHERE product_id=?", (pid,))
        cursor.execute("DELETE FROM products WHERE id=?", (pid,))
        log_action(cursor, "刪除商品", old["name"] if old else str(pid))
        conn.commit()
        return jsonify({"status": "success"})
    finally:
        conn.close()


@app.route("/api/variants", methods=["GET", "POST", "DELETE"])
@require_auth
def handle_variants():
    conn = get_db_connection()
    try:
        cursor = conn.cursor()
        pid = int(request.args.get("product_id") or (request.get_json(silent=True) or {}).get("product_id") or 0)
        product = cursor.execute("SELECT track_stock FROM products WHERE id=?", (pid,)).fetchone()
        if request.method == "GET":
            rows = cursor.execute("SELECT * FROM product_variants WHERE product_id=? ORDER BY id ASC", (pid,)).fetchall()
            return jsonify({"product_id": pid, "variants": [dict(v) for v in rows]})
        if not product or not product["track_stock"]:
            return jsonify({"message": "此商品未啟用庫存追蹤，不能建立細項"}), 400

        if request.method == "POST":
            data = request.get_json() or {}
            stock = max(0, int(float(data.get("stock", 0) or 0)))
            threshold = max(0, int(float(data.get("threshold", 5) or 0)))
            names = [n.strip() for n in str(data.get("name", "")).replace("，", ",").split(",") if n.strip()]
            if not names:
                return jsonify({"message": "請輸入細項名稱"}), 400
            for name in names:
                cursor.execute(
                    "INSERT INTO product_variants (product_id, name, stock, threshold) VALUES (?, ?, ?, ?)",
                    (pid, name, stock, threshold),
                )
            recalc_product_stock(cursor, pid)
            log_action(cursor, "新增商品細項", f"商品 ID {pid}：{', '.join(names)}")
            conn.commit()
            return jsonify({"status": "success"})

        vid = request.args.get("id")
        old = cursor.execute("SELECT name FROM product_variants WHERE id=? AND product_id=?", (vid, pid)).fetchone()
        cursor.execute("DELETE FROM product_variants WHERE id=? AND product_id=?", (vid, pid))
        recalc_product_stock(cursor, pid)
        log_action(cursor, "刪除商品細項", old["name"] if old else f"ID {vid}")
        conn.commit()
        return jsonify({"status": "success"})
    finally:
        conn.close()


@app.route("/api/variants/bulk", methods=["POST"])
@require_auth
def bulk_save_variants():
    data = request.get_json() or {}
    pid = int(data.get("product_id") or 0)
    conn = get_db_connection()
    try:
        cursor = conn.cursor()
        for v in data.get("variants", []):
            cursor.execute(
                "UPDATE product_variants SET name=?, stock=?, threshold=? WHERE id=? AND product_id=?",
                (str(v["name"]).strip(), max(0, int(v["stock"])), max(0, int(v["threshold"])), v["id"], pid),
            )
        recalc_product_stock(cursor, pid)
        log_action(cursor, "批次修改商品細項", f"商品 ID {pid}")
        conn.commit()
        return jsonify({"status": "success"})
    finally:
        conn.close()


@app.route("/api/variants/copy", methods=["POST"])
@require_auth
def copy_variants():
    data = request.get_json() or {}
    src_id, tgt_id = data.get("source_id"), data.get("target_id")
    conn = get_db_connection()
    try:
        cursor = conn.cursor()
        target = cursor.execute("SELECT track_stock FROM products WHERE id=?", (tgt_id,)).fetchone()
        if not target or not target["track_stock"]:
            return jsonify({"message": "目標商品未啟用庫存追蹤"}), 400
        variants = cursor.execute("SELECT name, threshold FROM product_variants WHERE product_id=?", (src_id,)).fetchall()
        for v in variants:
            cursor.execute(
                "INSERT INTO product_variants (product_id, name, stock, threshold) VALUES (?, ?, 0, ?)",
                (tgt_id, v["name"], v["threshold"]),
            )
        recalc_product_stock(cursor, tgt_id)
        log_action(cursor, "複製商品細項", f"來源 {src_id} → 目標 {tgt_id}")
        conn.commit()
        return jsonify({"status": "success"})
    finally:
        conn.close()


def ensure_stock_can_remove(cursor, product_id, variant_id, qty):
    if variant_id:
        v = cursor.execute("SELECT stock FROM product_variants WHERE id=? AND product_id=?", (variant_id, product_id)).fetchone()
        if not v or v["stock"] < qty:
            return False
    p = cursor.execute("SELECT stock FROM products WHERE id=?", (product_id,)).fetchone()
    return bool(p and p["stock"] >= qty)


@app.route("/api/restock", methods=["GET", "POST", "DELETE"])
@require_auth
def handle_restock():
    conn = get_db_connection()
    try:
        cursor = conn.cursor()
        if request.method == "GET":
            mode = request.args.get("mode", "daily")
            target = request.args.get("date")
            is_trash = int(request.args.get("trash", "0"))
            if not target:
                target = now_tw().strftime("%Y-%m-%d" if mode == "daily" else "%Y-%m" if mode == "monthly" else "%Y")
            rows = cursor.execute(
                "SELECT * FROM restock_logs WHERE date LIKE ? AND is_deleted=? ORDER BY id DESC",
                (f"{target}%", is_trash),
            ).fetchall()
            grouped = {}
            for row in rows:
                b_no = row["batch_no"] or f"OLD-{row['id']}"
                grouped.setdefault(b_no, {
                    "batch_no": b_no,
                    "date": row["date"],
                    "partner_name": row["partner_name"],
                    "is_deleted": bool(row["is_deleted"]),
                    "voided_at": row["voided_at"],
                    "voided_by": row["voided_by"],
                    "restored_at": row["restored_at"],
                    "restored_by": row["restored_by"],
                    "edited_at": row["edited_at"],
                    "edited_by": row["edited_by"],
                    "items": [],
                })
                grouped[b_no]["items"].append({
                    "product_id": row["product_id"],
                    "variant_id": row["variant_id"],
                    "name": row["product_name"],
                    "quantity": row["quantity"],
                })
            return jsonify(list(grouped.values()))

        if request.method == "POST":
            data = request.get_json() or {}
            items = data.get("items", [])
            if not items:
                return jsonify({"message": "無效資料"}), 400
            now_str = now_tw().strftime("%Y-%m-%d %H:%M:%S")
            batch_no = f"IN-{now_tw().strftime('%Y%m%d%H%M%S')}-{secrets.token_hex(2).upper()}"
            partner = session.get("partner_name", "未知")
            conn.execute("BEGIN IMMEDIATE")
            for item in items:
                pid = int(item.get("product_id") or 0)
                vid = item.get("variant_id")
                vid = int(vid) if vid not in (None, "", "null") else None
                qty = int(item.get("quantity", 0) or 0)
                if qty <= 0:
                    continue
                p = cursor.execute("SELECT name, cost, track_stock FROM products WHERE id=?", (pid,)).fetchone()
                if not p or not p["track_stock"]:
                    continue
                full_name = p["name"]
                if vid:
                    v = cursor.execute("SELECT name FROM product_variants WHERE id=? AND product_id=?", (vid, pid)).fetchone()
                    if not v:
                        conn.rollback()
                        return jsonify({"message": "找不到進貨細項"}), 400
                    cursor.execute("UPDATE product_variants SET stock=stock+? WHERE id=?", (qty, vid))
                    full_name = f"{p['name']} ({v['name']})"
                cursor.execute("UPDATE products SET stock=stock+? WHERE id=?", (qty, pid))
                cursor.execute(
                    "INSERT INTO restock_logs (batch_no, date, partner_name, product_id, variant_id, product_name, quantity, cost, is_deleted) VALUES (?, ?, ?, ?, ?, ?, ?, ?, 0)",
                    (batch_no, now_str, partner, pid, vid, full_name, qty, p["cost"]),
                )
            log_action(cursor, "進貨", f"{batch_no}；{len(items)} 個品項")
            conn.commit()
            return jsonify({"status": "success", "batch_no": batch_no})

        batch_no = request.args.get("batch_no")
        if not batch_no:
            return jsonify({"message": "缺少單號"}), 400
        # 舊 DELETE 路由保留相容性，但實際使用建議走 batch_action trash。
        return _restock_action(conn, [batch_no], "trash")
    finally:
        conn.close()


def _batch_rows(cursor, batch_no):
    if batch_no.startswith("OLD-"):
        try:
            log_id = int(batch_no.split("-", 1)[1])
        except ValueError:
            return []
        return cursor.execute("SELECT * FROM restock_logs WHERE id=?", (log_id,)).fetchall()
    return cursor.execute("SELECT * FROM restock_logs WHERE batch_no=?", (batch_no,)).fetchall()


def _set_restock_audit(cursor, batch_no, *, deleted=None, voided_at=None, voided_by=None, restored_at=None, restored_by=None):
    sets, values = [], []
    fields = {
        "is_deleted": deleted,
        "voided_at": voided_at,
        "voided_by": voided_by,
        "restored_at": restored_at,
        "restored_by": restored_by,
    }
    for key, value in fields.items():
        if value is not None:
            sets.append(f"{key}=?")
            values.append(value)
    if not sets:
        return
    if batch_no.startswith("OLD-"):
        log_id = int(batch_no.split("-", 1)[1])
        values.append(log_id)
        cursor.execute(f"UPDATE restock_logs SET {', '.join(sets)} WHERE id=?", values)
    else:
        values.append(batch_no)
        cursor.execute(f"UPDATE restock_logs SET {', '.join(sets)} WHERE batch_no=?", values)


def _delete_batch_rows_for_rebuild(cursor, batch_no):
    """Internal-only replacement step for editing an active restock batch."""
    if batch_no.startswith("OLD-"):
        log_id = int(batch_no.split("-", 1)[1])
        cursor.execute("DELETE FROM restock_logs WHERE id=?", (log_id,))
    else:
        cursor.execute("DELETE FROM restock_logs WHERE batch_no=?", (batch_no,))


def _restock_action(conn, batch_nos, action):
    cursor = conn.cursor()
    conn.execute("BEGIN IMMEDIATE")
    try:
        actor = session.get("partner_name", "未知")
        now_str = now_tw().strftime("%Y-%m-%d %H:%M:%S")
        for batch_no in batch_nos:
            rows = _batch_rows(cursor, batch_no)
            if not rows:
                continue
            current_deleted = bool(rows[0]["is_deleted"])
            if action == "trash" and not current_deleted:
                for row in rows:
                    pid, vid, qty = row["product_id"], row["variant_id"], row["quantity"]
                    if not ensure_stock_can_remove(cursor, pid, vid, qty):
                        raise ValueError(f"{row['product_name']} 現有庫存不足，無法作廢這張進貨單")
                    if vid:
                        cursor.execute("UPDATE product_variants SET stock=stock-? WHERE id=?", (qty, vid))
                    cursor.execute("UPDATE products SET stock=stock-? WHERE id=?", (qty, pid))
                _set_restock_audit(
                    cursor, batch_no,
                    deleted=1, voided_at=now_str, voided_by=actor,
                )
                log_action(cursor, "作廢進貨單", batch_no)
            elif action == "recover" and current_deleted:
                for row in rows:
                    pid, vid, qty = row["product_id"], row["variant_id"], row["quantity"]
                    if vid:
                        cursor.execute("UPDATE product_variants SET stock=stock+? WHERE id=?", (qty, vid))
                    cursor.execute("UPDATE products SET stock=stock+? WHERE id=?", (qty, pid))
                _set_restock_audit(
                    cursor, batch_no,
                    deleted=0, restored_at=now_str, restored_by=actor,
                )
                log_action(cursor, "復原進貨單", batch_no)
        conn.commit()
        return jsonify({"status": "success"})
    except ValueError as e:
        conn.rollback()
        return jsonify({"message": str(e)}), 409
    except Exception:
        conn.rollback()
        raise


@app.route("/api/restock/batch_action", methods=["POST"])
@require_auth
def restock_batch_action():
    data = request.get_json() or {}
    action = data.get("action")
    if action not in {"trash", "recover"}:
        return jsonify({"message": "進貨紀錄只允許作廢或復原，不提供永久刪除"}), 400
    batch_nos = data.get("batch_nos", [])
    if not batch_nos:
        return jsonify({"message": "未選擇單號"}), 400
    conn = get_db_connection()
    try:
        return _restock_action(conn, batch_nos, action)
    finally:
        conn.close()


@app.route("/api/restock/edit", methods=["POST"])
@require_auth
def edit_restock_batch():
    data = request.get_json() or {}
    batch_no = str(data.get("batch_no", ""))
    new_items = data.get("items", [])
    if not batch_no:
        return jsonify({"message": "缺少單號"}), 400
    if not new_items:
        return jsonify({"message": "進貨單至少要保留一個品項"}), 400

    conn = get_db_connection()
    try:
        cursor = conn.cursor()
        conn.execute("BEGIN IMMEDIATE")
        old_rows = _batch_rows(cursor, batch_no)
        if not old_rows or old_rows[0]["is_deleted"]:
            conn.rollback()
            return jsonify({"message": "找不到可編輯的進貨單"}), 404

        # 先把舊進貨量從現有庫存扣回，再重建同一張進貨單。
        for row in old_rows:
            if not ensure_stock_can_remove(cursor, row["product_id"], row["variant_id"], row["quantity"]):
                conn.rollback()
                return jsonify({"message": f"{row['product_name']} 現有庫存不足，無法修改此進貨單"}), 409
            if row["variant_id"]:
                cursor.execute("UPDATE product_variants SET stock=stock-? WHERE id=?", (row["quantity"], row["variant_id"]))
            cursor.execute("UPDATE products SET stock=stock-? WHERE id=?", (row["quantity"], row["product_id"]))

        first = old_rows[0]
        created_at = first["date"]
        created_by = first["partner_name"]
        voided_at, voided_by = first["voided_at"], first["voided_by"]
        restored_at, restored_by = first["restored_at"], first["restored_by"]
        _delete_batch_rows_for_rebuild(cursor, batch_no)
        if batch_no.startswith("OLD-"):
            batch_no = f"IN-{now_tw().strftime('%Y%m%d%H%M%S')}-{secrets.token_hex(2).upper()}"
        edited_at = now_tw().strftime("%Y-%m-%d %H:%M:%S")
        edited_by = session.get("partner_name", "未知")
        inserted = 0

        for item in new_items:
            pid = int(item.get("product_id") or 0)
            vid = item.get("variant_id")
            vid = int(vid) if vid not in (None, "", "null") else None
            qty = int(item.get("quantity", 0) or 0)
            if qty <= 0:
                continue
            p = cursor.execute("SELECT name, cost, track_stock FROM products WHERE id=?", (pid,)).fetchone()
            if not p or not p["track_stock"]:
                continue
            full_name = p["name"]
            if vid:
                v = cursor.execute("SELECT name FROM product_variants WHERE id=? AND product_id=?", (vid, pid)).fetchone()
                if not v:
                    conn.rollback()
                    return jsonify({"message": "找不到進貨細項"}), 400
                cursor.execute("UPDATE product_variants SET stock=stock+? WHERE id=?", (qty, vid))
                full_name = f"{p['name']} ({v['name']})"
            cursor.execute("UPDATE products SET stock=stock+? WHERE id=?", (qty, pid))
            cursor.execute("""
                INSERT INTO restock_logs
                (batch_no, date, partner_name, product_id, variant_id, product_name, quantity, cost, is_deleted,
                 voided_at, voided_by, restored_at, restored_by, edited_at, edited_by)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, 0, ?, ?, ?, ?, ?, ?)
            """, (
                batch_no, created_at, created_by, pid, vid, full_name, qty, p["cost"],
                voided_at, voided_by, restored_at, restored_by, edited_at, edited_by,
            ))
            inserted += 1

        if inserted == 0:
            conn.rollback()
            return jsonify({"message": "沒有可儲存的進貨品項"}), 400
        log_action(cursor, "編輯進貨單", batch_no)
        conn.commit()
        return jsonify({"status": "success", "batch_no": batch_no})
    except (TypeError, ValueError) as e:
        if conn.in_transaction:
            conn.rollback()
        return jsonify({"message": str(e)}), 400
    except Exception:
        if conn.in_transaction:
            conn.rollback()
        raise
    finally:
        conn.close()


@app.route("/api/low_stock", methods=["GET"])
@require_auth
def low_stock_api():
    conn = get_db_connection()
    try:
        cursor = conn.cursor()
        products = cursor.execute("SELECT id, name, stock, threshold, track_stock FROM products WHERE track_stock=1 ORDER BY id").fetchall()
        result = []
        for p in products:
            variants = cursor.execute(
                "SELECT id, name, stock, threshold FROM product_variants WHERE product_id=? ORDER BY id",
                (p["id"],),
            ).fetchall()
            if variants:
                for v in variants:
                    if int(v["stock"] or 0) <= int(v["threshold"] or 0):
                        stock = int(v["stock"] or 0)
                        threshold = int(v["threshold"] or 0)
                        target = max(threshold * 2, threshold + 1, 1)
                        result.append({
                            "product_id": p["id"], "variant_id": v["id"],
                            "product_name": p["name"], "variant_name": v["name"],
                            "stock": stock, "threshold": threshold,
                            "suggested_restock": max(1, target - stock),
                        })
            elif int(p["stock"] or 0) <= int(p["threshold"] or 0):
                stock = int(p["stock"] or 0)
                threshold = int(p["threshold"] or 0)
                target = max(threshold * 2, threshold + 1, 1)
                result.append({
                    "product_id": p["id"], "variant_id": None,
                    "product_name": p["name"], "variant_name": "",
                    "stock": stock, "threshold": threshold,
                    "suggested_restock": max(1, target - stock),
                })
        return jsonify(result)
    finally:
        conn.close()


@app.route("/api/stocktake", methods=["GET", "POST"])
@require_auth
def stocktake_api():
    conn = get_db_connection()
    try:
        cursor = conn.cursor()
        if request.method == "GET":
            result = []
            products = cursor.execute("SELECT id, name, stock, threshold FROM products WHERE track_stock=1 ORDER BY id").fetchall()
            for p in products:
                variants = cursor.execute(
                    "SELECT id, name, stock, threshold FROM product_variants WHERE product_id=? ORDER BY id",
                    (p["id"],),
                ).fetchall()
                if variants:
                    for v in variants:
                        result.append({
                            "product_id": p["id"], "variant_id": v["id"],
                            "product_name": p["name"], "variant_name": v["name"],
                            "stock": int(v["stock"] or 0), "threshold": int(v["threshold"] or 0),
                        })
                else:
                    result.append({
                        "product_id": p["id"], "variant_id": None,
                        "product_name": p["name"], "variant_name": "",
                        "stock": int(p["stock"] or 0), "threshold": int(p["threshold"] or 0),
                    })
            return jsonify(result)

        data = request.get_json() or {}
        items = data.get("items") or []
        note = str(data.get("note") or "").strip()
        if not items:
            return jsonify({"message": "沒有盤點資料"}), 400
        conn.execute("BEGIN IMMEDIATE")
        batch_no = f"ST-{now_tw().strftime('%Y%m%d%H%M%S')}-{secrets.token_hex(2).upper()}"
        now_str = now_tw().strftime("%Y-%m-%d %H:%M:%S")
        cursor.execute(
            "INSERT INTO stocktake_sessions (batch_no, created_at, partner_name, note) VALUES (?, ?, ?, ?)",
            (batch_no, now_str, current_actor(), note),
        )
        touched_parents = set()
        changed = 0
        for raw in items:
            pid = int(raw.get("product_id") or 0)
            vid_raw = raw.get("variant_id")
            vid = int(vid_raw) if vid_raw not in (None, "", "null") else None
            actual = int(raw.get("actual_stock"))
            if actual < 0:
                raise ValueError("盤點庫存不可小於 0")
            p = cursor.execute("SELECT name, track_stock, stock FROM products WHERE id=?", (pid,)).fetchone()
            if not p or not p["track_stock"]:
                raise ValueError("找不到可盤點商品")
            if vid:
                v = cursor.execute("SELECT name, stock FROM product_variants WHERE id=? AND product_id=?", (vid, pid)).fetchone()
                if not v:
                    raise ValueError(f"【{p['name']}】找不到指定型號")
                expected = int(v["stock"] or 0)
                full_name = f"{p['name']} ({v['name']})"
                cursor.execute("UPDATE product_variants SET stock=? WHERE id=?", (actual, vid))
                touched_parents.add(pid)
            else:
                variant_count = cursor.execute("SELECT COUNT(*) AS c FROM product_variants WHERE product_id=?", (pid,)).fetchone()["c"]
                if variant_count:
                    raise ValueError(f"【{p['name']}】有型號明細，請盤點型號庫存")
                expected = int(p["stock"] or 0)
                full_name = p["name"]
                cursor.execute("UPDATE products SET stock=? WHERE id=?", (actual, pid))
            diff = actual - expected
            if diff:
                changed += 1
            cursor.execute(
                "INSERT INTO stocktake_items (batch_no, product_id, variant_id, product_name, expected_stock, actual_stock, difference) VALUES (?, ?, ?, ?, ?, ?, ?)",
                (batch_no, pid, vid, full_name, expected, actual, diff),
            )
        for pid in touched_parents:
            recalc_product_stock(cursor, pid)
        log_action(cursor, "庫存盤點", f"{batch_no}；{len(items)} 項；差異 {changed} 項" + (f"；{note}" if note else ""))
        conn.commit()
        return jsonify({"status": "success", "batch_no": batch_no, "changed_count": changed})
    except (ValueError, TypeError) as e:
        if conn.in_transaction:
            conn.rollback()
        return jsonify({"message": str(e)}), 400
    except Exception:
        if conn.in_transaction:
            conn.rollback()
        raise
    finally:
        conn.close()


@app.route("/api/stocktake/logs", methods=["GET"])
@require_auth
def stocktake_logs_api():
    conn = get_db_connection()
    try:
        cursor = conn.cursor()
        rows = cursor.execute(
            "SELECT batch_no, created_at, partner_name, note FROM stocktake_sessions ORDER BY created_at DESC LIMIT 50"
        ).fetchall()
        result = []
        for r in rows:
            d = dict(r)
            d["items"] = [dict(x) for x in cursor.execute(
                "SELECT product_name, expected_stock, actual_stock, difference FROM stocktake_items WHERE batch_no=? ORDER BY id",
                (r["batch_no"],),
            ).fetchall()]
            result.append(d)
        return jsonify(result)
    finally:
        conn.close()


@app.route("/api/business_day", methods=["GET"])
@require_auth
def business_day_status():
    date_str = str(request.args.get("date") or today_tw()).strip()
    try:
        datetime.strptime(date_str, "%Y-%m-%d")
    except ValueError:
        return jsonify({"message": "日期格式錯誤"}), 400
    conn = get_db_connection()
    try:
        cursor = conn.cursor()
        row = _business_day_row(cursor, date_str)
        summary = _compute_day_summary(cursor, date_str)
        day = dict(row) if row else None
        if day and day.get("payment_summary"):
            try:
                day["payment_summary"] = json.loads(day["payment_summary"])
            except Exception:
                day["payment_summary"] = {}
        return jsonify({
            "status": day["status"] if day else "not_opened",
            "day": day,
            "summary": summary,
        })
    finally:
        conn.close()


@app.route("/api/business_day/open", methods=["POST"])
@require_auth
def business_day_open():
    data = request.get_json() or {}
    date_str = str(data.get("date") or today_tw()).strip()
    try:
        datetime.strptime(date_str, "%Y-%m-%d")
        opening_cash = max(0.0, float(data.get("opening_cash", 0) or 0))
    except (ValueError, TypeError):
        return jsonify({"message": "日期或備用金格式錯誤"}), 400
    conn = get_db_connection()
    try:
        cursor = conn.cursor()
        existing = _business_day_row(cursor, date_str)
        if existing:
            if existing["status"] == "closed":
                return jsonify({"message": "此日已關帳；如需修改請使用『重新開帳』"}), 409
            return jsonify({"message": "此日已經開班"}), 409
        now_str = now_tw().strftime("%Y-%m-%d %H:%M:%S")
        cursor.execute(
            "INSERT INTO business_days (date,status,opening_cash,opened_at,opened_by) VALUES (?, 'open', ?, ?, ?)",
            (date_str, opening_cash, now_str, current_actor()),
        )
        log_action(cursor, "開班", f"{date_str}；備用金 ${opening_cash:g}")
        conn.commit()
        return jsonify({"status": "success"})
    finally:
        conn.close()


@app.route("/api/business_day/opening_cash", methods=["POST"])
@require_auth
def business_day_update_opening_cash():
    data = request.get_json() or {}
    date_str = str(data.get("date") or today_tw()).strip()
    try:
        opening_cash = max(0.0, float(data.get("opening_cash", 0) or 0))
        datetime.strptime(date_str, "%Y-%m-%d")
    except (ValueError, TypeError):
        return jsonify({"message": "日期或備用金格式錯誤"}), 400
    conn = get_db_connection()
    try:
        cursor = conn.cursor()
        day = _business_day_row(cursor, date_str)
        if not day:
            return jsonify({"message": "此日尚未開班"}), 404
        if day["status"] != "open":
            return jsonify({"message": "已關帳日期不可直接調整備用金，請先重新開帳"}), 409
        old = float(day["opening_cash"] or 0)
        cursor.execute("UPDATE business_days SET opening_cash=? WHERE date=?", (opening_cash, date_str))
        log_action(cursor, "調整備用金", f"{date_str}；${old:g} → ${opening_cash:g}")
        conn.commit()
        return jsonify({"status": "success"})
    finally:
        conn.close()


@app.route("/api/business_day/close", methods=["POST"])
@require_auth
def business_day_close():
    data = request.get_json() or {}
    date_str = str(data.get("date") or today_tw()).strip()
    note = str(data.get("difference_note") or "").strip()
    closing_note = str(data.get("closing_note") or "").strip()
    try:
        datetime.strptime(date_str, "%Y-%m-%d")
        counted_cash = max(0.0, float(data.get("counted_cash", 0) or 0))
    except (ValueError, TypeError):
        return jsonify({"message": "日期或實際現金格式錯誤"}), 400
    conn = get_db_connection()
    try:
        cursor = conn.cursor()
        conn.execute("BEGIN IMMEDIATE")
        day = _business_day_row(cursor, date_str)
        if not day:
            conn.rollback()
            return jsonify({"message": "此日尚未開班，請先輸入備用金開班"}), 409
        if day["status"] == "closed":
            conn.rollback()
            return jsonify({"message": "此日已完成關帳"}), 409
        summary = _compute_day_summary(cursor, date_str, float(day["opening_cash"] or 0))
        difference = counted_cash - summary["expected_cash"]
        if abs(difference) >= 0.01 and not note:
            conn.rollback()
            return jsonify({"message": "實際現金與系統應有現金有差額，請填寫差異原因"}), 400
        now_str = now_tw().strftime("%Y-%m-%d %H:%M:%S")
        cursor.execute("""
            UPDATE business_days SET
                status='closed', closed_at=?, closed_by=?, counted_cash=?, expected_cash=?, cash_difference=?, difference_note=?, closing_note=?,
                cash_sales=?, cash_expenses=?, revenue=?, cost=?, expenses=?, net_profit=?, payment_summary=?
            WHERE date=?
        """, (
            now_str, current_actor(), counted_cash, summary["expected_cash"], difference, note, closing_note,
            summary["cash_sales"], summary["cash_expenses"], summary["revenue"], summary["cost"],
            summary["expenses"], summary["net_profit"], json.dumps(summary["payments"], ensure_ascii=False), date_str,
        ))
        log_action(cursor, "關帳", f"{date_str}；應有現金 ${summary['expected_cash']:g}；實盤 ${counted_cash:g}；差額 ${difference:g}")
        conn.commit()
        return jsonify({"status": "success", "difference": difference, "expected_cash": summary["expected_cash"]})
    except Exception:
        if conn.in_transaction:
            conn.rollback()
        raise
    finally:
        conn.close()


@app.route("/api/business_day/reopen", methods=["POST"])
@require_auth
def business_day_reopen():
    data = request.get_json() or {}
    date_str = str(data.get("date") or "").strip()
    reason = str(data.get("reason") or "").strip()
    if not reason:
        return jsonify({"message": "重新開帳必須填寫原因"}), 400
    try:
        datetime.strptime(date_str, "%Y-%m-%d")
    except ValueError:
        return jsonify({"message": "日期格式錯誤"}), 400
    conn = get_db_connection()
    try:
        cursor = conn.cursor()
        day = _business_day_row(cursor, date_str)
        if not day:
            return jsonify({"message": "找不到此營業日"}), 404
        if day["status"] != "closed":
            return jsonify({"message": "此日目前不是已關帳狀態"}), 409
        now_str = now_tw().strftime("%Y-%m-%d %H:%M:%S")
        cursor.execute("""
            UPDATE business_days SET status='open', reopened_at=?, reopened_by=?, reopen_reason=?, reopen_count=COALESCE(reopen_count,0)+1
            WHERE date=?
        """, (now_str, current_actor(), reason, date_str))
        log_action(cursor, "重新開帳", f"{date_str}；原因：{reason}")
        conn.commit()
        return jsonify({"status": "success"})
    finally:
        conn.close()


@app.route("/api/rent", methods=["GET", "POST"])
@require_auth
def handle_rent():
    date_str = request.args.get("date") or today_tw()
    conn = get_db_connection()
    try:
        cursor = conn.cursor()
        if request.method == "GET":
            row = cursor.execute("SELECT * FROM rent WHERE date=?", (date_str,)).fetchone()
            if row:
                return jsonify(dict(row))
            return jsonify({
                "amount": 0, "rent_base": 0, "cleaning": 0, "electricity": 0, "other": 0,
                "rent_base_source": "owner", "cleaning_source": "owner", "electricity_source": "owner", "other_source": "owner",
            })
        guard = _day_write_guard(cursor, date_str, require_open_today=True)
        if guard:
            return jsonify({"message": guard}), 409
        data = request.get_json() or {}
        try:
            rb = max(0, float(data.get("rent_base", 0) or 0))
            cl = max(0, float(data.get("cleaning", 0) or 0))
            el = max(0, float(data.get("electricity", 0) or 0))
            ot = max(0, float(data.get("other", 0) or 0))
        except (TypeError, ValueError):
            return jsonify({"message": "費用格式錯誤"}), 400
        allowed_sources = {"cash", "linepay", "transfer", "owner"}
        rbs = str(data.get("rent_base_source") or "owner").lower()
        cls = str(data.get("cleaning_source") or "owner").lower()
        els = str(data.get("electricity_source") or "owner").lower()
        ots = str(data.get("other_source") or "owner").lower()
        if any(x not in allowed_sources for x in [rbs, cls, els, ots]):
            return jsonify({"message": "費用付款來源格式錯誤"}), 400
        total = rb + cl + el + ot
        cursor.execute("""
            INSERT INTO rent (date, amount, rent_base, cleaning, electricity, other,
                              rent_base_source, cleaning_source, electricity_source, other_source)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(date) DO UPDATE SET
              amount=excluded.amount, rent_base=excluded.rent_base, cleaning=excluded.cleaning,
              electricity=excluded.electricity, other=excluded.other,
              rent_base_source=excluded.rent_base_source, cleaning_source=excluded.cleaning_source,
              electricity_source=excluded.electricity_source, other_source=excluded.other_source
        """, (date_str, total, rb, cl, el, ot, rbs, cls, els, ots))
        cash_out = sum(amount for amount, source in [(rb,rbs),(cl,cls),(el,els),(ot,ots)] if source == "cash")
        log_action(cursor, "費用支出", f"{date_str}；總計 ${total:g}；收銀現金支出 ${cash_out:g}")
        conn.commit()
        return jsonify({"status": "success"})
    finally:
        conn.close()


@app.route("/api/orders", methods=["GET", "POST", "DELETE"])
@require_auth
def handle_orders():
    conn = get_db_connection()
    try:
        cursor = conn.cursor()
        if request.method == "GET":
            date_str = request.args.get("date") or today_tw()
            orders = cursor.execute("""
                SELECT id, date AS sale_date, created_at, payment_method,
                       total_revenue AS total_amount, partner_name, is_void, voided_at, voided_by,
                       edited_at, edited_by, edit_count
                FROM orders WHERE date=? ORDER BY id DESC
            """, (date_str,)).fetchall()
            result = []
            for order in orders:
                d = dict(order)
                d["invoice_no"] = f"ORD-{order['id']:05d}"
                d["items"] = [dict(i) for i in cursor.execute(
                    "SELECT product_id, name, quantity, price_at_sale, cost_at_sale, variant_id, track_stock_at_sale FROM order_items WHERE order_id=?",
                    (order["id"],),
                ).fetchall()]
                result.append(d)
            return jsonify(result)

        if request.method == "POST":
            data = request.get_json() or {}
            items = data.get("items", [])
            if not items:
                return jsonify({"message": "購物車是空的"}), 400
            sale_date = str(data.get("date") or today_tw())
            try:
                datetime.strptime(sale_date, "%Y-%m-%d")
            except ValueError:
                return jsonify({"message": "結帳日期格式錯誤"}), 400
            guard = _day_write_guard(cursor, sale_date, require_open_today=True)
            if guard:
                return jsonify({"message": guard}), 409
            payment_method = str(data.get("payment_method") or "現金結帳").strip()
            if not cursor.execute("SELECT 1 FROM payment_methods WHERE name=?", (payment_method,)).fetchone():
                return jsonify({"message": "付款方式不存在，請重新選擇"}), 400
            partner_name = session.get("partner_name", "")
            created_at = now_tw().strftime("%Y-%m-%d %H:%M:%S")
            total_revenue = 0.0
            total_cost = 0.0

            conn.execute("BEGIN IMMEDIATE")
            try:
                normalized = []
                for raw in items:
                    pid = int(raw.get("product_id") or 0)
                    qty = int(raw.get("quantity") or 0)
                    if qty <= 0:
                        raise ValueError("商品數量必須大於 0")
                    price_at_sale = float(raw.get("price_at_sale") or 0)
                    if price_at_sale < 0:
                        raise ValueError("售價不可為負數")
                    prod = cursor.execute(
                        "SELECT id, name, cost, stock, track_stock FROM products WHERE id=?",
                        (pid,),
                    ).fetchone()
                    if not prod:
                        raise ValueError("找不到商品，請重新整理後再結帳")
                    vid = raw.get("variant_id")
                    vid = int(vid) if vid not in (None, "", "null") else None
                    track_stock = bool(prod["track_stock"])
                    if track_stock:
                        variant_count = cursor.execute(
                            "SELECT COUNT(*) AS c FROM product_variants WHERE product_id=?",
                            (pid,),
                        ).fetchone()["c"]
                        if variant_count > 0:
                            if not vid:
                                raise ValueError(f"【{prod['name']}】請先選擇正確型號")
                            updated = cursor.execute(
                                "UPDATE product_variants SET stock=stock-? WHERE id=? AND product_id=? AND stock>=?",
                                (qty, vid, pid, qty),
                            )
                            if updated.rowcount != 1:
                                v = cursor.execute("SELECT name, stock FROM product_variants WHERE id=?", (vid,)).fetchone()
                                v_name = v["name"] if v else "細項"
                                v_stock = v["stock"] if v else 0
                                raise ValueError(f"【{prod['name']} ({v_name})】庫存不足，剩餘 {v_stock} 件")
                            parent_updated = cursor.execute(
                                "UPDATE products SET stock=stock-? WHERE id=? AND stock>=?",
                                (qty, pid, qty),
                            )
                            if parent_updated.rowcount != 1:
                                raise ValueError(f"【{prod['name']}】總庫存資料異常，請先檢查庫存")
                        else:
                            updated = cursor.execute(
                                "UPDATE products SET stock=stock-? WHERE id=? AND stock>=?",
                                (qty, pid, qty),
                            )
                            if updated.rowcount != 1:
                                latest = cursor.execute("SELECT stock FROM products WHERE id=?", (pid,)).fetchone()
                                raise ValueError(f"【{prod['name']}】庫存不足，剩餘 {latest['stock'] if latest else 0} 件")

                    item_name = str(raw.get("name") or prod["name"]).strip()
                    cost = float(prod["cost"] or 0)
                    total_revenue += price_at_sale * qty
                    total_cost += cost * qty
                    normalized.append((pid, item_name, qty, price_at_sale, cost, vid, 1 if track_stock else 0))

                cursor.execute(
                    "INSERT INTO orders (date, created_at, payment_method, total_revenue, total_cost, partner_name, is_void) VALUES (?, ?, ?, ?, ?, ?, 0)",
                    (sale_date, created_at, payment_method, total_revenue, total_cost, partner_name),
                )
                order_id = cursor.lastrowid
                cursor.executemany(
                    "INSERT INTO order_items (order_id, product_id, name, quantity, price_at_sale, cost_at_sale, variant_id, track_stock_at_sale) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                    [(order_id, *row) for row in normalized],
                )
                log_action(cursor, "結帳", f"ORD-{order_id:05d}；${total_revenue:g}")
                conn.commit()
                return jsonify({"status": "success", "invoice_no": f"ORD-{order_id:05d}"})
            except (ValueError, TypeError) as e:
                conn.rollback()
                return jsonify({"message": str(e)}), 400
            except Exception:
                conn.rollback()
                raise
        order_id = request.args.get("id")
        conn.execute("BEGIN IMMEDIATE")
        order = cursor.execute("SELECT is_void, date FROM orders WHERE id=?", (order_id,)).fetchone()
        if not order:
            conn.rollback()
            return jsonify({"message": "找不到單據"}), 404
        if order["is_void"]:
            conn.rollback()
            return jsonify({"message": "此單據已作廢"}), 409
        guard = _day_write_guard(cursor, order["date"])
        if guard:
            conn.rollback()
            return jsonify({"message": guard}), 409
        items = cursor.execute(
            "SELECT product_id, quantity, variant_id, track_stock_at_sale FROM order_items WHERE order_id=?",
            (order_id,),
        ).fetchall()
        for item in items:
            if item["track_stock_at_sale"]:
                cursor.execute("UPDATE products SET stock=stock+? WHERE id=?", (item["quantity"], item["product_id"]))
                if item["variant_id"]:
                    cursor.execute("UPDATE product_variants SET stock=stock+? WHERE id=?", (item["quantity"], item["variant_id"]))
        cursor.execute(
            "UPDATE orders SET is_void=1, voided_at=?, voided_by=? WHERE id=?",
            (now_tw().strftime("%Y-%m-%d %H:%M:%S"), current_actor(), order_id),
        )
        log_action(cursor, "作廢銷售單", f"ORD-{int(order_id):05d}")
        conn.commit()
        return jsonify({"status": "success"})
    finally:
        conn.close()


@app.route("/api/orders/edit", methods=["POST"])
@require_auth
def edit_order():
    data = request.get_json() or {}
    order_id = int(data.get("order_id") or 0)
    items = data.get("items", [])
    payment_method = str(data.get("payment_method") or "").strip()
    if not order_id or not items:
        return jsonify({"message": "缺少單據或商品資料"}), 400

    conn = get_db_connection()
    try:
        cursor = conn.cursor()
        conn.execute("BEGIN IMMEDIATE")
        order = cursor.execute("SELECT * FROM orders WHERE id=?", (order_id,)).fetchone()
        if not order:
            conn.rollback()
            return jsonify({"message": "找不到單據"}), 404
        if order["is_void"]:
            conn.rollback()
            return jsonify({"message": "已作廢單據不可編輯"}), 409
        guard = _day_write_guard(cursor, order["date"])
        if guard:
            conn.rollback()
            return jsonify({"message": guard}), 409
        if not cursor.execute("SELECT 1 FROM payment_methods WHERE name=?", (payment_method,)).fetchone():
            conn.rollback()
            return jsonify({"message": "付款方式不存在"}), 400

        # 先把原單庫存完整退回；若新單任何一步失敗，整個交易會 rollback。
        old_items = cursor.execute(
            "SELECT product_id, quantity, variant_id, track_stock_at_sale FROM order_items WHERE order_id=?",
            (order_id,),
        ).fetchall()
        for item in old_items:
            if item["track_stock_at_sale"]:
                cursor.execute("UPDATE products SET stock=stock+? WHERE id=?", (item["quantity"], item["product_id"]))
                if item["variant_id"]:
                    cursor.execute("UPDATE product_variants SET stock=stock+? WHERE id=?", (item["quantity"], item["variant_id"]))

        normalized = []
        total_revenue = 0.0
        total_cost = 0.0
        for raw in items:
            pid = int(raw.get("product_id") or 0)
            qty = int(raw.get("quantity") or 0)
            price_at_sale = float(raw.get("price_at_sale") or 0)
            if qty <= 0:
                raise ValueError("商品數量必須大於 0")
            if price_at_sale < 0:
                raise ValueError("售價不可為負數")
            prod = cursor.execute(
                "SELECT id, name, cost, stock, track_stock FROM products WHERE id=?",
                (pid,),
            ).fetchone()
            if not prod:
                raise ValueError("找不到商品，請重新整理後再編輯")
            vid = raw.get("variant_id")
            vid = int(vid) if vid not in (None, "", "null") else None
            track_stock = bool(prod["track_stock"])
            variant_name = ""

            if track_stock:
                variant_count = cursor.execute(
                    "SELECT COUNT(*) AS c FROM product_variants WHERE product_id=?",
                    (pid,),
                ).fetchone()["c"]
                if variant_count > 0:
                    if not vid:
                        raise ValueError(f"【{prod['name']}】請選擇型號")
                    v = cursor.execute(
                        "SELECT name, stock FROM product_variants WHERE id=? AND product_id=?",
                        (vid, pid),
                    ).fetchone()
                    if not v:
                        raise ValueError(f"【{prod['name']}】找不到指定型號")
                    updated = cursor.execute(
                        "UPDATE product_variants SET stock=stock-? WHERE id=? AND product_id=? AND stock>=?",
                        (qty, vid, pid, qty),
                    )
                    if updated.rowcount != 1:
                        raise ValueError(f"【{prod['name']} ({v['name']})】庫存不足，剩餘 {v['stock']} 件")
                    parent_updated = cursor.execute(
                        "UPDATE products SET stock=stock-? WHERE id=? AND stock>=?",
                        (qty, pid, qty),
                    )
                    if parent_updated.rowcount != 1:
                        raise ValueError(f"【{prod['name']}】總庫存資料異常")
                    variant_name = v["name"]
                else:
                    updated = cursor.execute(
                        "UPDATE products SET stock=stock-? WHERE id=? AND stock>=?",
                        (qty, pid, qty),
                    )
                    if updated.rowcount != 1:
                        latest = cursor.execute("SELECT stock FROM products WHERE id=?", (pid,)).fetchone()
                        raise ValueError(f"【{prod['name']}】庫存不足，剩餘 {latest['stock'] if latest else 0} 件")

            item_name = prod["name"] + (f" ({variant_name})" if variant_name else "")
            cost = float(prod["cost"] or 0)
            total_revenue += price_at_sale * qty
            total_cost += cost * qty
            normalized.append((pid, item_name, qty, price_at_sale, cost, vid, 1 if track_stock else 0))

        cursor.execute("DELETE FROM order_items WHERE order_id=?", (order_id,))
        cursor.executemany(
            "INSERT INTO order_items (order_id, product_id, name, quantity, price_at_sale, cost_at_sale, variant_id, track_stock_at_sale) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            [(order_id, *row) for row in normalized],
        )
        cursor.execute(
            """
            UPDATE orders
            SET payment_method=?, total_revenue=?, total_cost=?, edited_at=?, edited_by=?, edit_count=COALESCE(edit_count,0)+1
            WHERE id=?
            """,
            (
                payment_method, total_revenue, total_cost,
                now_tw().strftime("%Y-%m-%d %H:%M:%S"), session.get("partner_name", ""), order_id,
            ),
        )
        log_action(cursor, "編輯銷售單", f"ORD-{order_id:05d}；修改後 ${total_revenue:g}")
        conn.commit()
        return jsonify({"status": "success", "total_revenue": total_revenue})
    except (TypeError, ValueError) as e:
        if conn.in_transaction:
            conn.rollback()
        return jsonify({"message": str(e)}), 400
    except Exception:
        if conn.in_transaction:
            conn.rollback()
        raise
    finally:
        conn.close()


@app.route("/api/orders/update_date", methods=["POST"])
@require_auth
def update_order_date():
    data = request.get_json() or {}
    order_id = data.get("order_id")
    new_date = str(data.get("new_date", "")).strip()
    try:
        datetime.strptime(new_date, "%Y-%m-%d")
    except ValueError:
        return jsonify({"message": "日期格式錯誤"}), 400
    conn = get_db_connection()
    try:
        cursor = conn.cursor()
        order = cursor.execute("SELECT date, is_void FROM orders WHERE id=?", (order_id,)).fetchone()
        if not order:
            return jsonify({"message": "找不到單據"}), 404
        if order["is_void"]:
            return jsonify({"message": "已作廢單據不可修改日期"}), 409
        for day in {order["date"], new_date}:
            guard = _day_write_guard(cursor, day, require_open_today=(day == new_date))
            if guard:
                return jsonify({"message": guard}), 409
        cursor.execute(
            "UPDATE orders SET date=?, edited_at=?, edited_by=?, edit_count=COALESCE(edit_count,0)+1 WHERE id=? AND is_void=0",
            (new_date, now_tw().strftime("%Y-%m-%d %H:%M:%S"), current_actor(), order_id),
        )
        log_action(cursor, "修改銷售日期", f"ORD-{int(order_id):05d} → {new_date}")
        conn.commit()
        return jsonify({"status": "success"})
    finally:
        conn.close()


@app.route("/api/orders/daily", methods=["DELETE"])
@require_auth
def void_daily_orders():
    date_str = request.args.get("date")
    if not date_str:
        return jsonify({"message": "缺少日期"}), 400
    conn = get_db_connection()
    try:
        cursor = conn.cursor()
        guard = _day_write_guard(cursor, date_str)
        if guard:
            return jsonify({"message": guard}), 409
        conn.execute("BEGIN IMMEDIATE")
        orders = cursor.execute("SELECT id FROM orders WHERE date=? AND is_void=0", (date_str,)).fetchall()
        for row in orders:
            items = cursor.execute(
                "SELECT product_id, quantity, variant_id, track_stock_at_sale FROM order_items WHERE order_id=?",
                (row["id"],),
            ).fetchall()
            for item in items:
                if item["track_stock_at_sale"]:
                    cursor.execute("UPDATE products SET stock=stock+? WHERE id=?", (item["quantity"], item["product_id"]))
                    if item["variant_id"]:
                        cursor.execute("UPDATE product_variants SET stock=stock+? WHERE id=?", (item["quantity"], item["variant_id"]))
            cursor.execute(
                "UPDATE orders SET is_void=1, voided_at=?, voided_by=? WHERE id=?",
                (now_tw().strftime("%Y-%m-%d %H:%M:%S"), session.get("partner_name", ""), row["id"]),
            )
        log_action(cursor, "批量作廢銷售單", f"{date_str}；共 {len(orders)} 筆")
        conn.commit()
        return jsonify({"status": "success", "voided_count": len(orders)})
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


@app.route("/api/audit_logs", methods=["GET"])
@require_auth
def audit_logs_api():
    date_str = request.args.get("date") or today_tw()
    conn = get_db_connection()
    try:
        rows = conn.execute(
            "SELECT id, created_at, partner_name, action, detail FROM audit_logs WHERE created_at LIKE ? ORDER BY id DESC LIMIT 500",
            (f"{date_str}%",),
        ).fetchall()
        return jsonify([dict(r) for r in rows])
    finally:
        conn.close()


@app.route("/api/report_target", methods=["GET", "POST"])
@require_auth
def report_target_api():
    data = request.get_json(silent=True) or {}
    mode = str((data.get("mode") if request.method == "POST" else request.args.get("mode")) or "monthly").strip()
    period = str((data.get("period") if request.method == "POST" else request.args.get("period")) or "").strip()
    if mode not in {"monthly", "yearly"}:
        return jsonify({"message": "目標類型只支援月目標或年目標"}), 400
    try:
        if mode == "monthly":
            datetime.strptime(period, "%Y-%m")
        else:
            if len(period) != 4:
                raise ValueError
            year = int(period)
            if year < 2000 or year > 2200:
                raise ValueError
    except (ValueError, TypeError):
        return jsonify({"message": "目標期間格式錯誤"}), 400

    conn = get_db_connection()
    try:
        cursor = conn.cursor()
        if request.method == "GET":
            row = cursor.execute(
                "SELECT period, target_amount, updated_at, updated_by FROM report_targets WHERE period=?",
                (period,),
            ).fetchone()
            if row:
                return jsonify(dict(row))
            return jsonify({"period": period, "target_amount": 0, "updated_at": None, "updated_by": None})

        try:
            amount = max(0.0, float(data.get("target_amount", 0) or 0))
        except (TypeError, ValueError):
            return jsonify({"message": "目標業績格式錯誤"}), 400
        now_str = now_tw().strftime("%Y-%m-%d %H:%M:%S")
        actor = current_actor()
        cursor.execute("""
            INSERT INTO report_targets (period, target_amount, updated_at, updated_by)
            VALUES (?, ?, ?, ?)
            ON CONFLICT(period) DO UPDATE SET
                target_amount=excluded.target_amount,
                updated_at=excluded.updated_at,
                updated_by=excluded.updated_by
        """, (period, amount, now_str, actor))
        label = "月目標" if mode == "monthly" else "年目標"
        log_action(cursor, f"設定{label}", f"{period}；${amount:g}")
        conn.commit()
        return jsonify({"status": "success", "period": period, "target_amount": amount, "updated_at": now_str, "updated_by": actor})
    finally:
        conn.close()


def _target_progress(cursor, mode, target, actual_revenue):
    if mode not in {"monthly", "yearly"}:
        return None
    row = cursor.execute(
        "SELECT target_amount, updated_at, updated_by FROM report_targets WHERE period=?",
        (target,),
    ).fetchone()
    target_amount = float(row["target_amount"] or 0) if row else 0.0
    now_date = now_tw().date()

    if mode == "monthly":
        year, month = map(int, target.split("-"))
        total_days = calendar.monthrange(year, month)[1]
        start_date = datetime(year, month, 1).date()
        end_date = datetime(year, month, total_days).date()
        if now_date < start_date:
            elapsed_days, remaining_days = 0, total_days
        elif now_date > end_date:
            elapsed_days, remaining_days = total_days, 0
        else:
            elapsed_days = now_date.day
            remaining_days = total_days - now_date.day + 1
    else:
        year = int(target)
        total_days = 366 if calendar.isleap(year) else 365
        start_date = datetime(year, 1, 1).date()
        end_date = datetime(year, 12, 31).date()
        if now_date < start_date:
            elapsed_days, remaining_days = 0, total_days
        elif now_date > end_date:
            elapsed_days, remaining_days = total_days, 0
        else:
            elapsed_days = int(now_date.strftime("%j"))
            remaining_days = total_days - elapsed_days + 1

    expected_revenue = target_amount * (elapsed_days / total_days) if target_amount > 0 and total_days else 0.0
    difference = actual_revenue - target_amount
    gap = max(target_amount - actual_revenue, 0.0)
    achievement_rate = (actual_revenue / target_amount * 100.0) if target_amount > 0 else 0.0
    expected_progress_rate = (elapsed_days / total_days * 100.0) if total_days else 0.0
    pace_difference = actual_revenue - expected_revenue
    needed_per_day = (gap / remaining_days) if target_amount > 0 and remaining_days > 0 else 0.0
    return {
        "target_amount": target_amount,
        "actual_revenue": float(actual_revenue or 0),
        "difference": difference,
        "gap": gap,
        "achievement_rate": achievement_rate,
        "expected_revenue": expected_revenue,
        "expected_progress_rate": expected_progress_rate,
        "pace_difference": pace_difference,
        "remaining_days": remaining_days,
        "needed_per_day": needed_per_day,
        "updated_at": row["updated_at"] if row else None,
        "updated_by": row["updated_by"] if row else None,
    }


@app.route("/api/report", methods=["GET"])
@require_auth
def handle_report():
    mode = request.args.get("mode", "daily")
    if mode not in {"daily", "monthly", "yearly"}:
        return jsonify({"message": "報表類型錯誤"}), 400

    if mode == "daily":
        target = request.args.get("date") or now_tw().strftime("%Y-%m-%d")
        try:
            datetime.strptime(target, "%Y-%m-%d")
        except ValueError:
            return jsonify({"message": "日期格式錯誤"}), 400
        query_date, op = target, "="
    elif mode == "monthly":
        target = request.args.get("month") or now_tw().strftime("%Y-%m")
        try:
            datetime.strptime(target, "%Y-%m")
        except ValueError:
            return jsonify({"message": "月份格式錯誤"}), 400
        query_date, op = f"{target}-%", "LIKE"
    else:
        target = request.args.get("year") or now_tw().strftime("%Y")
        try:
            if len(target) != 4:
                raise ValueError
            year_int = int(target)
            if year_int < 2000 or year_int > 2200:
                raise ValueError
        except (ValueError, TypeError):
            return jsonify({"message": "年份格式錯誤"}), 400
        query_date, op = f"{target}-%", "LIKE"

    conn = get_db_connection()
    try:
        cursor = conn.cursor()
        summary = cursor.execute(
            f"SELECT SUM(total_revenue) AS rev, SUM(total_cost) AS cos, COUNT(*) AS orders_cnt FROM orders WHERE date {op} ? AND is_void=0",
            (query_date,),
        ).fetchone()
        rent_row = cursor.execute(
            f"SELECT SUM(amount) AS amount, SUM(rent_base) AS rent_base, SUM(cleaning) AS cleaning, SUM(electricity) AS electricity, SUM(other) AS other FROM rent WHERE date {op} ?",
            (query_date,),
        ).fetchone()
        details = cursor.execute(f"""
            SELECT oi.name, oi.product_id, SUM(oi.quantity) AS quantity,
                   SUM(oi.quantity * oi.price_at_sale) AS total_sale,
                   SUM(oi.quantity * oi.cost_at_sale) AS total_cost
            FROM order_items oi
            JOIN orders o ON oi.order_id=o.id
            WHERE o.date {op} ? AND o.is_void=0
            GROUP BY oi.name, oi.product_id
            ORDER BY MIN(oi.id) ASC
        """, (query_date,)).fetchall()
        pm_rows = cursor.execute(
            f"SELECT payment_method AS name, SUM(total_revenue) AS total FROM orders WHERE date {op} ? AND is_void=0 GROUP BY payment_method",
            (query_date,),
        ).fetchall()

        if mode == "daily":
            audit_like, order_where, restock_like = f"{target}%", target, f"{target}%"
            partner_names = {r["partner_name"] for r in cursor.execute(
                "SELECT DISTINCT partner_name FROM audit_logs WHERE created_at LIKE ? AND partner_name!=''", (audit_like,)
            ).fetchall()}
            partner_names.update(r["partner_name"] for r in cursor.execute(
                "SELECT DISTINCT partner_name FROM orders WHERE date=? AND partner_name!=''", (order_where,)
            ).fetchall())
            partner_names.update(r["partner_name"] for r in cursor.execute(
                "SELECT DISTINCT partner_name FROM restock_logs WHERE date LIKE ? AND partner_name!=''", (restock_like,)
            ).fetchall())
        else:
            prefix = f"{target}-%"
            partner_names = {r["partner_name"] for r in cursor.execute(
                "SELECT DISTINCT partner_name FROM audit_logs WHERE created_at LIKE ? AND partner_name!=''", (prefix,)
            ).fetchall()}
            partner_names.update(r["partner_name"] for r in cursor.execute(
                "SELECT DISTINCT partner_name FROM orders WHERE date LIKE ? AND partner_name!=''", (prefix,)
            ).fetchall())
            partner_names.update(r["partner_name"] for r in cursor.execute(
                "SELECT DISTINCT partner_name FROM restock_logs WHERE date LIKE ? AND partner_name!=''", (prefix,)
            ).fetchall())
        partner_names = sorted(partner_names)

        main_cats = cursor.execute(f"""
            SELECT p.name, SUM(oi.quantity) AS qty
            FROM order_items oi
            JOIN orders o ON oi.order_id=o.id
            LEFT JOIN products p ON p.id=oi.product_id
            WHERE o.date {op} ? AND o.is_void=0
            GROUP BY oi.product_id, p.name
            HAVING SUM(oi.quantity) > 0
            ORDER BY MIN(oi.id) ASC
        """, (query_date,)).fetchall()

        revenue = float(summary["rev"] or 0)
        cost = float(summary["cos"] or 0)
        rent = float(rent_row["amount"] or 0)
        total_qty = sum(int(r["quantity"] or 0) for r in details)
        top_products = []
        if mode in {"monthly", "yearly"}:
            top_products = sorted(
                [dict(r) for r in details],
                key=lambda x: (float(x.get("total_sale") or 0), int(x.get("quantity") or 0)),
                reverse=True,
            )[:10]

        daily_breakdown = []
        best_day = None
        open_days = 0
        avg_daily_revenue = 0.0
        if mode == "monthly":
            sales_by_day = {
                r["date"]: r for r in cursor.execute("""
                    SELECT o.date, SUM(o.total_revenue) AS revenue, SUM(o.total_cost) AS cost, COUNT(*) AS orders_count
                    FROM orders o
                    WHERE o.date LIKE ? AND o.is_void=0
                    GROUP BY o.date ORDER BY o.date ASC
                """, (query_date,)).fetchall()
            }
            expense_by_day = {
                r["date"]: float(r["amount"] or 0)
                for r in cursor.execute("SELECT date, amount FROM rent WHERE date LIKE ? ORDER BY date ASC", (query_date,)).fetchall()
            }
            all_dates = sorted(set(sales_by_day) | set(expense_by_day))
            for day in all_dates:
                r = sales_by_day.get(day)
                day_rev = float(r["revenue"] or 0) if r else 0.0
                day_cost = float(r["cost"] or 0) if r else 0.0
                day_orders = int(r["orders_count"] or 0) if r else 0
                day_exp = expense_by_day.get(day, 0.0)
                daily_breakdown.append({
                    "date": day,
                    "revenue": day_rev,
                    "cost": day_cost,
                    "expenses": day_exp,
                    "profit": day_rev - day_cost - day_exp,
                    "orders_count": day_orders,
                })
            sales_days = [row for row in daily_breakdown if row["orders_count"] > 0]
            open_days = len(sales_days)
            avg_daily_revenue = revenue / open_days if open_days else 0.0
            if sales_days:
                best_day = max(sales_days, key=lambda x: x["revenue"])

        monthly_breakdown = []
        active_months = 0
        avg_monthly_revenue = 0.0
        avg_monthly_profit = 0.0
        best_month = None
        worst_month = None
        previous_year_revenue = 0.0
        yoy_growth = None
        if mode == "yearly":
            sales_by_month = {
                r["month"]: r for r in cursor.execute("""
                    SELECT substr(date,1,7) AS month, SUM(total_revenue) AS revenue,
                           SUM(total_cost) AS cost, COUNT(*) AS orders_count
                    FROM orders
                    WHERE date LIKE ? AND is_void=0
                    GROUP BY substr(date,1,7) ORDER BY month ASC
                """, (query_date,)).fetchall()
            }
            expense_by_month = {
                r["month"]: float(r["amount"] or 0)
                for r in cursor.execute("""
                    SELECT substr(date,1,7) AS month, SUM(amount) AS amount
                    FROM rent WHERE date LIKE ? GROUP BY substr(date,1,7) ORDER BY month ASC
                """, (query_date,)).fetchall()
            }
            for month_num in range(1, 13):
                key = f"{target}-{month_num:02d}"
                r = sales_by_month.get(key)
                m_rev = float(r["revenue"] or 0) if r else 0.0
                m_cost = float(r["cost"] or 0) if r else 0.0
                m_orders = int(r["orders_count"] or 0) if r else 0
                m_exp = expense_by_month.get(key, 0.0)
                monthly_breakdown.append({
                    "month": key,
                    "revenue": m_rev,
                    "cost": m_cost,
                    "expenses": m_exp,
                    "profit": m_rev - m_cost - m_exp,
                    "orders_count": m_orders,
                })
            sales_months = [row for row in monthly_breakdown if row["orders_count"] > 0]
            active_months = len(sales_months)
            avg_monthly_revenue = revenue / active_months if active_months else 0.0
            avg_monthly_profit = sum(row["profit"] for row in sales_months) / active_months if active_months else 0.0
            if sales_months:
                best_month = max(sales_months, key=lambda x: x["revenue"])
                worst_month = min(sales_months, key=lambda x: x["revenue"])
            prev_year = str(int(target) - 1)
            current_year = now_tw().year
            if int(target) == current_year:
                today = now_tw().date()
                try:
                    prev_cutoff = datetime(int(prev_year), today.month, today.day).strftime("%Y-%m-%d")
                except ValueError:
                    prev_cutoff = datetime(int(prev_year), today.month, 28).strftime("%Y-%m-%d")
                prev = cursor.execute(
                    "SELECT COALESCE(SUM(total_revenue),0) AS revenue FROM orders WHERE date>=? AND date<=? AND is_void=0",
                    (f"{prev_year}-01-01", prev_cutoff),
                ).fetchone()
            else:
                prev = cursor.execute(
                    "SELECT COALESCE(SUM(total_revenue),0) AS revenue FROM orders WHERE date LIKE ? AND is_void=0",
                    (f"{prev_year}-%",),
                ).fetchone()
            previous_year_revenue = float(prev["revenue"] or 0)
            if previous_year_revenue > 0:
                yoy_growth = (revenue - previous_year_revenue) / previous_year_revenue * 100.0

        expenses = {
            "rent_base": float(rent_row["rent_base"] or 0),
            "cleaning": float(rent_row["cleaning"] or 0),
            "electricity": float(rent_row["electricity"] or 0),
            "other": float(rent_row["other"] or 0),
            "total": rent,
        }
        business_day = None
        if mode == "daily":
            bd = _business_day_row(cursor, target)
            if bd:
                business_day = dict(bd)
                if business_day.get("payment_summary"):
                    try:
                        business_day["payment_summary"] = json.loads(business_day["payment_summary"])
                    except Exception:
                        business_day["payment_summary"] = {}

        target_progress = _target_progress(cursor, mode, target, revenue)
        return jsonify({
            "mode": mode,
            "period": target,
            "revenue": revenue,
            "cost": cost,
            "rent": rent,
            "expenses": expenses,
            "net_profit": revenue - cost - rent,
            "orders_count": int(summary["orders_cnt"] or 0),
            "total_qty": total_qty,
            "details": [dict(r) for r in details],
            "main_categories": [dict(r) for r in main_cats],
            "payments": {r["name"]: float(r["total"] or 0) for r in pm_rows},
            "partners": partner_names,
            "daily_breakdown": daily_breakdown,
            "top_products": top_products,
            "open_days": open_days,
            "avg_daily_revenue": avg_daily_revenue,
            "best_day": best_day,
            "monthly_breakdown": monthly_breakdown,
            "active_months": active_months,
            "avg_monthly_revenue": avg_monthly_revenue,
            "avg_monthly_profit": avg_monthly_profit,
            "best_month": best_month,
            "worst_month": worst_month,
            "previous_year_revenue": previous_year_revenue,
            "yoy_growth": yoy_growth,
            "target": target_progress,
            "business_day": business_day,
        })
    finally:
        conn.close()


@app.route("/")
def index():
    return render_template("index.html")


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 8888))
    app.run(host="0.0.0.0", port=port)
