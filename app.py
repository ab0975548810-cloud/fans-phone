from flask import Flask, render_template, jsonify, request, session
import sqlite3
import os
import shutil
import threading
import time
import secrets
from datetime import datetime
from functools import wraps
from zoneinfo import ZoneInfo
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
TW_TZ = ZoneInfo("Asia/Taipei")
DB_NAME = "pos.db"


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
    SESSION_COOKIE_SECURE=os.environ.get("SESSION_COOKIE_SECURE", "0") == "1",
)


@app.after_request
def add_header(response):
    response.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, max-age=0"
    response.headers["Pragma"] = "no-cache"
    response.headers["Expires"] = "-1"
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "SAMEORIGIN"
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


def require_auth(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not session.get("partner_id"):
            return jsonify({"message": "⛔ 登入已失效，請重新登入"}), 401
        return f(*args, **kwargs)
    return decorated_function


def is_manager():
    return bool(session.get("manager_unlocked"))


def require_manager():
    if not is_manager():
        return jsonify({"message": "⛔ 權限不足，請先解鎖主管模式"}), 403
    return None


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
                other REAL DEFAULT 0
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
                voided_by TEXT DEFAULT NULL
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
                is_deleted INTEGER DEFAULT 0
            )
        """)

        # 兼容舊資料庫欄位；母版新建 DB 時不會用到，但可避免誤放舊 DB 直接炸掉。
        product_cols = {r[1] for r in cursor.execute("PRAGMA table_info(products)").fetchall()}
        if "track_stock" not in product_cols:
            cursor.execute("ALTER TABLE products ADD COLUMN track_stock INTEGER NOT NULL DEFAULT 1")
        if "price_mode" not in product_cols:
            cursor.execute("ALTER TABLE products ADD COLUMN price_mode TEXT NOT NULL DEFAULT 'fixed'")

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


def start_auto_backup():
    base_dir = get_db_dir()
    backup_dir = os.path.join(base_dir, "POS_Backup")
    os.makedirs(backup_dir, exist_ok=True)
    while True:
        time.sleep(3600)
        try:
            src = os.path.join(base_dir, DB_NAME)
            if os.path.exists(src):
                today_str = now_tw().strftime("%Y-%m-%d")
                dst = os.path.join(backup_dir, f"pos_{today_str}.db")
                shutil.copy2(src, dst)
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
    manager_pin = str(data.get("manager_pin", "")).strip()
    partner_name = str(data.get("partner_name", "")).strip()
    partner_pin = str(data.get("partner_pin", "")).strip()
    if not store_name or len(manager_pin) < 4 or not partner_name or len(partner_pin) < 4:
        return jsonify({"message": "店名必填，主管與員工 PIN 至少 4 碼"}), 400

    conn = get_db_connection()
    try:
        cursor = conn.cursor()
        if setup_completed(cursor):
            return jsonify({"message": "系統已完成初始化"}), 409
        set_setting(cursor, "store_name", store_name)
        set_setting(cursor, "report_title", "營業報表總覽")
        set_setting(cursor, "manager_pin_hash", generate_password_hash(manager_pin))
        set_setting(cursor, "setup_completed", "1")
        cursor.execute(
            "INSERT INTO partners (name, password_hash) VALUES (?, ?)",
            (partner_name, generate_password_hash(partner_pin)),
        )
        partner_id = cursor.lastrowid
        conn.commit()
        session.clear()
        session["partner_id"] = partner_id
        session["partner_name"] = partner_name
        session["manager_unlocked"] = True
        return jsonify({"status": "success", "partner": partner_name, "store_name": store_name})
    except sqlite3.IntegrityError:
        conn.rollback()
        return jsonify({"message": "員工名稱已存在"}), 400
    finally:
        conn.close()


@app.route("/api/auth/status", methods=["GET"])
def auth_status():
    return jsonify({
        "logged_in": bool(session.get("partner_id")),
        "partner": session.get("partner_name", ""),
        "manager": bool(session.get("manager_unlocked")),
    })


@app.route("/api/auth/login", methods=["POST"])
def auth_login():
    data = request.get_json() or {}
    partner_name = str(data.get("partner_name", "")).strip()
    pwd = str(data.get("password", "")).strip()
    conn = get_db_connection()
    try:
        cursor = conn.cursor()
        if not setup_completed(cursor):
            return jsonify({"message": "請先完成首次設定"}), 409
        user = cursor.execute(
            "SELECT id, name, password_hash FROM partners WHERE name=?",
            (partner_name,),
        ).fetchone()
        if user and user["password_hash"] and check_password_hash(user["password_hash"], pwd):
            session.clear()
            session["partner_id"] = user["id"]
            session["partner_name"] = user["name"]
            session["manager_unlocked"] = False
            return jsonify({"status": "success", "partner": user["name"]})
        return jsonify({"status": "error", "message": "PIN 錯誤"}), 401
    finally:
        conn.close()


@app.route("/api/auth/manager", methods=["POST"])
@require_auth
def auth_manager():
    data = request.get_json() or {}
    pwd = str(data.get("password", "")).strip()
    conn = get_db_connection()
    try:
        cursor = conn.cursor()
        pin_hash = get_setting(cursor, "manager_pin_hash", "")
        if pin_hash and check_password_hash(pin_hash, pwd):
            session["manager_unlocked"] = True
            return jsonify({"status": "success"})
        return jsonify({"status": "error", "message": "主管 PIN 錯誤"}), 401
    finally:
        conn.close()


@app.route("/api/auth/manager/lock", methods=["POST"])
@require_auth
def lock_manager():
    session["manager_unlocked"] = False
    return jsonify({"status": "success"})


@app.route("/api/auth/logout", methods=["POST"])
def auth_logout():
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

        denied = require_manager()
        if denied:
            return denied
        data = request.get_json() or {}
        store_name = str(data.get("store_name", "")).strip()
        report_title = str(data.get("report_title", "")).strip()
        new_manager_pin = str(data.get("new_manager_pin", "")).strip()
        if store_name:
            set_setting(cursor, "store_name", store_name)
        if report_title:
            set_setting(cursor, "report_title", report_title)
        if new_manager_pin:
            if len(new_manager_pin) < 4:
                return jsonify({"message": "主管 PIN 至少 4 碼"}), 400
            set_setting(cursor, "manager_pin_hash", generate_password_hash(new_manager_pin))
        conn.commit()
        return jsonify({"status": "success"})
    finally:
        conn.close()


@app.route("/api/payment_methods", methods=["GET", "POST", "DELETE"])
@require_auth
def payment_methods_api():
    conn = get_db_connection()
    try:
        cursor = conn.cursor()
        if request.method == "GET":
            rows = cursor.execute("SELECT id, name FROM payment_methods ORDER BY id ASC").fetchall()
            return jsonify([dict(r) for r in rows])

        denied = require_manager()
        if denied:
            return denied
        if request.method == "POST":
            name = str((request.get_json() or {}).get("name", "")).strip()
            if not name:
                return jsonify({"message": "付款方式不可空白"}), 400
            try:
                cursor.execute("INSERT INTO payment_methods (name) VALUES (?)", (name,))
                conn.commit()
                return jsonify({"status": "success"})
            except sqlite3.IntegrityError:
                return jsonify({"message": "付款方式已存在"}), 400
        method_id = request.args.get("id")
        if cursor.execute("SELECT COUNT(*) FROM payment_methods").fetchone()[0] <= 1:
            return jsonify({"message": "至少保留一種付款方式"}), 400
        cursor.execute("DELETE FROM payment_methods WHERE id=?", (method_id,))
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
        denied = require_manager()
        if denied:
            return denied

        if request.method == "POST":
            data = request.get_json() or {}
            pid = data.get("id")
            name = str(data.get("name", "")).strip()
            pin = str(data.get("password", "")).strip()
            if not name:
                return jsonify({"message": "員工名稱不可空白"}), 400
            try:
                if pid:
                    if pin:
                        if len(pin) < 4:
                            return jsonify({"message": "PIN 至少 4 碼"}), 400
                        cursor.execute(
                            "UPDATE partners SET name=?, password_hash=? WHERE id=?",
                            (name, generate_password_hash(pin), pid),
                        )
                    else:
                        cursor.execute("UPDATE partners SET name=? WHERE id=?", (name, pid))
                else:
                    if len(pin) < 4:
                        return jsonify({"message": "新增員工時 PIN 至少 4 碼"}), 400
                    cursor.execute(
                        "INSERT INTO partners (name, password_hash) VALUES (?, ?)",
                        (name, generate_password_hash(pin)),
                    )
                conn.commit()
                return jsonify({"status": "success"})
            except sqlite3.IntegrityError:
                return jsonify({"message": "員工名稱已存在"}), 400

        pid = request.args.get("id")
        if cursor.execute("SELECT COUNT(*) FROM partners").fetchone()[0] <= 1:
            return jsonify({"message": "至少保留一位員工"}), 400
        cursor.execute("DELETE FROM partners WHERE id=?", (pid,))
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

        denied = require_manager()
        if denied:
            return denied
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
            conn.commit()
            return jsonify({"status": "success"})

        pid = request.args.get("id")
        used = cursor.execute("SELECT 1 FROM order_items WHERE product_id=? LIMIT 1", (pid,)).fetchone()
        restocked = cursor.execute("SELECT 1 FROM restock_logs WHERE product_id=? LIMIT 1", (pid,)).fetchone()
        if used or restocked:
            return jsonify({"message": "此商品已有歷史單據或進貨紀錄，為保留資料完整性不可永久刪除；可改名或停用庫存追蹤。"}), 409
        cursor.execute("DELETE FROM product_variants WHERE product_id=?", (pid,))
        cursor.execute("DELETE FROM products WHERE id=?", (pid,))
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

        denied = require_manager()
        if denied:
            return denied
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
            conn.commit()
            return jsonify({"status": "success"})

        vid = request.args.get("id")
        cursor.execute("DELETE FROM product_variants WHERE id=? AND product_id=?", (vid, pid))
        recalc_product_stock(cursor, pid)
        conn.commit()
        return jsonify({"status": "success"})
    finally:
        conn.close()


@app.route("/api/variants/bulk", methods=["POST"])
@require_auth
def bulk_save_variants():
    denied = require_manager()
    if denied:
        return denied
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
        conn.commit()
        return jsonify({"status": "success"})
    finally:
        conn.close()


@app.route("/api/variants/copy", methods=["POST"])
@require_auth
def copy_variants():
    denied = require_manager()
    if denied:
        return denied
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
                    "items": [],
                })
                grouped[b_no]["items"].append({
                    "product_id": row["product_id"],
                    "variant_id": row["variant_id"],
                    "name": row["product_name"],
                    "quantity": row["quantity"],
                })
            return jsonify(list(grouped.values()))

        denied = require_manager()
        if denied:
            return denied

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


def _set_batch_deleted(cursor, batch_no, value):
    if batch_no.startswith("OLD-"):
        log_id = int(batch_no.split("-", 1)[1])
        cursor.execute("UPDATE restock_logs SET is_deleted=? WHERE id=?", (value, log_id))
    else:
        cursor.execute("UPDATE restock_logs SET is_deleted=? WHERE batch_no=?", (value, batch_no))


def _hard_delete_batch(cursor, batch_no):
    if batch_no.startswith("OLD-"):
        log_id = int(batch_no.split("-", 1)[1])
        cursor.execute("DELETE FROM restock_logs WHERE id=?", (log_id,))
    else:
        cursor.execute("DELETE FROM restock_logs WHERE batch_no=?", (batch_no,))


def _restock_action(conn, batch_nos, action):
    cursor = conn.cursor()
    conn.execute("BEGIN IMMEDIATE")
    try:
        for batch_no in batch_nos:
            rows = _batch_rows(cursor, batch_no)
            if not rows:
                continue
            current_deleted = rows[0]["is_deleted"]
            if action == "trash" and current_deleted == 0:
                for row in rows:
                    pid, vid, qty = row["product_id"], row["variant_id"], row["quantity"]
                    if not ensure_stock_can_remove(cursor, pid, vid, qty):
                        raise ValueError(f"{row['product_name']} 現有庫存不足，無法作廢這張進貨單")
                    if vid:
                        cursor.execute("UPDATE product_variants SET stock=stock-? WHERE id=?", (qty, vid))
                    cursor.execute("UPDATE products SET stock=stock-? WHERE id=?", (qty, pid))
                _set_batch_deleted(cursor, batch_no, 1)
            elif action == "recover" and current_deleted == 1:
                for row in rows:
                    pid, vid, qty = row["product_id"], row["variant_id"], row["quantity"]
                    if vid:
                        cursor.execute("UPDATE product_variants SET stock=stock+? WHERE id=?", (qty, vid))
                    cursor.execute("UPDATE products SET stock=stock+? WHERE id=?", (qty, pid))
                _set_batch_deleted(cursor, batch_no, 0)
            elif action == "hard_delete" and current_deleted == 1:
                _hard_delete_batch(cursor, batch_no)
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
    denied = require_manager()
    if denied:
        return denied
    data = request.get_json() or {}
    action = data.get("action")
    if action not in {"trash", "recover", "hard_delete"}:
        return jsonify({"message": "無效操作"}), 400
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
    denied = require_manager()
    if denied:
        return denied
    data = request.get_json() or {}
    batch_no = str(data.get("batch_no", ""))
    new_items = data.get("items", [])
    if not batch_no:
        return jsonify({"message": "缺少單號"}), 400
    conn = get_db_connection()
    try:
        cursor = conn.cursor()
        conn.execute("BEGIN IMMEDIATE")
        old_rows = _batch_rows(cursor, batch_no)
        if not old_rows or old_rows[0]["is_deleted"]:
            conn.rollback()
            return jsonify({"message": "找不到可編輯的進貨單"}), 404

        for row in old_rows:
            if not ensure_stock_can_remove(cursor, row["product_id"], row["variant_id"], row["quantity"]):
                conn.rollback()
                return jsonify({"message": f"{row['product_name']} 現有庫存不足，無法修改此進貨單"}), 409
            if row["variant_id"]:
                cursor.execute("UPDATE product_variants SET stock=stock-? WHERE id=?", (row["quantity"], row["variant_id"]))
            cursor.execute("UPDATE products SET stock=stock-? WHERE id=?", (row["quantity"], row["product_id"]))

        _hard_delete_batch(cursor, batch_no)
        if batch_no.startswith("OLD-"):
            batch_no = f"IN-{now_tw().strftime('%Y%m%d%H%M%S')}-{secrets.token_hex(2).upper()}"
        now_str = now_tw().strftime("%Y-%m-%d %H:%M:%S")
        partner = session.get("partner_name", "未知")

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
            cursor.execute(
                "INSERT INTO restock_logs (batch_no, date, partner_name, product_id, variant_id, product_name, quantity, cost, is_deleted) VALUES (?, ?, ?, ?, ?, ?, ?, ?, 0)",
                (batch_no, now_str, partner, pid, vid, full_name, qty, p["cost"]),
            )
        conn.commit()
        return jsonify({"status": "success"})
    except Exception:
        if conn.in_transaction:
            conn.rollback()
        raise
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
            return jsonify({"amount": 0, "rent_base": 0, "cleaning": 0, "electricity": 0, "other": 0})

        denied = require_manager()
        if denied:
            return denied
        data = request.get_json() or {}
        try:
            rb = max(0, float(data.get("rent_base", 0) or 0))
            cl = max(0, float(data.get("cleaning", 0) or 0))
            el = max(0, float(data.get("electricity", 0) or 0))
            ot = max(0, float(data.get("other", 0) or 0))
        except (TypeError, ValueError):
            return jsonify({"message": "費用格式錯誤"}), 400
        total = rb + cl + el + ot
        cursor.execute("""
            INSERT INTO rent (date, amount, rent_base, cleaning, electricity, other)
            VALUES (?, ?, ?, ?, ?, ?)
            ON CONFLICT(date) DO UPDATE SET
              amount=excluded.amount, rent_base=excluded.rent_base, cleaning=excluded.cleaning,
              electricity=excluded.electricity, other=excluded.other
        """, (date_str, total, rb, cl, el, ot))
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
                       total_revenue AS total_amount, partner_name, is_void, voided_at, voided_by
                FROM orders WHERE date=? ORDER BY id DESC
            """, (date_str,)).fetchall()
            result = []
            for order in orders:
                d = dict(order)
                d["invoice_no"] = f"ORD-{order['id']:05d}"
                d["items"] = [dict(i) for i in cursor.execute(
                    "SELECT product_id, name, quantity, price_at_sale, cost_at_sale FROM order_items WHERE order_id=?",
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
                conn.commit()
                return jsonify({"status": "success", "invoice_no": f"ORD-{order_id:05d}"})
            except (ValueError, TypeError) as e:
                conn.rollback()
                return jsonify({"message": str(e)}), 400
            except Exception:
                conn.rollback()
                raise

        denied = require_manager()
        if denied:
            return denied
        order_id = request.args.get("id")
        conn.execute("BEGIN IMMEDIATE")
        order = cursor.execute("SELECT is_void FROM orders WHERE id=?", (order_id,)).fetchone()
        if not order:
            conn.rollback()
            return jsonify({"message": "找不到單據"}), 404
        if order["is_void"]:
            conn.rollback()
            return jsonify({"message": "此單據已作廢"}), 409
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
            (now_tw().strftime("%Y-%m-%d %H:%M:%S"), session.get("partner_name", ""), order_id),
        )
        conn.commit()
        return jsonify({"status": "success"})
    finally:
        conn.close()


@app.route("/api/orders/update_date", methods=["POST"])
@require_auth
def update_order_date():
    denied = require_manager()
    if denied:
        return denied
    data = request.get_json() or {}
    order_id = data.get("order_id")
    new_date = str(data.get("new_date", "")).strip()
    try:
        datetime.strptime(new_date, "%Y-%m-%d")
    except ValueError:
        return jsonify({"message": "日期格式錯誤"}), 400
    conn = get_db_connection()
    try:
        conn.execute("UPDATE orders SET date=? WHERE id=?", (new_date, order_id))
        conn.commit()
        return jsonify({"status": "success"})
    finally:
        conn.close()


@app.route("/api/orders/daily", methods=["DELETE"])
@require_auth
def void_daily_orders():
    denied = require_manager()
    if denied:
        return denied
    date_str = request.args.get("date")
    if not date_str:
        return jsonify({"message": "缺少日期"}), 400
    conn = get_db_connection()
    try:
        cursor = conn.cursor()
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
        conn.commit()
        return jsonify({"status": "success", "voided_count": len(orders)})
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


@app.route("/api/report", methods=["GET"])
@require_auth
def handle_report():
    mode = request.args.get("mode", "daily")
    target = request.args.get("date") if mode == "daily" else request.args.get("month")
    if not target:
        target = now_tw().strftime("%Y-%m-%d" if mode == "daily" else "%Y-%m")
    query_date = target if mode == "daily" else f"{target}-%"
    op = "=" if mode == "daily" else "LIKE"

    conn = get_db_connection()
    try:
        cursor = conn.cursor()
        summary = cursor.execute(
            f"SELECT SUM(total_revenue) AS rev, SUM(total_cost) AS cos, COUNT(*) AS orders_cnt FROM orders WHERE date {op} ? AND is_void=0",
            (query_date,),
        ).fetchone()
        rent_row = cursor.execute(
            f"SELECT SUM(amount) AS amount FROM rent WHERE date {op} ?",
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
        partners_rows = cursor.execute(
            f"SELECT DISTINCT partner_name FROM orders WHERE date {op} ? AND is_void=0 AND partner_name!=''",
            (query_date,),
        ).fetchall()
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
        return jsonify({
            "revenue": revenue,
            "cost": cost,
            "rent": rent,
            "net_profit": revenue - cost - rent,
            "orders_count": int(summary["orders_cnt"] or 0),
            "details": [dict(r) for r in details],
            "main_categories": [dict(r) for r in main_cats],
            "payments": {r["name"]: r["total"] for r in pm_rows},
            "partners": [r["partner_name"] for r in partners_rows],
        })
    finally:
        conn.close()


@app.route("/")
def index():
    return render_template("index.html")


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 8888))
    app.run(host="0.0.0.0", port=port)
