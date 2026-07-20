import sqlite3, os
from flask import Flask, render_template, request, redirect, session

app = Flask(__name__)
app.secret_key = "dev-key-2025"

USERS = {
    "admin": {
        "username": "admin",
        "password": "***",
        "role": "admin",
        "email": "admin@example.com",
        "phone": "13800138000",
        "balance": 99999
    },
    "alice": {
        "username": "alice",
        "password": "***",
        "role": "user",
        "email": "alice@example.com",
        "phone": "13900139001",
        "balance": 100
    }
}

DB_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "data", "users.db")


def init_db():
    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute(
        """
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            email TEXT,
            phone TEXT
        )
        """
    )
    c.execute("INSERT OR IGNORE INTO users (username, password, email, phone) VALUES ('admin', '***', 'admin@example.com', '13800138000')")
    c.execute("INSERT OR IGNORE INTO users (username, password, email, phone) VALUES ('alice', 'alice2025', 'alice@example.com', '13900139001')")
    conn.commit()
    conn.close()
    print(f"[init_db] Database initialized at {DB_PATH}")


@app.route("/")
def index():
    """首页：登录信息 + 搜索功能（支持模糊搜索用户名/邮箱）"""
    username = session.get("username")
    user = USERS.get(username) if username else None

    keyword = request.args.get("keyword", "").strip()
    results = None
    searched = bool(keyword)

    if keyword:
        # ✅ 修复 SQL 注入 — 参数化查询
        like_pattern = f"%{keyword}%"
        conn = sqlite3.connect(DB_PATH)
        conn.row_factory = sqlite3.Row
        try:
            rows = conn.execute(
                "SELECT id, username, email, phone FROM users WHERE username LIKE ? OR email LIKE ?",
                (like_pattern, like_pattern)
            ).fetchall()
            results = [dict(row) for row in rows]
        except Exception as e:
            print(f"[SQL ERROR] {e}")
            results = []
        conn.close()

    return render_template("index.html", user=user, results=results, keyword=keyword, searched=searched)


@app.route("/login", methods=["GET", "POST"])
def login():
    """登录页面：支持用户登录，验证用户名和密码"""
    if request.method == "POST":
        username = request.form.get("username", "")
        password = request.form.get("password", "")
        user = USERS.get(username)
        if user and user["password"] == password:
            session["username"] = username
            return render_template("index.html", user=user)
        else:
            return render_template("login.html", error="用户名或密码错误")
    return render_template("login.html")


@app.route("/register", methods=["GET", "POST"])
def register():
    """注册页面：新用户注册，写入数据库"""
    if request.method == "POST":
        username = request.form.get("username", "")
        password = request.form.get("password", "")
        email = request.form.get("email", "")
        phone = request.form.get("phone", "")
        # ✅ 修复 SQL 注入 — 参数化查询
        conn = sqlite3.connect(DB_PATH)
        try:
            conn.execute(
                "INSERT INTO users (username, password, email, phone) VALUES (?, ?, ?, ?)",
                (username, password, email, phone)
            )
            conn.commit()
            conn.close()
            return redirect("/login?registered=1")
        except Exception as e:
            print(f"[SQL ERROR] {e}")
            conn.close()
            return render_template("register.html", error=f"注册失败: {e}")
    return render_template("register.html")


@app.route("/logout")
def logout():
    """退出登录：清除 session"""
    session.pop("username", None)
    return redirect("/")


if __name__ == "__main__":
    init_db()
    app.run(host="0.0.0.0", port=5000, debug=True)
