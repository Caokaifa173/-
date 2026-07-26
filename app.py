import sqlite3, os, subprocess, platform
from flask import Flask, render_template, render_template_string, request, redirect, session, url_for
from werkzeug.utils import secure_filename

app = Flask(__name__)
app.secret_key = "dev-key-2025"

# ========== 新增配置：文件上传 ==========
app.config["MAX_CONTENT_LENGTH"] = 16 * 1024 * 1024  # 16MB
UPLOAD_FOLDER = os.path.join(
    os.path.dirname(os.path.abspath(__file__)), "static", "uploads"
)
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
# ==========================================

USERS = {
    "admin": {
        "username": "admin",
        "password": "***",
        "role": "admin",
        "email": "admin@example.com",
        "phone": "13800138000",
        "balance": 99999,
    },
    "alice": {
        "username": "alice",
        "password": "***",
        "role": "user",
        "email": "alice@example.com",
        "phone": "13900139001",
        "balance": 100,
    },
}

DB_PATH = os.path.join(
    os.path.dirname(os.path.abspath(__file__)), "data", "users.db"
)


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
            phone TEXT,
            balance REAL DEFAULT 0.0,
            avatar TEXT DEFAULT NULL
        )
        """
    )
    # 兼容旧表：动态添加新字段
    try:
        c.execute("SELECT balance FROM users LIMIT 1")
    except sqlite3.OperationalError:
        c.execute("ALTER TABLE users ADD COLUMN balance REAL DEFAULT 0.0")
    try:
        c.execute("SELECT avatar FROM users LIMIT 1")
    except sqlite3.OperationalError:
        c.execute("ALTER TABLE users ADD COLUMN avatar TEXT DEFAULT NULL")

    c.execute(
        "INSERT OR IGNORE INTO users (username, password, email, phone) VALUES ('admin', '***', 'admin@example.com', '13800138000')"
    )
    c.execute(
        "INSERT OR IGNORE INTO users (username, password, email, phone) VALUES ('alice', 'alice2025', 'alice@example.com', '13900139001')"
    )
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
        like_pattern = f"%{keyword}%"
        conn = sqlite3.connect(DB_PATH)
        conn.row_factory = sqlite3.Row
        try:
            rows = conn.execute(
                "SELECT id, username, email, phone FROM users WHERE username LIKE ? OR email LIKE ?",
                (like_pattern, like_pattern),
            ).fetchall()
            results = [dict(row) for row in rows]
        except Exception as e:
            print(f"[SQL ERROR] {e}")
            results = []
        conn.close()

    return render_template(
        "index.html", user=user, results=results, keyword=keyword, searched=searched
    )


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
        conn = sqlite3.connect(DB_PATH)
        try:
            conn.execute(
                "INSERT INTO users (username, password, email, phone) VALUES (?, ?, ?, ?)",
                (username, password, email, phone),
            )
            conn.commit()
            conn.close()
            return redirect("/login?registered=1")
        except Exception as e:
            print(f"[SQL ERROR] {e}")
            conn.close()
            return render_template("register.html", error=f"注册失败: {e}")
    return render_template("register.html")


# ========== 新增路由：头像上传 ==========
@app.route("/upload", methods=["GET", "POST"])
def upload():
    """头像上传页面：登录用户可上传任意文件"""
    if "username" not in session:
        return redirect("/login")

    user = USERS.get(session["username"])
    result = None
    error = None

    if request.method == "POST":
        if "file" not in request.files:
            error = "没有选择文件"
        else:
            f = request.files["file"]
            if f.filename == "":
                error = "文件名为空"
            else:
                # ⚠️ 漏洞：使用原始文件名保存，不做类型检查
                filename = f.filename
                save_path = os.path.join(UPLOAD_FOLDER, filename)
                f.save(save_path)
                file_url = url_for("static", filename=f"uploads/{filename}")

                # 更新用户头像字段（从表单获取 user_id）
                user_id = request.form.get("user_id", "")
                if user_id:
                    conn = sqlite3.connect(DB_PATH)
                    c = conn.cursor()
                    c.execute(f"UPDATE users SET avatar='{file_url}' WHERE id={user_id}")
                    conn.commit()
                    conn.close()

                result = {
                    "filename": filename,
                    "url": file_url,
                    "size": os.path.getsize(save_path),
                }

    return render_template("upload.html", user=user, result=result, error=error)
# ==========================================


# ========== 新增路由：个人中心 ==========
@app.route("/profile")
def profile():
    """个人中心：通过 URL 参数查询任意用户资料（无权限校验）"""
    user_id = request.args.get("user_id", "")
    if not user_id:
        return render_template("profile.html", error="缺少 user_id 参数")

    # ⚠️ 漏洞：直接拼接 SQL，不验证当前用户是否匹配
    sql = f"SELECT id, username, email, phone, balance, avatar FROM users WHERE id={user_id}"
    print(f"[SQL] {sql}")
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    c = conn.cursor()
    try:
        c.execute(sql)
        row = c.fetchone()
        user = dict(row) if row else None
    except Exception as e:
        print(f"[SQL ERROR] {e}")
        user = None
    conn.close()

    if not user:
        return render_template("profile.html", error=f"用户不存在 (user_id={user_id})")

    return render_template("profile.html", user=user)
# ==========================================


# ========== 新增路由：充值 ==========
@app.route("/recharge", methods=["POST"])
def recharge():
    """充值：直接修改用户余额，不做正负校验"""
    user_id = request.form.get("user_id", "")
    amount = request.form.get("amount", "0")

    # ⚠️ 漏洞：直接拼接 SQL，amount 可为负数
    sql = f"UPDATE users SET balance = balance + {amount} WHERE id = {user_id}"
    print(f"[SQL] {sql}")
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    try:
        c.execute(sql)
        conn.commit()
    except Exception as e:
        print(f"[SQL ERROR] {e}")
    conn.close()

    return redirect(url_for("profile", user_id=user_id))
# ==========================================


# ========== 新增路由：欢迎页 ==========
@app.route("/welcome")
def welcome():
    """欢迎页：从 URL 参数获取姓名，拼接后渲染（render_template_string + 拼接方式）"""
    name = request.args.get("name", "").strip()
    if not name:
        name = "亲爱的用户"
    # ⚠️ 漏洞：直接拼接用户输入到模板字符串，无转义
    html = f"""<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>欢迎页</title>
    <link rel="stylesheet" href="/static/css/style.css">
</head>
<body>
    <nav class="navbar">
        <div class="nav-brand">用户管理系统</div>
        <div class="nav-menu">
            <a href="/" class="nav-link">首页</a>
            <a href="/welcome" class="nav-link">欢迎页</a>
            <a href="/feedback" class="nav-link">反馈</a>
        </div>
    </nav>
    <main class="container">
        <h1>欢迎你，{name}！</h1>
        <p style="margin-top: 20px; color: #666;">今天是个好日子，愿你开心每一天！</p>
    </main>
</body>
</html>
"""
    return render_template_string(html)
# ==========================================


# ========== 新增路由：反馈 ==========
@app.route("/feedback", methods=["GET", "POST"])
def feedback():
    """反馈页面：GET 显示表单，POST 以拼接方式渲染结果"""
    if request.method == "POST":
        name = request.form.get("name", "")
        message = request.form.get("message", "")
        # ⚠️ 漏洞：直接拼接用户输入到模板字符串，无转义
        html = f"""<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>反馈结果</title>
    <link rel="stylesheet" href="/static/css/style.css">
</head>
<body>
    <nav class="navbar">
        <div class="nav-brand">用户管理系统</div>
        <div class="nav-menu">
            <a href="/" class="nav-link">首页</a>
            <a href="/welcome" class="nav-link">欢迎页</a>
            <a href="/feedback" class="nav-link">反馈</a>
        </div>
    </nav>
    <main class="container">
        <h2>{name} 的反馈：</h2>
        <p>{message}</p>
        <p style="margin-top: 20px;"><a href="/feedback" class="nav-link">返回反馈表单</a></p>
    </main>
</body>
</html>
"""
        return render_template_string(html)

    # GET - 显示反馈表单
    html = """<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>反馈</title>
    <link rel="stylesheet" href="/static/css/style.css">
</head>
<body>
    <nav class="navbar">
        <div class="nav-brand">用户管理系统</div>
        <div class="nav-menu">
            <a href="/" class="nav-link">首页</a>
            <a href="/welcome" class="nav-link">欢迎页</a>
            <a href="/feedback" class="nav-link">反馈</a>
        </div>
    </nav>
    <main class="container">
        <h2>提交反馈</h2>
        <form method="post" action="/feedback">
            <div style="margin-bottom: 15px;">
                <label>姓名：</label><br>
                <input type="text" name="name" style="width:300px;padding:8px;">
            </div>
            <div style="margin-bottom: 15px;">
                <label>留言：</label><br>
                <textarea name="message" rows="5" style="width:300px;padding:8px;"></textarea>
            </div>
            <div>
                <input type="submit" value="提交反馈" style="padding:8px 20px;cursor:pointer;">
            </div>
        </form>
    </main>
</body>
</html>
"""
    return render_template_string(html)
# ==========================================


# ========== 新增路由：Ping 网络诊断 ==========
@app.route("/ping", methods=["GET", "POST"])
def ping():
    """Ping 网络诊断：登录用户可对目标 IP 执行 ping 命令"""
    if "username" not in session:
        return redirect("/login")

    result = None
    error = None

    if request.method == "POST":
        ip = request.form.get("ip", "")
        # ⚠️ 漏洞：直接拼接命令，无任何过滤
        cmd = f"ping -c 3 {ip}"
        print(f"[CMD] {cmd}")
        try:
            output = subprocess.check_output(cmd, shell=True, timeout=30, stderr=subprocess.STDOUT)
            result = output.decode("utf-8", errors="replace")
        except subprocess.CalledProcessError as e:
            error = e.output.decode("utf-8", errors="replace")
        except Exception as e:
            error = str(e)

    return render_template("ping.html", result=result, error=error)
# ==========================================


@app.route("/logout")
def logout():
    """退出登录：清除 session"""
    session.pop("username", None)
    return redirect("/")


if __name__ == "__main__":
    init_db()
    app.run(host="0.0.0.0", port=5000, debug=True)
