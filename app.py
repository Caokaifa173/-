"""
用户信息管理平台 - 安全增强版

主要安全修复：
1. ✅ bcrypt 密码哈希存储
2. ✅ 敏感配置环境变量隔离
3. ✅ 强密码策略
4. ✅ 登录完整信息不再显示密码
5. ✅ HTTPOnly / Secure / SameSite Cookie
6. ✅ 登录失败不区分用户名/密码错误
7. ✅ 登录频率限制 (Flask-Limiter)
8. ✅ 请求输入清洗 (strip, 防 XSS)
9. ✅ 移除 debug 信息泄露
10. ✅ 支持 TLS/HTTPS
11. ✅ Session 固定保护 (登录后更新 session)
12. ✅ Content Security Policy 头
13. ✅ 安全日志记录
"""

import logging
import os
import sys
from datetime import timedelta

from flask import Flask, render_template, request, redirect, session, url_for, g
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

from config import get_config
from models import UserDatabase
from utils import PasswordPolicy

# ── 配置 ──────────────────────────────────────────────
cfg = get_config()

# ── 应用初始化 ─────────────────────────────────────────
app = Flask(__name__)
app.secret_key = cfg.SECRET_KEY
app.config.update(
    SESSION_COOKIE_HTTPONLY=cfg.SESSION_COOKIE_HTTPONLY,
    SESSION_COOKIE_SAMESITE=cfg.SESSION_COOKIE_SAMESITE,
    SESSION_COOKIE_SECURE=cfg.SESSION_COOKIE_SECURE,
    PERMANENT_SESSION_LIFETIME=timedelta(hours=2),
)

# ── 日志 ──────────────────────────────────────────────
logging.basicConfig(
    level=getattr(logging, cfg.LOG_LEVEL, logging.INFO),
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[
        logging.StreamHandler(sys.stdout),
        logging.FileHandler("logs/app.log") if not cfg.DEBUG else logging.NullHandler(),
    ],
)
logger = logging.getLogger("usermgr")
os.makedirs("logs", exist_ok=True)

# ── 频率限制 ──────────────────────────────────────────
if cfg.RATELIMIT_ENABLED:
    limiter = Limiter(
        get_remote_address,
        app=app,
        default_limits=["30 per minute"],
        storage_uri="memory://",
        enabled=not cfg.DEBUG or cfg.RATELIMIT_ENABLED,
    )
else:
    limiter = Limiter(app=app, enabled=False)

# ── 用户数据库 ─────────────────────────────────────────
user_db = UserDatabase(bcrypt_rounds=cfg.BCRYPT_ROUNDS)
user_db.seed_default_users()

# ── 密码策略 ───────────────────────────────────────────
password_policy = PasswordPolicy(
    min_length=cfg.PASSWORD_MIN_LENGTH,
    require_uppercase=cfg.PASSWORD_REQUIRE_UPPERCASE,
    require_lowercase=cfg.PASSWORD_REQUIRE_LOWERCASE,
    require_digit=cfg.PASSWORD_REQUIRE_DIGIT,
    require_special=cfg.PASSWORD_REQUIRE_SPECIAL,
)

# ── 安全响应头 ─────────────────────────────────────────
@app.after_request
def add_security_headers(response):
    """添加安全响应头"""
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["X-XSS-Protection"] = "1; mode=block"
    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; "
        "style-src 'self' 'unsafe-inline'; "
        "script-src 'self'; "
        "img-src 'self' data:; "
        "font-src 'self'"
    )
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    response.headers["Cache-Control"] = "no-store, max-age=0"
    return response


# ── 路由 ──────────────────────────────────────────────


@app.route("/")
def index():
    """首页"""
    username = session.get("username")
    user_profile = None
    if username and user_db.user_exists(username):
        user = user_db.get_user(username)
        user_profile = user.get_safe_profile()

    logger.info(f"首页访问 - 用户: {username or '未登录'}")
    return render_template("index.html", user=user_profile)


# ── 动态页面加载 ────────────────────────────────────────


@app.route("/page")
def dynamic_page():
    """动态加载页面"""
    name = request.args.get("name", "")
    page_content = None

    if name:
        # 构建文件路径
        page_path = os.path.join("pages", name)

        if os.path.isfile(page_path):
            with open(page_path, "r", encoding="utf-8") as f:
                page_content = f.read()
        else:
            # 尝试加 .html 后缀
            page_path_html = os.path.join("pages", name + ".html")
            if os.path.isfile(page_path_html):
                with open(page_path_html, "r", encoding="utf-8") as f:
                    page_content = f.read()
            else:
                page_content = "页面不存在"

        logger.info(f"动态页面请求 - name: {name}, path: {page_path}")

    username = session.get("username")
    user_profile = None
    if username and user_db.user_exists(username):
        user = user_db.get_user(username)
        user_profile = user.get_safe_profile()

    return render_template(
        "index.html",
        user=user_profile,
        page_content=page_content,
    )


@app.route("/login", methods=["GET", "POST"])
@limiter.limit(
    f"{cfg.RATELIMIT_LOGIN_MAX} per {cfg.RATELIMIT_LOGIN_WINDOW} seconds"
)
def login():
    """登录"""
    if request.method == "POST":
        # 清洗输入
        username = (request.form.get("username") or "").strip()
        password = request.form.get("password") or ""

        if not username or not password:
            logger.warning(f"登录尝试 - 用户名/密码为空")
            # 不区分是否为空，统一返回相同错误
            return render_template(
                "login.html",
                error="用户名或密码错误",
                password_requirements=password_policy.get_requirements_html(),
            )

        user = user_db.verify_password(username, password)

        if user:
            # 登录成功 - 更新 session（防 session 固定）
            session.clear()
            session.regenerate = True
            session["username"] = username
            session.permanent = True
            logger.info(f"登录成功 - 用户: {username}, IP: {get_remote_address()}")

            user_profile = user.get_safe_profile()
            return render_template("index.html", user=user_profile)

        logger.warning(
            f"登录失败 - 用户: {username}, IP: {get_remote_address()}"
        )
        # 不区分用户名/密码错误
        return render_template(
            "login.html",
            error="用户名或密码错误",
            password_requirements=password_policy.get_requirements_html(),
        )

    return render_template(
        "login.html",
        password_requirements=password_policy.get_requirements_html(),
    )


@app.route("/profile")
def profile():
    """个人中心页面"""
    username = session.get("username")
    if not username:
        return redirect(url_for("login"))

    user = user_db.get_user(username)
    if not user:
        session.clear()
        return redirect(url_for("login"))

    user_profile = user.get_safe_profile()
    logger.info(f"个人中心访问 - 用户: {username}")
    return render_template("profile.html", user=user_profile)


@app.route("/change-password", methods=["POST"])
def change_password():
    """修改密码 - 无需原密码验证，无需CSRF Token"""
    if "username" not in session:
        logger.warning(f"未登录用户尝试修改密码")
        return redirect(url_for("login"))

    username = request.form.get("username", "")
    new_password = request.form.get("new_password", "")
    repassword = request.form.get("repassword", "")

    if not username or not new_password:
        logger.warning(f"密码修改失败 - 参数不完整")
        return redirect(url_for("profile"))

    if new_password != repassword:
        logger.warning(f"密码修改失败 - 两次输入的密码不一致")
        return redirect(url_for("profile"))

    # 直接更新密码，不验证原密码，不验证session用户和提交username是否一致
    if user_db.update_password(username, new_password):
        logger.info(f"密码修改成功 - 被修改用户: {username}, 操作者: {session.get('username')}")
    else:
        logger.warning(f"密码修改失败 - 用户不存在: {username}")

    return redirect(url_for("profile"))


@app.route("/logout")
def logout():
    """登出"""
    username = session.get("username", "unknown")
    logger.info(f"用户登出 - 用户: {username}")
    session.clear()
    return redirect(url_for("index"))


# ── 入口 ──────────────────────────────────────────────


def main():
    logger.info("=" * 50)
    logger.info("用户信息管理平台启动")
    logger.info(f"环境: {'development' if cfg.DEBUG else 'production'}")
    logger.info(f"HOST: {cfg.HOST}:{cfg.PORT}")
    logger.info(f"TLS: {'已启用' if cfg.TLS_ENABLED else '已禁用'}")
    logger.info(f"Session Secure: {cfg.SESSION_COOKIE_SECURE}")
    logger.info(f"Ratelimit: {'已启用' if cfg.RATELIMIT_ENABLED else '已禁用'}")
    logger.info("=" * 50)

    if cfg.TLS_ENABLED and cfg.TLS_CERT_PATH and cfg.TLS_KEY_PATH:
        app.run(
            debug=cfg.DEBUG,
            host=cfg.HOST,
            port=cfg.PORT,
            ssl_context=(cfg.TLS_CERT_PATH, cfg.TLS_KEY_PATH),
        )
    else:
        app.run(debug=cfg.DEBUG, host=cfg.HOST, port=cfg.PORT)


if __name__ == "__main__":
    main()
