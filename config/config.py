"""
敏感配置管理模块

从环境变量加载配置，支持 .env 文件加载。
所有敏感信息不硬编码在代码中。
"""

import os
from pathlib import Path


class Config:
    """应用配置类 - 从环境变量读取配置"""

    # 基础配置
    SECRET_KEY = os.environ.get(
        "USERMGR_SECRET_KEY",
        os.environ.get("SECRET_KEY", ""),
    )

    # Flask 运行配置
    DEBUG = os.environ.get("USERMGR_DEBUG", "false").lower() == "true"
    HOST = os.environ.get("USERMGR_HOST", "127.0.0.1")
    PORT = int(os.environ.get("USERMGR_PORT", "5000"))

    # 数据库连接（预留扩展）
    DATABASE_URL = os.environ.get("DATABASE_URL", "")

    # Session 安全配置
    SESSION_COOKIE_SECURE = os.environ.get(
        "USERMGR_SESSION_COOKIE_SECURE", "true"
    ).lower() == "true"
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = "Lax"

    # 密码策略
    PASSWORD_MIN_LENGTH = int(os.environ.get("USERMGR_PASSWORD_MIN_LENGTH", "8"))
    PASSWORD_REQUIRE_UPPERCASE = (
        os.environ.get("USERMGR_PASSWORD_REQUIRE_UPPERCASE", "true").lower() == "true"
    )
    PASSWORD_REQUIRE_LOWERCASE = (
        os.environ.get("USERMGR_PASSWORD_REQUIRE_LOWERCASE", "true").lower() == "true"
    )
    PASSWORD_REQUIRE_DIGIT = (
        os.environ.get("USERMGR_PASSWORD_REQUIRE_DIGIT", "true").lower() == "true"
    )
    PASSWORD_REQUIRE_SPECIAL = (
        os.environ.get("USERMGR_PASSWORD_REQUIRE_SPECIAL", "true").lower() == "true"
    )

    # Bcrypt 轮次
    BCRYPT_ROUNDS = int(os.environ.get("USERMGR_BCRYPT_ROUNDS", "12"))

    # 请求限制
    RATELIMIT_ENABLED = (
        os.environ.get("USERMGR_RATELIMIT_ENABLED", "true").lower() == "true"
    )
    RATELIMIT_LOGIN_MAX = int(os.environ.get("USERMGR_RATELIMIT_LOGIN_MAX", "5"))
    RATELIMIT_LOGIN_WINDOW = int(
        os.environ.get("USERMGR_RATELIMIT_LOGIN_WINDOW", "300")
    )  # 5分钟

    # HTTPS/TLS 配置
    TLS_ENABLED = os.environ.get("USERMGR_TLS_ENABLED", "false").lower() == "true"
    TLS_CERT_PATH = os.environ.get("USERMGR_TLS_CERT_PATH", "")
    TLS_KEY_PATH = os.environ.get("USERMGR_TLS_KEY_PATH", "")

    # 日志级别
    LOG_LEVEL = os.environ.get("USERMGR_LOG_LEVEL", "INFO").upper()


class DevelopmentConfig(Config):
    """开发环境配置"""

    DEBUG = True
    HOST = os.environ.get("USERMGR_HOST", "127.0.0.1")
    SESSION_COOKIE_SECURE = False
    TLS_ENABLED = False


class ProductionConfig(Config):
    """生产环境配置"""

    DEBUG = False
    HOST = "0.0.0.0"
    SESSION_COOKIE_SECURE = True
    TLS_ENABLED = True


def get_config():
    """根据环境返回配置对象"""
    env = os.environ.get("FLASK_ENV", "development")
    if env == "production":
        return ProductionConfig()
    return DevelopmentConfig()
