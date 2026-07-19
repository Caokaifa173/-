# 用户信息管理平台 - 安全审计版

## 快速启动

```bash
# 1. 安装依赖
pip install -r requirements.txt

# 2. 配置环境变量
cp .env.example .env
# 编辑 .env，将 USERMGR_SECRET_KEY 改为强随机密钥

# 3. 加载环境变量并启动
export $(grep -v '^\s*#' .env | xargs)
python app.py

# 或者使用 dotenv 加载
pip install python-dotenv
python -c "from dotenv import load_dotenv; load_dotenv()"
python app.py
```

## 默认账号（初始化后）

| 用户名 | 密码 | 角色 |
|--------|------|------|
| admin | Admin@12345 | admin |
| alice | Alice@2025 | user |

**注意：** 密码已使用 bcrypt 哈希存储，符合强密码策略要求。

## 环境要求

- Python 3.9+
- Flask 3.0+
- bcrypt
- Flask-Limiter（可选，用于登录频率限制）

## 目录结构

```
/opt/Class01/
├── app.py                 # 主应用（安全增强版）
├── requirements.txt       # Python 依赖
├── .env.example           # 环境变量模板
├── config/
│   ├── __init__.py
│   └── config.py          # 敏感配置管理
├── models/
│   ├── __init__.py
│   └── user.py            # 用户数据模型 + bcrypt
├── utils/
│   ├── __init__.py
│   └── password_policy.py # 密码策略验证
├── templates/
│   ├── base.html          # 基础模板
│   ├── login.html         # 登录页面
│   └── index.html         # 首页
├── static/
│   └── css/
│       └── style.css      # 样式文件
└── docs/
    └── vulnerability_report.docx  # 漏洞修复报告
```

## 安全特性

- ✅ bcrypt 密码哈希（PBKDF2 + 加盐）
- ✅ 环境变量隔离敏感配置
- ✅ 强密码策略（8位+大小写+数字+特殊字符）
- ✅ Session Cookie 安全属性（HTTPOnly, Secure, SameSite）
- ✅ 登录频率限制（5次/5分钟）
- ✅ 输入清洗（strip + maxlength）
- ✅ 统一的登录错误提示（不区分用户是否存在）
- ✅ Session 固定攻击防护
- ✅ Content Security Policy 头
- ✅ 完整的安全响应头
- ✅ 脱敏显示（邮箱、手机号）
- ✅ 安全日志记录
- ✅ 支持 TLS/HTTPS
- ✅ 不含硬编码密码
