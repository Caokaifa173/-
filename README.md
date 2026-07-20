# 🛡️ SQL 注入漏洞演示 + 修复 + 学习项目

> **完整网页代码集合** — 含漏洞演示版、SQL注入修复版、WAF绕过学习内容
>
> 基于 [Caokaifa173/-](https://github.com/Caokaifa173/-) 仓库整合

---

## 📋 项目结构

```
/opt/sqli-vuln-app-complete/
├── app.py                         # Flask Web 应用（已修复 SQL 注入）
├── requirements.txt               # Python 依赖
├── .gitignore                     # Git 忽略规则
├── README.md                      # 📘 本文件
├── static/
│   └── css/
│       └── style.css              # 页面样式
├── templates/
│   ├── base.html                  # 基础模板（导航栏）
│   ├── index.html                 # 首页（用户信息 + 搜索）
│   ├── login.html                 # 登录页面
│   └── register.html              # 注册页面
├── scripts/
│   ├── blind_inject.py            # WAF 绕过盲注脚本（安全狗）
│   └── waf_bypass_fuzz.py         # WAF 绕过模糊测试脚本
└── docs/
    ├── SQL_INJECTION_FIX_REPORT.md      # 🐛 SQL 注入修复报告（2026-07-20）
    ├── VULNERABILITY_REPORT.md          # 🐛 完整漏洞报告（11个漏洞全景）
    ├── sqli-cheatsheet.md               # SQL 注入 Cheat Sheet
    ├── WAF_Bypass_Fuzz_Report.md        # WAF 绕过模糊测试报告
    └── blind_result.txt                 # 盲注结果示例
```

---

## 🚀 快速启动

```bash
# 1. 安装依赖
pip install -r requirements.txt

# 2. 启动应用
python app.py

# 3. 浏览器访问
# http://localhost:5000
```

### 默认测试账号

| 用户名 | 密码 | 角色  |
|--------|------|-------|
| admin  | ***  | admin |
| alice  | alice2025 | user  |

---

## 🎯 功能列表

### 昨日现有功能（登录流程）

| 路由 | 功能 | 说明 |
|:---|:---|:---|
| `GET /` | 首页 | 显示已登录用户信息 + 用户搜索 |
| `GET/POST /login` | 登录 | 支持用户名/密码认证 |
| `GET/POST /register` | 注册 | 新用户注册（用户名/密码/邮箱/手机号） |
| `GET /logout` | 退出 | 清除登录状态 |

### 今日新增/修复

| 内容 | 说明 |
|:---|:---|
| 🔒 **SQL 注入修复** | 搜索功能 + 注册功能 → **参数化查询**替代 f-string 拼接 |
| 📕 **SQL 注入修复报告** | `docs/SQL_INJECTION_FIX_REPORT.md` |

### 配套学习资源

| 文件 | 说明 |
|:---|:---|
| `scripts/blind_inject.py` | 针对 WAF（安全狗）的布尔盲注脚本 |
| `scripts/waf_bypass_fuzz.py` | WAF 绕过 Fuzz 测试脚本 |
| `docs/sqli-cheatsheet.md` | SQL 注入常用语法速查表 |
| `docs/WAF_Bypass_Fuzz_Report.md` | WAF 绕过测试分析报告 |

---

## 🐛 已修复的 SQL 注入漏洞

### 漏洞1：搜索功能 SQL 注入

**修复前：**
```python
# f-string 直接拼接用户输入 → 可注入
sql = f"SELECT ... WHERE username LIKE '%{keyword}%' OR email LIKE '%{keyword}%'"
```

**修复后：**
```python
# 参数化查询（? 占位符）→ 注入无效
rows = conn.execute(
    "SELECT ... WHERE username LIKE ? OR email LIKE ?",
    (like_pattern, like_pattern)
).fetchall()
```

### 漏洞2：注册功能 SQL 注入

**修复前：**
```python
# f-string 直接拼接用户输入 → 可注入
sql = f"INSERT INTO users (...) VALUES ('{username}', '{password}', ...)"
```

**修复后：**
```python
# 参数化查询（? 占位符）→ 注入无效
conn.execute(
    "INSERT INTO users (...) VALUES (?, ?, ?, ?)",
    (username, password, email, phone)
)
```

---

## 🔄 分支说明

| 分支 | 内容 | 状态 |
|:---|:---|:---:|
| `vuln-version` | 有漏洞版本（f-string SQL拼接） | ✅ 远程已存在 |
| `fix-sqli-0720` | 仅 SQL 注入修复 | ✅ 远程已存在 |
| `main` | 完整安全版本 | 远程仓库已存在 |

---

## 📂 合集版本

本目录 (`sqli-vuln-app-complete`) 是将 `vuln-version` 分支的完整代码与今天 SQL 注入修复内容整合后的 **完整网页代码集合**，同时加入了 SQL 注入学习辅助资源。

---

*项目整合时间：2026-07-20 05:39 EDT*
