# day5漏洞修复报告 — 个人中心 & 充值功能

> **项目名称：** SQL 注入学习平台  
> **新增功能：** 个人中心（`GET /profile`）、充值（`POST /recharge`）、头像上传改进（`POST /upload`）  
> **报告日期：** 2026-07-22  
> **审计版本：** `sqli-vuln-app-complete` 分支 + 新功能叠加

---

## 一、漏洞概述

| 漏洞类型 | 风险等级 | 影响路由 |
|:---|:---:|:---|
| SQL 注入（拼接查询） | 🔴 严重 | `/profile`, `/recharge`, `/upload` |
| IDOR 水平/垂直越权 | 🔴 严重 | `/profile` |
| 任意文件上传 | 🔴 严重 | `/upload` |
| 充值金额无校验 | 🔴 严重 | `/recharge` |
| 敏感信息泄露 | 🟡 中危 | `/profile` |
| CSRF 防护缺失 | 🟡 中危 | `/recharge`, `/upload` |
| 路径遍历 | 🟡 中危 | `/upload` |

---

## 二、逐条漏洞分析

### 🔴 漏洞 1：SQL 注入 — 个人中心（GET /profile）

**位置：** `app.py` — `profile()` 路由

```python
user_id = request.args.get("user_id", "")
sql = f"SELECT id, username, email, phone, balance, avatar FROM users WHERE id={user_id}"
c.execute(sql)
```

**危害：** `user_id` 直接从 URL 参数获取并拼接进 SQL 语句，攻击者可执行任意 SQL：

```
GET /profile?user_id=1 UNION SELECT 1,2,3,4,5,6--
GET /profile?user_id=1; DROP TABLE users--
```

---

### 🔴 漏洞 2：SQL 注入 — 充值（POST /recharge）

**位置：** `app.py` — `recharge()` 路由

```python
user_id = request.form.get("user_id", "")
amount = request.form.get("amount", "0")
sql = f"UPDATE users SET balance = balance + {amount} WHERE id = {user_id}"
c.execute(sql)
```

**危害：** `user_id` 和 `amount` 均直接拼接，攻击者可构造：

```
POST /recharge  user_id=1&amount=100000     → 给自己充钱
POST /recharge  user_id=2&amount=-99999     → 扣别人余额
POST /recharge  user_id=1; UPDATE users SET balance=999999 WHERE id=2--&amount=100
```

---

### 🔴 漏洞 3：SQL 注入 — 头像上传（POST /upload）

**位置：** `app.py` — `upload()` 路由

```python
user_id = request.form.get("user_id", "")
c.execute(f"UPDATE users SET avatar='{file_url}' WHERE id={user_id}")
```

**危害：** 上传头像时 user_id 未做参数化处理，可注入修改任意用户字段。

---

### 🔴 漏洞 4：IDOR — 无权限校验（GET /profile）

**位置：** `app.py` — `profile()` 路由

```python
# 无任何 session 校验，直接根据 user_id 查询并返回资料
user_id = request.args.get("user_id", "")
```

**危害：**
- 未登录也可访问：`GET /profile?user_id=1`
- 可遍历所有用户资料：`/profile?user_id=1` → `/profile?user_id=100`
- 可查看管理员（admin）和任意普通用户的手机号、余额、邮箱等敏感字段

---

### 🔴 漏洞 5：充值金额无正负校验（POST /recharge）

**位置：** `app.py` — `recharge()` 路由

```python
# amount 未做任何校验，正数负数均可
amount = request.form.get("amount", "0")
sql = f"UPDATE users SET balance = balance + {amount} WHERE id = {user_id}"
```

**危害：** 攻击者可利用负数金额扣减他人余额，或通过 SQL 注入直接篡改他人余额：
```
POST /recharge  user_id=3&amount=-1000000
```

---

### 🔴 漏洞 6：任意文件上传（POST /upload）

**位置：** `app.py` — `upload()` 路由

```python
filename = f.filename
save_path = os.path.join(UPLOAD_FOLDER, filename)
f.save(save_path)
```

**危害：** 上传任意类型文件（PHP 脚本、Python 脚本、可执行文件等），且不重命名、不做类型校验：

```
上传 shell.php → GET /static/uploads/shell.php → PHP 代码执行
上传 ../../etc/cronjob.sh → 路径遍历写入系统目录
```

---

### 🟡 漏洞 7：敏感信息泄露

**位置：** `app.py` — `profile()` 路由返回全部字段

**缺陷：** 个人中心返回完整用户资料（邮箱、手机号、余额、头像路径）给任意访问者，无需登录。

---

### 🟡 漏洞 8：CSRF 防护缺失

**位置：** `POST /recharge`, `POST /upload`

**缺陷：** 无 CSRF Token，攻击者可构造恶意页面诱导已登录用户执行充值/上传操作。

---

## 三、攻击路径复现

### 攻击链 1：越权查看全部用户资料

```
步骤 1：不登录，直接访问
       GET /profile?user_id=1
       → 返回 admin 的邮箱、手机、余额

步骤 2：遍历 user_id
       GET /profile?user_id=2  → alice 的资料
       GET /profile?user_id=3  → 其他用户

步骤 3：收集到所有用户的敏感信息
```

### 攻击链 2：SQL 注入篡改余额

```
步骤 1：构造充值请求
       POST /recharge
       user_id=2&amount=99999
       → alice 余额变为 99999

步骤 2：使用 UNION 注入窃取数据
       GET /profile?user_id=1 UNION SELECT 1,(SELECT group_concat(username||":"||password) FROM users),3,4,5,6--
       → 得到所有用户的密码哈希
```

### 攻击链 3：任意文件上传 + Webshell

```
步骤 1：上传 PHP webshell
       POST /upload → file=shell.php

步骤 2：直接访问执行
       GET /static/uploads/shell.php
       → PHP 代码执行，服务器沦陷
```

---

## 四、修复方案

### ✅ 修复 1：SQL 注入修复（所有路由）

所有用户输入必须使用参数化查询：

**修复前：**
```python
sql = f"SELECT * FROM users WHERE id={user_id}"
c.execute(sql)
```

**修复后：**
```python
sql = "SELECT * FROM users WHERE id=?"
c.execute(sql, (user_id,))
```

**涉及路由：** `/profile`、`/recharge`、`/upload` 中所有 SQL 操作。

---

### ✅ 修复 2：权限校验（/profile）

- 必须验证 `session` 中是否存在已登录用户
- 限制普通用户只能查看自己的资料
- 可设置管理员可查看全部，普通用户仅限本人

```python
if "username" not in session:
    return redirect("/login")

current_user = session.get("username")
# 校验当前登录用户与查询 user_id 是否匹配
# 或只允许查看自己的信息
```

---

### ✅ 修复 3：充值金额校验（/recharge）

```python
try:
    amount = float(amount)
    if amount <= 0:
        return "充值金额必须大于 0", 400
except ValueError:
    return "无效的金额格式", 400
```

---

### ✅ 修复 4：文件上传安全加固（/upload）

参考 `UPLOAD_VULNERABILITY_REPORT.md` 中的完整修复方案：

- 白名单校验文件后缀（仅允许 jpg/png/gif/webp）
- Magic Number 验证文件头
- UUID 重命名 + secure_filename 过滤
- 文件大小上限降至 2MB
- 上传目录配置禁止脚本执行

---

### ✅ 修复 5：CSRF Token（/recharge, /upload）

```python
import secrets

@app.before_request
def generate_csrf_token():
    if "csrf_token" not in session:
        session["csrf_token"] = secrets.token_hex(32)

# 模板中：
# <input type="hidden" name="csrf_token" value="{{ session.csrf_token }}">
```

---

## 五、修复前后对比

| 检查项 | 修复前 | 修复后 |
|:---|:---|:---|
| **SQL 注入防护** | ❌ 直接拼接用户输入 | ✅ 参数化查询 |
| **个人中心权限** | ❌ 无需登录即可查看任意用户 | ✅ 需登录且只能查看本人 |
| **充值金额校验** | ❌ 正负数均可 | ✅ 仅允许正数 |
| **文件类型校验** | ❌ 任意文件可上传 | ✅ 白名单 + Magic Number |
| **文件名处理** | ❌ 原始文件名 | ✅ UUID 重命名 |
| **目录遍历防护** | ❌ 无 | ✅ secure_filename |
| **CSRF 防护** | ❌ 无 | ✅ CSRF Token |
| **最大文件大小** | ⚠️ 16MB | ✅ 2MB |

---

## 六、总结

本次新增的个人中心（`/profile`）和充值（`/recharge`）功能存在 **SQL 注入、IDOR 越权、金额注入** 等严重安全漏洞。结合已存在的任意文件上传漏洞，攻击者可实现：

```
信息泄露 → 越权操作 → SQL 注入 → 数据窃取/篡改 → 任意文件上传 → 服务器沦陷
```

形成完整的攻击链。建议优先修复 **SQL 注入** 和 **权限校验** 两个最高风险项，随后依次解决文件上传和 CSRF 问题。

---

*报告生成日期：2026-07-22*
