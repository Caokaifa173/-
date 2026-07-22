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
| 负数充值/套现 | 🔴 严重 | `/recharge` |
| 越权操作他人余额 | 🔴 严重 | `/recharge` |
| 头像绑定他人 | 🔴 严重 | `/upload` |
| 金额格式无校验 | 🟡 中危 | `/recharge` |
| 无操作审计日志 | 🟡 中危 | `/recharge` |
| 用户 ID 可遍历枚举 | 🟡 中危 | `/profile` |
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

## 三、业务逻辑漏洞

### 🔴 业务漏洞 1：负数充值 — 从系统"套现"

**位置：** `POST /recharge`

**问题：** 充值金额没有校验正负，可以为负数充值。

```
POST /recharge  user_id=1&amount=-99999   # 把 admin 余额扣光
POST /recharge  user_id=3&amount=-1000000 # 让 testuser 欠系统 100 万
```

**业务影响：**
- 把自己的余额扣成负数后，如果后续有消费功能且未校验余额 ≥ 0，可无限透支
- 可恶意清空他人余额
- 系统没有"余额不足"的校验层，负余额可继续操作

---

### 🔴 业务漏洞 2：越权操作他人账户

**位置：** `GET /profile` + `POST /recharge`

**问题：** 两个功能都用 `user_id` 来自 URL/表单参数，完全不校验当前登录用户身份。

```
# 用户 A 可以操作任意用户：
POST /recharge  user_id=1&amount=999999    # 给 admin 充 100 万
POST /recharge  user_id=1&amount=-999999   # 把 admin 余额清空
```

**业务影响：** 等于所有用户共享一个管理员权限，没有任何归属校验，业务权限体系完全失效。

---

### 🔴 业务漏洞 3：头像绑定他人

**位置：** `POST /upload`

**问题：** 上传头像时可以指定 `user_id` 为任意值。

```
# 用户 A 上传违规图片，绑定到 admin 的头像
POST /upload  user_id=1&file=malicious.jpg
→ admin 的头像被篡改为 A 上传的图片
```

**业务影响：**
- 可给任意用户设置违规/恶意/色情头像
- 可用于钓鱼：修改他人头像为仿冒官方通知图片
- 平台运营方难以追责（上传者和被绑定者不是同一人）

---

### 🟡 业务漏洞 4：非整数金额

**位置：** `POST /recharge`

**问题：** `amount` 没有做类型校验，可接收科学计数法、小数等非常规格式。

```
POST /recharge  user_id=1&amount=1e10     # 科学计数法
POST /recharge  user_id=1&amount=9.99     # 小数
POST /recharge  user_id=1&amount=.1       # 非标准格式
```

**业务影响：**
- 浮点数精度问题可能导致余额计算误差累积
- 科学计数法可能绕过后端简单校验
- 数据库浮点存储可能导致多次操作后余额异常

---

### 🟡 业务漏洞 5：无操作审计日志

**位置：** `POST /recharge`

**问题：** 充值操作没有记录任何日志。

**业务影响：**
- 用户反馈"充了 1000 块没到账" → 无法追溯
- 攻击者利用漏洞篡改余额后 → 无任何审计记录
- 异常操作无法回滚
- 合规审计完全缺失

---

### 🟡 业务漏洞 6：用户 ID 可遍历枚举

**位置：** `GET /profile`

**问题：** `user_id` 为自增整数，可通过遍历枚举所有注册用户。

```
/profile?user_id=1   → 200, 返回 admin
/profile?user_id=2   → 200, 返回 alice
/profile?user_id=99  → 用户不存在（遍历失败时可知不存在）
```

**业务影响：**
- 可枚举出系统中所有注册用户数量及资料
- 可通过监控 user_id 最大值变化了解平台用户增长情况
- 配合其他功能可做精准钓鱼攻击

---

## 四、攻击路径复现

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

### 攻击链 4：业务逻辑 — 余额体系崩溃

```
步骤 1：枚举出所有用户的 user_id
       GET /profile?user_id=1~100

步骤 2：遍历清空所有人余额
       POST /recharge  user_id=1&amount=-999999
       POST /recharge  user_id=2&amount=-999999
       ...

步骤 3：给自己充入巨额余额
       POST /recharge  user_id=自己&amount=999999999

步骤 4：如果有消费功能，可无限消费
       系统余额体系已完全崩溃
```

---

## 五、修复方案

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

### ✅ 修复 2：权限校验（/profile + /recharge）

- 必须验证 `session` 中是否存在已登录用户
- 限制普通用户只能操作自己的账户
- 管理后台才允许查看全部用户

```python
if "username" not in session:
    return redirect("/login")

current_username = session.get("username")
# 校验当前用户与操作目标是否匹配
# SELECT id FROM users WHERE username=?
user_id = request.args.get("user_id", "")
if str(current_user_id) != user_id and not is_admin:
    return "无权访问", 403
```

---

### ✅ 修复 3：充值金额校验（/recharge）

```python
try:
    amount = float(amount)
    if amount <= 0:
        return "充值金额必须大于 0", 400
    if amount > 1000000:
        return "单次充值金额不能超过 100 万", 400
except (ValueError, TypeError):
    return "无效的金额格式", 400
```

---

### ✅ 修复 4：头像绑定校验（/upload）

- 从 session 中获取当前登录用户的 ID
- 禁止指定他人的 user_id
- 如需要管理后台设置头像，额外校验管理员权限

```python
# 从 session 获取当前用户，而非从表单获取 user_id
current_username = session.get("username")
conn = sqlite3.connect(DB_PATH)
c = conn.cursor()
c.execute("SELECT id FROM users WHERE username=?", (current_username,))
current_user_id = c.fetchone()[0]

# 仅更新自己的头像
c.execute("UPDATE users SET avatar=? WHERE id=?", (avatar_url, current_user_id))
```

---

### ✅ 修复 5：文件上传安全加固（/upload）

参考 `UPLOAD_VULNERABILITY_REPORT.md` 中的完整修复方案：

- 白名单校验文件后缀（仅允许 jpg/png/gif/webp）
- Magic Number 验证文件头
- UUID 重命名 + secure_filename 过滤
- 文件大小上限降至 2MB
- 上传目录配置禁止脚本执行

---

### ✅ 修复 6：CSRF Token（/recharge, /upload）

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

### ✅ 修复 7：操作审计日志

```python
import logging

logging.basicConfig(filename="recharge.log", level=logging.INFO)

# 每次充值记录：
logging.info(
    f"[RECHARGE] user_id={user_id}, amount={amount}, "
    f"operator={session.get('username')}, ip={request.remote_addr}"
)
```

---

### ✅ 修复 8：禁止用户 ID 枚举

- 对 `/profile` 等接口限制访问频率
- 未登录时不返回用户详情（统一返回 401）
- 用 UUID 替代自增 ID 作为对外标识

---

## 六、修复前后对比

| 检查项 | 修复前 | 修复后 |
|:---|:---|:---|
| **SQL 注入防护** | ❌ 直接拼接用户输入 | ✅ 参数化查询 |
| **个人中心权限** | ❌ 无需登录即可查看任意用户 | ✅ 需登录且只能查看本人 |
| **充值金额校验** | ❌ 正负数均可 | ✅ 仅允许正数 + 上限校验 |
| **越权操作余额** | ❌ 可操作任意用户余额 | ✅ 校验归属 |
| **头像绑定归属** | ❌ 可绑定到任意用户 | ✅ 仅能绑定本人 |
| **操作审计日志** | ❌ 无任何记录 | ✅ 完整日志 |
| **用户 ID 枚举** | ❌ 自增 ID 可遍历 | ✅ 频率限制 + UUID |
| **文件类型校验** | ❌ 任意文件可上传 | ✅ 白名单 + Magic Number |
| **文件名处理** | ❌ 原始文件名 | ✅ UUID 重命名 |
| **目录遍历防护** | ❌ 无 | ✅ secure_filename |
| **CSRF 防护** | ❌ 无 | ✅ CSRF Token |
| **最大文件大小** | ⚠️ 16MB | ✅ 2MB |

---

## 七、总结

本次新增的个人中心（`/profile`）和充值（`/recharge`）功能存在 **SQL 注入、IDOR 越权、业务逻辑漏洞** 等多种安全缺陷。结合已存在的任意文件上传漏洞，攻击者可实现：

```
信息泄露 → 越权操作 → 业务逻辑滥用 → SQL 注入 → 余额体系崩溃 → 任意文件上传 → 服务器沦陷
```

业务逻辑层面的漏洞（负数充值、越权操作、头像绑定他人）与传统安全漏洞（SQL 注入、文件上传）叠加后，风险被进一步放大。建议优先修复业务逻辑漏洞和 SQL 注入，其次补充权限校验和 CSRF 防护。

---

*报告生成日期：2026-07-22*
