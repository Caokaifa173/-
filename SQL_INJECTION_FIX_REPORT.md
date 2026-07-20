# 🛡️ SQL 注入漏洞修复报告 — 2026-07-20

> **基于漏洞分支 `vuln-version` → 修复分支 `fix-sqli-0720`**
> 本报告仅包含今天（2026-07-20）对 **SQL 注入漏洞** 的修复内容，不含其他漏洞修复。

---

## 🔴 漏洞1：SQL 注入 — 搜索功能

**严重程度：⭐⭐⭐⭐⭐ 致命**

**问题代码（修复前）：**
```python
# app.py 搜索功能，f-string 直接拼接用户输入
sql = f"SELECT id, username, email, phone FROM users WHERE username LIKE '%{keyword}%' OR email LIKE '%{keyword}%'"
```

**攻击方式：**
| 请求 | 效果 |
|:---|:---|
| `/?keyword=' OR 1=1 --` | 爆出全部用户数据 |
| `/?keyword=' UNION SELECT id,username,password,email FROM users WHERE '1'='1` | 爆出密码列 |

**修复方案：**
使用参数化查询（parameterized query）替代 f-string 拼接：

```python
# ✅ 修复后 — 参数化查询
like_pattern = f"%{keyword}%"
rows = conn.execute(
    "SELECT id, username, email, phone FROM users WHERE username LIKE ? OR email LIKE ?",
    (like_pattern, like_pattern)
).fetchall()
results = [dict(row) for row in rows]
```

**修复效果验证：**
- `/?keyword=' OR 1=1 --` → ✅ 返回空结果（注入失败）
- `/?keyword=' UNION SELECT ...` → ✅ 返回空结果（注入失败）

---

## 🔴 漏洞2：SQL 注入 — 注册功能

**严重程度：⭐⭐⭐⭐⭐ 致命**

**问题代码（修复前）：**
```python
# app.py 注册功能，f-string 直接拼接用户输入
sql = f"INSERT INTO users (username, password, email, phone) VALUES ('{username}', '{password}', '{email}', '{phone}')"
```

**攻击方式：**
在用户名/密码/邮箱/手机号任意输入框中构造闭合语句即可在数据库内插入任意数据，甚至通过堆叠查询执行 DELETE / UPDATE 操作。

**修复方案：**
改用参数化查询：

```python
# ✅ 修复后 — 参数化查询
conn.execute(
    "INSERT INTO users (username, password, email, phone) VALUES (?, ?, ?, ?)",
    (username, password, email, phone)
)
conn.commit()
```

**修复效果验证：**
- 注册注入 `'); DELETE FROM users; --` → ✅ 被拦截（作为普通字符串处理）
- 尝试注入执行任意 SQL → ✅ 参数化查询阻止所有拼接攻击

---

## 🔧 修复文件对照

| 文件 | 漏洞版本 | 修复版本 |
|:---|:---|:---|
| `app.py` | f-string 拼接 SQL → SQL 注入 | 参数化查询（`?` 占位符） |
| `SQL_INJECTION_FIX_REPORT.md` | — | ✅ 新增（本报告） |

---

## 📁 分支说明

| 分支 | 内容 |
|:---|:---|
| `vuln-version` | 有漏洞版本（f-string SQL 拼接） |
| `fix-sqli-0720` | ✅ **仅修复 SQL 注入问题**（参数化查询） |

---

*报告生成时间：2026-07-20 05:37 EDT*
