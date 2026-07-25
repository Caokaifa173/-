# 个性化页面功能 - 安全审计报告

**审计日期：** 2026-07-25
**新增功能：** 欢迎页 (`/welcome`) + 反馈页 (`/feedback`)
**审计范围：** 本次新增的 app.py 路由及渲染逻辑

---

## 漏洞 1：欢迎页 Server-Side Template Injection (SSTI) — `/welcome`

| 项目 | 内容 |
|------|------|
| **漏洞名称** | Server-Side Template Injection（SSTI） |
| **严重等级** | 🔴 **严重** |
| **漏洞位置** | `app.py` — `welcome()` 函数，第 7 行：`render_template_string(html)` |
| **触发方式** | `GET /welcome?name={{config.__class__.__init__.__globals__}}` |
| **风险描述** | 使用 `render_template_string` 处理直接拼接用户输入的字符串。虽然代码使用了 f-string 拼接 `{name}`，但 `render_template_string` 会对结果字符串**二次解析 Jinja2 模板语法**。如果用户在 name 参数中注入 `{{ }}` 模板表达式（如 `{{7*7}}`），Jinja2 会执行该表达式。攻击者可进一步利用 SSTI 读取 Flask 配置、环境变量、文件内容，甚至实现远程代码执行（RCE）。 |
| **影响范围** | 任意未登录用户可触发 |
| **修复建议** | 1. 改用 `render_template` + 模板变量传参，而非直接拼接字符串 |
|   | 2. 若必须使用 `render_template_string`，先对用户输入进行 HTML/Jinja2 转义（如用 `str.replace` 替换 `{{` 等关键字） |
|   | 3. 使用 `Markup.escape()` 对用户输入进行转义后再拼接 |

**验证 Payload：**
```
/welcome?name={{7*7}}
```
返回页面显示"欢迎你，49！"即为 SSTI 漏洞存在。

---

## 漏洞 2：反馈页 SSTI — `/feedback` POST

| 项目 | 内容 |
|------|------|
| **漏洞名称** | Server-Side Template Injection（SSTI） |
| **严重等级** | 🔴 **严重** |
| **漏洞位置** | `app.py` — `feedback()` 函数（POST 分支） |
| **触发方式** | 提交反馈表单，name 或 message 字段中注入 Jinja2 模板语法 |
| **风险描述** | 同漏洞 1，POST 提交的 `name` 和 `message` 均通过 f-string 拼接到 HTML 字符串中，再被 `render_template_string` 二次解析。攻击者可在表单字段中注入 `{{ }}` 模板表达式，实现任意代码执行。 |
| **影响范围** | 任意未登录用户可触发 |
| **修复建议** | 同漏洞 1，对用户输入做转义或使用模板变量传参 |

---

## 漏洞 3：反馈页反射型 XSS — `/feedback` POST

| 项目 | 内容 |
|------|------|
| **漏洞名称** | 反射型跨站脚本（Reflected XSS） |
| **严重等级** | 🔴 **高危** |
| **漏洞位置** | `app.py` — `feedback()` 函数的 POST 分支 |
| **触发方式** | 提交反馈时 name 或 message 中包含 `<script>alert(1)</script>` |
| **风险描述** | 用户输入未经任何 HTML 转义直接渲染到页面中。即使不考虑 SSTI，攻击者也可以提交任意 JavaScript 代码在受害者浏览器中执行，如盗取 Cookie、重定向钓鱼页面等。 |
| **影响范围** | 任意未登录用户可触发 |
| **修复建议** | 使用 `html.escape()` 对用户输入进行 HTML 实体转义后再渲染 |

**验证 Payload：**
```
name = <script>alert(document.cookie)</script>
```

---

## 漏洞 4：欢迎页反射型 XSS — `/welcome`

| 项目 | 内容 |
|------|------|
| **漏洞名称** | 反射型跨站脚本（Reflected XSS） |
| **严重等级** | 🔴 **高危** |
| **漏洞位置** | `app.py` — `welcome()` 函数 |
| **触发方式** | `GET /welcome?name=<script>alert(1)</script>` |
| **风险描述** | 同漏洞 3，name 参数直接拼接进 HTML 的 `<h1>` 标签内，攻击者可构造恶意链接诱导用户点击。 |
| **影响范围** | 任意未登录用户可触发 |
| **修复建议** | 对 name 进行 HTML 实体转义 |

---

## 漏洞 5：欢迎页导航栏缺少登录态信息

| 项目 | 内容 |
|------|------|
| **漏洞名称** | 导航栏未展示用户登录状态 |
| **严重等级** | 🟢 **低危** |
| **漏洞位置** | `app.py` — `welcome()` 和 `feedback()` 的 render_template_string 中的硬编码导航栏 |
| **风险描述** | 欢迎页和反馈页使用独立的硬编码导航栏，没有读取 session 中的用户登录信息，登录用户访问这些页面时看不到自己的用户名等上下文信息。虽无安全直接危害，但可能配合其他钓鱼场景。 |
| **影响范围** | 所有已登录用户 |
| **修复建议** | 在 render_template_string 生成的导航栏中，根据 `session.get('username')` 动态显示用户信息 |

---

## 漏洞 6：反馈 GET 表单无 CSRF 防护

| 项目 | 内容 |
|------|------|
| **漏洞名称** | 缺少 CSRF Token 保护 |
| **严重等级** | 🟡 **中危** |
| **漏洞位置** | `app.py` — `feedback()` GET 分支的表单 |
| **触发方式** | 攻击者构造恶意页面，诱导已登录用户提交表单 |
| **风险描述** | 反馈表单没有 CSRF Token 校验，攻击者可构造跨站请求伪造，让受害者在不知情下提交反馈内容。 |
| **影响范围** | 已登录用户 |
| **修复建议** | 引入 Flask-WTF 或手动生成/校验 CSRF Token |

---

## 漏洞 7：反馈 GET 表单以 GET 方式提交

| 项目 | 内容 |
|------|------|
| **漏洞名称** | 反馈表单 method=GET 时的设计缺陷 |
| **严重等级** | 🟢 **低危** |
| **漏洞位置** | 表单 method 为 `post`（无误，但无 CSRF） |
| **备注** | 已正确配置 method="post"，此项为误报标记，实际无此问题 |

---

## 漏洞汇总

| # | 漏洞名称 | 等级 | 涉及路由 |
|---|---------|------|---------|
| 1 | Server-Side Template Injection（SSTI） | 🔴 严重 | `/welcome` |
| 2 | Server-Side Template Injection（SSTI） | 🔴 严重 | `/feedback` POST |
| 3 | 反射型 XSS | 🔴 高危 | `/feedback` POST |
| 4 | 反射型 XSS | 🔴 高危 | `/welcome` |
| 5 | 导航栏缺失登录态 | 🟢 低危 | `/welcome`, `/feedback` |
| 6 | 缺少 CSRF Token | 🟡 中危 | `/feedback` POST |

---

## 修复优先级建议

1. **立即修复** — 漏洞 1、2（SSTI → 可导致 RCE）
2. **尽快修复** — 漏洞 3、4（反射型 XSS）
3. **建议修复** — 漏洞 5、6（CSRF、导航栏）

---

*报告生成时间：2026-07-25 04:20 EDT*
*审计工具：人工代码审查*
