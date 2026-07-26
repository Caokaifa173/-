# MEMORY.md - 长期记忆

## 项目：用户信息管理平台（安全审计版）

**仓库：** https://github.com/Caokaifa173/-.git
**框架说明：** 这个框架每天会新增一些内容（新功能新文件），对应的日期就是当天新增的项目内容。

### 2026-07-19（初始化 + 安全增强修复）
完成了 Flask 用户信息管理平台的搭建和安全审计加固，共 2 个 commit：

1. **初始化（845f629）**：Flask 基础框架 — app.py 主应用、login/index/base 模板、CSS 样式、初始搜索模块
2. **安全增强修复（6ffe8f6）**：全面安全大整改 — bcrypt 密码哈希、环境变量配置隔离、密码策略验证模块、Session 安全、频率限制、CSP 头、用户脱敏、安全日志记录等 13 项安全修复
   - 重构了项目结构（config/models/utils 模块化）
   - 删除了 `hunter_search.py`
   - 生成了漏洞修复报告 `docs/vulnerability_report.docx`

**GitHub Token：** ***已移除***
**默认用户：** admin / Admin@12345（admin 角色），alice / Alice@2025（user 角色）
**技术栈：** Flask 3.0+, bcrypt, Flask-Limiter, python-dotenv

### 2026-07-24（新增密码修改功能 + 漏洞修复报告）

#### 第一次提交（commit: 38b1159）- 新增密码修改功能

1. **app.py** — 新增两个路由：
   - `/profile`：个人中心页面，展示用户信息
   - `/change-password`（POST）：修改密码功能
     - 无需验证原密码
     - 无需 CSRF Token
     - 不验证 session 用户和提交的 username 是否一致
     - 只要 session 中有登录状态即可修改

2. **templates/profile.html** — 全新个人中心页面
   - 展示用户个人信息
   - 包含修改密码表单（新密码、确认密码、修改按钮）
   - 通过隐藏字段传递 username

3. **templates/index.html** — 已登录状态增加「个人中心」入口

4. **models/user.py** — 新增 `update_password()` 方法
   - 直接使用 bcrypt 哈希新密码并更新
   - 不验证原密码

**安全隐患：** 任何已登录用户可修改任何人的密码（包括 admin）

#### 第二次提交（commit: 7fc6809）- 新增密码修改功能漏洞修复报告

- 生成 `docs/day7漏洞修复报告.docx`（39,888 bytes）
- 发现 5 个漏洞：

  | # | 漏洞名称 | 等级 |
  |---|---------|------|
  | 1 | 任意用户密码修改（越权） | 🔴 严重 |
  | 2 | 无需验证原密码 | 🔴 高危 |
  | 3 | 无 CSRF Token 防护 | 🔴 高危 |
  | 4 | 敏感字段暴露在前端 | 🟡 中危 |
  | 5 | 无请求来源校验 | 🟡 中危 |
