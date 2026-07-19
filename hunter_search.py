#!/usr/bin/env python3
"""
鹰图 (Hunter) 网络空间搜索引擎 - API 查询工具
=============================================
使用奇安信鹰图开放 API 搜索网络资产信息。

API 文档: https://hunter.qianxin.com/home/helpCenter?r=5-1-2

积分说明：
  - 每天赠送 500 免费积分
  - 每次搜索消耗 1 积分/条（即 page_size=10 消耗 10 积分）
  - 免费积分每日重置，不累计

默认每次只搜索 10 条数据（硬限制），除非使用者通过 --page-size 明确更改。
"""

import argparse
import base64
import csv
import json
import os
import sys
import time
from datetime import datetime, timedelta
from typing import Any, Optional

import requests

API_BASE = "https://hunter.qianxin.com/openApi/search"


def load_api_key(key_path: Optional[str] = None) -> str:
    """从文件或环境变量加载 API Key"""
    if key_path:
        with open(key_path) as f:
            return f.read().strip()

    env_key = os.environ.get("HUNTER_API_KEY")
    if env_key:
        return env_key

    # 尝试从默认路径读取
    default_paths = [
        os.path.expanduser("~/.hunter/api-key"),
        os.path.expanduser("~/.config/hunter/api-key"),
    ]
    for p in default_paths:
        if os.path.isfile(p):
            with open(p) as f:
                return f.read().strip()

    raise ValueError(
        "未找到 API Key。请通过 --api-key 参数传入，"
        "或设置 HUNTER_API_KEY 环境变量，"
        "或将 Key 写入 ~/.hunter/api-key"
    )


def encode_search(query: str) -> str:
    """对搜索语法进行 Base64 URL-safe 编码"""
    return base64.urlsafe_b64encode(query.encode("utf-8")).decode("ascii")


def search(
    api_key: str,
    query: str,
    page: int = 1,
    page_size: int = 10,
    is_web: str = "3",
    start_time: str = "",
    end_time: str = "",
    port_filter: bool = False,
) -> dict[str, Any]:
    """
    执行鹰图 API 搜索

    参数:
        api_key: API 密钥
        query: 搜索语法（明文，函数内部自动编码）
        page: 页码
        page_size: 每页数量
        is_web: 资产类型（1=Web, 2=非Web, 3=全部）
        start_time: 开始时间 YYYY-MM-DD
        end_time: 结束时间 YYYY-MM-DD
        port_filter: 是否端口过滤
    """
    if not start_time:
        start_time = (datetime.now() - timedelta(days=365)).strftime("%Y-%m-%d")
    if not end_time:
        end_time = datetime.now().strftime("%Y-%m-%d")

    params = {
        "api-key": api_key,
        "search": encode_search(query),
        "page": str(page),
        "page_size": str(page_size),
        "is_web": is_web,
        "start_time": start_time,
        "end_time": end_time,
        "port_filter": "true" if port_filter else "false",
    }

    print(f"[*] 请求参数: page={page}, page_size={page_size}, query={query}")
    print(f"[*] 时间范围: {start_time} ~ {end_time}")

    resp = requests.get(API_BASE, params=params, timeout=30)
    data = resp.json()

    code = data.get("code")
    if code != 200:
        msg = data.get("message", data.get("msg", "未知错误"))
        raise Exception(f"API 错误 (code={code}): {msg}")

    return data


def format_results(data: dict[str, Any], show_raw: bool = False) -> list[dict[str, Any]]:
    """格式化结果列表"""
    results = []
    items = (
        data.get("data", {})
        .get("arr", [])
        or data.get("data", {})
        .get("list", [])
        or data.get("data", {})
        .get("results", [])
    )

    for item in items:
        if show_raw:
            results.append(item)
        else:
            results.append(
                {
                    "ip": item.get("ip", ""),
                    "port": item.get("port", ""),
                    "protocol": item.get("protocol", ""),
                    "domain": item.get("domain", ""),
                    "url": item.get("url", ""),
                    "title": item.get("web_title", item.get("title", "")),
                    "status_code": item.get("status_code", ""),
                    "country": item.get("country", ""),
                    "province": item.get("province", ""),
                    "city": item.get("city", ""),
                    "company": item.get("company", item.get("organization", "")),
                    "server": item.get("server", ""),
                    "os": item.get("os", ""),
                    "banner": (item.get("banner", "") or "")[:200],
                }
            )
    return results


def print_results(results: list[dict[str, Any]], show_raw: bool = False):
    """打印结果到终端"""
    if not results:
        print("[!] 未找到匹配的资产")
        return

    print(f"\n{'='*90}")
    print(f"  共 {len(results)} 条结果")
    print(f"{'='*90}")

    if show_raw:
        for r in results:
            print(json.dumps(r, ensure_ascii=False, indent=2))
            print("-" * 40)
        return

    for i, r in enumerate(results, 1):
        print(f"\n  [{i:>3}] {r['ip']}:{r['port']}  ({r['protocol']})")
        if r["domain"]:
            print(f"       域名: {r['domain']}")
        if r["url"]:
            print(f"       URL: {r['url']}")
        if r["title"]:
            print(f"       标题: {r['title']}")
        print(f"       状态码: {r['status_code']}")
        if r["city"]:
            print(f"       位置: {r['country']} {r['province']} {r['city']}")
        if r["company"]:
            print(f"       归属: {r['company']}")
        if r["server"]:
            print(f"       服务器: {r['server']}")
        if r["banner"]:
            print(f"       Banner: {r['banner'][:100]}")
    print(f"\n{'='*90}")
    print(f"  共 {len(results)} 条结果")
    print(f"{'='*90}\n")


def save_csv(results: list[dict[str, Any]], output_path: str):
    """保存结果为 CSV 文件"""
    if not results:
        print("[!] 无数据可保存")
        return

    fieldnames = results[0].keys()
    with open(output_path, "w", newline="", encoding="utf-8-sig") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(results)

    print(f"[✓] 已保存 {len(results)} 条结果到 {output_path}")


def save_json(results: list[dict[str, Any]], output_path: str):
    """保存结果为 JSON 文件"""
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(results, f, ensure_ascii=False, indent=2)
    print(f"[✓] 已保存 {len(results)} 条结果到 {output_path}")


def main():
    parser = argparse.ArgumentParser(
        description="鹰图 (Hunter) 网络资产搜索工具",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
使用示例:
  # 基础搜索（默认 page_size=10，硬限制）
  python3 hunter_search.py --api-key YOUR_KEY --search 'ip="1.1.1.1"'

  # 搜索 Web 资产
  python3 hunter_search.py --search 'web.body="phpinfo"' --is-web 1

  # 指定时间范围
  python3 hunter_search.py --search 'port="8080"' --start 2024-01-01 --end 2024-12-31

  # 搜索多页（总消耗积分 = page_size × total_page）
  python3 hunter_search.py --search 'app="nginx"' --pages 3

  # 明确覆盖 page_size（需使用者主动操作，非误触）
  python3 hunter_search.py --search 'app="tomcat"' --page-size 50

  # 输出 JSON/CSV
  python3 hunter_search.py --search 'domain="example.com"' -o results.json
  python3 hunter_search.py --search 'port="443"' -o results.csv

  # 使用环境变量（推荐）
  export HUNTER_API_KEY="your_key_here"
  python3 hunter_search.py --search 'app="nps"'
        """,
    )

    # 搜索参数
    parser.add_argument("--api-key", help="鹰图 API Key（也可通过 HUNTER_API_KEY 环境变量设置）")
    parser.add_argument("--key-file", help="从文件读取 API Key")
    parser.add_argument("--search", "-s", required=True, help="搜索语法（如 app='nginx'、ip='1.1.1.1'）")
    parser.add_argument("--page-size", type=int, default=10,
                        help="每页条数，默认 10（硬限制，除非你明确知道并有意修改）")
    parser.add_argument("--page", type=int, default=1, help="起始页码（默认 1）")
    parser.add_argument("--pages", type=int, default=1, help="总共获取多少页（默认 1）")
    parser.add_argument("--is-web", type=int, choices=[1, 2, 3], default=3,
                        help="资产类型：1=Web, 2=非Web, 3=全部（默认）")
    parser.add_argument("--start", default="", help="开始时间 YYYY-MM-DD")
    parser.add_argument("--end", default="", help="结束时间 YYYY-MM-DD")
    parser.add_argument("--port-filter", action="store_true", help="开启端口过滤")

    # 输出控制
    parser.add_argument("--output", "-o", default="", help="输出文件路径（.json 或 .csv）")
    parser.add_argument("--raw", action="store_true", help="显示原始 API 返回数据")
    parser.add_argument("--delay", type=float, default=1.0, help="翻页间隔秒数（默认 1.0s）")

    # 配额信息
    parser.add_argument("--quota", action="store_true", help="仅查询剩余积分，不执行搜索")

    args = parser.parse_args()

    # 加载 API Key
    api_key = None
    if args.api_key:
        api_key = args.api_key
    elif args.key_file:
        api_key = load_api_key(args.key_file)
    else:
        api_key = load_api_key()

    if not api_key:
        print("[!] 错误: 未提供 API Key")
        sys.exit(1)

    # 显示 API Key 前缀用于确认
    print(f"[*] API Key: {api_key[:8]}...{api_key[-4:]}")

    # 仅查询积分
    if args.quota:
        print("[*] 查询剩余积分...")
        try:
            # 用一个空搜索来获取积分信息
            result = search(api_key, 'ip="8.8.8.8"', page=1, page_size=1)
            data = result.get("data", {})
            rest_quota = data.get("rest_quota", data.get("remain_quota", data.get("total_quota", "未知")))
            print(f"[✓] 剩余积分: {rest_quota}")
        except Exception as e:
            print(f"[!] 查询失败: {e}")
        return

    # 核对 page_size 硬限制
    if args.page_size != 10:
        print(f"\n{'='*60}")
        print(f"  ⚠️  page_size 已从默认 10 修改为 {args.page_size}")
        print(f"  确认继续? 输入 YES 确认: ", end="", flush=True)
        confirm = input().strip()
        if confirm != "YES":
            print("[!] 已取消")
            return
        print(f"{'='*60}\n")

    # 估算积分消耗
    total_pages = args.pages
    total_results = args.page_size * total_pages
    print(f"\n[*] 搜索配置:")
    print(f"    搜索语法: {args.search}")
    print(f"    每页条数: {args.page_size}")
    print(f"    总页数:   {total_pages}")
    print(f"    预估消耗: ~{total_results} 积分")
    print(f"    资产类型: {['', 'Web', '非Web', '全部'][args.is_web]}")
    print()

    if total_results > 500:
        print(f"[!] 警告: 预估消耗 {total_results} 积分，可能超出每日配额（500）")
        print(f"    确认继续? 输入 YES 确认: ", end="", flush=True)
        confirm = input().strip()
        if confirm != "YES":
            print("[!] 已取消")
            return

    # 执行搜索
    all_results: list[dict[str, Any]] = []
    total = 0

    for page in range(args.page, args.page + total_pages):
        print(f"\n[{'-'*40}]")
        print(f"  正在获取第 {page} 页...")

        try:
            data = search(
                api_key,
                args.search,
                page=page,
                page_size=args.page_size,
                is_web=str(args.is_web),
                start_time=args.start,
                end_time=args.end,
                port_filter=args.port_filter,
            )

            # 显示配额信息
            rest = data.get("data", {}).get("rest_quota", data.get("data", {}).get("remain_quota", "?"))
            total = data.get("data", {}).get("total", data.get("data", {}).get("total_count", 0))
            consume = data.get("data", {}).get("consume_quota", data.get("data", {}).get("cost_quota", "?"))
            print(f"    总匹配数: {total} | 本页消耗: {consume} | 剩余积分: {rest}")

            results = format_results(data, show_raw=args.raw)
            if not results:
                print("    [-] 本页无结果")
                break

            all_results.extend(results)
            print_results(results, show_raw=args.raw)

            # 如果已获取完所有结果，提前结束
            if len(all_results) >= total:
                print(f"[*] 已获取全部 {total} 条结果，停止翻页")
                break

            # 翻页间隔
            if page < args.page + total_pages - 1:
                delay = args.delay
                print(f"\n[*] 等待 {delay}s 后翻到下一页...")
                time.sleep(delay)

        except KeyboardInterrupt:
            print("\n[!] 用户中断")
            break
        except Exception as e:
            print(f"[!] 搜索失败: {e}")
            break

    # 输出汇总
    print(f"\n{'='*50}")
    print(f"  搜索完成")
    print(f"  共获取: {len(all_results)} 条结果")
    print(f"{'='*50}")

    # 保存结果
    if args.output and all_results:
        if args.output.endswith(".csv"):
            save_csv(all_results, args.output)
        elif args.output.endswith(".json"):
            save_json(all_results, args.output)
        else:
            # 根据内容自动选择
            if args.raw:
                save_json(all_results, args.output)
            else:
                save_json(all_results, args.output)


if __name__ == "__main__":
    main()
