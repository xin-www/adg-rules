import re
import urllib.request
from datetime import datetime

# 上游规则
RULE_URLS = [
    # 1. 基础全能拦截库 (HaGeZi PRO + AdGuard 基础)
    "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/adblock/pro.txt",
    "https://adguardteam.github.io/HostlistsRegistry/assets/filter_1.txt",
    # 2.  秋风规则 (国内 App 开屏与跳转打点) 
    "https://raw.githubusercontent.com/TG-Twilight/AWAvenue-Ads-Rule/main/AWAvenue-Ads-Rule.txt",
    # 3. 封堵国内主流 HTTPDNS 绕过 (blackmatrix7 HTTPDNS 专库)
    "https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/master/rule/AdGuard/HTTPDNS/HTTPDNS.txt",
    # 4. AdGuard 防追踪 （错误监控、遥测打点、A/B测试、邮件跟踪）
    "https://adguardteam.github.io/HostlistsRegistry/assets/filter_3.txt",
    # 5. 补齐 Cookie 横幅与弹窗通知 (AdGuard 烦人元素)
    "https://adguardteam.github.io/HostlistsRegistry/assets/filter_4.txt",
]

OUTPUT_FILE = "rules.txt"
DOMAIN_REGEX = re.compile(
    r"^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-_]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,63}$"
)


def fetch_rules(url):
    print(f"Downloading: {url}")
    req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
    try:
        with urllib.request.urlopen(req, timeout=60) as resp:
            return resp.read().decode("utf-8", errors="ignore").splitlines()
    except Exception as e:
        print(f"Failed to fetch {url}: {e}")
        return []


def normalize_line(line):
    line = line.strip()
    if not line or line.startswith(
        ("!", "#", "[", ";", "/*", "*", "</", "<!", "<html")
    ):
        return None

    # 去除行末注释
    for sep in [" #", " !"]:
        if sep in line:
            line = line.split(sep)[0].strip()

    # 处理 Adblock 语法: ||example.com^
    if line.startswith("||"):
        match = re.match(r"^\|\|([a-zA-Z0-9.\-_]+)\^", line)
        if match:
            domain = match.group(1).lower()
            return domain if DOMAIN_REGEX.match(domain) else None

    # 处理 Hosts 语法: 0.0.0.0 example.com
    parts = line.split()
    if len(parts) >= 2 and parts[0] in [
        "0.0.0.0",
        "127.0.0.1",
        "::1",
        "::",
        "broadcasthost",
    ]:
        domain = parts[1].lower()
        if domain not in ["localhost", "local", "broadcasthost"]:
            return domain if DOMAIN_REGEX.match(domain) else None

    # 处理纯域名语法: example.com
    if len(parts) == 1 and DOMAIN_REGEX.match(parts[0].lower()):
        return parts[0].lower()

    return None


def main():
    unique_domains = set()

    for url in RULE_URLS:
        lines = fetch_rules(url)
        for line in lines:
            domain = normalize_line(line)
            if domain:
                unique_domains.add(domain)

    sorted_domains = sorted(unique_domains)
    now_str = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC")

    with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
        f.write("! Title: Personal Merged AdGuard Rules\n")
        f.write(f"! Last Modified: {now_str}\n")
        f.write(f"! Total Count: {len(sorted_domains)}\n")
        f.write("!\n")
        for domain in sorted_domains:
            f.write(f"||{domain}^\n")

    print(f"Successfully generated {len(sorted_domains)} rules.")


if __name__ == "__main__":
    main()
