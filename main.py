import re
import urllib.request
from datetime import datetime

RULE_URLS = [
    # 基础全能拦截
    "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/adblock/pro.txt",
    "https://adguardteam.github.io/HostlistsRegistry/assets/filter_1.txt",
    # 国内应用开屏与移动端
    "https://raw.githubusercontent.com/TG-Twilight/AWAvenue-Ads-Rule/main/AWAvenue-Ads-Rule.txt",
    # 封堵 HTTPDNS
    "https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/master/rule/AdGuard/HTTPDNS/HTTPDNS.txt",
    # 防追踪、遥测、报错、社交打点 (Filter 3)
    "https://adguardteam.github.io/HostlistsRegistry/assets/filter_3.txt",
    # Cookie横幅、弹窗通知、烦人元素 (Filter 4)
    "https://adguardteam.github.io/HostlistsRegistry/assets/filter_4.txt",
]

OUTPUT_FILE = "rules.txt"

# 放宽的域名校验：允许标准域名，也兼容通配符
DOMAIN_PATTERN = re.compile(
    r"^(?:\*\.)?(?:[a-zA-Z0-9](?:[a-zA-Z0-9-_]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,63}$"
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

def extract_domain(line):
    line = line.strip()
    if not line or line.startswith(("!", "#", "[", ";", "/*", "*", "</", "<!", "<html")):
        return None

    # 去掉尾部注释
    for sep in [" #", " !"]:
        if sep in line:
            line = line.split(sep)[0].strip()

    # 去掉 AdGuard 修饰符 (如 $third-party, $image, $popup 等)
    if "$" in line:
        line = line.split("$")[0].strip()

    # 处理 Adblock 语法: ||domain^
    if line.startswith("||"):
        # 去掉开头的 ||
        line = line[2:]
        # 去掉分隔符及后面的路径 (例如 ||domain.com/path^ 或 ||domain.com^)
        for delim in ["^", "/", ":"]:
            if delim in line:
                line = line.split(delim)[0]
        domain = line.strip().lower()
        if DOMAIN_PATTERN.match(domain):
            return domain

    # 处理 Hosts 语法: 0.0.0.0 domain.com
    parts = line.split()
    if len(parts) >= 2 and parts[0] in ["0.0.0.0", "127.0.0.1", "::1", "::"]:
        domain = parts[1].strip().lower()
        if domain not in ["localhost", "local", "broadcasthost"] and DOMAIN_PATTERN.match(domain):
            return domain

    # 处理纯域名列表
    if len(parts) == 1:
        domain = parts[0].strip().lower()
        if DOMAIN_PATTERN.match(domain):
            return domain

    return None

def main():
    unique_domains = set()

    for url in RULE_URLS:
        lines = fetch_rules(url)
        for line in lines:
            domain = extract_domain(line)
            if domain:
                unique_domains.add(domain)

    # 排序输出标准 AdGuard 语法
    sorted_domains = sorted(unique_domains)
    now_str = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC")

    with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
        f.write("! Title: Personal Merged AdGuard Rules\n")
        f.write(f"! Last Modified: {now_str}\n")
        f.write(f"! Total Count: {len(sorted_domains)}\n")
        f.write("!\n")
        for domain in sorted_domains:
            f.write(f"||{domain}^\n")

    print(f"Generated {len(sorted_domains)} clean rules.")

if __name__ == "__main__":
    main()
