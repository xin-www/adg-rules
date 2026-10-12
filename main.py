import re
import urllib.request
from datetime import datetime

RULE_URLS = [
    "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/adblock/pro.txt",
    "https://adguardteam.github.io/HostlistsRegistry/assets/filter_1.txt",
    "https://raw.githubusercontent.com/TG-Twilight/AWAvenue-Ads-Rule/main/AWAvenue-Ads-Rule.txt",
    "https://adguardteam.github.io/HostlistsRegistry/assets/filter_3.txt",
    "https://adguardteam.github.io/HostlistsRegistry/assets/filter_4.txt",
]

OUTPUT_FILE = "rules.txt"

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

def extract_pure_domain(line):
    """只提取最普通的域名，遇到白名单或修饰符直接返回 None，交给外部原样保留"""
    # 处理 Adblock 语法: ||domain^
    if line.startswith("||"):
        line = line[2:]
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

def optimize_domains(domains):
    """对纯净的拦截域名进行父子覆盖去重"""
    optimized = set()
    for domain in domains:
        clean_domain = domain[2:] if domain.startswith("*.") else domain
        parts = clean_domain.split('.')
        is_covered = False
        
        for i in range(1, len(parts) - 1):
            parent_domain = '.'.join(parts[i:])
            if parent_domain in domains or f"*.{parent_domain}" in domains:
                is_covered = True
                break
                
        if not is_covered:
            optimized.add(domain)
    return optimized

def main():
    whitelists = set()       # 存放 @@ 白名单
    modifier_rules = set()   # 存放带 $ 的修饰符规则
    pure_domains = set()     # 存放需要去重的纯域名

    for url in RULE_URLS:
        lines = fetch_rules(url)
        for line in lines:
            line = line.strip()
            # 过滤空行和注释
            if not line or line.startswith(("!", "#", "[", ";", "/*", "*", "</", "<!", "<html")):
                continue
            
            # 去除行尾注释
            for sep in [" #", " !"]:
                if sep in line:
                    line = line.split(sep)[0].strip()

            # 1. 优先提取并原样保留白名单 (防止误杀)
            if line.startswith("@@"):
                whitelists.add(line)
                continue
            
            # 2. 提取并原样保留带修饰符的高级规则 (防止破坏规则逻辑)
            if "$" in line:
                modifier_rules.add(line)
                continue

            # 3. 对普通的拦截规则进行域名提取
            domain = extract_pure_domain(line)
            if domain:
                pure_domains.add(domain)

    print(f"✅ 抓取分类完成：白名单 {len(whitelists)} 条，高级规则 {len(modifier_rules)} 条，待精简普通域名 {len(pure_domains)} 条")

    # 4. 仅对普通域名进行父子瘦身
    print("⏳ 正在执行父子域名深度比对剔除...")
    optimized_domains = optimize_domains(pure_domains)
    
    sorted_whitelists = sorted(whitelists)
    sorted_modifiers = sorted(modifier_rules)
    sorted_domains = sorted(optimized_domains)
    now_str = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC")
    
    final_count = len(sorted_whitelists) + len(sorted_modifiers) + len(sorted_domains)
    saved_count = len(pure_domains) - len(optimized_domains)

    with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
        f.write("! Title: Personal Merged AdGuard Rules (Safe Edition)\n")
        f.write(f"! Last Modified: {now_str}\n")
        f.write(f"! Total Count: {final_count}\n")
        f.write("!\n")
        
        # 按优先级输出：白名单 > 高级规则 > 普通规则
        for w in sorted_whitelists:
            f.write(f"{w}\n")
        for m in sorted_modifiers:
            f.write(f"{m}\n")
        for domain in sorted_domains:
            clean_domain = domain[2:] if domain.startswith("*.") else domain
            f.write(f"||{clean_domain}^\n")

    print(f"🎯 瘦身完成！剔除冗余子域名: {saved_count} 条")
    print(f"📦 最终生成安全规则数: {final_count} 条")

if __name__ == "__main__":
    main()
