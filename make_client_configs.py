#!/usr/bin/env python3
"""Generate strict-TLS, foreign-proxy / domestic-direct client profiles."""
import concurrent.futures
import hashlib
import json
import os
import subprocess
import time
import urllib.request
import ipaddress
from pathlib import Path
import argparse
from common import load_settings
from urllib.parse import quote

import yaml

ROOT = Path(__file__).resolve().parent
OUT = ROOT / "private"
CACHE = ROOT / "rules-cache"
CLI = "/Applications/Surge.app/Contents/Applications/surge-cli"
BASE = "https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/master/rule/Surge"
SERVICES = ["Google", "OpenAI", "Claude", "YouTube", "Twitch", "Discord", "GitHub"]
PINNED_FOREIGN = [
    "google.com", "google.cn", "googleapis.com", "gstatic.com", "googleusercontent.com", "googlevideo.com",
    "youtube.com", "youtu.be", "ytimg.com", "ggpht.com", "withgoogle.com", "gemini.google.com",
    "openai.com", "chatgpt.com", "oaistatic.com", "oaiusercontent.com", "openaiapi-site.azureedge.net",
    "anthropic.com", "claude.ai", "claude.com", "claudeusercontent.com", "claudecontent.com",
    "twitch.tv", "ttvnw.net", "jtvnw.net", "twitchcdn.net", "ext-twitch.tv",
    "discord.com", "discord.gg", "discordapp.com", "discordapp.net", "discord.media", "discordcdn.com",
    "github.com", "githubusercontent.com", "githubassets.com", "auth0.com", "challenges.cloudflare.com",
    "dns.google", "cloudflare-dns.com",
]
PINNED_DOMESTIC = [
    "baidu.com", "bdstatic.com", "qq.com", "qpic.cn", "qlogo.cn", "wechat.com", "weixin.qq.com",
    "taobao.com", "tmall.com", "alipay.com", "alipayobjects.com", "aliyun.com", "alicdn.com",
    "jd.com", "360buyimg.com", "bilibili.com", "bilivideo.com", "biliapi.net", "hdslb.com",
    "douyin.com", "douyincdn.com", "douyinpic.com", "amemv.com", "snssdk.com", "zijieapi.com",
    "toutiao.com", "pstatp.com", "bytedance.com", "feishu.cn", "feishucdn.com", "dingtalk.com",
    "zhihu.com", "zhimg.com", "weibo.com", "weibocdn.com", "sina.com.cn", "xiaohongshu.com",
    "xhscdn.com", "xiaohongshu.net", "meituan.com", "dianping.com", "163.com", "126.net",
    "netease.com", "music.163.com", "youku.com", "iqiyi.com", "ctyun.cn", "wosms.cn", "cn",
]

def private_write(path, content):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as f:
        f.write(content)
    Path(path).chmod(0o600)

def fetch(service):
    url = f"{BASE}/{service}/{service}.list"
    p = CACHE / f"{service}.list"
    if p.exists() and time.time() - p.stat().st_mtime < 86400:
        text = p.read_text()
    else:
        text = urllib.request.urlopen(url, timeout=25).read().decode()
        p.write_text(text)
    return service, url, text

def build_nodes(credentials):
    """Return ordered node dictionaries and their import URIs."""
    host, password = credentials["server"], credentials["password"]
    blueprint = OUT / "optimized-nodes.json"
    nodes = []
    if blueprint.exists():
        spec = json.loads(blueprint.read_text())
        for entry in spec.get("nodes", []):
            kind = entry["type"].lower()
            if kind not in ("trojan", "hysteria2"):
                raise ValueError("optimized node type must be trojan or hysteria2")
            parsed_address = ipaddress.ip_address(entry["server"])
            # The blueprint may also list the established IPv4 fallback nodes so
            # its complete order can be preserved. Other entries must be IPv6.
            if parsed_address.version != 6 and str(parsed_address) != str(ipaddress.ip_address(host)):
                raise ValueError("optimized node server must be IPv6 or the configured IPv4 fallback")
            address = str(parsed_address)
            name = entry["name"]
            for value in [name, entry.get("password", password), entry.get("sni", host), entry.get("obfs_password", "")]:
                if not isinstance(value, str) or any(char in value for char in "\r\n,="):
                    raise ValueError("node fields must be single-line INI-safe strings")
            for rate in ("download_mbps", "upload_mbps"):
                if rate in entry and (isinstance(entry[rate], bool) or not isinstance(entry[rate], (int,float)) or not 0 < entry[rate] <= 10000):
                    raise ValueError("bandwidth must be numeric and in (0,10000]")
            port = int(entry["port"])
            if not 1 <= port <= 65535:
                raise ValueError("optimized node port is out of range")
            node = {"name":name, "type":kind, "server":address, "port":port,
                "password":entry.get("password", password), "sni":entry.get("sni", address)}
            for field in ("download_mbps", "upload_mbps", "obfs_password"):
                if field in entry:
                    node[field] = entry[field]
            nodes.append(node)
    # Always retain the existing IPv4 profiles as fallbacks, preserving their ordering.
    existing = {(n["type"], n["server"], n["port"]) for n in nodes}
    if (OUT / "hysteria-enabled").exists() and ("hysteria2", host, credentials["port"]) not in existing:
        nodes.append({"name":"VPS-Hysteria2", "type":"hysteria2", "server":host,
            "port":credentials["port"], "password":password, "sni":host,
            "download_mbps":20, "upload_mbps":10})
    if ("trojan", host, credentials["port"]) not in existing:
        nodes.append({"name":"VPS-Trojan", "type":"trojan", "server":host,
            "port":credentials["port"], "password":password, "sni":host})
    uris = []
    for n in nodes:
        server = f"[{n['server']}]" if ":" in n["server"] else n["server"]
        pw, sni = quote(str(n["password"]), safe=""), quote(str(n["sni"]), safe="")
        if n["type"] == "trojan":
            uri = f"trojan://{pw}@{server}:{n['port']}?security=tls&sni={sni}&type=tcp#{quote(n['name'])}"
        else:
            obfs = f"&obfs=salamander&obfs-password={quote(str(n['obfs_password']), safe='')}" if n.get("obfs_password") else ""
            uri = f"hysteria2://{pw}@{server}:{n['port']}?sni={sni}{obfs}&insecure=0#{quote(n['name'])}"
        uris.append(uri)
    return nodes, uris

def surge_node(n, include_ipv6_options=True):
    host = n["server"]
    opts = [f"password={n['password']}", f"sni={n['sni']}", "skip-cert-verify=false"]
    if n["type"] == "hysteria2":
        obfs_key = "salamander-password" if include_ipv6_options else "obfs-password"
        if "obfs_password" in n:
            if not include_ipv6_options: opts.append("obfs=salamander")
            opts.append(f"{obfs_key}={n['obfs_password']}")
        opts.append("test-timeout=20")
        if "download_mbps" in n: opts.append(f"download-bandwidth={n['download_mbps']}")
        if not include_ipv6_options and "upload_mbps" in n: opts.append(f"upload-bandwidth={n['upload_mbps']}")
    if include_ipv6_options and ":" in n["server"]:
        interface = load_settings().get("surge_interface", "")
        if interface: opts.extend([f"interface={interface}", "allow-other-interface=true"])
    return f"{n['name']} = {n['type']}, {host}, {n['port']}, " + ", ".join(opts)

def mihomo_node(n):
    result = {"name":n["name"], "type":n["type"], "server":n["server"], "port":n["port"],
        "password":n["password"], "sni":n["sni"], "skip-cert-verify":False}
    if n["type"] == "trojan": result["udp"] = True
    else:
        if "download_mbps" in n: result["down"] = f"{n['download_mbps']} Mbps"
        if "upload_mbps" in n: result["up"] = f"{n['upload_mbps']} Mbps"
        if "obfs_password" in n: result.update({"obfs":"salamander", "obfs-password":n["obfs_password"]})
    return result

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--offline", action="store_true", help="Generate with bundled seed domains; clients still use online rule providers")
    parser.add_argument("--check-surge", action="store_true", help="Validate using an installed Surge CLI")
    args = parser.parse_args()
    settings = load_settings()
    CACHE.mkdir(exist_ok=True)
    OUT.mkdir(exist_ok=True)
    OUT.chmod(0o700)
    credentials = json.loads((OUT / "credentials.json").read_text())
    host, port, password = credentials["server"], credentials["port"], credentials["password"]
    nodes, uris = build_nodes(credentials)
    node_names = [n["name"] for n in nodes]
    preferred_nodes = ", ".join(node_names)
    has_ipv6 = any(":" in n["server"] for n in nodes)
    hy_line = "\n".join(surge_node(n) for n in nodes if n["type"] == "hysteria2")
    if hy_line: hy_line += "\n"
    trojan_lines = "\n".join(surge_node(n) for n in nodes if n["type"] == "trojan")
    all_shadowrocket_lines = "\n".join(surge_node(n, False) for n in nodes)
    foreign = [f"DOMAIN-SUFFIX,{d}" for d in PINNED_FOREIGN]
    sources = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=7) as pool:
        for service, url, text in ([(service, f"{BASE}/{service}/{service}.list", "") for service in SERVICES] if args.offline else pool.map(fetch, SERVICES)):
            accepted = []
            for line in text.splitlines():
                line = line.strip()
                if line.startswith(("DOMAIN,", "DOMAIN-SUFFIX,", "DOMAIN-KEYWORD,", "IP-CIDR,", "IP-CIDR6,")):
                    accepted.append(line.removesuffix(",no-resolve"))
            foreign.extend(accepted)
            sources.append({"service":service, "url":url, "rule_count":len(accepted), "sha256":hashlib.sha256(text.encode()).hexdigest()})
    foreign = list(dict.fromkeys(foreign))
    def apply_policy(rule, policy):
        return rule + "," + policy + (",no-resolve" if rule.startswith(("IP-CIDR,", "IP-CIDR6,")) else "")

    foreign_rules = [apply_policy(r, "PROXY") for r in foreign]
    domestic_rules = [f"DOMAIN-SUFFIX,{d},DIRECT" for d in PINNED_DOMESTIC]
    lan_rules = [f"IP-CIDR,{host}/32,DIRECT,no-resolve"] + ([f"IP-CIDR6,{n['server']}/128,DIRECT,no-resolve" for n in nodes if ":" in n["server"]]) + ["DOMAIN,localhost,DIRECT", "DOMAIN-SUFFIX,local,DIRECT",
        "DOMAIN-SUFFIX,lan,DIRECT", "IP-CIDR,127.0.0.0/8,DIRECT,no-resolve", "IP-CIDR,10.0.0.0/8,DIRECT,no-resolve",
        "IP-CIDR,172.16.0.0/12,DIRECT,no-resolve", "IP-CIDR,192.168.0.0/16,DIRECT,no-resolve",
        "IP-CIDR6,::1/128,DIRECT,no-resolve", "IP-CIDR6,fc00::/7,DIRECT,no-resolve", "IP-CIDR6,fe80::/10,DIRECT,no-resolve"]
    sg_base = "https://raw.githubusercontent.com/Loyalsoldier/surge-rules/release"
    lan_rules += [f"DOMAIN-SUFFIX,{d},DIRECT" for d in settings.get("direct_domains", [])]
    surge_rules = lan_rules + foreign_rules + [f"RULE-SET,{BASE}/{s}/{s}.list,PROXY" for s in SERVICES]
    surge_rules += domestic_rules + [f"DOMAIN-SET,{sg_base}/direct.txt,DIRECT", f"RULE-SET,{sg_base}/cncidr.txt,DIRECT,no-resolve",
        "GEOIP,CN,DIRECT,no-resolve", "FINAL,PROXY"]
    surge = f"""#!name=VPS
#!desc=Foreign services use encrypted Trojan; mainland services connect directly.
[General]
loglevel = notify
dns-server = 223.5.5.5, 119.29.29.29
encrypted-dns-server = https://dns.alidns.com/dns-query, https://doh.pub/dns-query
encrypted-dns-follow-outbound-mode = true
encrypted-dns-skip-cert-verification = false
use-local-host-item-for-proxy = false
hijack-dns = *:53
ipv6 = {str(has_ipv6).lower()}
skip-proxy = 127.0.0.1, 192.168.0.0/16, 10.0.0.0/8, 172.16.0.0/12, localhost, *.local
test-timeout = 15
proxy-test-url = http://www.gstatic.com/generate_204
http-listen = 127.0.0.1:6152
socks5-listen = 127.0.0.1:6153

[Proxy]
{hy_line}{trojan_lines}

[Proxy Group]
PROXY = select, {preferred_nodes}

[Rule]
""" + "\n".join(surge_rules) + "\n"
    private_write(OUT / "VPS-Surge.conf", surge)
    if args.check_surge:
        checked = subprocess.run([os.environ.get("VPS_SURGE_CLI", CLI), "--check", str(OUT / "VPS-Surge.conf")], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        if checked.returncode:
            raise RuntimeError("Surge --check failed; output suppressed because it may contain node secrets")

    sr_base = "https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/master/rule/Shadowrocket"
    sr_rules = lan_rules + foreign_rules + [f"RULE-SET,{sr_base}/{s}/{s}.list,PROXY" for s in SERVICES] + domestic_rules
    sr_rules += [f"DOMAIN-SET,{sr_base}/ChinaMax/ChinaMax_Domain.list,DIRECT", f"RULE-SET,{sr_base}/ChinaMax/ChinaMax.list,DIRECT",
        "GEOIP,CN,DIRECT,no-resolve", "FINAL,PROXY"]
    shadowrocket = f"""# VPS: configuration mode; encrypted Trojan with certificate verification.
[General]
bypass-system = true
skip-proxy = 127.0.0.1, 192.168.0.0/16, 10.0.0.0/8, 172.16.0.0/12, localhost, *.local
dns-server = https://dns.alidns.com/dns-query, https://doh.pub/dns-query
ipv6 = {str(has_ipv6).lower()}
dns-direct-system = false

[Proxy]
{all_shadowrocket_lines}

[Proxy Group]
PROXY = select, {preferred_nodes}

[Rule]
""" + "\n".join(sr_rules) + "\n"
    private_write(OUT / "VPS-Shadowrocket.conf", shadowrocket)
    private_write(OUT / "Shadowrocket-nodes.txt", "\n".join(uris) + "\n")
    private_write(OUT / "Shadowrocket-import.txt", uris[0] + "\n")

    cl_base = "https://raw.githubusercontent.com/Loyalsoldier/clash-rules/release"
    providers = {
        "cn-domains":{"type":"http", "behavior":"domain", "url":f"{cl_base}/direct.txt", "path":"./ruleset/cn-domains.yaml", "interval":86400},
        "cn-ips":{"type":"http", "behavior":"ipcidr", "url":f"{cl_base}/cncidr.txt", "path":"./ruleset/cn-ips.yaml", "interval":86400},
    }
    for service in SERVICES:
        providers[service.lower()] = {"type":"http", "behavior":"classical",
            "url":f"https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/master/rule/Clash/{service}/{service}.yaml",
            "path":f"./ruleset/{service.lower()}.yaml", "interval":86400}
    common = {"mixed-port":7890, "allow-lan":False, "bind-address":"127.0.0.1", "mode":"rule", "log-level":"warning", "ipv6":has_ipv6,
        "proxies":[mihomo_node(n) for n in nodes],
        "proxy-groups":[{"name":"PROXY", "type":"select", "proxies":node_names}],
        "rule-providers":providers,
        "rules":lan_rules + foreign_rules + [f"RULE-SET,{s.lower()},PROXY" for s in SERVICES] + domestic_rules + [
            "RULE-SET,cn-domains,DIRECT", "RULE-SET,cn-ips,DIRECT,no-resolve", "GEOIP,CN,DIRECT,no-resolve", "MATCH,PROXY"]}
    modern = dict(common)
    modern.update({"geodata-mode":False, "geo-auto-update":True, "geo-update-interval":24,
        "geox-url":{"mmdb":"https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/release/country.mmdb"},
        "tun":{"enable":True, "stack":"mixed", "auto-route":True, "auto-detect-interface":True, "strict-route":True, "dns-hijack":["any:53"]},
        "dns":{"enable":True, "listen":"127.0.0.1:1053", "ipv6":False, "enhanced-mode":"fake-ip", "fake-ip-range":"198.18.0.1/16",
            "fake-ip-filter":["*.lan", "*.local", "localhost"], "respect-rules":True,
            "default-nameserver":["223.5.5.5", "119.29.29.29"],
            "proxy-server-nameserver":["https://dns.alidns.com/dns-query", "https://doh.pub/dns-query"],
            "direct-nameserver":["https://dns.alidns.com/dns-query", "https://doh.pub/dns-query"],
            "nameserver":["https://1.1.1.1/dns-query#PROXY", "https://8.8.8.8/dns-query#PROXY"],
            "nameserver-policy":{"rule-set:cn-domains":["https://dns.alidns.com/dns-query", "https://doh.pub/dns-query"]}}})
    private_write(OUT / "VPS-Clash-Mihomo.yaml", yaml.safe_dump(modern,allow_unicode=True,sort_keys=False))
    legacy = dict(common)
    legacy["dns"] = {"enable":True,"listen":"127.0.0.1:1053", "ipv6":False,"enhanced-mode":"fake-ip","fake-ip-range":"198.18.0.1/16",
        "fake-ip-filter":["*.lan","*.local","localhost"], "default-nameserver":["223.5.5.5", "119.29.29.29"],
        "nameserver":["https://dns.alidns.com/dns-query", "https://doh.pub/dns-query"],
        "fallback":["https://1.1.1.1/dns-query", "https://8.8.8.8/dns-query"],
        "fallback-filter":{"geoip":True,"geoip-code":"CN","ipcidr":["240.0.0.0/4"],"domain":[f"+.{d}" for d in PINNED_FOREIGN]}}
    legacy_nodes = [n for n in nodes if n["type"] == "trojan"]
    legacy["proxies"] = [mihomo_node(n) for n in legacy_nodes]
    legacy["proxy-groups"] = [{"name":"PROXY", "type":"select", "proxies":[n["name"] for n in legacy_nodes]}]
    legacy["rules"] = common["rules"]
    private_write(OUT / "VPS-Clash-Legacy.yaml", yaml.safe_dump(legacy,allow_unicode=True,sort_keys=False))
    (OUT / "rule-sources.json").write_text(json.dumps({"sources":sources,"foreign_inline_rules":len(foreign),
        "surge_direct":f"{sg_base}/direct.txt", "clash_direct":f"{cl_base}/direct.txt", "clash_cn_ips":f"{cl_base}/cncidr.txt",
        "geoip_mmdb":modern["geox-url"]["mmdb"]},indent=2)+"\n")
    print("Generated four client profiles; foreign inline rules:",len(foreign))

if __name__ == "__main__":
    main()
