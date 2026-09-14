# subreaper.py - Python 3.11
# SubReaper v2.2: async subdomain enumeration + origin IP discovery + email enumeration
# Deps: pip install -r requirements.txt
#   (optional, for WHOIS registrant email lookup) pip install python-whois
# Usage:
#   python subreaper.py example.com --wordlist subs.txt --hunt-origin --hunt-emails
# WARNING: authorized security testing only. You are responsible for your scope.

import asyncio
import aiohttp
import dns.asyncresolver
import dns.resolver
import dns.exception
import argparse
import random
import string
import re
import sys
import json
from pathlib import Path
from collections import defaultdict
from ipaddress import ip_address

if sys.platform == "win32":
    asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())

RESOLVER_TIMEOUT = 2.5
CONCURRENCY      = 200
ORIGIN_CONCURRENCY = 30
EMAIL_CONCURRENCY  = 30
BUFFER           = 65535
USER_AGENT       = "SubReaper/2.2"

PASSIVE_SOURCES = {
    "crtsh":        "https://crt.sh/?q=%25.{d}&output=json",
    "hackertarget": "https://api.hackertarget.com/hostsearch/?q={d}",
    "rapiddns":     "https://rapiddns.io/subdomain/{d}?full=1",
    "urlscan":      "https://urlscan.io/api/v1/search/?q=domain:{d}",
    "otx":          "https://otx.alienvault.com/api/v1/indicators/domain/{d}/passive_dns",
    "bufferover":   "https://dns.bufferover.run/dns?q=.{d}",
    "anubis":       "https://jldc.me/anubis/subdomains/{d}",
    "threatcrowd":  "https://www.threatcrowd.org/searchApi/v2/domain/report/?domain={d}",
}

HOSTNAME_RE = re.compile(r'[a-zA-Z0-9_\-\.]+\.[a-zA-Z]{2,}')
IPV4_RE     = re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b')

# broad email regex; results are filtered afterwards
EMAIL_RE = re.compile(r'[a-zA-Z0-9_.+\-]+@[a-zA-Z0-9\-]+\.[a-zA-Z0-9\-.]+')

CDN_PREFIXES = [
    "104.16.", "104.17.", "104.18.", "104.19.", "104.20.", "104.21.",
    "104.22.", "104.23.", "104.24.", "104.25.", "104.26.", "104.27.",
    "172.64.", "172.65.", "172.66.", "172.67.", "172.68.", "172.69.",
    "172.70.", "172.71.", "188.114.96.", "188.114.97.", "188.114.98.",
    "188.114.99.", "162.158.", "162.159.", "162.160.", "162.161.",
    "13.32.", "13.33.", "13.35.", "13.224.", "13.225.", "13.226.",
    "13.227.", "13.228.", "13.249.", "13.250.", "18.64.", "18.65.",
    "99.84.", "99.86.", "151.101.", "23.32.", "23.33.", "23.34.",
]

ORIGIN_PREFIXES = [
    "direct", "origin", "origin-www", "www-origin", "origin1", "origin2",
    "backend", "internal", "ftp", "mail", "smtp", "pop", "imap", "webmail",
    "cpanel", "whm", "origin-server", "staging", "dev", "old", "legacy",
    "vpn", "ssh", "gateway", "direct-connect", "directorigin", "orig",
]

# ---- email enumeration config ----
EMAIL_PATHS = [
    "", "contact", "contact-us", "about", "about-us", "team",
    "support", "help", "privacy", "privacy-policy", "terms",
    "legal", "imprint", "impressum", "careers", "press",
]

EMAIL_JUNK_DOMAINS = {
    "example.com", "example.org", "example.net", "sentry.io",
    "wixpress.com", "godaddy.com", "schema.org", "w3.org",
    "gstatic.com", "google.com", "googleapis.com", "your-domain.com",
    "yourdomain.com", "domain.com", "email.com", "test.com",
}

EMAIL_JUNK_TLDS = {"png", "jpg", "jpeg", "gif", "svg", "webp", "css", "js"}


# ============ colors / banner ============
class C:
    RESET   = "\033[0m"
    BOLD    = "\033[1m"
    CYAN    = "\033[96m"
    MAGENTA = "\033[95m"
    YELLOW  = "\033[93m"
    GREEN   = "\033[92m"
    RED     = "\033[91m"


def print_banner():
    lines = [
        (C.CYAN,    "   ____        _     ____                            "),
        (C.CYAN,    "  / ___| _   _| |__ |  _ \\ ___  __ _ _ __   ___ _ __ "),
        (C.MAGENTA, "  \\___ \\| | | | '_ \\| |_) / _ \\/ _` | '_ \\ / _ \\ '__|"),
        (C.MAGENTA, "   ___) | |_| | |_) |  _ <  __/ (_| | |_) |  __/ |   "),
        (C.YELLOW,  "  |____/ \\__,_|_.__/|_| \\_\\___|\\__,_| .__/ \\___|_|   "),
        (C.YELLOW,  "                                     |_|              "),
    ]
    print()
    for color, text in lines:
        print(f"{C.BOLD}{color}{text}{C.RESET}")
    print(f"{C.BOLD}{C.GREEN}{'=' * 60}{C.RESET}")
    print(f"{C.BOLD}{C.YELLOW}   Developer : mukidul islam zihad{C.RESET}")
    print(f"{C.BOLD}{C.YELLOW}   GitHub    : https://github.com/mukidulislamzihad{C.RESET}")
    print(f"{C.BOLD}{C.GREEN}{'=' * 60}{C.RESET}")


# ============ helpers ============
def is_cdn_ip(ip_str):
    for prefix in CDN_PREFIXES:
        if ip_str.startswith(prefix):
            return True
    return False

def is_public(ip_str):
    try:
        ip = ip_address(ip_str)
        return not (ip.is_private or ip.is_loopback or ip.is_multicast or ip.is_reserved)
    except ValueError:
        return False

def make_resolver():
    r = dns.asyncresolver.Resolver()
    r.timeout  = RESOLVER_TIMEOUT
    r.lifetime = RESOLVER_TIMEOUT
    return r

def clean_emails(raw_matches):
    out = set()
    for m in raw_matches:
        e = m.lower().strip().strip(".,;:'\"()<>[]")
        if e.count("@") != 1:
            continue
        local, _, dom = e.partition("@")
        if not local or not dom or "." not in dom:
            continue
        tld = dom.rsplit(".", 1)[-1]
        if tld in EMAIL_JUNK_TLDS:
            continue
        if dom in EMAIL_JUNK_DOMAINS:
            continue
        out.add(e)
    return out

def classify_email(email, root_domain):
    dom = email.split("@", 1)[1]
    if dom == root_domain or dom.endswith("." + root_domain):
        return "internal"
    return "external"

# ============ Layer 1: Passive ============
async def fetch_passive(session, name, url_tpl, domain):
    url = url_tpl.format(d=domain)
    found = set()
    try:
        async with session.get(url, timeout=aiohttp.ClientTimeout(total=15)) as r:
            if r.status != 200:
                return found
            text = await r.text(errors="ignore")
            for m in HOSTNAME_RE.findall(text):
                m = m.lower().strip(".")
                if m.endswith(domain) and "*" not in m:
                    found.add(m)
    except (aiohttp.ClientError, asyncio.TimeoutError):
        pass
    return found

async def layer_passive(domain):
    found = set()
    async with aiohttp.ClientSession(headers={"User-Agent": USER_AGENT}) as s:
        tasks = [fetch_passive(s, n, u, domain) for n, u in PASSIVE_SOURCES.items()]
        for coro in asyncio.as_completed(tasks):
            try:
                found |= await coro
            except Exception:
                continue
    return found

# ============ Layer 2: Wildcard ============
async def is_wildcard(domain):
    rnd  = "".join(random.choices(string.ascii_lowercase, k=20))
    test = f"{rnd}.{domain}"
    resolver = make_resolver()
    try:
        ans = await resolver.resolve(test, "A")
        return [str(r) for r in ans]
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer,
            dns.resolver.NoNameservers, dns.exception.DNSException,
            asyncio.TimeoutError):
        return None

# ============ Layer 3: Brute ============
async def resolve_host(host, resolver, wildcard_ips):
    try:
        ans = await resolver.resolve(host, "A")
        ips = [str(r) for r in ans]
        if wildcard_ips and set(ips) == set(wildcard_ips):
            return None
        return (host, ips)
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer,
            dns.resolver.NoNameservers, dns.exception.DNSException,
            asyncio.TimeoutError):
        return None

async def layer_brute(domain, wordlist, concurrency=CONCURRENCY):
    resolver = make_resolver()
    wildcard_ips = await is_wildcard(domain)

    sem  = asyncio.Semaphore(concurrency)
    hits = []
    q    = asyncio.Queue(BUFFER)

    async def worker():
        while True:
            host = await q.get()
            if host is None:
                q.task_done()
                return
            try:
                async with sem:
                    res = await resolve_host(host, resolver, wildcard_ips)
                if res:
                    hits.append(res)
            except Exception:
                pass
            finally:
                q.task_done()

    workers = [asyncio.create_task(worker()) for _ in range(concurrency)]
    for w in wordlist:
        w = w.strip() if isinstance(w, str) else ""
        if w and not w.startswith("#"):
            await q.put(f"{w}.{domain}")
    for _ in workers:
        await q.put(None)
    await q.join()
    for w in workers:
        w.cancel()
    await asyncio.gather(*workers, return_exceptions=True)
    return hits, wildcard_ips

# ============ Layer 4: Permutation ============
PREFIXES = ["dev","stg","stage","test","qa","uat","prod","api","admin",
            "internal","intranet","vpn","git","jenkins","ci","cd","db",
            "mysql","redis","mongo","kibana","grafana","prometheus",
            "portal","app","web","mail","smtp","ftp","ns1","ns2","dns"]

SUFFIXES = ["-dev","-stg","-test","-prod","-old","-bak","-backup",
            "-internal","-api","-admin","1","2","01","02","x"]

def permute(known, root):
    out = set()
    root = root.lower()
    suffix = "." + root
    for h in known:
        if not h.endswith(suffix):
            continue
        label = h[: -len(suffix)]
        if "." in label:
            continue
        for p in PREFIXES:
            out.add(f"{p}-{label}.{root}")
            out.add(f"{p}{label}.{root}")
        for s in SUFFIXES:
            out.add(f"{label}{s}.{root}")
    return out

# ============ Layer 5: HTTP probe ============
async def probe_http(session, host):
    results = {}
    for scheme in ("https", "http"):
        try:
            async with session.get(
                f"{scheme}://{host}",
                timeout=aiohttp.ClientTimeout(total=5),
                allow_redirects=False,
                ssl=False,
            ) as r:
                try:
                    body  = await r.text(errors="ignore")
                    title = ""
                    if "<title>" in body.lower():
                        title = body.split("<title>")[-1].split("</title>")[0][:80].strip()
                except Exception:
                    title = ""
                results[scheme] = {
                    "status": r.status,
                    "server": r.headers.get("Server", ""),
                    "title":  title,
                }
                return results
        except (aiohttp.ClientError, asyncio.TimeoutError):
            continue
    return results

async def layer_probe(hosts):
    out = {}
    if not hosts:
        return out
    async with aiohttp.ClientSession(headers={"User-Agent": USER_AGENT}) as s:
        async def _wrapped(h):
            try:
                return h, await probe_http(s, h)
            except Exception:
                return h, {}
        coros = [_wrapped(h) for h in hosts]
        for fut in asyncio.as_completed(coros):
            try:
                h, res = await fut
                out[h] = res
            except Exception:
                continue
    return out

# ============ ORIGIN IP HUNTER ============
async def resolve_a(host, resolver):
    try:
        ans = await resolver.resolve(host, "A")
        return [str(r) for r in ans]
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer,
            dns.resolver.NoNameservers, dns.exception.DNSException,
            asyncio.TimeoutError):
        return []

async def resolve_mx(domain, resolver):
    try:
        ans = await resolver.resolve(domain, "MX")
        return [str(r.exchange).rstrip(".") for r in ans]
    except Exception:
        return []

async def resolve_txt(domain, resolver):
    try:
        ans = await resolver.resolve(domain, "TXT")
        return [r.to_text().strip('"') for r in ans]
    except Exception:
        return []

async def resolve_cname(host, resolver):
    try:
        ans = await resolver.resolve(host, "CNAME")
        return [str(r).rstrip(".") for r in ans]
    except Exception:
        return []

async def origin_via_subdomains(host, resolver):
    parts = host.split(".")
    if len(parts) < 2:
        return {}
    root = ".".join(parts[-2:])
    candidates = {}
    sem = asyncio.Semaphore(ORIGIN_CONCURRENCY)

    async def probe(prefix):
        sub = f"{prefix}.{root}"
        async with sem:
            ips = await resolve_a(sub, resolver)
        for ip in ips:
            if is_public(ip) and not is_cdn_ip(ip):
                candidates.setdefault(sub, []).append(ip)

    await asyncio.gather(*(probe(p) for p in ORIGIN_PREFIXES))
    return candidates

async def origin_via_mx(domain, resolver):
    mxs = await resolve_mx(domain, resolver)
    candidates = {}
    for mx in mxs:
        ips = await resolve_a(mx, resolver)
        for ip in ips:
            if is_public(ip) and not is_cdn_ip(ip):
                candidates.setdefault(mx, []).append(ip)
    return candidates

async def origin_via_spf(domain, resolver):
    txts = await resolve_txt(domain, resolver)
    candidates = {}
    for t in txts:
        for m in re.findall(r'ip4:([0-9\./]+)', t):
            ip = m.split("/")[0]
            if is_public(ip) and not is_cdn_ip(ip):
                candidates.setdefault(f"SPF:{domain}", []).append(ip)
        for m in re.findall(r'include:([^\s]+)', t):
            sub_ips = await resolve_a(m, resolver)
            for ip in sub_ips:
                if is_public(ip) and not is_cdn_ip(ip):
                    candidates.setdefault(f"SPF-include:{m}", []).append(ip)
    return candidates

async def origin_via_cname(host, resolver):
    candidates = {}
    seen = set()
    current = host
    for _ in range(6):
        if current in seen:
            break
        seen.add(current)
        cnames = await resolve_cname(current, resolver)
        if not cnames:
            break
        for cn in cnames:
            ips = await resolve_a(cn, resolver)
            for ip in ips:
                if is_public(ip) and not is_cdn_ip(ip):
                    candidates.setdefault(cn, []).append(ip)
        current = cnames[0]
    return candidates

async def origin_via_headers(session, host):
    candidates = {}
    interesting = [
        "x-forwarded-for", "x-real-ip", "x-origin-ip", "x-backend",
        "x-server-ip", "via", "x-host", "x-forwarded-host",
        "forwarded", "x-served-by",
    ]
    for scheme in ("https", "http"):
        try:
            async with session.get(
                f"{scheme}://{host}",
                timeout=aiohttp.ClientTimeout(total=6),
                allow_redirects=False,
                ssl=False,
            ) as r:
                for h in interesting:
                    v = r.headers.get(h)
                    if not v:
                        continue
                    for ip in IPV4_RE.findall(v):
                        if is_public(ip) and not is_cdn_ip(ip):
                            candidates.setdefault(f"header:{h}", []).append(ip)
                break
        except (aiohttp.ClientError, asyncio.TimeoutError):
            continue
    return candidates

async def favicon_hash(session, host):
    try:
        import mmh3
        import base64
    except ImportError:
        return None
    for scheme in ("https", "http"):
        try:
            async with session.get(
                f"{scheme}://{host}/favicon.ico",
                timeout=aiohttp.ClientTimeout(total=6),
                ssl=False,
            ) as r:
                if r.status != 200:
                    continue
                data = await r.read()
                if not data:
                    continue
                b64 = base64.encodebytes(data)
                h   = mmh3.hash(b64)
                return {"scheme": scheme, "hash": h, "size": len(data),
                        "shodan_query": f"http.favicon.hash:{h}"}
        except (aiohttp.ClientError, asyncio.TimeoutError):
            continue
    return None

async def hunt_origin(host, resolver, session):
    parts = host.split(".")
    root = ".".join(parts[-2:]) if len(parts) >= 2 else host

    primary = await resolve_a(host, resolver)
    cdn_active = any(is_cdn_ip(ip) for ip in primary)

    subs   = await origin_via_subdomains(host, resolver)
    mxs    = await origin_via_mx(root, resolver)
    spf    = await origin_via_spf(root, resolver)
    cnames = await origin_via_cname(host, resolver)
    hdrs   = await origin_via_headers(session, host)
    fav    = await favicon_hash(session, host)

    aggregated = {}
    for source, d in [("subdomain", subs), ("mx", mxs), ("spf", spf),
                      ("cname", cnames), ("header", hdrs)]:
        for k, ips in d.items():
            aggregated.setdefault(k, {"source": source, "ips": []})
            aggregated[k]["ips"].extend(ips)

    seen_ips = set()
    final = []
    for k, v in aggregated.items():
        for ip in v["ips"]:
            if ip in seen_ips:
                continue
            seen_ips.add(ip)
            final.append({"host": k, "ip": ip, "source": v["source"]})

    return {
        "host": host,
        "primary_ips": primary,
        "cdn_detected": cdn_active,
        "candidates": final,
        "favicon": fav,
    }

async def layer_origin(all_hosts):
    resolver = make_resolver()
    sem = asyncio.Semaphore(ORIGIN_CONCURRENCY)
    results = {}

    async with aiohttp.ClientSession(headers={"User-Agent": USER_AGENT}) as session:
        async def worker(h):
            async with sem:
                try:
                    return h, await hunt_origin(h, resolver, session)
                except Exception as e:
                    return h, {"host": h, "error": str(e)}

        tasks = [asyncio.create_task(worker(h)) for h in all_hosts]
        for t in asyncio.as_completed(tasks):
            try:
                h, res = await t
                results[h] = res
            except Exception:
                continue
    return results

# ============ EMAIL ENUMERATION ============
async def fetch_page_text(session, url):
    try:
        async with session.get(
            url, timeout=aiohttp.ClientTimeout(total=7),
            allow_redirects=True, ssl=False,
        ) as r:
            if r.status >= 400:
                return ""
            return await r.text(errors="ignore")
    except (aiohttp.ClientError, asyncio.TimeoutError):
        return ""

async def crawl_host_emails(session, host, sem):
    found = set()
    async with sem:
        for path in EMAIL_PATHS:
            got_any = False
            for scheme in ("https", "http"):
                url = f"{scheme}://{host}/{path}"
                text = await fetch_page_text(session, url)
                if not text:
                    continue
                got_any = True
                for m in re.findall(r'mailto:([^"\'\s?&<>]+)', text, flags=re.I):
                    found.add(m)
                found |= set(EMAIL_RE.findall(text))
                break
            if not got_any and path == "":
                break
    return clean_emails(found)

async def layer_email_crawl(hosts, root_domain):
    sem = asyncio.Semaphore(EMAIL_CONCURRENCY)
    per_host = {}
    targets = sorted(set(hosts) | {root_domain, f"www.{root_domain}"})
    async with aiohttp.ClientSession(headers={"User-Agent": USER_AGENT}) as session:
        async def worker(h):
            emails = await crawl_host_emails(session, h, sem)
            return h, emails
        tasks = [asyncio.create_task(worker(h)) for h in targets]
        for t in asyncio.as_completed(tasks):
            try:
                h, emails = await t
                if emails:
                    per_host[h] = emails
            except Exception:
                continue
    return per_host

async def email_via_dmarc(domain, resolver):
    found = set()
    txts = await resolve_txt(f"_dmarc.{domain}", resolver)
    for t in txts:
        for m in re.findall(r'mailto:([^\s,;]+)', t, flags=re.I):
            found.add(m)
    return clean_emails(found)

async def email_via_spf_include_domains(domain, resolver):
    found = set()
    txts = await resolve_txt(domain, resolver)
    for t in txts:
        found |= set(EMAIL_RE.findall(t))
    return clean_emails(found)

async def email_via_whois(domain):
    try:
        import whois as pywhois
    except ImportError:
        return set(), False
    try:
        loop = asyncio.get_event_loop()
        w = await loop.run_in_executor(None, pywhois.whois, domain)
        raw = set()
        emails = getattr(w, "emails", None)
        if emails:
            raw |= set(emails) if isinstance(emails, (list, set)) else {emails}
        text = str(w)
        raw |= set(EMAIL_RE.findall(text))
        return clean_emails(raw), True
    except Exception:
        return set(), True

async def layer_email(all_hosts, domain):
    resolver = make_resolver()

    crawl_task  = layer_email_crawl(all_hosts, domain)
    dmarc_task  = email_via_dmarc(domain, resolver)
    spf_task    = email_via_spf_include_domains(domain, resolver)
    whois_task  = email_via_whois(domain)

    per_host, dmarc_emails, spf_emails, (whois_emails, whois_available) = \
        await asyncio.gather(crawl_task, dmarc_task, spf_task, whois_task)

    merged = {}

    def add(email, source, host=None):
        e = merged.setdefault(email, {
            "type": classify_email(email, domain),
            "sources": set(),
            "seen_on": set(),
        })
        e["sources"].add(source)
        if host:
            e["seen_on"].add(host)

    for host, emails in per_host.items():
        for e in emails:
            add(e, "web-crawl", host)
    for e in dmarc_emails:
        add(e, "dmarc")
    for e in spf_emails:
        add(e, "dns-txt")
    for e in whois_emails:
        add(e, "whois")

    return merged, whois_available

# ============ Output ============
def print_results(all_hosts, probe):
    print(f"\n[+] TOTAL unique subdomains: {len(all_hosts)}")
    for h in all_hosts:
        p   = probe.get(h, {})
        tag = ""
        if "https" in p:
            tag = f" [{p['https']['status']}] {p['https']['server']}"
        elif "http" in p:
            tag = f" [http:{p['http']['status']}] {p['http']['server']}"
        print(f"    {h}{tag}")

def print_origin_results(origin_data):
    print("\n" + "=" * 70)
    print("[+] ORIGIN IP HUNT RESULTS")
    print("=" * 70)
    for host, data in origin_data.items():
        if "error" in data:
            print(f"\n[*] {host}  -> error: {data['error']}")
            continue
        cdn = "CDN" if data["cdn_detected"] else "direct"
        print(f"\n[*] {host}  ({cdn})")
        print(f"    Primary: {', '.join(data['primary_ips']) or 'none'}")
        cands = data.get("candidates", [])
        if not cands:
            print(f"    Candidates: none found")
        else:
            for c in cands:
                print(f"    -> {c['ip']:<18} from {c['host']:<40} [{c['source']}]")
        fav = data.get("favicon")
        if fav:
            print(f"    Favicon hash: {fav['hash']}")
            print(f"    Shodan: https://www.shodan.io/search?query={fav['shodan_query']}")

def print_email_results(emails, whois_available):
    print("\n" + "=" * 70)
    print("[+] EMAIL ENUMERATION RESULTS")
    print("=" * 70)
    if not emails:
        print("    none found")
        return
    internal = {e: v for e, v in emails.items() if v["type"] == "internal"}
    external = {e: v for e, v in emails.items() if v["type"] == "external"}

    print(f"\n[*] Internal / same-domain ({len(internal)}):")
    for e, v in sorted(internal.items()):
        srcs = ",".join(sorted(v["sources"]))
        hosts = ", ".join(sorted(v["seen_on"])[:3]) if v["seen_on"] else "-"
        print(f"    {e:<40} [{srcs}]  seen on: {hosts}")

    print(f"\n[*] External / third-party addresses appearing on-site ({len(external)}):")
    for e, v in sorted(external.items()):
        srcs = ",".join(sorted(v["sources"]))
        hosts = ", ".join(sorted(v["seen_on"])[:3]) if v["seen_on"] else "-"
        print(f"    {e:<40} [{srcs}]  seen on: {hosts}")

    if not whois_available:
        print("\n    (tip: pip install python-whois to also try WHOIS registrant contacts)")

def write_output(path, all_hosts, probe):
    try:
        Path(path).write_text("\n".join(all_hosts) + "\n")
        print(f"[+] Saved: {path}  ({len(all_hosts)} hosts)")

        detail_path = Path(path).with_suffix(".detail.txt")
        lines = []
        for h in all_hosts:
            p = probe.get(h, {})
            if "https" in p:
                d = p["https"]
                lines.append(f"{h}\t{d['status']}\t{d['server']}\t{d['title']}")
            elif "http" in p:
                d = p["http"]
                lines.append(f"{h}\thttp:{d['status']}\t{d['server']}\t{d['title']}")
            else:
                lines.append(f"{h}\t-\t-\t-")
        detail_path.write_text("\n".join(lines) + "\n")
        print(f"[+] Detail: {detail_path}")
    except OSError as e:
        print(f"[!] Could not write output: {e}")

def write_origin_json(path, origin_data):
    try:
        Path(path).write_text(json.dumps(origin_data, indent=2))
        print(f"[+] Origin JSON: {path}")
    except OSError as e:
        print(f"[!] Could not write origin JSON: {e}")

def write_email_output(path, emails):
    try:
        json_path = Path(path).with_suffix(".emails.json")
        serializable = {
            e: {"type": v["type"], "sources": sorted(v["sources"]),
                "seen_on": sorted(v["seen_on"])}
            for e, v in emails.items()
        }
        json_path.write_text(json.dumps(serializable, indent=2))
        print(f"[+] Email JSON: {json_path}")

        txt_path = Path(path).with_suffix(".emails.txt")
        lines = [e for e in sorted(emails)]
        txt_path.write_text("\n".join(lines) + ("\n" if lines else ""))
        print(f"[+] Email list: {txt_path}  ({len(lines)} addresses)")
    except OSError as e:
        print(f"[!] Could not write email output: {e}")

# ============ Orchestrator: full pipeline (used by CLI flags) ============
async def reap(domain, wordlist_path=None, concurrency=CONCURRENCY,
               out_path=None, hunt_origin_flag=False, hunt_emails_flag=False):
    print(f"[*] Target: {domain}")
    results = defaultdict(set)

    print("[1/7] passive sources...")
    results["passive"] = await layer_passive(domain)
    print(f"      -> {len(results['passive'])} hosts")

    print("[2/7] wildcard check + brute...")
    if wordlist_path and Path(wordlist_path).exists():
        wl = Path(wordlist_path).read_text(errors="ignore").splitlines()
    else:
        wl = PREFIXES
        print(f"      (no wordlist - using built-in {len(PREFIXES)} prefixes)")
    brute_hits, wc = await layer_brute(domain, wl, concurrency=concurrency)
    results["brute"] = {h for h, _ in brute_hits}
    print(f"      -> {len(results['brute'])} hosts  (wildcard: {wc})")

    known = results["passive"] | results["brute"]

    print("[3/7] permutations...")
    perms = permute(known, domain)
    print(f"      -> {len(perms)} candidates")
    perm_hits, _ = await layer_brute(
        domain, perms, concurrency=max(50, concurrency // 2)
    )
    results["perm"] = {h for h, _ in perm_hits}
    print(f"      -> {len(results['perm'])} hosts")

    all_hosts = sorted(known | results["perm"])

    print("[4/7] http probing...")
    probe = await layer_probe(all_hosts[:500])
    print(f"      -> probed {len(probe)}")

    print("[5/7] done.")
    print_results(all_hosts, probe)

    origin_data = {}
    if hunt_origin_flag:
        print(f"[6/7] origin IP hunt on {len(all_hosts)} subdomains...")
        origin_data = await layer_origin(all_hosts)
        print_origin_results(origin_data)
    else:
        print("[6/7] skipped (--hunt-origin not set)")

    email_data, whois_available = {}, False
    if hunt_emails_flag:
        crawl_targets = [h for h in all_hosts if h in probe] or all_hosts[:200]
        print(f"[7/7] email enumeration on {len(crawl_targets)} live hosts "
              f"(+ DMARC/TXT/WHOIS on apex)...")
        email_data, whois_available = await layer_email(crawl_targets, domain)
        print_email_results(email_data, whois_available)
    else:
        print("[7/7] skipped (--hunt-emails not set)")

    if out_path:
        write_output(out_path, all_hosts, probe)
        if hunt_origin_flag:
            json_path = Path(out_path).with_suffix(".origin.json")
            write_origin_json(str(json_path), origin_data)
        if hunt_emails_flag:
            write_email_output(out_path, email_data)

    return all_hosts

# ============ Orchestrator: email-only (interactive menu path) ============
async def reap_email_only(domain, out_path=None):
    """Skip subdomain enumeration entirely - just hit the apex + www with
    every email-discovery technique (web crawl, DMARC, TXT/SPF, WHOIS)."""
    print(f"[*] Target: {domain}")
    print("[1/1] email enumeration only (no subdomain scan)...")
    targets = [domain, f"www.{domain}"]
    email_data, whois_available = await layer_email(targets, domain)
    print_email_results(email_data, whois_available)

    if out_path:
        write_email_output(out_path, email_data)

    return email_data

def prompt_modes():
    """Interactive menu - email enumeration only."""
    print(f"\n{C.BOLD}{C.GREEN}{'=' * 60}{C.RESET}")
    print(f"{C.BOLD}{C.CYAN} SubReaper - what do you want to run?{C.RESET}")
    print(f"{C.BOLD}{C.GREEN}{'=' * 60}{C.RESET}")
    print(f"{C.YELLOW} 1) Email enumeration only{C.RESET}")
    print(f"{C.BOLD}{C.GREEN}{'=' * 60}{C.RESET}")
    while True:
        choice = input("Choose an option [1]: ").strip()
        if choice == "1":
            break
        print("  -> invalid choice, pick 1")
    return "email_only"

def main():
    print_banner()

    ap = argparse.ArgumentParser(
        prog="subreaper",
        description="SubReaper v2.2 - subdomain enumeration + origin IP discovery + email enumeration",
    )
    ap.add_argument("domain", help="root domain, e.g. example.com")
    ap.add_argument("--wordlist", default=None, help="path to wordlist file")
    ap.add_argument("--threads", type=int, default=CONCURRENCY,
                    help="concurrency (default 200)")
    ap.add_argument("-o", "--output", default=None,
                    help="save host list / email results to file")
    ap.add_argument("--hunt-origin", action="store_true",
                    help="run full pipeline with origin IP hunt (non-interactive)")
    ap.add_argument("--hunt-emails", action="store_true",
                    help="run full pipeline with email enumeration (non-interactive)")
    ap.add_argument("--email-only", action="store_true",
                    help="skip subdomain scan entirely, email enumeration only (non-interactive)")
    ap.add_argument("-y", "--yes", action="store_true",
                    help="skip the interactive menu (use only the flags above; "
                         "needed for cron/scripts/non-tty runs)")
    args = ap.parse_args()

    try:
        if args.email_only:
            asyncio.run(reap_email_only(args.domain, args.output))
            return

        if not args.yes and not args.hunt_origin and not args.hunt_emails and sys.stdin.isatty():
            mode = prompt_modes()
            if mode == "email_only":
                asyncio.run(reap_email_only(args.domain, args.output))
                return

        asyncio.run(reap(
            args.domain, args.wordlist, args.threads,
            args.output, args.hunt_origin, args.hunt_emails,
        ))
    except KeyboardInterrupt:
        print("\n[!] aborted")

if __name__ == "__main__":
    main()
