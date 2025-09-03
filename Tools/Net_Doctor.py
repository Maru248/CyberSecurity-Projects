# Net Doctor - Beginner network diagnostics tool
import argparse
import json
import os
import platform
import socket
import subprocess
import sys
import time
from urllib.request import urlopen, Request
from urllib.error import URLError, HTTPError

#        DEFAULTS
DEFAULT_IP_TARGETS = ["1.1.1.1", "8.8.8.8"]      # Cloudflare + Google
DEFAULT_DOMAIN = "wikipedia.org"                 # known domain
DEFAULT_URL = "https://www.wikipedia.org"        # known HTTPS URL
DEFAULT_PORTS = [53, 80, 443]                    # DNS / HTTP / HTTPS
DEFAULT_SPEED_URL = "https://www.wikipedia.org"  # small, safe page
DEFAULT_IPV6_TEST_HOST = "ipv6.google.com"       # common IPv6 hostname

#         HELPERS
def get_local_info():
    host = socket.gethostname()
    local_ip = "unknown"
    try:
        # UDP trick (no packets actually sent) to learn the outbound interface IP
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("1.1.1.1", 80))
        local_ip = s.getsockname()[0]
        s.close()
    except Exception:
        pass
    return {"hostname": host, "local_ip": local_ip, "platform": platform.platform()}

def get_public_ip(timeout=6):
    """
    Get public IP via simple HTTPS calls. Tries two providers.
    """
    providers = [
        "https://api64.ipify.org?format=json",  # returns {"ip":"x.x.x.x"}
        "https://ifconfig.me/all.json"          # returns {"ip_addr":"x.x.x.x", ...}
    ]
    for url in providers:
        try:
            req = Request(url, headers={"User-Agent": "NetDoctorPlus/1.0"})
            with urlopen(req, timeout=timeout) as r:
                text = r.read().decode("utf-8", errors="ignore")
                data = json.loads(text)
                ip = data.get("ip") or data.get("ip_addr")
                if ip:
                    return {"ok": True, "ip": ip, "source": url}
        except Exception as e:
            last_err = str(e)
    return {"ok": False, "error": last_err if 'last_err' in locals() else "lookup failed"}

def ping(host, count=2, timeout=2):
    """Cross-platform-ish ping using system ping."""
    win = sys.platform.startswith("win")
    cmd = ["ping"]
    if win:
        cmd += ["-n", str(count), "-w", str(timeout * 1000), host]
    else:
        cmd += ["-c", str(count), "-W", str(timeout), host]
    try:
        out = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout * count + 3)
        ok = (out.returncode == 0)
        tail = "\n".join(out.stdout.splitlines()[-6:])
        return {"ok": ok, "output": tail}
    except Exception as e:
        return {"ok": False, "error": str(e)}

def dns_resolve(domain, timeout=4):
    try:
        socket.setdefaulttimeout(timeout)
        ip = socket.gethostbyname(domain)
        return {"ok": True, "ip": ip}
    except Exception as e:
        return {"ok": False, "error": str(e)}

def dns_resolve_ipv6(domain, timeout=5):
    """Resolve AAAA; returns first IPv6 address if available."""
    try:
        socket.setdefaulttimeout(timeout)
        infos = socket.getaddrinfo(domain, None, socket.AF_INET6)
        addrs = sorted({i[4][0] for i in infos})
        return {"ok": bool(addrs), "ipv6": addrs[0] if addrs else None}
    except Exception as e:
        return {"ok": False, "error": str(e), "ipv6": None}

def tcp_check(host, port, timeout=3, family=socket.AF_UNSPEC):
    try:
        # Support IPv4/IPv6 by resolving with chosen family
        for res in socket.getaddrinfo(host, port, family, socket.SOCK_STREAM):
            af, socktype, proto, canonname, sa = res
            try:
                with socket.socket(af, socktype, proto) as s:
                    s.settimeout(timeout)
                    s.connect(sa)
                    return {"ok": True}
            except Exception as e:
                last_err = str(e)
        return {"ok": False, "error": last_err if 'last_err' in locals() else "connect failed"}
    except Exception as e:
        return {"ok": False, "error": str(e)}

def http_fetch(url, timeout=6):
    start = time.time()
    try:
        req = Request(url, headers={"User-Agent": "NetDoctorPlus/1.0"})
        with urlopen(req, timeout=timeout) as r:
            _ = r.read(512)  # only a small bite
            ms = int((time.time() - start) * 1000)
            return {"ok": True, "status": r.status, "latency_ms": ms, "final_url": r.geturl()}
    except Exception as e:
        return {"ok": False, "error": str(e)}

def http_fetch_ipv6(hostname, timeout=7):
    """Try HTTPS over IPv6 explicitly by checking IPv6 TCP reachability then fetching."""
    try:
        v6 = dns_resolve_ipv6(hostname, timeout=max(3, timeout - 2))
        if not v6["ok"] or not v6.get("ipv6"):
            return {"ok": False, "error": "No AAAA record / IPv6 address found"}
        ipv6 = v6["ipv6"]
        # Validate reachability to 443/tcp on the IPv6 literal first:
        pre = tcp_check(ipv6, 443, timeout=timeout, family=socket.AF_INET6)
        if not pre["ok"]:
            return {"ok": False, "error": f"IPv6 TCP 443 failed: {pre.get('error')}"}
        # Normal fetch by hostname so TLS SNI works
        url = f"https://{hostname}/"
        start = time.time()
        req = Request(url, headers={"User-Agent": "NetDoctorPlus/1.0"})
        with urlopen(req, timeout=timeout) as r:
            _ = r.read(256)
            ms = int((time.time() - start) * 1000)
            return {"ok": True, "status": r.status, "latency_ms": ms, "ipv6": ipv6}
    except Exception as e:
        return {"ok": False, "error": str(e)}

def captive_portal_check(timeout=6):
    """
    Try plain HTTP to a known site; captive portals often 302/redirect to a login page on a different domain.
    """
    test_url = "http://wikipedia.org"
    try:
        start = time.time()
        req = Request(test_url, headers={"User-Agent": "NetDoctorPlus/1.0"})
        with urlopen(req, timeout=timeout) as r:
            final = r.geturl()
            ms = int((time.time() - start) * 1000)
            # If final URL's domain is not wikipedia.org, likely a captive redirect.
            final_host = (final.split("://", 1)[-1].split("/", 1)[0]).lower()
            captive = ("wikipedia.org" not in final_host)
            return {"ok": True, "status": r.status, "latency_ms": ms, "final_url": final, "captive_portal_suspected": captive}
    except HTTPError as he:
        return {"ok": True, "status": he.code, "latency_ms": None, "final_url": test_url, "captive_portal_suspected": False}
    except URLError as ue:
        return {"ok": False, "error": str(ue)}
    except Exception as e:
        return {"ok": False, "error": str(e)}

def traceroute(target, max_hops=20, timeout=3):
    """
    Use system traceroute/tracert. Return short text output.
    """
    win = sys.platform.startswith("win")
    if win:
        cmd = ["tracert", "-h", str(max_hops), target]
    else:
        cmd = ["traceroute", "-m", str(max_hops), "-w", str(timeout), target]
    try:
        out = subprocess.run(cmd, capture_output=True, text=True, timeout=max_hops * (timeout + 1) + 10)
        ok = (out.returncode == 0) or (out.stdout.strip() != "")
        text = out.stdout if out.stdout else out.stderr
        # Keep last ~30 lines to avoid huge output
        lines = text.splitlines()[-30:]
        return {"ok": ok, "output": "\n".join(lines)}
    except Exception as e:
        return {"ok": False, "error": str(e)}

def speed_probe(url=DEFAULT_SPEED_URL, seconds=3, timeout=8):
    """
    Very rough 'speed' check: download small chunks for a few seconds and measure bytes/sec.
    Not a real speedtest; just basic signal.
    """
    try:
        req = Request(url, headers={"User-Agent": "NetDoctorPlus/1.0"})
        start = time.time()
        total = 0
        with urlopen(req, timeout=timeout) as r:
            while True:
                chunk = r.read(4096)
                if not chunk:
                    break
                total += len(chunk)
                if time.time() - start >= seconds:
                    break
        elapsed = time.time() - start
        bps = total / elapsed if elapsed > 0 else 0
        kbps = int(bps / 1024)
        mbps = round(bps / (1024*1024), 2)
        return {"ok": True, "kilobytes": int(total/1024), "seconds": round(elapsed, 2), "kbps": kbps, "mbps": mbps}
    except Exception as e:
        return {"ok": False, "error": str(e)}

# ===== Summary & Reporting =====
def summarize(results):
    lines = []
    # Local
    li = results.get("local", {})
    lines.append(f"- Host: {li.get('hostname','?')}  Local IP: {li.get('local_ip','?')}  ({li.get('platform','')})")

    # Public IP
    pub = results.get("public_ip", {})
    if pub.get("ok"):
        lines.append(f"- Public IP: {pub.get('ip')}")
    else:
        lines.append("- Public IP: unavailable")

    # Ping
    ping_all_ok = all(t["ok"] for t in results["ping"].values()) if results.get("ping") else True
    if ping_all_ok:
        lines.append("- Basic connectivity (ping): OK")
    else:
        bad = [h for h, r in results["ping"].items() if not r["ok"]]
        lines.append(f"- Basic connectivity (ping): PROBLEM → failed: {', '.join(bad)}")

    # DNS
    if results["dns"].get("ok"):
        lines.append(f"- DNS resolution: OK ({results['dns']['ip']})")
    else:
        lines.append(f"- DNS resolution: PROBLEM → {results['dns'].get('error','unknown error')}")

    # TCP
    if results["tcp"]:
        bad_ports = [p for p, r in results["tcp"].items() if not r["ok"]]
        if bad_ports:
            lines.append(f"- TCP ports failed: {', '.join(map(str, bad_ports))} (firewall/ISP?)")
        else:
            lines.append("- TCP connectivity (53/80/443): OK")

    # HTTP
    if results["http"]["ok"]:
        lines.append(f"- HTTP(S) fetch: OK (status {results['http']['status']}, {results['http']['latency_ms']} ms)")
    else:
        lines.append(f"- HTTP(S) fetch: PROBLEM → {results['http'].get('error','unknown error')}")

    # Captive portal
    if "captive" in results:
        cap = results["captive"]
        if cap.get("ok"):
            if cap.get("captive_portal_suspected"):
                lines.append("- Captive portal suspected: HTTP redirected to a different domain (login page likely).")
            else:
                lines.append("- Captive portal: no obvious redirect.")
        else:
            lines.append(f"- Captive portal check failed: {cap.get('error')}")

    # IPv6
    if "ipv6" in results:
        v6 = results["ipv6"]
        if v6.get("ok"):
            lines.append(f"- IPv6: OK (AAAA present, HTTPS reachable, {v6.get('latency_ms','?')} ms)")
        else:
            lines.append(f"- IPv6: PROBLEM → {v6.get('error','no IPv6')}")

    # DNS servers reachability
    if "dns_servers" in results and results["dns_servers"]:
        bad = [ip for ip, r in results["dns_servers"].items() if not r["ok"]]
        if bad:
            lines.append(f"- Public DNS reachability: FAILED for {', '.join(bad)}")
        else:
            lines.append("- Public DNS reachability (TCP:53): OK")

    # Speed
    if "speed" in results:
        sp = results["speed"]
        if sp.get("ok"):
            lines.append(f"- Basic speed probe: ~{sp['mbps']} Mbps (very rough)")
        else:
            lines.append(f"- Basic speed probe: FAILED → {sp.get('error')}")

    # Hints
    hints = []
    if not ping_all_ok:
        hints.append("Check router/cable/ISP or try a different Wi-Fi/AP.")
    if not results["dns"].get("ok"):
        hints.append("Change DNS to 1.1.1.1 or 8.8.8.8 and retry.")
    if not results["http"].get("ok"):
        hints.append("Firewall/SSL/proxy could be blocking HTTPS; try another URL.")
    if "captive" in results and results["captive"].get("captive_portal_suspected"):
        hints.append("Open a browser and complete the Wi-Fi login/consent page.")
    if "ipv6" in results and not results["ipv6"].get("ok"):
        hints.append("If you need IPv6, enable it on router/ISP; otherwise safe to ignore.")
    if "dns_servers" in results and any(not r["ok"] for r in results["dns_servers"].values()):
        hints.append("If DNS servers unreachable, check ISP blocks or local firewall.")
    if hints:
        lines.append("\nHints:")
        for h in hints:
            lines.append(f"• {h}")
    return "\n".join(lines)

def write_html(path, results, summary_text):
    def esc(s):
        s = "" if s is None else str(s)
        return s.replace("&","&amp;").replace("<","&lt;").replace(">","&gt;")
    blocks = []
    blocks.append(f"<h1>Net Doctor Plus Report</h1>")
    li = results.get("local", {})
    blocks.append(f"<p><b>Host:</b> {esc(li.get('hostname','?'))} &nbsp; <b>Local IP:</b> {esc(li.get('local_ip','?'))} &nbsp; <b>OS:</b> {esc(li.get('platform',''))}</p>")

    pub = results.get("public_ip", {})
    if pub:
        blocks.append(f"<p><b>Public IP:</b> {esc(pub.get('ip','unavailable'))}</p>")

    def pre(name, content):
        blocks.append(f"<h3>{esc(name)}</h3><pre>{esc(content)}</pre>")

    # Ping
    ping_blk = []
    for host, r in results.get("ping", {}).items():
        if r.get("ok"):
            ping_blk.append(f"[PING] {host}: OK\n{r.get('output','').strip()}")
        else:
            ping_blk.append(f"[PING] {host}: FAIL\n{r.get('error','')}")
    if ping_blk:
        pre("Ping", "\n\n".join(ping_blk))

    # DNS
    pre("DNS", json.dumps(results.get("dns", {}), indent=2))

    # TCP
    pre("TCP Ports", json.dumps(results.get("tcp", {}), indent=2))

    # HTTP
    pre("HTTP(S)", json.dumps(results.get("http", {}), indent=2))

    # Captive
    if "captive" in results:
        pre("Captive Portal", json.dumps(results["captive"], indent=2))

    # IPv6
    if "ipv6" in results:
        pre("IPv6", json.dumps(results["ipv6"], indent=2))

    # DNS servers reachability
    if "dns_servers" in results:
        pre("DNS Servers Reachability", json.dumps(results["dns_servers"], indent=2))

    # Speed
    if "speed" in results:
        pre("Basic Speed Probe", json.dumps(results["speed"], indent=2))

    # Traceroute
    if "traceroute" in results:
        pre("Traceroute", results["traceroute"].get("output") or results["traceroute"].get("error",""))

    blocks.append("<h2>Summary</h2>")
    blocks.append(f"<pre>{esc(summary_text)}</pre>")

    html = f"""<!doctype html>
<html><head>
<meta charset="utf-8">
<title>Net Doctor Plus Report</title>
<style>
body{{font-family:system-ui,-apple-system,Segoe UI,Roboto,Arial,sans-serif;max-width:900px;margin:2rem auto;padding:0 1rem;}}
pre{{background:#f6f8fa;border:1px solid #ddd;padding:1rem;overflow:auto;border-radius:8px}}
h1,h2,h3{{margin-top:1.2rem}}
</style>
</head><body>
{''.join(blocks)}
</body></html>"""
    with open(path, "w", encoding="utf-8") as f:
        f.write(html)

#        MAIN
def main():
    ap = argparse.ArgumentParser(description="Net Doctor Plus – Beginner Network Diagnostic (Enhanced)")
    ap.add_argument("--targets", nargs="*", default=DEFAULT_IP_TARGETS, help="IP addresses to ping")
    ap.add_argument("--domain", default=DEFAULT_DOMAIN, help="Domain to resolve for DNS test")
    ap.add_argument("--url", default=DEFAULT_URL, help="URL to GET for HTTP test")
    ap.add_argument("--ports", nargs="*", type=int, default=DEFAULT_PORTS, help="Ports to test via TCP")
    ap.add_argument("--dns-servers", nargs="*", default=[], help="Public DNS servers to test TCP:53 against (e.g., 1.1.1.1 8.8.8.8)")
    ap.add_argument("--traceroute", action="store_true", help="Run traceroute/tracert to the test URL host")
    ap.add_argument("--ipv6", action="store_true", help="Try IPv6 DNS + HTTPS")
    ap.add_argument("--speed", action="store_true", help="Run a very rough download speed probe")
    ap.add_argument("--html", help="Write an HTML report to this path")
    ap.add_argument("--json", help="Save a JSON report to this path")
    ap.add_argument("--count", type=int, default=2, help="Ping count (per host)")
    ap.add_argument("--timeout", type=int, default=3, help="Per-step timeout seconds")
    args = ap.parse_args()

    print("=== Net Doctor Plus ===")
    print(f"Targets (ping): {', '.join(args.targets)}")
    print(f"DNS domain:     {args.domain}")
    print(f"HTTP URL:       {args.url}")
    print(f"TCP ports:      {', '.join(map(str, args.ports))}")
    if args.dns_servers:
        print(f"DNS servers:    {', '.join(args.dns_servers)}")
    if args.traceroute: print("Traceroute:     enabled")
    if args.ipv6:       print("IPv6 checks:    enabled")
    if args.speed:      print("Speed probe:    enabled")
    if args.html:       print(f"HTML report:    {args.html}")
    print()

    results = {
        "local": get_local_info(),
        "ping": {},
        "dns": {},
        "tcp": {},
        "http": {},
    }

    # 0) Local info
    print(f"[LOCAL] Host={results['local']['hostname']}  IP={results['local']['local_ip']}  OS={results['local']['platform']}")

    # Public IP
    results["public_ip"] = get_public_ip(timeout=args.timeout + 3)
    if results["public_ip"].get("ok"):
        print(f"[PUB  ] Public IP: {results['public_ip']['ip']}")
    else:
        print(f"[PUB  ] Public IP: FAIL → {results['public_ip'].get('error')}")

    # 1) Ping (raw IPs)
    for host in args.targets:
        r = ping(host, count=args.count, timeout=args.timeout)
        results["ping"][host] = r
        status = "OK" if r["ok"] else "FAIL"
        print(f"[PING ] {host}: {status}")
        for line in (r.get("output") or "").splitlines():
            if line.strip():
                print("   ", line)

    # 2) DNS
    results["dns"] = dns_resolve(args.domain, timeout=args.timeout)
    if results["dns"]["ok"]:
        print(f"[DNS  ] {args.domain}: OK → {results['dns']['ip']}")
    else:
        print(f"[DNS  ] {args.domain}: FAIL → {results['dns'].get('error')}")

    # 3) TCP (to resolved domain if possible, else test against the raw targets)
    tcp_host = results["dns"]["ip"] if results["dns"]["ok"] else None
    targets_for_tcp = [tcp_host] if tcp_host else args.targets
    for port in args.ports:
        ok_any = False
        last_err = None
        for host in targets_for_tcp:
            r = tcp_check(host, port, timeout=args.timeout)
            if r["ok"]:
                ok_any = True
                break
            last_err = r.get("error")
        results["tcp"][port] = {"ok": ok_any, "error": None if ok_any else last_err}
        print(f"[TCP  ] port {port} @ {targets_for_tcp[0] if tcp_host else 'targets'}: {'OK' if ok_any else 'FAIL'}")

    # 4) HTTP
    results["http"] = http_fetch(args.url, timeout=args.timeout + 3)
    if results["http"]["ok"]:
        print(f"[HTTP ] {args.url}: OK (status {results['http']['status']}, {results['http']['latency_ms']} ms)")
    else:
        print(f"[HTTP ] {args.url}: FAIL → {results['http'].get('error')}")

    # 5) Captive portal check
    results["captive"] = captive_portal_check(timeout=args.timeout + 3)
    if results["captive"].get("ok"):
        if results["captive"].get("captive_portal_suspected"):
            print("[CAPT ] Captive portal likely (HTTP redirect to login page).")
        else:
            print("[CAPT ] No captive portal detected.")
    else:
        print(f"[CAPT ] Check failed → {results['captive'].get('error')}")

    # 6) IPv6 (optional)
    if args.ipv6:
        v6 = http_fetch_ipv6(DEFAULT_IPV6_TEST_HOST, timeout=args.timeout + 4)
        results["ipv6"] = v6
        if v6.get("ok"):
            print(f"[IPv6 ] OK via {DEFAULT_IPV6_TEST_HOST} (status {v6['status']}, {v6['latency_ms']} ms, {v6.get('ipv6')})")
        else:
            print(f"[IPv6 ] FAIL → {v6.get('error')}")

    # 7) Public DNS servers reachability (optional)
    if args.dns_servers:
        results["dns_servers"] = {}
        for ip in args.dns_servers:
            chk = tcp_check(ip, 53, timeout=args.timeout)
            results["dns_servers"][ip] = chk
            print(f"[DNS53] {ip}: {'OK' if chk['ok'] else 'FAIL'}")

    # 8) Traceroute (optional; to host of test URL)
    if args.traceroute:
        try:
            host_for_trace = args.url.split("://", 1)[-1].split("/", 1)[0]
        except Exception:
            host_for_trace = args.domain
        tr = traceroute(host_for_trace, max_hops=20, timeout=max(2, args.timeout))
        results["traceroute"] = tr
        if tr.get("ok"):
            print("[TRCE ] traceroute success (showing last lines):")
            for line in tr["output"].splitlines():
                print("   ", line)
        else:
            print(f"[TRCE ] traceroute failed → {tr.get('error')}")

    # 9) Speed probe (optional)
    if args.speed:
        sp = speed_probe(DEFAULT_SPEED_URL, seconds=3, timeout=args.timeout + 5)
        results["speed"] = sp
        if sp.get("ok"):
            print(f"[SPEED] ~{sp['mbps']} Mbps (very rough; {sp['kilobytes']} KB in {sp['seconds']}s)")
        else:
            print(f"[SPEED] FAILED → {sp.get('error')}")

    # 10) Summary
    print("\n=== Summary ===")
    summary_text = summarize(results)
    print(summary_text)

    # 11) Save JSON/HTML
    if args.json:
        try:
            with open(args.json, "w", encoding="utf-8") as f:
                json.dump(results, f, indent=2)
            print(f"\n[+] Saved JSON report to {args.json}")
        except Exception as e:
            print(f"[!] Could not save JSON report: {e}")

    if args.html:
        try:
            write_html(args.html, results, summary_text)
            print(f"[+] Saved HTML report to {args.html}")
        except Exception as e:
            print(f"[!] Could not save HTML report: {e}")

if __name__ == "__main__":
    main()
