#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
rename.py
================
پروژه‌ی ۲: ساب دستی (داخل همین ریپوی عمومی subs)

ورودی: manual/raw.txt — این خودش «pool» هست: بدون سقف/کف، هر بار که
        دستی جایگزینش کنی، قبلی‌ها کلاً از رده خارج می‌شن و فقط
        محتوای تازه اثر داره (هیچ تاریخچه/pool.json ای نگه داشته نمی‌شه).

خروجی: manual/sub.txt (base64) — فقط ۵ تای برتر (بر اساس پینگ عمومی)

مراحل:
  ۱. پارس کامل همه‌ی لینک‌های manual/raw.txt
  ۲. تست واقعی با sing-box: هم پینگ عمومی (gstatic) هم پینگ یه سایت داخل ایران
  ۳. فقط زنده‌ها، مرتب‌شده بر اساس بهترین پینگ عمومی؛ ۵ تای اول انتخاب می‌شن
  ۴. برای همون ۵ تا: تشخیص کشور/Cloudflare/CDN ایرانی + نام‌گذاری (منطق قبلی، دست‌نخورده)

این اسکریپت هم با push به manual/raw.txt اجرا می‌شه، هم هر ۶ ساعت خودکار
(حتی اگه raw.txt عوض نشده باشه) — چون کیفیت/پینگ نودها با گذشت زمان تغییر می‌کنه.
"""

import argparse
import base64
import json
import re
import socket
import subprocess
import sys
import time
import urllib.parse as urlparse
from pathlib import Path

import requests

# --------------------------------------------------------------------
# این متن رو هروقت خواستی تعریف کنی، همینجا جایگزین کن (خالی = نادیده گرفته می‌شه)
CUSTOM_LABEL = "کانفیگ های عمومی و رایگان"
# سایت ایرانی که برای تست پینگ استفاده می‌شه (هر آدرس دیگه‌ای هم بخوای همینجا عوضش کن)
IRAN_TEST_URL = "https://www.digikala.com"
GENERAL_TEST_URL = "http://www.gstatic.com/generate_204"
TOP_N = 5
# --------------------------------------------------------------------

CLASH_API = "http://127.0.0.1:9090"
IPV4_RE = re.compile(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$")


def b64pad(s: str) -> str:
    return s + "=" * (-len(s) % 4)


# ---------------------------------------------------------------------------
# پارسر کامل (برای تست واقعی نیاز به همه‌ی فیلدها داریم، نه فقط server/protocol)
# ---------------------------------------------------------------------------

def parse_vmess(link):
    raw = link[len("vmess://"):]
    data = json.loads(base64.b64decode(b64pad(raw)).decode("utf-8", "ignore"))
    return {
        "protocol": "vmess", "raw_link": link,
        "server": data.get("add"), "port": int(data.get("port", 0) or 0),
        "uuid": data.get("id"), "alter_id": int(data.get("aid", 0) or 0),
        "cipher": data.get("scy", "auto"), "network": data.get("net", "tcp"),
        "tls": data.get("tls", "") == "tls",
        "sni": data.get("sni") or data.get("host") or data.get("add"),
        "host": data.get("host"), "path": data.get("path", ""),
        "serviceName": data.get("path", "") if data.get("net") == "grpc" else "",
        "name": data.get("ps") or "vmess-node",
    }


def parse_uri_style(link, protocol):
    parsed = urlparse.urlparse(link)
    name = urlparse.unquote(parsed.fragment) if parsed.fragment else f"{protocol}-node"
    q = dict(urlparse.parse_qsl(parsed.query))
    node = {
        "protocol": protocol, "raw_link": link,
        "server": parsed.hostname, "port": parsed.port, "name": name,
        "network": q.get("type", "tcp"), "security": q.get("security", ""),
        "sni": q.get("sni") or q.get("host") or parsed.hostname,
        "host": q.get("host"), "path": q.get("path", ""),
        "fp": q.get("fp", ""), "pbk": q.get("pbk", ""), "sid": q.get("sid", ""),
        "flow": q.get("flow", ""), "alpn": q.get("alpn", ""),
        "serviceName": q.get("serviceName", ""),
    }
    if protocol == "vless":
        node["uuid"] = parsed.username
    elif protocol == "trojan":
        node["password"] = parsed.username
    return node


def parse_ss(link):
    body = link[len("ss://"):]
    if "#" in body:
        body, frag = body.split("#", 1)
        name = urlparse.unquote(frag)
    else:
        name = "ss-node"
    if "@" in body:
        userinfo, hostport = body.rsplit("@", 1)
        userinfo = urlparse.unquote(userinfo)
        try:
            userinfo = base64.b64decode(b64pad(userinfo)).decode()
        except Exception:
            pass
        method, password = userinfo.split(":", 1)
        hostport = hostport.split("?")[0].split("/")[0]
        host, port = hostport.rsplit(":", 1)
    else:
        body = urlparse.unquote(body)
        decoded = base64.b64decode(b64pad(body)).decode()
        methodpass, hostport = decoded.rsplit("@", 1)
        method, password = methodpass.split(":", 1)
        host, port = hostport.rsplit(":", 1)
    return {"protocol": "ss", "raw_link": link, "server": host, "port": int(port),
            "cipher": method, "password": password, "name": name}


def parse_hysteria2(link):
    parsed = urlparse.urlparse(link)
    q = dict(urlparse.parse_qsl(parsed.query))
    name = urlparse.unquote(parsed.fragment) if parsed.fragment else "hy2-node"
    return {"protocol": "hysteria2", "raw_link": link, "server": parsed.hostname,
            "port": parsed.port, "password": parsed.username or q.get("password", ""),
            "sni": q.get("sni", parsed.hostname), "insecure": q.get("insecure", "0") == "1",
            "name": name}


def parse_tuic(link):
    parsed = urlparse.urlparse(link)
    q = dict(urlparse.parse_qsl(parsed.query))
    name = urlparse.unquote(parsed.fragment) if parsed.fragment else "tuic-node"
    return {"protocol": "tuic", "raw_link": link, "server": parsed.hostname,
            "port": parsed.port, "uuid": parsed.username or "",
            "password": parsed.password or q.get("password", ""),
            "sni": q.get("sni", parsed.hostname), "alpn": q.get("alpn", "h3"), "name": name}


PARSERS = {
    "vmess://": parse_vmess,
    "vless://": lambda l: parse_uri_style(l, "vless"),
    "trojan://": lambda l: parse_uri_style(l, "trojan"),
    "ss://": parse_ss,
    "hysteria2://": parse_hysteria2,
    "hy2://": parse_hysteria2,
    "tuic://": parse_tuic,
}


def parse_link(link: str):
    link = link.strip()
    if not link or link.startswith("#"):
        return None
    for prefix, fn in PARSERS.items():
        if link.startswith(prefix):
            try:
                node = fn(link)
                if not node.get("server") or not node.get("port"):
                    return None
                return node
            except Exception as e:
                print(f"[WARN] پارس ناموفق: {link[:60]}... ({e})", file=sys.stderr)
                return None
    return None


# ---------------------------------------------------------------------------
# ساخت outbound سینگ‌باکس (مشترک با پروژه‌های دیگه)
# ---------------------------------------------------------------------------

def sanitize_flow(flow: str):
    if not flow:
        return ""
    if "xtls-rprx-vision" in flow:
        return "xtls-rprx-vision"
    return ""


def build_tls(node):
    if node.get("security") == "reality":
        return {"enabled": True, "server_name": node.get("sni") or node["server"],
                "utls": {"enabled": True, "fingerprint": node.get("fp") or "chrome"},
                "reality": {"enabled": True, "public_key": node.get("pbk", ""), "short_id": node.get("sid", "")}}
    if node.get("security") == "tls" or node.get("tls"):
        return {"enabled": True, "server_name": node.get("sni") or node["server"], "insecure": True}
    return None


def build_transport(node):
    net = node.get("network")
    if net == "ws":
        return {"type": "ws", "path": node.get("path", "/") or "/",
                "headers": {"Host": node.get("host") or node.get("sni") or ""}}
    if net == "grpc":
        return {"type": "grpc", "service_name": node.get("serviceName", "")}
    return None


def to_singbox_outbound(node, tag):
    proto = node["protocol"]
    base = {"tag": tag, "server": node["server"], "server_port": node["port"]}
    if proto == "vless":
        out = {**base, "type": "vless", "uuid": node["uuid"]}
        flow = sanitize_flow(node.get("flow", ""))
        if flow:
            out["flow"] = flow
        tls = build_tls(node)
        if tls:
            out["tls"] = tls
        tr = build_transport(node)
        if tr:
            out["transport"] = tr
        return out
    if proto == "vmess":
        out = {**base, "type": "vmess", "uuid": node["uuid"],
               "security": node.get("cipher") or "auto", "alter_id": node.get("alter_id", 0)}
        if node.get("tls"):
            out["tls"] = {"enabled": True, "server_name": node.get("sni") or node["server"], "insecure": True}
        tr = build_transport(node)
        if tr:
            out["transport"] = tr
        return out
    if proto == "trojan":
        out = {**base, "type": "trojan", "password": node["password"]}
        out["tls"] = build_tls(node) or {"enabled": True, "server_name": node.get("sni") or node["server"], "insecure": True}
        tr = build_transport(node)
        if tr:
            out["transport"] = tr
        return out
    if proto == "ss":
        return {**base, "type": "shadowsocks", "method": node["cipher"], "password": node["password"]}
    if proto == "hysteria2":
        return {**base, "type": "hysteria2", "password": node["password"],
                "tls": {"enabled": True, "server_name": node.get("sni") or node["server"], "insecure": node.get("insecure", True)}}
    if proto == "tuic":
        return {**base, "type": "tuic", "uuid": node.get("uuid", ""), "password": node.get("password", ""),
                "tls": {"enabled": True, "server_name": node.get("sni") or node["server"], "insecure": True,
                        "alpn": [node.get("alpn", "h3")]}}
    return None


# ---------------------------------------------------------------------------
# راه‌اندازی مقاوم sing-box (مثل پروژه‌های دیگه)
# ---------------------------------------------------------------------------

def wait_for_port(host, port, timeout=15):
    start = time.time()
    while time.time() - start < timeout:
        try:
            with socket.create_connection((host, port), timeout=1):
                return True
        except OSError:
            time.sleep(0.3)
    return False


def start_singbox(sing_box_bin, outbounds, work_dir: Path, startup_timeout: int):
    config = {
        "log": {"level": "warn"},
        "outbounds": outbounds + [{"tag": "direct", "type": "direct"}],
        "experimental": {"clash_api": {"external_controller": "127.0.0.1:9090"}},
    }
    cfg_path = work_dir / "rename_singbox_config.json"
    cfg_path.write_text(json.dumps(config, ensure_ascii=False, indent=2), encoding="utf-8")
    log_path = work_dir / "rename_singbox.log"
    log_file = open(log_path, "w", encoding="utf-8")
    proc = subprocess.Popen([sing_box_bin, "run", "-c", str(cfg_path)],
                             stdout=log_file, stderr=subprocess.STDOUT)
    if not wait_for_port("127.0.0.1", 9090, timeout=startup_timeout):
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except Exception:
            proc.kill()
        log_file.close()
        return None, log_path.read_text(encoding="utf-8", errors="ignore")
    return proc, None


OUTBOUND_ERROR_RE = re.compile(r"initialize outbound\[(\d+)\]")


def start_singbox_resilient(sing_box_bin, outbounds, work_dir: Path, startup_timeout: int, max_retries: int = 15):
    current = list(outbounds)
    dropped = 0
    for attempt in range(max_retries + 1):
        proc, err = start_singbox(sing_box_bin, current, work_dir, startup_timeout)
        if proc is not None:
            return proc, current, dropped
        m = OUTBOUND_ERROR_RE.search(err or "")
        if not m:
            print("[SING-BOX LOG]\n" + (err or ""), file=sys.stderr)
            raise RuntimeError("sing-box بالا نیامد و نتونستیم outbound خراب رو شناسایی کنیم")
        idx = int(m.group(1))
        if idx >= len(current):
            raise RuntimeError(f"ایندکس outbound نامعتبر ({idx})")
        print(f"[SING-BOX] outbound[{idx}] خراب بود، حذف و تلاش دوباره... ({attempt + 1}/{max_retries})",
              file=sys.stderr)
        del current[idx]
        dropped += 1
    raise RuntimeError(f"بعد از {max_retries} بار تلاش، sing-box بالا نیامد")


def test_delay(tag, url, timeout_ms=5000):
    try:
        r = requests.get(f"{CLASH_API}/proxies/{urlparse.quote(tag)}/delay",
                          params={"url": url, "timeout": timeout_ms}, timeout=(timeout_ms / 1000) + 2)
        if r.status_code == 200:
            data = r.json()
            if "delay" in data:
                return data["delay"]
        return None
    except Exception:
        return None


# ---------------------------------------------------------------------------
# geoip / تشخیص Cloudflare / CDN ایرانی (منطق قبلی، دست‌نخورده)
# ---------------------------------------------------------------------------

def resolve_ip(server: str):
    if IPV4_RE.match(server or ""):
        return server
    try:
        return socket.gethostbyname(server)
    except Exception:
        return None


def flag_emoji(country_code: str) -> str:
    if not country_code or len(country_code) != 2:
        return "🏳️"
    return "".join(chr(0x1F1E6 + (ord(c.upper()) - ord("A"))) for c in country_code)


_geoip_cache = {}
IRANIAN_CDN_KEYWORDS = ["arvan", "arvancloud", "parspack", "asiatech", "respina",
                        "afranet", "fanava", "shatel", "mobinnet", "tci", "pars online"]


def get_geo_info(ip: str):
    if not ip:
        return {"flag": "🏳️", "is_cloudflare": False, "is_iranian_cdn": False}
    if ip in _geoip_cache:
        return _geoip_cache[ip]
    result = {"flag": "🏳️", "is_cloudflare": False, "is_iranian_cdn": False}
    try:
        r = requests.get(f"http://ip-api.com/json/{ip}",
                          params={"fields": "countryCode,isp,org,as"}, timeout=6)
        if r.status_code == 200:
            data = r.json()
            cc = data.get("countryCode")
            combined = " ".join(filter(None, [data.get("isp"), data.get("org"), data.get("as")])).lower()
            is_cloudflare = "cloudflare" in combined
            is_iranian_cdn = any(kw in combined for kw in IRANIAN_CDN_KEYWORDS)
            flag = flag_emoji("IR") if is_iranian_cdn else flag_emoji(cc)
            result = {"flag": flag, "is_cloudflare": is_cloudflare, "is_iranian_cdn": is_iranian_cdn}
    except Exception:
        pass
    _geoip_cache[ip] = result
    time.sleep(0.3)
    return result


def rebuild_link(node, new_name):
    if node["protocol"] == "vmess":
        try:
            data = json.loads(base64.b64decode(b64pad(node["raw_link"][len("vmess://"):])).decode("utf-8", "ignore"))
            data["ps"] = new_name
            return "vmess://" + base64.b64encode(json.dumps(data, ensure_ascii=False).encode()).decode()
        except Exception:
            return node["raw_link"]
    base = node["raw_link"].split("#")[0]
    return base + "#" + urlparse.quote(new_name)


# ---------------------------------------------------------------------------
# main
# ---------------------------------------------------------------------------

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--raw-file", default="manual/raw.txt")
    ap.add_argument("--out-file", default="manual/sub.txt")
    ap.add_argument("--sing-box", default=None, help="مسیر باینری sing-box")
    args = ap.parse_args()

    raw_path = Path(args.raw_file)
    out_path = Path(args.out_file)

    if not raw_path.exists():
        print(f"[ERROR] {raw_path} پیدا نشد", file=sys.stderr)
        sys.exit(1)

    lines = [l for l in raw_path.read_text(encoding="utf-8").splitlines() if l.strip()]
    print(f"[INFO] تعداد خط خوانده‌شده: {len(lines)}", file=sys.stderr)

    nodes = [n for n in (parse_link(l) for l in lines) if n]
    print(f"[INFO] تعداد نود پارس‌شده: {len(nodes)}", file=sys.stderr)

    if not nodes:
        out_path.write_bytes(base64.b64encode(b""))
        print("[DONE] هیچ نودی پارس نشد، sub.txt خالی نوشته شد.", file=sys.stderr)
        return

    if not args.sing_box:
        print("[INFO] sing-box داده نشده؛ بدون تست، همون ترتیب فعلی به‌عنوان برترین‌ها استفاده می‌شه.",
              file=sys.stderr)
        survivors = nodes[:TOP_N]
        for n in survivors:
            n["delay"] = 0
            n["iran_delay"] = None
    else:
        import os
        work_dir = Path(os.environ.get("RUNNER_TEMP", "/tmp"))
        outbounds, tag_map = [], {}
        for i, n in enumerate(nodes):
            tag = f"node-{i}"
            ob = to_singbox_outbound(n, tag)
            if ob is None:
                continue
            outbounds.append(ob)
            tag_map[tag] = n

        startup_timeout = max(20, min(60, len(outbounds) // 10 + 15))
        proc, working_outbounds, dropped = start_singbox_resilient(
            args.sing_box, outbounds, work_dir, startup_timeout)
        working_tags = {ob["tag"] for ob in working_outbounds}

        try:
            alive = []
            for tag, n in tag_map.items():
                if tag not in working_tags:
                    continue
                delay = test_delay(tag, GENERAL_TEST_URL)
                if delay is None:
                    print(f"[DEAD] {n.get('name')}", file=sys.stderr)
                    continue
                iran_delay = test_delay(tag, IRAN_TEST_URL)
                n["delay"] = delay
                n["iran_delay"] = iran_delay
                alive.append(n)
                print(f"[OK] {n.get('name')} عمومی={delay}ms ایران={iran_delay}ms", file=sys.stderr)
        finally:
            proc.terminate()
            try:
                proc.wait(timeout=5)
            except Exception:
                proc.kill()

        alive.sort(key=lambda n: n["iran_delay"] if n["iran_delay"] is not None else 999999)
        survivors = alive[:TOP_N]
        print(f"[INFO] {len(alive)} نود زنده، {len(survivors)} تای برتر بر اساس پینگ ایران انتخاب شد",
              file=sys.stderr)

    final_links = []
    for n in survivors:
        ip = resolve_ip(n["server"])
        geo = get_geo_info(ip)

        prefix_parts = [geo["flag"]]
        if geo["is_cloudflare"]:
            prefix_parts.append("☁️")
        if CUSTOM_LABEL:
            prefix_parts.append(CUSTOM_LABEL)
        prefix_parts.append(n["protocol"].upper())

        suffix_parts = []
        if geo["is_cloudflare"]:
            suffix_parts.append("پشت کلادفلر")
        if geo["is_iranian_cdn"]:
            suffix_parts.append("تونل شده از CDN ایرانی")

        new_name = " ".join(prefix_parts + suffix_parts)
        final_links.append(rebuild_link(n, new_name))
        print(f"[FINAL] {n['server']} -> {new_name}", file=sys.stderr)

    blob = "\n".join(final_links).encode("utf-8")
    out_path.write_bytes(base64.b64encode(blob))
    print(f"[DONE] {len(final_links)} نود در {out_path} نوشته شد.", file=sys.stderr)


if __name__ == "__main__":
    main()
