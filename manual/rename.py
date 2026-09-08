#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
rename.py
================
پروژه‌ی ۲: ساب دستی (داخل همین ریپوی عمومی subs)

ورودی: manual/raw.txt (لینک‌هایی که خودت دستی اضافه/جایگزین می‌کنی)
خروجی: manual/sub.txt (base64، آماده برای v2rayNG/v2Box)

تنها کاری که خودکار انجام می‌شه: نام‌گذاری هر نود به فرمت:
    {پرچم کشور} {نوع پروتکل} {CUSTOM_LABEL}

هیچ تست زنده‌بودنی، هیچ حذف تکراری‌ای انجام نمی‌شه — دقیقاً همون چیزی
که دستی گذاشتی (فقط با اسم جدید) در sub.txt نهایی قرار می‌گیره.

CUSTOM_LABEL رو بعداً خودت همین‌جا (متغیر پایین فایل) تعریف کن.
"""

import base64
import json
import re
import socket
import sys
import time
import urllib.parse as urlparse
from pathlib import Path

import requests

# --------------------------------------------------------------------
# این متن رو هروقت خواستی تعریف کنی، همینجا جایگزین کن (خالی = نادیده گرفته می‌شه)
CUSTOM_LABEL = "سرویس پشتیبان(از محل سرور های رایگان سطح اینترنت)"
# --------------------------------------------------------------------

IPV4_RE = re.compile(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$")


def b64pad(s: str) -> str:
    return s + "=" * (-len(s) % 4)


# --- پارسرهای مینیمال، فقط برای گرفتن protocol/server (بدون نیاز به همه‌ی فیلدها) ---

def parse_link_minimal(link: str):
    link = link.strip()
    if not link or link.startswith("#"):
        return None
    if link.startswith("vmess://"):
        try:
            data = json.loads(base64.b64decode(b64pad(link[len("vmess://"):])).decode("utf-8", "ignore"))
            return {"protocol": "vmess", "raw_link": link, "server": data.get("add")}
        except Exception:
            return None
    for proto in ("vless", "trojan", "ss", "hysteria2", "hy2", "tuic"):
        prefix = f"{proto}://"
        if link.startswith(prefix):
            try:
                if proto == "ss":
                    body = link[len("ss://"):].split("#")[0]
                    hostpart = body.rsplit("@", 1)[-1] if "@" in body else body
                    host = hostpart.split(":")[0].split("?")[0]
                    return {"protocol": "ss", "raw_link": link, "server": host}
                parsed = urlparse.urlparse(link)
                real_proto = "hysteria2" if proto == "hy2" else proto
                return {"protocol": real_proto, "raw_link": link, "server": parsed.hostname}
            except Exception:
                return None
    return None


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
    """یک استعلام، هم پرچم کشور هم تشخیص Cloudflare/CDN ایرانی رو می‌ده."""
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

            # اگه واقعاً CDN ایرانی تشخیص داده شد، پرچم رو مجبوراً ایران بذار
            # (حتی اگه geoip کشور دیگه‌ای گزارش داده باشه)
            flag = flag_emoji("IR") if is_iranian_cdn else flag_emoji(cc)

            result = {"flag": flag, "is_cloudflare": is_cloudflare, "is_iranian_cdn": is_iranian_cdn}
    except Exception:
        pass

    _geoip_cache[ip] = result
    time.sleep(0.3)  # رعایت محدودیت نرخ ip-api.com
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


def main():
    raw_path = Path("manual/raw.txt")
    out_path = Path("manual/sub.txt")

    if not raw_path.exists():
        print(f"[ERROR] {raw_path} پیدا نشد", file=sys.stderr)
        sys.exit(1)

    lines = [l for l in raw_path.read_text(encoding="utf-8").splitlines() if l.strip()]
    print(f"[INFO] تعداد خط خوانده‌شده: {len(lines)}", file=sys.stderr)

    final_links = []
    for line in lines:
        node = parse_link_minimal(line)
        if not node:
            print(f"[WARN] پارس نشد، دست‌نخورده رد شد: {line[:50]}", file=sys.stderr)
            final_links.append(line.strip())
            continue
        ip = resolve_ip(node["server"])
        geo = get_geo_info(ip)

        prefix_parts = [geo["flag"]]
        if geo["is_cloudflare"]:
            prefix_parts.append("☁️")
        if CUSTOM_LABEL:
            prefix_parts.append(CUSTOM_LABEL)
        prefix_parts.append(node["protocol"].upper())

        suffix_parts = []
        if geo["is_cloudflare"]:
            suffix_parts.append("پشت کلادفلر")
        if geo["is_iranian_cdn"]:
            suffix_parts.append("تونل شده از CDN ایرانی")

        new_name = " ".join(prefix_parts + suffix_parts)
        final_links.append(rebuild_link(node, new_name))
        print(f"[OK] {node['server']} -> {new_name}", file=sys.stderr)

    blob = "\n".join(final_links).encode("utf-8")
    out_path.write_bytes(base64.b64encode(blob))
    print(f"[DONE] {len(final_links)} نود در {out_path} نوشته شد.", file=sys.stderr)


if __name__ == "__main__":
    main()
