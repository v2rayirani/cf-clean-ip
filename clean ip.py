# tester.py
# - Forced AND when both download & upload > 0 (no prompt)
# - Random order option (within groups)
# - Group-by-input-line execution with clear banners
# - Percentage sampling of IPs (0..100); 0% -> immediate exit
# - Persist clean IPs on the fly + safe on unexpected exit (signals, atexit)
# - Fixed minor bugs (httpupgrade host, try_upload arg)

import os
import json
import time
import queue
import base64
import shutil
import signal
import socket
import threading
import subprocess
import random
import math
import atexit
from pathlib import Path
from urllib.parse import urlparse, unquote

import requests
import ipaddress

# =========================
# User settings / files
# =========================
PROJECT_ROOT = Path(".").resolve()
INPUT_FILE = PROJECT_ROOT / "input.txt"    # URI template(s) (one per line)
IP_FILE = PROJECT_ROOT / "ip4.txt"         # IP or ranges (one per line)
CONFIG_DIR = PROJECT_ROOT / "configs"
CLEAN_IP_FILE = PROJECT_ROOT / "clean_ip.txt"

HTTP_TIMEOUT = 10.0                 # per HTTP attempt (fallback if no deadline)
SOCKS_READY_TIMEOUT = 6.0           # wait until SOCKS port is listening
XRAY_BOOT_GRACE = 0.3               # short grace after process start
BASE_LOCAL_PORT = 19000
PRETTY_JSON = True

# Download endpoints
TEST_ENDPOINTS = [
    "https://speed.cloudflare.com/__down?bytes={n}",
    "https://cf.loxal.net/__down?bytes={n}",
    "https://detectportal.firefox.com/success.txt",
    "https://example.com/",
]

# Upload endpoints
UPLOAD_ENDPOINTS = [
    "https://httpbin.org/post",
    "https://postman-echo.com/post",
]

# xray binary candidates
XRAY_CANDIDATES = [
    PROJECT_ROOT / "xray.exe",
    PROJECT_ROOT / "vendor" / "xray.exe",
    PROJECT_ROOT / "core_engine" / "xray.exe",
    PROJECT_ROOT / "xray",
    PROJECT_ROOT / "vendor" / "xray",
    PROJECT_ROOT / "core_engine" / "xray",
]
# =========================

# ---------- shared state for persistence ----------
overall_good_ips = set()
good_ips_lock = threading.Lock()
shutdown_flag = threading.Event()

def _ip_sort_key(ipstr: str):
    return tuple(int(p) for p in ipstr.split("."))

def write_clean_ips_atomic(ips_set: set[str]):
    """Atomically write clean IPs to CLEAN_IP_FILE (create/replace only if there is at least one IP)."""
    # اگر هیچ آی‌پی تمیز نداریم، فایل رو دست نمی‌زنیم تا «خروج بدون آی‌پی» حفظ بشه
    if not ips_set:
        return
    CLEAN_IP_FILE.parent.mkdir(parents=True, exist_ok=True)
    tmp = CLEAN_IP_FILE.with_suffix(".tmp")
    with open(tmp, "w", encoding="utf-8") as fc:
        for ip in sorted(ips_set, key=_ip_sort_key):
            fc.write(ip + "\n")
    tmp.replace(CLEAN_IP_FILE)

def persist_now():
    with good_ips_lock:
        write_clean_ips_atomic(overall_good_ips)

def handle_signal(signum, frame):
    try:
        print(f"\n[INFO] Received signal {signum}. Persisting results and exiting...")
    except Exception:
        pass
    shutdown_flag.set()
    persist_now()
    # بعدش اجازه می‌دیم main و نخ‌ها خودشون تمیز خارج بشن

# Register signal handlers (best-effort on Windows for SIGINT)
signal.signal(signal.SIGINT, handle_signal)
try:
    signal.signal(signal.SIGTERM, handle_signal)
except Exception:
    pass  # may not be available on some platforms

@atexit.register
def _on_exit():
    # آخرین شانس برای ذخیره‌ی نتایج
    persist_now()
    # configs را هم تمیز کنیم (اگر main قبلاً نکرد)
    try:
        cleanup_configs()
    except Exception:
        pass


# ---------- helpers ----------
def find_xray_binary() -> Path:
    for p in XRAY_CANDIDATES:
        if p.exists():
            return p
    x = shutil.which("xray.exe") or shutil.which("xray")
    if x:
        return Path(x)
    raise FileNotFoundError("xray binary not found. Put it in ./, ./vendor/, or ./core_engine/")

def parse_qs_flat(u):
    raw = u.query if hasattr(u, "query") else str(u)
    result = {}
    if not raw:
        return result
    for pair in raw.split("&"):
        if not pair:
            continue
        if "=" in pair:
            k, v = pair.split("=", 1)
            result[k] = unquote(v)
        else:
            result[pair] = ""
    return result

def ensure_leading_slash(p: str | None) -> str:
    if not p:
        return "/"
    p = unquote(p)
    return p if p.startswith("/") else ("/" + p)

def b64_decode(data: str) -> str:
    data = data.strip().replace("-", "+").replace("_", "/")
    pad = len(data) % 4
    if pad:
        data += "=" * (4 - pad)
    return base64.b64decode(data).decode("utf-8", errors="ignore")

def wait_until_listening(port: int, timeout: float) -> bool:
    deadline = time.time() + timeout
    while time.time() < deadline:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(0.25)
        try:
            if s.connect_ex(("127.0.0.1", port)) == 0:
                s.close()
                return True
        finally:
            try:
                s.close()
            except Exception:
                pass
        time.sleep(0.1)
    return False


# ---------- parsers ----------
def parse_vless(uri: str) -> dict:
    u = urlparse(uri)
    uuid = u.username or ""
    host = u.hostname
    port = u.port or 443
    q = parse_qs_flat(u)
    return {
        "proto": "vless",
        "uuid": uuid,
        "host": host,
        "port": int(port),
        "security": (q.get("security", "none") or "none").lower(),
        "sni": q.get("sni"),
        "alpn": [p.strip() for p in (q.get("alpn", "") or "").split(",") if p.strip()] or None,
        "transport": (q.get("type") or "").lower() or None,
        "host_header": q.get("host"),
        "path": ensure_leading_slash(q.get("path")),
        "tag": unquote(u.fragment) if u.fragment else None,
        "encryption": q.get("encryption", "none"),
    }

def parse_vmess(uri: str) -> dict:
    payload = uri[len("vmess://"):]
    raw = b64_decode(payload)
    d = json.loads(raw)
    host = d.get("add")
    port = int(d.get("port", 443))
    uuid = d.get("id")
    aid = int(d.get("aid", 0)) if str(d.get("aid", "0")).isdigit() else 0
    net = (d.get("net") or "").lower() or None
    tls_flag = str(d.get("tls", "")).lower()
    security = "tls" if tls_flag in ("tls", "reality") else "none"
    sni = d.get("sni")
    host_header = d.get("host") or d.get("sni")
    path = ensure_leading_slash(d.get("path"))
    alpn_raw = d.get("alpn")
    if isinstance(alpn_raw, list):
        alpn = [str(x).strip() for x in alpn_raw if str(x).strip()]
    elif isinstance(alpn_raw, str) and alpn_raw.strip():
        alpn = [p.strip() for p in alpn_raw.split(",") if p.strip()]
    else:
        alpn = None
    tag = d.get("ps")
    cipher = d.get("scy") or "auto"
    return {
        "proto": "vmess",
        "uuid": uuid,
        "aid": aid,
        "cipher": cipher,
        "host": host,
        "port": port,
        "security": security,
        "sni": sni,
        "alpn": alpn,
        "transport": net,
        "host_header": host_header,
        "path": path,
        "tag": tag,
    }

def parse_trojan(uri: str) -> dict:
    u = urlparse(uri)
    password = u.username or ""
    host = u.hostname
    port = u.port or 443
    q = parse_qs_flat(u)
    return {
        "proto": "trojan",
        "password": password,
        "host": host,
        "port": int(port),
        "security": (q.get("security", "tls") or "tls").lower(),
        "sni": q.get("sni"),
        "alpn": [p.strip() for p in (q.get("alpn", "") or "").split(",") if p.strip()] or None,
        "transport": (q.get("type") or "").lower() or None,
        "host_header": q.get("host"),
        "path": ensure_leading_slash(q.get("path")),
        "tag": unquote(u.fragment) if u.fragment else None,
    }

def parse_ss(uri: str) -> dict:
    u = urlparse(uri)
    host = u.hostname
    port = u.port or 8388
    tag = unquote(u.fragment) if u.fragment else None
    method = None
    password = None
    if u.username and u.password:
        method = unquote(u.username)
        password = unquote(u.password)
    else:
        body = uri[len("ss://"):]
        if "#" in body:
            body = body.split("#", 1)[0]
        try:
            decoded = b64_decode(body)
            if "@" in decoded and ":" in decoded:
                creds, _rest = decoded.split("@", 1)
                method, password = creds.split(":", 1)
            elif ":" in decoded:
                method, password = decoded.split(":", 1)
        except Exception:
            pass
    if not (method and password and host and port):
        raise ValueError("Invalid SS URI")
    return {
        "proto": "ss",
        "method": method,
        "password": password,
        "host": host,
        "port": int(port),
        "tag": tag,
    }

def parse_hysteria2(uri: str) -> dict:
    u = urlparse(uri)
    auth = u.username or ""
    host = u.hostname
    port = u.port or 443
    q = parse_qs_flat(u)
    insecure = str(q.get("insecure", "0")).strip().lower() in ("1", "true")
    sni = q.get("sni")
    alpn = [p.strip() for p in (q.get("alpn", "") or "").split(",") if p.strip()] or None
    tag = unquote(u.fragment) if u.fragment else None
    return {
        "proto": "hysteria2",
        "auth": auth,
        "host": host,
        "port": int(port),
        "sni": sni,
        "alpn": alpn,
        "insecure": insecure,
        "tag": tag,
    }

def parse_uri_generic(uri: str) -> dict:
    low = uri.lower()
    if low.startswith("vless://"):
        return parse_vless(uri)
    if low.startswith("vmess://"):
        return parse_vmess(uri)
    if low.startswith("trojan://"):
        return parse_trojan(uri)
    if low.startswith("ss://"):
        return parse_ss(uri)
    if low.startswith("hysteria2://") or low.startswith("hy2://"):
        return parse_hysteria2(uri)
    raise ValueError("Unsupported scheme")


# ---------- JSON builders ----------
def inbound_socks(port: int) -> dict:
    return {
        "tag": "socks-in",
        "port": port,
        "listen": "127.0.0.1",
        "protocol": "socks",
        "settings": {"udp": True, "auth": "noauth"},
        "sniffing": {"enabled": True, "destOverride": ["http", "tls", "quic"]},
    }

def build_stream_settings(parsed: dict, force_tls: bool = False) -> dict:
    stream = {}
    sec = parsed.get("security", "none")
    is_tls = force_tls or sec in ("tls", "reality")
    if is_tls:
        stream["security"] = "tls"
        tls = {}
        sni = parsed.get("sni") or parsed.get("host_header") or parsed.get("host")
        if sni:
            tls["serverName"] = sni
        alpn = parsed.get("alpn") or ["h2", "http/1.1"]
        tls["nextProto"] = alpn
        tls["fingerprint"] = "chrome"
        if tls:
            stream["tlsSettings"] = tls

    net = parsed.get("transport")
    if net in ("ws", "httpupgrade", "xhttp"):
        stream["network"] = net
        if net == "ws":
            ws = {"path": parsed.get("path", "/")}
            if parsed.get("host_header"):
                ws["headers"] = {"Host": parsed["host_header"]}
            stream["wsSettings"] = ws
        elif net == "httpupgrade":
            hu = {}
            if parsed.get("path"):
                hu["path"] = parsed["path"]
            if parsed.get("host_header"):
                hu["host"] = parsed["host_header"]
            stream["httpupgradeSettings"] = hu
        elif net == "xhttp":
            xh = {}
            if parsed.get("path"):
                xh["path"] = parsed["path"]
            if parsed.get("host_header"):
                xh["host"] = parsed["host_header"]
            stream["xhttpSettings"] = xh

    return stream

def build_outbound(parsed: dict) -> dict:
    p = parsed["proto"]
    if p == "vless":
        vnext = {
            "address": parsed["host"],
            "port": parsed["port"],
            "users": [{"id": parsed["uuid"], "encryption": parsed.get("encryption", "none")}],
        }
        outbound = {"tag": "proxy", "protocol": "vless", "settings": {"vnext": [vnext]}}
        stream = build_stream_settings(parsed)
        if stream:
            outbound["streamSettings"] = stream
        return outbound
    if p == "vmess":
        vnext = {
            "address": parsed["host"],
            "port": parsed["port"],
            "users": [{"id": parsed["uuid"], "alterId": parsed.get("aid", 0), "security": parsed.get("cipher", "auto")}],
        }
        outbound = {"tag": "proxy", "protocol": "vmess", "settings": {"vnext": [vnext]}}
        stream = build_stream_settings(parsed)
        if stream:
            outbound["streamSettings"] = stream
        return outbound
    if p == "trojan":
        servers = [{"address": parsed["host"], "port": parsed["port"], "password": parsed["password"]}]
        outbound = {"tag": "proxy", "protocol": "trojan", "settings": {"servers": servers}}
        stream = build_stream_settings(parsed, force_tls=True)
        if stream:
            outbound["streamSettings"] = stream
        return outbound
    if p == "ss":
        servers = [{"address": parsed["host"], "port": parsed["port"], "method": parsed["method"], "password": parsed["password"]}]
        return {"tag": "proxy", "protocol": "shadowsocks", "settings": {"servers": servers}}
    if p == "hysteria2":
        settings = {"server": parsed["host"], "serverPort": parsed["port"], "password": parsed["auth"]}
        tls_settings = {}
        sni = parsed.get("sni") or parsed.get("host_header") or parsed.get("host")
        if sni:
            tls_settings["serverName"] = sni
        alpn = parsed.get("alpn") or ["h2", "http/1.1"]
        tls_settings["nextProto"] = alpn
        outbound = {"tag": "proxy", "protocol": "hysteria2", "settings": settings}
        outbound["streamSettings"] = {"network": "quic", "security": "tls", "tlsSettings": tls_settings}
        return outbound
    raise ValueError("Unsupported protocol in builder")

def build_one_config(parsed: dict, local_socks_port: int) -> dict:
    dns_block = {
        "servers": [
            {"address": "https+local://1.1.1.1/dns-query"},
            {"address": "https+local://8.8.8.8/dns-query"},
            "localhost"
        ],
        "queryStrategy": "UseIP"
    }
    routing = {"rules": [{"type": "field", "outboundTag": "proxy", "network": "tcp,udp"}]}
    conf = {
        "log": {"loglevel": "warning"},
        "dns": dns_block,
        "inbounds": [inbound_socks(local_socks_port)],
        "outbounds": [
            build_outbound(parsed),
            {"tag": "direct", "protocol": "freedom"},
            {"tag": "blocked", "protocol": "blackhole"},
        ],
        "routing": routing,
    }
    return conf


# ---------- runner ----------
def write_json(path: Path, data: dict):
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        if PRETTY_JSON:
            json.dump(data, f, ensure_ascii=False, indent=2)
        else:
            json.dump(data, f, ensure_ascii=False)

def run_xray(xray_path: Path, json_path: Path) -> subprocess.Popen:
    creationflags = 0
    if os.name == "nt":
        creationflags = subprocess.CREATE_NO_WINDOW
    return subprocess.Popen(
        [str(xray_path), "-c", str(json_path)],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        creationflags=creationflags,
    )

# ---- try_download with deadline/timeout ----
def try_download(port: int, bytes_to_download: int,
                 timeout_override: float | None = None,
                 deadline_ts: float | None = None) -> bool:
    if bytes_to_download < 1:
        return False
    proxies = {"http": f"socks5h://127.0.0.1:{port}", "https": f"socks5h://127.0.0.1:{port}"}
    def effective_timeout():
        base = HTTP_TIMEOUT
        if timeout_override is not None:
            base = min(base, float(timeout_override))
        if deadline_ts is not None:
            rem = deadline_ts - time.time()
            if rem <= 0: return 0.0
            base = min(base, rem)
        return max(0.5, float(base))
    for url_tpl in TEST_ENDPOINTS:
        if deadline_ts is not None and (deadline_ts - time.time()) <= 0:
            return False
        url = url_tpl.format(n=bytes_to_download) if "{n}" in url_tpl else url_tpl
        try:
            to = effective_timeout()
            if to <= 0.0: return False
            r = requests.get(url, proxies=proxies, timeout=to, stream=True)
            if r.status_code != 200:
                r.close(); continue
            read_total = 0
            for chunk in r.iter_content(chunk_size=min(8192, bytes_to_download)):
                if not chunk: break
                read_total += len(chunk)
                if read_total >= bytes_to_download: break
                if deadline_ts is not None and (deadline_ts - time.time()) <= 0: break
            r.close()
            if read_total >= bytes_to_download:
                return True
        except Exception:
            pass
    return False

# ---- try_upload with deadline/timeout ----
def try_upload(port: int, bytes_to_upload: int,
               timeout_override: float | None = None,
               deadline_ts: float | None = None) -> bool:
    if bytes_to_upload < 1:
        return False
    proxies = {"http": f"socks5h://127.0.0.1:{port}", "https": f"socks5h://127.0.0.1:{port}"}
    def effective_timeout():
        base = HTTP_TIMEOUT
        if timeout_override is not None:
            base = min(base, float(timeout_override))
        if deadline_ts is not None:
            rem = deadline_ts - time.time()
            if rem <= 0: return 0.0
            base = min(base, rem)
        return max(0.5, float(base))
    payload = b"x" * bytes_to_upload
    headers = {"Content-Type": "application/octet-stream"}
    for url in UPLOAD_ENDPOINTS:
        if deadline_ts is not None and (deadline_ts - time.time()) <= 0:
            return False
        try:
            to = effective_timeout()
            if to <= 0.0: return False
            r = requests.post(url, data=payload, headers=headers, proxies=proxies, timeout=to)
            status = r.status_code
            r.close()
            if status in (200, 201, 202):
                return True
        except Exception:
            pass
    return False


# ---------- progress UI ----------
def format_eta(seconds: float) -> str:
    if seconds is None or seconds == float("inf"):
        return "--:--"
    seconds = max(0, int(seconds))
    m, s = divmod(seconds, 60)
    return f"{m:02d}:{s:02d}"

def print_progress(done: int, total: int, start_time: float, bar_width: int = 30):
    if total <= 0:
        return
    pct = done / total if total > 0 else 1.0
    filled = int(bar_width * pct)
    bar = "█" * filled + "-" * (bar_width - filled)
    elapsed = time.time() - start_time
    rate = done / elapsed if elapsed > 0 else 0.0
    eta = (total - done) / rate if rate > 0 else float("inf")
    msg = f"\r[{bar}]  {pct*100:5.1f}%  ({done}/{total})  ETA {format_eta(eta)}"
    print(msg, end="", flush=True)


# ---------- IP expansion ----------
def is_single_ip_line(line: str) -> bool:
    s = line.strip()
    if not s or "/" in s or "-" in s:
        return False
    try:
        ipaddress.ip_address(s)
        return True
    except Exception:
        return False

def expand_ip_line(line: str):
    line = line.strip()
    if not line:
        return []
    if "/" in line:
        try:
            net = ipaddress.ip_network(line, strict=False)
            return [str(ip) for ip in net.hosts()] if net.num_addresses > 1 else [str(next(net.hosts()))]
        except Exception:
            return []
    if "-" in line:
        try:
            start_s, end_s = line.split("-", 1)
            start_ip = ipaddress.ip_address(start_s.strip())
            end_ip = ipaddress.ip_address(end_s.strip())
            if int(end_ip) < int(start_ip):
                return []
            ips = []
            cur = int(start_ip)
            endi = int(end_ip)
            MAX_RANGE = 65536
            if (endi - cur) > MAX_RANGE:
                raise ValueError("Range too large")
            while cur <= endi:
                ips.append(str(ipaddress.ip_address(cur)))
                cur += 1
            return ips
        except Exception:
            return []
    try:
        ipaddress.ip_address(line)
        return [line]
    except Exception:
        return []


# ---------- worker ----------
def worker(task_queue: "queue.Queue[tuple[int,str,str]]",
           xray_path: Path,
           download_bytes: int,
           upload_bytes: int,
           retries: int,
           per_op_time_budget: int,   # seconds (0 = no limit) — for each op (DL/UL) separately
           require_both_when_both_selected: bool,
           progress_dict: dict,
           progress_lock: threading.Lock,
           total_count: int,
           start_time: float):
    while not shutdown_flag.is_set():
        try:
            idx, uri, ip = task_queue.get_nowait()
        except queue.Empty:
            return

        ok = False
        proc = None
        local_port = BASE_LOCAL_PORT + (idx % 40000)
        try:
            parsed = parse_uri_generic(uri)
            parsed["host"] = ip  # override host with candidate IP

            conf = build_one_config(parsed, local_port)
            json_path = CONFIG_DIR / f"cfg_{idx+1}_{ip}.json"
            write_json(json_path, conf)

            proc = run_xray(xray_path, json_path)
            time.sleep(XRAY_BOOT_GRACE)

            if not wait_until_listening(local_port, SOCKS_READY_TIMEOUT):
                raise RuntimeError("SOCKS inbound did not become ready in time")

            # per-op deadlines
            dl_deadline = (time.time() + per_op_time_budget) if (per_op_time_budget and per_op_time_budget > 0 and download_bytes > 0) else None
            ul_deadline = (time.time() + per_op_time_budget) if (per_op_time_budget and per_op_time_budget > 0 and upload_bytes > 0) else None

            download_ok = False
            upload_ok = False

            for attempt in range(1, max(1, retries) + 1):
                if shutdown_flag.is_set():
                    break

                if download_bytes > 0 and not download_ok:
                    timeout_override = None
                    if dl_deadline is not None:
                        remaining = dl_deadline - time.time()
                        if remaining > 0:
                            timeout_override = min(HTTP_TIMEOUT, remaining)
                    if dl_deadline is None or (dl_deadline - time.time()) > 0:
                        if try_download(local_port, download_bytes,
                                        timeout_override=timeout_override,
                                        deadline_ts=dl_deadline):
                            download_ok = True

                if upload_bytes > 0 and not upload_ok:
                    timeout_override_u = None
                    if ul_deadline is not None:
                        remaining_u = ul_deadline - time.time()
                        if remaining_u > 0:
                            timeout_override_u = min(HTTP_TIMEOUT, remaining_u)
                    if ul_deadline is None or (ul_deadline - time.time()) > 0:
                        if try_upload(local_port, upload_bytes,
                                      timeout_override=timeout_override_u,
                                      deadline_ts=ul_deadline):
                            upload_ok = True

                if download_bytes > 0 and upload_bytes > 0:
                    if require_both_when_both_selected:
                        if download_ok and upload_ok:
                            break
                    else:
                        if download_ok or upload_ok:
                            break
                else:
                    if (download_bytes == 0 or download_ok) and (upload_bytes == 0 or upload_ok):
                        break

                time.sleep(0.6 * attempt)

            if download_bytes > 0 and upload_bytes > 0:
                ok = (download_ok and upload_ok) if require_both_when_both_selected else (download_ok or upload_ok)
            elif download_bytes > 0:
                ok = download_ok
            else:
                ok = upload_ok

        except Exception as e:
            ok = False
            try:
                print(f"\n[ERROR] uri={uri} ip={ip} exception: {e}\n")
            except Exception:
                pass
        finally:
            if proc and proc.poll() is None:
                try:
                    if os.name == "nt":
                        proc.send_signal(signal.SIGTERM)
                        proc.wait(timeout=2)
                    else:
                        proc.terminate()
                        proc.wait(timeout=2)
                except Exception:
                    try:
                        proc.kill()
                    except Exception:
                        pass

            # --- persist per success immediately ---
            if ok:
                with good_ips_lock:
                    overall_good_ips.add(ip)
                    write_clean_ips_atomic(overall_good_ips)

            # progress
            with progress_lock:
                progress_dict["done"] += 1
                print_progress(progress_dict["done"], total_count, start_time)
            task_queue.task_done()


def ask_int(prompt: str, default_val: int, min_val: int = 0, max_val: int = 10_000_000) -> int:
    try:
        raw = input(f"{prompt} [{default_val}]: ").strip()
        val = int(raw) if raw else default_val
        return max(min_val, min(val, max_val))
    except Exception:
        return default_val

def ask_bool(prompt: str, default_yes: bool = True) -> bool:
    default_txt = "Y/n" if default_yes else "y/N"
    raw = input(f"{prompt} [{default_txt}]: ").strip().lower()
    if not raw:
        return default_yes
    return raw in ("y", "yes", "1", "true", "t")

def cleanup_configs():
    if CONFIG_DIR.exists() and CONFIG_DIR.is_dir():
        for f in CONFIG_DIR.iterdir():
            try:
                if f.is_file():
                    f.unlink()
            except Exception:
                pass


def main():
    try:
        xray_path = find_xray_binary()
    except FileNotFoundError as e:
        print(str(e)); return

    if not INPUT_FILE.exists():
        print("input.txt not found."); return
    uris = [l.strip() for l in INPUT_FILE.read_text(encoding="utf-8").splitlines() if l.strip()]
    if not uris:
        print("No URIs in input.txt."); return

    if not IP_FILE.exists():
        print("ip4.txt not found. Create ip4.txt with IPs/ranges (one per line)."); return
    ip_lines = [l.strip() for l in IP_FILE.read_text(encoding="utf-8").splitlines() if l.strip()]

    # Build raw groups: each line -> expanded IP list + type info
    groups_raw = []
    any_range_line = False
    all_single_ip_lines = True
    for ln in ip_lines:
        ex = expand_ip_line(ln)
        if not ex:
            print(f"Warning: couldn't parse IP line: {ln}")
            continue
        is_single = is_single_ip_line(ln)
        if not is_single:
            any_range_line = True
            all_single_ip_lines = False
        groups_raw.append({"label": ln, "ips": ex, "single_line": is_single})

    if not groups_raw:
        print("No valid IPs parsed from ip4.txt."); return

    CONFIG_DIR.mkdir(parents=True, exist_ok=True)
    # نکته: دیگه فایل clean_ip.txt رو اول کار حذف نمی‌کنیم تا اگر اجرای قبلی چیزی نوشته، با اجرا شدن و پیدا شدن اولین IP تمیز، فایل جدید جایگزین بشه.
    # اگر می‌خوای همیشه از صفر شروع کنه، می‌تونم اینجا حذف رو برگردونم.

    concurrency = ask_int("How many concurrent tests?", 8, 1, 128)
    download_bytes = ask_int("How many bytes to download per test? (0 = skip download)", 1, 0, 10_000_000)
    upload_bytes = ask_int("How many bytes to upload per test? (0 = skip upload)", 0, 0, 10_000_000)
    if download_bytes == 0 and upload_bytes == 0:
        print("Both download and upload set to 0 -> exiting as requested."); return
    retries = ask_int("How many retries per test?", 2, 1, 10)
    per_op_time_budget = ask_int("Max seconds per operation (download/upload) (0 = no limit)", 8, 0, 600)

    # FORCE AND mode when both download & upload are enabled (no prompt)
    require_both_when_both_selected = True

    # Ask whether to shuffle tests WITHIN each (final) group
    random_order = ask_bool("Shuffle tests within each group (random order)?", default_yes=False)

    # Percentage sampling (0..100, default 100)
    percent = ask_int("What percent of IPs to test? (0-100)", 100, 0, 100)

    # If 0%, exit immediately as requested
    if percent == 0:
        print("Sampling percent is 0% -> no tests will run. Exiting as requested.")
        cleanup_configs()
        return

    # Prepare final groups after sampling
    final_groups = []

    if all_single_ip_lines and not any_range_line:
        # Global sampling across ALL IPs
        all_ips = []
        for g in groups_raw:
            all_ips.extend(g["ips"])
        total_ips = len(all_ips)
        if total_ips == 0:
            print("No IPs to test."); return
        if percent >= 100:
            sampled = all_ips
        else:
            k = max(1, math.ceil(total_ips * (percent / 100.0)))
            k = min(k, total_ips)
            sampled = random.sample(all_ips, k)
        if not sampled:
            print("Sampling selected 0 IPs; nothing to do.")
            return
        final_groups.append({"label": f"ALL_IPS (global {percent}%)", "ips": sampled})
    else:
        # Per-group sampling
        for g in groups_raw:
            ips = g["ips"]
            n = len(ips)
            if n == 0:
                continue
            if percent >= 100:
                sampled = ips
            else:
                k = max(1, math.ceil(n * (percent / 100.0)))
                k = min(k, n)
                sampled = ips if k == n else random.sample(ips, k)
            final_groups.append({"label": g["label"] + f"  (sample {percent}%)", "ips": sampled})

    overall_total_ips_selected = sum(len(g["ips"]) for g in final_groups)
    overall_total_combos = 0

    # Process groups sequentially
    for gi, group in enumerate(final_groups, start=1):
        if shutdown_flag.is_set():
            break

        label = group["label"]
        ips = group["ips"]
        tasks_list = [(u, ip) for u in uris for ip in ips]
        total = len(tasks_list)
        overall_total_combos += total

        print(f"\n=== Testing group {gi}/{len(final_groups)}: '{label}'  (IPs: {len(ips)}, combinations: {total}) ===")

        if random_order:
            random.shuffle(tasks_list)

        # prepare queue and shared state for THIS group
        q_tasks = queue.Queue()
        for i, (u, ip) in enumerate(tasks_list):
            q_tasks.put((i, u, ip))

        progress_dict = {"done": 0}
        progress_lock = threading.Lock()
        start_time = time.time()
        print_progress(0, total, start_time)

        threads = []
        for _ in range(min(concurrency, total)):
            t = threading.Thread(
                target=worker,
                args=(q_tasks, xray_path, download_bytes, upload_bytes, retries,
                      per_op_time_budget, require_both_when_both_selected,
                      progress_dict, progress_lock, total, start_time),
                daemon=True
            )
            t.start()
            threads.append(t)

        for t in threads:
            t.join()

        print_progress(total, total, start_time); print()

        # خلاصهٔ گروه (از روی overall_good_ips می‌تونیم بفهمیم، اما گزارش دقیق گروهی ساده‌تره اگر بخوای ذخیرهٔ per-group هم اضافه می‌کنم)
        print(f"Group '{label}' done.")

    # Final summary (whatever we got so far)
    with good_ips_lock:
        clean_count = len(overall_good_ips)
        if clean_count:
            print("\n=== All finished (or interrupted) ===")
            print(f"Total IPs selected for testing: {overall_total_ips_selected}")
            print(f"Total combinations attempted (URIs × selected IPs): {overall_total_combos}")
            print(f"Clean IPs so far: {clean_count}")
            print(f"Clean IP file -> {CLEAN_IP_FILE}")
        else:
            print("\n=== Finished with no clean IPs ===")

    cleanup_configs()
    print(f"Configs cleaned inside {CONFIG_DIR}")

if __name__ == "__main__":
    main()
