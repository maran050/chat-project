
import json
import logging
from logging.handlers import RotatingFileHandler
from fastapi import APIRouter, Request, HTTPException
from datetime import datetime, timezone
import ipaddress
import os
import redis  
import re
from typing import List


LOG_PATH = os.environ.get("HONEYPOT_LOG", "logs/honeypot-events.json")
LOG_MAX_BYTES = 5 * 1024 * 1024
LOG_BACKUP_COUNT = 5

REDIS_URL = os.environ.get("HONEYPOT_REDIS", None)  
BLOCK_SECONDS = int(os.environ.get("HONEYPOT_BLOCK_SECONDS", 60 * 60))  
TRAP_WEBHOOK = os.environ.get("HONEYPOT_TRAP_WEBHOOK", "")  
LOG_DIR = os.path.dirname(LOG_PATH) or "."
os.makedirs(LOG_DIR, exist_ok=True)


HONEYPOT_ADMIN_KEY = os.environ.get("HONEYPOT_ADMIN_KEY", "") 
HONEYPOT_ADMIN_IPS = os.environ.get("HONEYPOT_ADMIN_IPS", "127.0.0.1")  
ALLOWED_ADMIN_IPS: List[str] = [ip.strip() for ip in HONEYPOT_ADMIN_IPS.split(",") if ip.strip()]


logger = logging.getLogger("honeypot")
logger.setLevel(logging.INFO)
handler = RotatingFileHandler(LOG_PATH, maxBytes=LOG_MAX_BYTES, backupCount=LOG_BACKUP_COUNT, encoding="utf-8")
formatter = logging.Formatter('%(message)s') 
handler.setFormatter(formatter)
logger.addHandler(handler)
print(f"[honeypot] logging to: {os.path.abspath(LOG_PATH)}")
print(f"[honeypot] admin key set: {'YES' if HONEYPOT_ADMIN_KEY else 'NO'}, admin IPs: {ALLOWED_ADMIN_IPS}")

redis_client = None
if REDIS_URL:
    try:
        redis_client = redis.from_url(REDIS_URL, decode_responses=True)
    except Exception:
        redis_client = None

router = APIRouter()


def get_client_ip(request: Request) -> str:
    xff = request.headers.get("x-forwarded-for")
    if xff:
        
        ip = xff.split(",")[0].strip()
    else:
        client = request.client
        ip = client.host if client else "0.0.0.0"
    # normalize
    try:
        ipaddress.ip_address(ip)
    except Exception:
        ip = "0.0.0.0"
    return ip

def log_event(event: dict):
    logger.info(json.dumps(event, ensure_ascii=False))

def block_ip(ip: str, seconds: int = BLOCK_SECONDS):
    if redis_client:
        try:
            redis_client.setex(f"honeypot:blocked:{ip}", seconds, "1")
        except Exception:
            pass

def is_blocked(ip: str) -> bool:
    if not redis_client:
        return False
    try:
        return redis_client.exists(f"honeypot:blocked:{ip}") == 1
    except Exception:
        return False


def send_webhook(payload: dict):
    if not TRAP_WEBHOOK:
        return
    try:
        import requests
        requests.post(TRAP_WEBHOOK, json=payload, timeout=3)
    except Exception:
        pass

SQLI_PATTERNS = [
    r"(\bUNION\b\s+\bSELECT\b)",
    r"(\bSELECT\b.+\bFROM\b)",
    r"(\bOR\b\s+1=1)",
    r"(--\s*$)",
    r"(\bDROP\b|\bINSERT\b|\bUPDATE\b|\bDELETE\b)"
]
RCE_PATTERNS = [
    r"(;|\|\||&&)\s*(rm|curl|wget|nc|bash|sh|python|perl|php)",
    r"exec\(", r"system\(", r"popen\("
]
WEBSHELL_PATTERNS = [
    r"<\?php", r"eval\(", r"base64_decode\(", r"shell_exec\(", r"preg_replace\(.*/e"
]
SUSPICIOUS_HEADERS = [
    "sqlmap", "nikto", "acunetix", "nmap", "curl", "wget"
]

def classify_risk(entry: dict) -> str:
 
    body = (entry.get("body_text") or "").lower()
    ua = (entry.get("headers", {}).get("user_agent") or "").lower()
    note = (entry.get("note") or "").lower()
    path = (entry.get("path") or "").lower()

    
    if note and "trap" in note:
        return "high"
   
    for p in WEBSHELL_PATTERNS:
        if re.search(p, body, flags=re.IGNORECASE):
            return "high"

    for p in RCE_PATTERNS:
        if re.search(p, body, flags=re.IGNORECASE):
            return "high"


    for p in SQLI_PATTERNS:
        if re.search(p, body, flags=re.IGNORECASE):
            return "high"

   
    if "file_upload_probe" in note:
        for p in WEBSHELL_PATTERNS:
            if re.search(p, body, flags=re.IGNORECASE):
                return "high"
        return "medium"

    
    for s in SUSPICIOUS_HEADERS:
        if s in ua:
            return "medium"

    
    if path.endswith("/.git/config") or path.endswith("/config.php") or "phpmyadmin" in path:
        return "medium"

    
    sql_kw_count = sum(1 for kw in ["select", "union", "insert", "update", "delete", "drop", "from", "where"] if kw in body)
    if sql_kw_count >= 2:
        return "medium"

 
    xff = entry.get("headers", {}).get("x_forwarded_for") or ""
    if xff and "," in xff and len(xff.split(",")) > 3:
        return "medium"

    return "low"


async def record_request(request: Request, endpoint_name: str, note: str = ""):
    ip = get_client_ip(request)
    blocked = is_blocked(ip)
    if blocked:
       
        pass

    now = datetime.now(timezone.utc).isoformat()
    headers = dict(request.headers)
    try:
        body_bytes = await request.body()
        body_text = body_bytes.decode("utf-8", errors="replace") if body_bytes else ""
    except Exception:
        body_text = ""

    entry = {
        "time_utc": now,
        "ip": ip,
        "endpoint": endpoint_name,
        "method": request.method,
        "path": str(request.url.path),
        "query": dict(request.query_params),
        "headers": {
            "user_agent": headers.get("user-agent"),
            "referer": headers.get("referer"),
            "x_forwarded_for": headers.get("x-forwarded-for"),
        },
        "body_text": body_text[:2000],  
        "note": note
    }

    entry["severity"] = classify_risk(entry)

   
    if redis_client and entry["severity"] == "high":
        try:
            counter_key = f"honeypot:attempts:{ip}"
            attempts = redis_client.incr(counter_key)
            if attempts == 1:
                redis_client.expire(counter_key, 3600)  
         
            if attempts >= 5:
                block_ip(ip, BLOCK_SECONDS)
                send_webhook({"type": "auto_block", "ip": ip, "time": now, "attempts": attempts, "severity": entry.get("severity")})
        except Exception:
            pass

    log_event(entry)
    return entry


def _is_admin_key_valid(request: Request) -> bool:
    if not HONEYPOT_ADMIN_KEY:
        return False
    header_val = request.headers.get("x-admin-key", "")
    return header_val == HONEYPOT_ADMIN_KEY

def _is_admin_ip_allowed(request: Request) -> bool:
    ip = get_client_ip(request)
    return ip in ALLOWED_ADMIN_IPS

def require_admin(request: Request):
    
    if _is_admin_key_valid(request) or _is_admin_ip_allowed(request):
        return
  
    try:
      
        now = datetime.now(timezone.utc).isoformat()
        entry = {
            "time_utc": now,
            "ip": get_client_ip(request),
            "endpoint": "admin-protected",
            "method": request.method,
            "path": str(request.url.path),
            "query": dict(request.query_params),
            "headers": {
                "user_agent": request.headers.get("user-agent"),
                "referer": request.headers.get("referer"),
                "x_forwarded_for": request.headers.get("x-forwarded-for"),
            },
            "body_text": "",
            "note": "admin_access_denied",
            "severity": "medium"
        }
        log_event(entry)
    except Exception:
        pass
    raise HTTPException(status_code=403, detail="forbidden")


@router.get("/trap/{trapid}")
async def trap(trapid: str, request: Request):
    entry = await record_request(request, endpoint_name=f"trap/{trapid}", note="trap_hit")
    ip = entry["ip"]
    block_ip(ip, BLOCK_SECONDS)
    
    send_webhook({"type": "trap", "trapid": trapid, "ip": ip, "time": entry["time_utc"], "severity": entry.get("severity")})
    
    raise HTTPException(status_code=404, detail="Not found")


@router.post("/admin/login")
async def fake_admin_login(request: Request):
    entry = await record_request(request, endpoint_name="admin/login", note="fake_admin_login")
  
    return {"status": "error", "message": "Invalid credentials", "note": "This admin portal is currently under maintenance.", "severity": entry.get("severity")}


@router.get("/config.php")
async def fake_config(request: Request):
    entry = await record_request(request, endpoint_name="config.php", note="config_probe")
    
    return {"db_host": "localhost", "db_user": "root", "db_pass": "********", "severity": entry.get("severity")}

@router.get("/.git/config")
async def fake_git_config(request: Request):
    entry = await record_request(request, endpoint_name=".git/config", note="git_probe")
    raise HTTPException(status_code=404, detail="Not found")


@router.post("/debug/exec")
async def fake_debug_exec(request: Request):
    entry = await record_request(request, endpoint_name="debug/exec", note="rce_probe")
   
    send_webhook({"type": "rce_probe", "ip": entry["ip"], "time": entry["time_utc"], "severity": entry.get("severity")})
    return {"result": "command executed", "output": "sh: command not found", "severity": entry.get("severity")}


@router.post("/db_query")
async def fake_db_query(request: Request):
    entry = await record_request(request, endpoint_name="db_query", note="sql_injection_probe")
    send_webhook({"type": "sql_probe", "ip": entry["ip"], "time": entry["time_utc"], "severity": entry.get("severity")})

    return {"status": "error", "error": "Database error: syntax near ...", "severity": entry.get("severity")}


@router.post("/upload")
async def fake_upload(request: Request):
    entry = await record_request(request, endpoint_name="upload", note="file_upload_probe")
    
    body_lower = entry["body_text"].lower() if entry["body_text"] else ""
    if "<?php" in body_lower or "eval(" in body_lower or "base64_decode(" in body_lower:

        block_ip(entry["ip"], BLOCK_SECONDS)
        send_webhook({"type": "webshell_upload", "ip": entry["ip"], "time": entry["time_utc"], "severity": entry.get("severity")})
    return {"status": "ok", "message": "File uploaded successfully (processing delayed).", "severity": entry.get("severity")}


@router.get("/honeypot/logs")
async def get_logs(request: Request, limit: int = 50):
    require_admin(request)
    lines = []
    try:
        with open(LOG_PATH, "r", encoding="utf-8") as f:
            all_lines = f.readlines()[-limit:]
            lines = [json.loads(l) for l in all_lines if l.strip()]
    except Exception:
        lines = []
    return {"count": len(lines), "items": lines}

@router.get("/honeypot/blocked")
async def get_blocked(request: Request):
    require_admin(request)
    if not redis_client:
        return {"blocked": []}
    keys = redis_client.keys("honeypot:blocked:*")
    result = []
    for k in keys:
        ip = k.split(":")[-1]
        ttl = redis_client.ttl(k)
        result.append({"ip": ip, "ttl": ttl})
    return {"blocked": result}
