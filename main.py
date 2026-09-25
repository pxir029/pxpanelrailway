# ============================================================
# PXPanel 15.0.0
# Railway Ready
# Created By PIXON
# ============================================================
import asyncio
import base64
import hashlib
import json
import logging
import os
import secrets
import string
import time
from collections import defaultdict, deque
from datetime import datetime, timedelta
from pathlib import Path
from urllib.parse import quote, parse_qs
import aiofiles
import httpx
import uvicorn
from fastapi import (
    FastAPI,
    Request,
    HTTPException,
    Depends,
)
from fastapi.staticfiles import StaticFiles
from fastapi.responses import (
    FileResponse,
    Response,
    HTMLResponse,
    JSONResponse,
    RedirectResponse,
)
from fastapi.middleware.cors import CORSMiddleware

# ============================================================
# APP
# ============================================================

APP_NAME = "PXPanel"
APP_VERSION = "15.0.0"

SUPPORT_USERNAME = "@logic_sec"
SUPPORT_URL = "https://t.me/logic_sec"

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
)

logger = logging.getLogger(APP_NAME)

# ============================================================
# TIMEZONE
# ============================================================

try:
    from zoneinfo import ZoneInfo

    IRAN_TZ = ZoneInfo("Asia/Tehran")

except Exception:
    IRAN_TZ = None


# ============================================================
# RAILWAY
# ============================================================

PORT = int(
    os.environ.get(
        "PORT",
        "8000",
    )
)

DATA_DIR = Path(
    os.environ.get(
        "RAILWAY_VOLUME_MOUNT_PATH",
        os.environ.get(
            "DATA_DIR",
            "./data",
        ),
    )
)

DATA_DIR.mkdir(
    parents=True,
    exist_ok=True,
)

DATA_FILE = DATA_DIR / "pixonpanel_state.json"
TG_FILE = DATA_DIR / "telegram_settings.json"

SECRET_FILE = DATA_DIR / "pixonpanel_secret.key"


# ============================================================
# FASTAPI
# ============================================================

app = FastAPI(
    title=APP_NAME,
    version=APP_VERSION,
    docs_url=None,
    redoc_url=None,
)

# Static assets (login / dashboard / sub)
try:
    app.mount("/static", StaticFiles(directory="static"), name="static")
except Exception:
    pass


app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# ============================================================
# LOCKS
# ============================================================

SAVE_LOCK = asyncio.Lock()
LINKS_LOCK = asyncio.Lock()
SUBS_LOCK = asyncio.Lock()
SESSIONS_LOCK = asyncio.Lock()


# ============================================================
# SECRET
# ============================================================

def load_or_create_secret() -> str:
    env_secret = os.environ.get("SECRET_KEY")

    if env_secret:
        return env_secret

    try:
        if SECRET_FILE.exists():
            existing = (
                SECRET_FILE
                .read_text(
                    encoding="utf-8"
                )
                .strip()
            )

            if existing:
                return existing

        generated = secrets.token_urlsafe(48)

        SECRET_FILE.write_text(
            generated,
            encoding="utf-8",
        )

        return generated

    except Exception as exc:
        logger.warning(
            "Could not persist SECRET_KEY: %s",
            exc,
        )

        return secrets.token_urlsafe(48)


SECRET_KEY = load_or_create_secret()


# ============================================================
# CONFIG
# ============================================================

CONFIG = {
    "port": PORT,
    "secret": SECRET_KEY,
    "host": os.environ.get(
        "RAILWAY_PUBLIC_DOMAIN",
        "localhost",
    ),
}


# ============================================================
# STATE
# ============================================================

LINKS: dict = {}
SUBS: dict = {}
SESSIONS: dict = {}
connections: dict = {}
CATEGORIES: dict = {}

stats = {
    "total_bytes": 0,
    "total_requests": 0,
    "total_errors": 0,
    "start_time": time.time(),
}

error_logs = deque(maxlen=100)
activity_logs = deque(maxlen=250)

hourly_traffic = defaultdict(int)

http_client: httpx.AsyncClient | None = None


# ============================================================
# PROTOCOL
# ============================================================

PROTOCOLS = (
    "vless-ws",
    "xhttp-packet-up",
    "xhttp-stream-up",
    "xhttp-stream-one",
    "vmess-ws",
    "trojan-ws",
    "shadowsocks",
    "socks5",
    "http",
    "hysteria2",
    "tuic",
    "highspeed-demo",
    "gaming-lite-demo",
)

PROTOCOL_LABELS = {
    "vless-ws": "VLESS WebSocket ⭐",
    "xhttp-packet-up": "XHTTP Packet Up",
    "xhttp-stream-up": "XHTTP Stream Up",
    "xhttp-stream-one": "XHTTP Stream One",
    "vmess-ws": "VMess WebSocket",
    "trojan-ws": "Trojan WebSocket",
    "shadowsocks": "Shadowsocks",
    "socks5": "SOCKS5",
    "http": "HTTP Proxy",
    "hysteria2": "Hysteria 2",
    "tuic": "TUIC",
    "highspeed-demo": "HighSpeed Upload/Download (دمو)",
    "gaming-lite-demo": "Gaming Lite (دمو)",
}

PROTOCOL_ALIASES = {
    "vmess": "vmess-ws", "trojan": "trojan-ws", "ss": "shadowsocks",
    "socks": "socks5", "hy2": "hysteria2", "hysteria": "hysteria2",
}

DEFAULT_PROTOCOL = "vless-ws"

FINGERPRINTS = (
    "chrome",
    "firefox",
    "safari",
    "ios",
    "android",
    "edge",
    "360",
    "qq",
    "random",
    "randomized",
)

DEFAULT_FINGERPRINT = "chrome"

DEFAULT_ALPN_BY_PROTOCOL = {
    "vless-ws": "http/1.1",
    "xhttp-packet-up": "h2,http/1.1",
    "xhttp-stream-up": "h2,http/1.1",
    "xhttp-stream-one": "h2,http/1.1",
}

DEFAULT_PORT = 443
MIN_PORT = 1
MAX_PORT = 65535

DEFAULT_SPEED_LIMIT = 0


def normalize_protocol(protocol: str | None) -> str:
    value = str(protocol or DEFAULT_PROTOCOL).strip().lower()
    value = PROTOCOL_ALIASES.get(value, value)
    return value if value in PROTOCOLS else DEFAULT_PROTOCOL


# ============================================================
# LOGGING
# ============================================================

def log_activity(
    kind: str,
    message: str,
    level: str = "info",
):
    activity_logs.append(
        {
            "kind": kind,
            "level": level,
            "message": message,
            "time": datetime.now().isoformat(),
        }
    )


# ============================================================
# HELPERS
# ============================================================

def escape_html(value) -> str:
    return (
        str(
            value
            if value is not None
            else ""
        )
        .replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace('"', "&quot;")
        .replace("'", "&#039;")
    )


def safe_int(
    value,
    default=0,
    minimum=0,
    maximum=None,
):
    try:
        number = int(value)
    except Exception:
        number = default

    if number < minimum:
        number = minimum

    if maximum is not None and number > maximum:
        number = maximum

    return number


def safe_float(
    value,
    default=0.0,
    minimum=0.0,
):
    try:
        number = float(value)
    except Exception:
        number = default

    return max(
        minimum,
        number,
    )


def generate_uuid():
    value = secrets.token_hex(16)

    return (
        f"{value[:8]}-"
        f"{value[8:12]}-"
        f"{value[12:16]}-"
        f"{value[16:20]}-"
        f"{value[20:32]}"
    )


def random_config_name(existing=None):
    existing = existing or set()
    alphabet = string.ascii_lowercase + string.digits
    for _ in range(80):
        length = secrets.randbelow(6) + 8
        name = "".join(secrets.choice(alphabet) for _ in range(length))
        if name not in existing and name and not name[0].isdigit():
            return name
    return secrets.token_hex(6)

def sanitize_config_name(name: str) -> str:
    if not name:
        return random_config_name()
    cleaned = "".join(ch for ch in str(name) if ch.isascii() and ch.isalnum())
    if not cleaned or cleaned[0].isdigit():
        cleaned = ("a" + cleaned) if cleaned else random_config_name()
    return cleaned[:40]

def auto_config_name() -> str:
    return random_config_name()


def now_ir():
    if IRAN_TZ:
        return datetime.now(IRAN_TZ)

    return datetime.now()


def uptime():
    seconds = int(
        time.time()
        - stats["start_time"]
    )

    h = seconds // 3600

    m = (
        seconds
        % 3600
    ) // 60

    s = (
        seconds
        % 60
    )

    return (
        f"{h:02d}:"
        f"{m:02d}:"
        f"{s:02d}"
    )


def fmt_bytes(value: int):
    value = int(
        value or 0
    )

    if value < 1024:
        return f"{value} B"

    if value < 1024 ** 2:
        return (
            f"{value / 1024:.1f} KB"
        )

    if value < 1024 ** 3:
        return (
            f"{value / 1024 ** 2:.2f} MB"
        )

    return (
        f"{value / 1024 ** 3:.2f} GB"
    )


def parse_size_to_bytes(
    value: float,
    unit: str,
):
    if value <= 0:
        return 0

    unit = (
        unit
        or "GB"
    ).upper()

    if unit == "TB":
        return int(
            value
            * 1024 ** 4
        )

    if unit == "GB":
        return int(
            value
            * 1024 ** 3
        )

    if unit == "MB":
        return int(
            value
            * 1024 ** 2
        )

    if unit == "KB":
        return int(
            value
            * 1024
        )

    return int(value)


def parse_speed_to_bytes(
    value: float,
    unit: str,
):
    if value <= 0:
        return 0

    unit = (
        unit
        or "MBIT"
    ).upper()

    if unit == "MBIT":
        return int(
            value
            * 1024
            * 1024
            / 8
        )

    if unit == "KB":
        return int(
            value * 1024
        )

    if unit == "MB":
        return int(
            value
            * 1024
            * 1024
        )

    return int(value)


def is_link_expired(
    link: dict,
):
    expiry = link.get(
        "expires_at"
    )

    if not expiry:
        return False

    try:
        return (
            datetime.now()
            > datetime.fromisoformat(
                expiry
            )
        )

    except Exception:
        return False


def is_link_allowed(
    link: dict | None,
):
    if link is None:
        return False

    if not link.get(
        "active",
        True,
    ):
        return False

    if is_link_expired(link):
        return False

    limit = int(
        link.get(
            "limit_bytes",
            0,
        )
        or 0
    )

    used = int(
        link.get(
            "used_bytes",
            0,
        )
        or 0
    )

    if (
        limit > 0
        and used >= limit
    ):
        return False

    return True


def unique_ips_for_uuid(
    uuid: str,
):
    return {
        connection.get("ip")
        for connection in connections.values()
        if connection.get("uuid") == uuid
        and connection.get("ip")
    }


def client_ip(
    request: Request,
):
    forwarded = request.headers.get(
        "x-forwarded-for"
    )

    if forwarded:
        return (
            forwarded
            .split(",")[0]
            .strip()
        )

    real = request.headers.get(
        "x-real-ip"
    )

    if real:
        return real.strip()

    if request.client:
        return request.client.host

    return "unknown"


def is_ip_allowed(
    link: dict | None,
    uuid: str,
    ip: str,
):
    if link is None:
        return False

    limit = int(
        link.get(
            "ip_limit",
            0,
        )
        or 0
    )

    if limit <= 0:
        return True

    ips = unique_ips_for_uuid(uuid)

    if ip in ips:
        return True

    return len(ips) < limit


def get_host(
    request: Request | None = None,
) -> str:

    if request is not None:
        forwarded = request.headers.get(
            "x-forwarded-host"
        )

        normal = request.headers.get(
            "host"
        )

        host = (
            forwarded
            or normal
        )

        if host:
            host = host.split(":")[0].strip()

            CONFIG["host"] = host

            return host

    railway_domain = os.environ.get(
        "RAILWAY_PUBLIC_DOMAIN"
    )

    if railway_domain:
        return railway_domain

    return CONFIG["host"]


# ============================================================
# PASSWORD
# ============================================================

def hash_password(
    password: str,
) -> str:

    payload = (
        password
        + SECRET_KEY
    ).encode("utf-8")

    return hashlib.sha256(
        payload
    ).hexdigest()


# No default password — first-run setup required unless ADMIN_PASSWORD env is set
_env_pw = os.environ.get("ADMIN_PASSWORD", "").strip()
AUTH = {
    "password_hash": hash_password(_env_pw) if _env_pw else "",
    "password_configured": bool(_env_pw),
}

# Sub-admin accounts (panel operators with granular permissions)
ADMIN_ACCOUNTS: dict = {}
USER_BOTS: dict = {}  # id -> user-connected telegram bots
# session_token -> {"role": "owner"|"admin", "admin_id": str|None, "username": str}
SESSION_META: dict = {}

ALL_PERMS = (
    "dash", "configs", "create", "stats", "logs",
    "settings", "support", "telegram", "news", "admins",
)
DEFAULT_PERMS = {p: True for p in ALL_PERMS}


def default_admin_record(username: str, password: str, **kwargs) -> dict:
    return {
        "id": secrets.token_hex(8),
        "username": username.strip().lower(),
        "password_hash": hash_password(password),
        "label": kwargs.get("label") or username,
        "limit_bytes": int(kwargs.get("limit_bytes") or 0),
        "used_bytes": 0,
        "expires_at": kwargs.get("expires_at"),
        "active": True,
        "blocked": False,
        "permissions": {**DEFAULT_PERMS, **(kwargs.get("permissions") or {})},
        "created_at": datetime.now().isoformat(),
    }


def find_admin_by_username(username: str):
    u = (username or "").strip().lower()
    for aid, a in ADMIN_ACCOUNTS.items():
        if a.get("username") == u:
            return aid, a
    return None, None


def admin_is_valid(admin: dict) -> bool:
    if not admin or admin.get("blocked") or not admin.get("active", True):
        return False
    exp = admin.get("expires_at")
    if exp:
        try:
            if datetime.now() > datetime.fromisoformat(str(exp)):
                return False
        except Exception:
            pass
    limit = int(admin.get("limit_bytes") or 0)
    used = int(admin.get("used_bytes") or 0)
    if limit > 0 and used >= limit:
        return False
    return True



# ============================================================
# LOGIN BRUTE-FORCE PROTECTION
# ============================================================
# Maximum failed login attempts per IP inside the rolling window.
LOGIN_MAX_ATTEMPTS = 5
LOGIN_WINDOW_SECONDS = 15 * 60
LOGIN_LOCKOUT_SECONDS = 30 * 60  # 30 minutes lockout
LOGIN_MIN_PASSWORD_LENGTH = 6

LOGIN_FAILURES = defaultdict(deque)
LOGIN_LOCKED_UNTIL = {}


def _cleanup_login_state(ip: str, now: float | None = None):
    now = now if now is not None else time.time()

    locked_until = LOGIN_LOCKED_UNTIL.get(ip, 0)
    if locked_until and locked_until <= now:
        LOGIN_LOCKED_UNTIL.pop(ip, None)

    failures = LOGIN_FAILURES.get(ip)
    if not failures:
        return

    cutoff = now - LOGIN_WINDOW_SECONDS
    while failures and failures[0] <= cutoff:
        failures.popleft()

    if not failures:
        LOGIN_FAILURES.pop(ip, None)


def login_is_blocked(ip: str):
    now = time.time()
    _cleanup_login_state(ip, now)

    locked_until = LOGIN_LOCKED_UNTIL.get(ip, 0)
    if locked_until > now:
        return True, max(1, int(locked_until - now))

    return False, 0


def register_login_failure(ip: str):
    now = time.time()
    _cleanup_login_state(ip, now)

    failures = LOGIN_FAILURES.setdefault(ip, deque())
    failures.append(now)

    if len(failures) >= LOGIN_MAX_ATTEMPTS:
        LOGIN_LOCKED_UNTIL[ip] = now + LOGIN_LOCKOUT_SECONDS
        failures.clear()
        log_activity(
            "auth",
            f"IP به دلیل تلاش‌های متعدد ورود ناموفق به مدت {LOGIN_LOCKOUT_SECONDS // 60} دقیقه مسدود شد: {ip}",
            "err",
        )
        return True, LOGIN_LOCKOUT_SECONDS

    return False, max(0, LOGIN_MAX_ATTEMPTS - len(failures))


def clear_login_failures(ip: str):
    LOGIN_FAILURES.pop(ip, None)
    LOGIN_LOCKED_UNTIL.pop(ip, None)


# ============================================================
# SESSION
# ============================================================


def _static_html(rel: str) -> HTMLResponse:
    p = Path("static") / rel
    if p.exists():
        return HTMLResponse(p.read_text(encoding="utf-8"))
    raise HTTPException(status_code=404, detail="page not found")


SESSION_COOKIE = "pixonpanel_session"

SESSION_TTL = (
    60
    * 60
    * 24
    * 365
)


async def create_session(meta: dict | None = None) -> str:

    token = secrets.token_urlsafe(48)

    async with SESSIONS_LOCK:
        SESSIONS[token] = (
            time.time()
            + SESSION_TTL
        )
        SESSION_META[token] = meta or {"role": "owner", "admin_id": None, "username": "owner"}

    return token


async def is_valid_session(
    token: str | None,
) -> bool:

    if not token:
        return False

    async with SESSIONS_LOCK:

        expiry = SESSIONS.get(token)

        if expiry is None:
            return False

        if expiry < time.time():

            SESSIONS.pop(
                token,
                None,
            )
            SESSION_META.pop(token, None)

            return False

        # sliding session: renew TTL on activity to prevent sudden logout
        SESSIONS[token] = time.time() + SESSION_TTL

        return True


async def destroy_session(
    token: str | None,
):
    if not token:
        return

    async with SESSIONS_LOCK:
        SESSIONS.pop(
            token,
            None,
        )
        SESSION_META.pop(token, None)


def get_session_meta(token: str | None) -> dict:
    if not token:
        return {"role": "owner", "admin_id": None, "username": "owner", "permissions": {p: True for p in ALL_PERMS}}
    meta = dict(SESSION_META.get(token) or {"role": "owner", "admin_id": None, "username": "owner"})
    if meta.get("role") == "owner":
        meta["permissions"] = {p: True for p in ALL_PERMS}
    else:
        aid = meta.get("admin_id")
        admin = ADMIN_ACCOUNTS.get(aid or "") or {}
        meta["permissions"] = {p: bool((admin.get("permissions") or {}).get(p, False)) for p in ALL_PERMS}
        meta["blocked"] = bool(admin.get("blocked"))
    return meta


def require_perm(perm: str):
    async def _dep(request: Request, token=Depends(require_auth)):
        meta = get_session_meta(token)
        if meta.get("role") == "owner":
            return token
        if not (meta.get("permissions") or {}).get(perm):
            raise HTTPException(status_code=403, detail="دسترسی به این بخش مجاز نیست")
        return token
    return _dep


async def require_auth(
    request: Request,
):
    token = request.cookies.get(
        SESSION_COOKIE
    )

    if not await is_valid_session(
        token
    ):
        raise HTTPException(
            status_code=401,
            detail="unauthorized",
        )

    meta = get_session_meta(token)
    if meta.get("role") == "admin":
        aid = meta.get("admin_id")
        admin = ADMIN_ACCOUNTS.get(aid or "")
        if not admin_is_valid(admin or {}):
            await destroy_session(token)
            raise HTTPException(status_code=401, detail="حساب منقضی یا مسدود شده است")

    return token


def set_auth_cookie(
    response,
    request: Request,
    token: str,
):
    forwarded_proto = (
        request.headers
        .get(
            "x-forwarded-proto",
            "",
        )
        .lower()
    )

    is_https = (
        forwarded_proto == "https"
        or request.url.scheme == "https"
    )

    response.set_cookie(
        key=SESSION_COOKIE,
        value=token,
        max_age=SESSION_TTL,
        httponly=True,
        samesite="lax",
        path="/",
        secure=is_https,
    )


# ============================================================
# VLESS LINK GENERATION
# ============================================================

def generate_vless_link(
    uuid: str, host: str, remark: str = "PXPanel",
    protocol: str = DEFAULT_PROTOCOL, fingerprint: str | None = None,
    alpn: str | None = None, port: int | None = None,
):
    protocol = normalize_protocol(protocol)
    fp = (fingerprint or DEFAULT_FINGERPRINT).strip().lower()
    if fp not in FINGERPRINTS: fp = DEFAULT_FINGERPRINT
    port_value = safe_int(port, DEFAULT_PORT, MIN_PORT, MAX_PORT)
    alpn_value = (alpn or DEFAULT_ALPN_BY_PROTOCOL.get(protocol, "http/1.1")).strip()
    label = quote(str(remark or "PXPanel"), safe="")
    if protocol == "vless-ws":
        q = {"encryption":"none","security":"tls","type":"ws","host":host,"path":f"/ws/{uuid}","sni":host,"fp":fp,"alpn":alpn_value}
        return "vless://" + uuid + "@" + host + ":" + str(port_value) + "?" + "&".join(f"{k}={quote(str(v), safe=',/')}" for k,v in q.items()) + "#" + label
    if protocol.startswith("xhttp-"):
        mode = protocol.replace("xhttp-", "")
        # path must match xhttp_siz10 routes: /xhttp-siz10/{mode}/{uuid}
        path = f"/xhttp-siz10/{mode}/{uuid}"
        # packet-up: keep chrome fp for speed, but ALPN must stay h2,http/1.1 for client compatibility
        if mode == "packet-up":
            if fp not in ("chrome", "edge", "firefox", "safari", "ios", "android", "random", "randomized"):
                fp = "chrome"
            if not alpn:
                alpn_value = "h2,http/1.1"
        q = {
            "encryption": "none",
            "security": "tls",
            "type": "xhttp",
            "mode": mode,
            "host": host,
            "path": path,
            "sni": host,
            "fp": fp,
            "alpn": alpn_value,
        }
        return "vless://" + uuid + "@" + host + ":" + str(port_value) + "?" + "&".join(f"{k}={quote(str(v), safe=',/')}" for k, v in q.items()) + "#" + label
    if protocol == "vmess-ws":
        raw = {"v":"2","ps":remark,"add":host,"port":port_value,"id":uuid,"aid":0,"scy":"auto","net":"ws","type":"none","host":host,"path":f"/ws/{uuid}","tls":"tls","sni":host,"fp":fp}
        return "vmess://" + base64.b64encode(json.dumps(raw,separators=(",",":"),ensure_ascii=False).encode()).decode()
    if protocol == "trojan-ws":
        return f"trojan://{uuid}@{host}:{port_value}?security=tls&type=ws&host={quote(host)}&path={quote('/ws/'+uuid)}&sni={quote(host)}#{label}"
    if protocol == "shadowsocks":
        method = os.getenv("SS_METHOD", "aes-256-gcm")
        userinfo = base64.urlsafe_b64encode(f"{method}:{uuid}".encode()).decode().rstrip("=")
        return f"ss://{userinfo}@{host}:{port_value}#{label}"
    if protocol == "socks5": return f"socks5://{uuid}:{uuid}@{host}:{port_value}#{label}"
    if protocol == "http": return f"http://{uuid}:{uuid}@{host}:{port_value}#{label}"
    if protocol == "hysteria2": return f"hysteria2://{uuid}@{host}:{port_value}/?sni={quote(host)}&insecure=0#{label}"
    if protocol == "tuic": return f"tuic://{uuid}:{uuid}@{host}:{port_value}?sni={quote(host)}&alpn=h3#{label}"
    if protocol == "highspeed-demo":
        q = {"encryption":"none","security":"tls","type":"xhttp","mode":"packet-up","host":host,"path":f"/xhttp-siz10/packet-up/{uuid}","sni":host,"fp":fp,"alpn":"h2,http/1.1"}
        return "vless://" + uuid + "@" + host + ":" + str(port_value) + "?" + "&".join(f"{k}={quote(str(v), safe=',/')}" for k,v in q.items()) + "#" + label
    if protocol == "gaming-lite-demo":
        return f"hysteria2://{uuid}@{host}:{port_value}/?sni={quote(host)}&insecure=0&obfs=salamander#{label}"
    return f"vless://{uuid}@{host}:{port_value}"

def vless_link_for_link(
    link: dict,
    uid: str,
    host: str,
):
    return generate_vless_link(
        uid,
        host,
        remark=str(link.get("label") or "Config"),
        protocol=link.get(
            "protocol",
            DEFAULT_PROTOCOL,
        ),
        fingerprint=link.get(
            "fingerprint",
            DEFAULT_FINGERPRINT,
        ),
        alpn=link.get(
            "alpn"
        ),
        port=link.get(
            "port",
            DEFAULT_PORT,
        ),
    )


def get_link_info(
    link: dict,
    uid: str,
    host: str,
):
    connected_count = len(unique_ips_for_uuid(uid))
    is_active = is_link_allowed(link)
    limit_b = int(link.get("limit_bytes", 0) or 0)
    used_b = int(link.get("used_bytes", 0) or 0)
    is_expired = is_link_expired(link) or (limit_b > 0 and used_b >= limit_b)
    if not is_active or is_expired:
        status_color = "red"
    elif connected_count > 0:
        status_color = "green"
    else:
        status_color = "gray"
    clean_ips = link.get("clean_ips") or []
    cfg_count = int(link.get("config_count") or 1)
    show_vless = len(clean_ips) <= 1 and cfg_count <= 1
    cat = CATEGORIES.get(str(link.get("category_id") or "0")) or {}
    return {
        "uuid": uid,
        "name": link.get("label", ""),
        "label": link.get("label", ""),
        "protocol": link.get("protocol", DEFAULT_PROTOCOL),
        "active": is_active,
        "used_bytes": used_b,
        "limit_bytes": limit_b,
        "expires_at": link.get("expires_at"),
        "ip_limit": int(link.get("ip_limit", 0) or 0),
        "speed_limit_bytes": int(link.get("speed_limit_bytes", 0) or 0),
        "connection_limit": int(link.get("connection_limit", 0) or 0),
        "fragment": link.get("fragment", "off"),
        "fingerprint": link.get("fingerprint", DEFAULT_FINGERPRINT),
        "alpn": link.get("alpn", ""),
        "port": link.get("port", DEFAULT_PORT),
        "note": link.get("note", ""),
        "clean_ips": clean_ips,
        "alarm_enabled": bool(link.get("alarm_enabled", False)),
        "category_id": str(link.get("category_id") or "0"),
        "sort_order": int(link.get("sort_order") or 0),
        "category_number": int(cat.get("number", 0)),
        "category_name": str(cat.get("name", "عمومی")),
        "config_count": cfg_count,
        "status_color": status_color,
        "connected_ips": connected_count,
        "show_vless": show_vless,
        "vless": vless_link_for_link(link, uid, host) if show_vless else "",
        "vless_full": vless_link_for_link(link, uid, host),
        "sub": f"https://{host}/sub/{uid}",
        "info": f"https://{host}/info/{uid}",
        "support": SUPPORT_USERNAME,
    }


# ============================================================
# PERSISTENCE
# ============================================================

async def load_state():

    global AUTH

    try:

        DATA_DIR.mkdir(
            parents=True,
            exist_ok=True,
        )

        if not DATA_FILE.exists():
            return

        async with aiofiles.open(
            DATA_FILE,
            "r",
            encoding="utf-8",
        ) as file:
            raw = await file.read()

        data = json.loads(raw)

        LINKS.update(
            data.get(
                "links",
                {},
            )
        )

        SUBS.update(
            data.get(
                "subs",
                {},
            )
        )

        CATEGORIES.update(
            data.get(
                "categories",
                {},
            )
        )

        ADMIN_ACCOUNTS.clear()
        ub = data.get("user_bots") or {}
        if isinstance(ub, dict):
            USER_BOTS.clear()
            USER_BOTS.update(ub)
        ADMIN_ACCOUNTS.update(data.get("admin_accounts") or {})

        stored_password = data.get(
            "password_hash"
        )

        if stored_password:
            AUTH["password_hash"] = stored_password
            AUTH["password_configured"] = True

        # Compatibility for older records
        for uid, link in LINKS.items():

            link.setdefault(
                "protocol",
                DEFAULT_PROTOCOL,
            )

            link.setdefault(
                "fingerprint",
                DEFAULT_FINGERPRINT,
            )

            link.setdefault(
                "alpn",
                "",
            )

            link.setdefault(
                "port",
                DEFAULT_PORT,
            )

            link.setdefault(
                "ip_limit",
                0,
            )

            link.setdefault(
                "speed_limit_bytes",
                0,
            )

            link.setdefault(
                "connection_limit",
                0,
            )

            link.setdefault(
                "fragment",
                "off",
            )

            link.setdefault(
                "used_bytes",
                0,
            )
            link.setdefault("clean_ips", [])
            link.setdefault("alarm_enabled", False)
            link.setdefault("category_id", "0")
            link.setdefault("config_count", 1)
            link.setdefault("sort_order", 0)
            link.setdefault("usage_history", [])

        logger.info(
            "State loaded: %d links / %d subscriptions",
            len(LINKS),
            len(SUBS),
        )

    except Exception as exc:

        logger.exception(
            "Could not load state: %s",
            exc,
        )


async def save_state():

    async with SAVE_LOCK:

        try:

            DATA_DIR.mkdir(
                parents=True,
                exist_ok=True,
            )

            payload = {
                "links":
                    dict(LINKS),

                "subs":
                    dict(SUBS),

                "categories":
                    dict(CATEGORIES),

                "admin_accounts":
                    dict(ADMIN_ACCOUNTS),

                "user_bots":
                    dict(USER_BOTS),

                "password_hash":
                    AUTH[
                        "password_hash"
                    ],

                "saved_at":
                    datetime.now().isoformat(),
            }

            temp_file = (
                DATA_FILE.with_suffix(
                    ".tmp"
                )
            )

            async with aiofiles.open(
                temp_file,
                "w",
                encoding="utf-8",
            ) as file:

                await file.write(
                    json.dumps(
                        payload,
                        ensure_ascii=False,
                        indent=2,
                    )
                )

            temp_file.replace(
                DATA_FILE
            )

        except Exception as exc:

            logger.exception(
                "Could not save state: %s",
                exc,
            )


# ============================================================
# DEFAULT LINK
# ============================================================

_default_link_created = False



async def ensure_default_categories():
    # گروه‌های پیش‌فرض ساخته نمی‌شوند — کاربر خودش می‌سازد
    return


async def ensure_default_link():

    global _default_link_created

    if _default_link_created:
        return

    async with LINKS_LOCK:

        if not any(
            item.get("is_default")
            for item in LINKS.values()
        ):

            digest = hashlib.sha256(
                (
                    "default"
                    + SECRET_KEY
                ).encode("utf-8")
            ).hexdigest()

            uid = (
                f"{digest[:8]}-"
                f"{digest[8:12]}-"
                f"{digest[12:16]}-"
                f"{digest[16:20]}-"
                f"{digest[20:32]}"
            )

            LINKS[uid] = {
                "label":
                    "لینک پیش‌فرض",

                "limit_bytes":
                    0,

                "used_bytes":
                    0,

                "created_at":
                    datetime.now().isoformat(),

                "active":
                    True,

                "expires_at":
                    None,

                "note":
                    "",

                "is_default":
                    True,

                "sub_id":
                    None,

                "protocol":
                    DEFAULT_PROTOCOL,

                "fingerprint":
                    DEFAULT_FINGERPRINT,

                "alpn":
                    "http/1.1",

                "port":
                    DEFAULT_PORT,

                "ip_limit":
                    0,

                "speed_limit_bytes":
                    DEFAULT_SPEED_LIMIT,

                "connection_limit":
                    0,

                "fragment":
                    "off",
            }

            asyncio.create_task(
                save_state()
            )

    _default_link_created = True


# ============================================================
# LINK MANAGEMENT
# ============================================================

async def make_link(
    label: str = "لینک جدید",
    limit_bytes: int = 0,
    expires_at: str | None = None,
    note: str = "",
    sub_id: str | None = None,
    protocol: str = DEFAULT_PROTOCOL,
    fingerprint: str = DEFAULT_FINGERPRINT,
    alpn: str = "",
    port: int = DEFAULT_PORT,
    ip_limit: int = 0,
    speed_limit_bytes: int = 0,
    connection_limit: int = 0,
    fragment: str = "off",
    clean_ips=None,
    alarm_enabled: bool = False,
    category_id: str = "0",
    config_count: int = 1,
):

    protocol = normalize_protocol(protocol)

    fingerprint = (
        fingerprint
        or DEFAULT_FINGERPRINT
    ).strip().lower()

    if fingerprint not in FINGERPRINTS:
        fingerprint = DEFAULT_FINGERPRINT

    if not (
        MIN_PORT
        <= port
        <= MAX_PORT
    ):
        port = DEFAULT_PORT

    uid = generate_uuid()

    record = {
        "label":
            sanitize_config_name((label or "").strip() or random_config_name()),

        "limit_bytes":
            max(
                0,
                int(limit_bytes),
            ),

        "used_bytes":
            0,

        "created_at":
            datetime.now().isoformat(),

        "active":
            True,

        "expires_at":
            expires_at,

        "note":
            (
                note
                or ""
            ).strip()[:500],

        "is_default":
            False,

        "sub_id":
            sub_id,

        "protocol":
            protocol,

        "fingerprint":
            fingerprint,

        "alpn":
            (
                alpn
                or ""
            ).strip()[:100],

        "port":
            port,

        "ip_limit":
            max(
                0,
                int(ip_limit),
            ),

        "speed_limit_bytes":
            max(
                0,
                int(speed_limit_bytes),
            ),

        "connection_limit":
            max(
                0,
                int(connection_limit),
            ),

        "fragment":
            (
                fragment
                or "off"
            ).strip().lower(),

        "security_profile": "balanced",
        "multi_login": False,
        "protocol_label": PROTOCOL_LABELS.get(protocol, protocol),
        "clean_ips": list(clean_ips or []),
        "alarm_enabled": bool(alarm_enabled),
        "category_id": str(category_id or "0"),
        "config_count": max(1, min(40, int(config_count or 1))),
        "usage_history": [],
    }

    async with LINKS_LOCK:
        LINKS[uid] = record

    if sub_id:

        async with SUBS_LOCK:

            if sub_id in SUBS:

                ids = SUBS[
                    sub_id
                ].setdefault(
                    "link_ids",
                    [],
                )

                if uid not in ids:
                    ids.append(uid)

    await save_state()

    log_activity(
        "link",
        (
            f"کانفیگ "
            f"«{record['label']}» "
            f"ساخته شد"
        ),
        "ok",
    )

    return uid, record


async def remove_link(
    uid: str,
):

    async with LINKS_LOCK:

        if uid not in LINKS:
            return None

        label = LINKS[
            uid
        ].get(
            "label",
            uid,
        )

        sub_id = LINKS[
            uid
        ].get(
            "sub_id"
        )

        del LINKS[uid]

    if sub_id:

        async with SUBS_LOCK:

            if sub_id in SUBS:

                ids = SUBS[
                    sub_id
                ].get(
                    "link_ids",
                    [],
                )

                if uid in ids:
                    ids.remove(uid)

    await save_state()

    log_activity(
        "link",
        (
            f"کانفیگ "
            f"«{label}» "
            f"حذف شد"
        ),
        "warn",
    )

    return label


async def set_link_active(
    uid: str,
    active: bool,
):

    async with LINKS_LOCK:

        if uid not in LINKS:
            return None

        LINKS[
            uid
        ][
            "active"
        ] = bool(active)

        record = LINKS[uid]

    await save_state()

    log_activity(
        "link",
        (
            f"کانفیگ "
            f"«{record['label']}» "
            f"{'فعال' if active else 'غیرفعال'} شد"
        ),
        "ok"
        if active
        else "warn",
    )

    return record


# ============================================================
# SUB GROUPS
# ============================================================

async def create_sub_group(
    name: str = "گروه جدید",
    desc: str = "",
    password: str = "",
):

    name = (
        name
        or "گروه جدید"
    ).strip()[:60]

    desc = (
        desc
        or ""
    ).strip()[:200]

    password = (
        password
        or ""
    ).strip()

    sub_id = generate_uuid()

    uuid_key = secrets.token_urlsafe(16)

    record = {
        "name":
            name,

        "desc":
            desc,

        "password_hash":
            (
                hash_password(password)
                if password
                else None
            ),

        "uuid_key":
            uuid_key,

        "created_at":
            datetime.now().isoformat(),

        "link_ids":
            [],
    }

    async with SUBS_LOCK:
        SUBS[sub_id] = record

    await save_state()

    log_activity(
        "sub",
        (
            f"گروه "
            f"«{name}» "
            f"ساخته شد"
        ),
        "ok",
    )

    return (
        sub_id,
        record,
    )


async def set_link_sub(
    uid: str,
    sub_id: str | None,
):

    async with LINKS_LOCK:

        if uid not in LINKS:
            return False

        old_sub = LINKS[
            uid
        ].get(
            "sub_id"
        )

        label = LINKS[
            uid
        ].get(
            "label",
            uid,
        )

    if sub_id is not None:

        async with SUBS_LOCK:

            if sub_id not in SUBS:
                return False

    async with SUBS_LOCK:

        if (
            old_sub
            and old_sub in SUBS
        ):

            ids = SUBS[
                old_sub
            ].get(
                "link_ids",
                [],
            )

            if uid in ids:
                ids.remove(uid)

        if (
            sub_id
            and sub_id in SUBS
        ):

            ids = SUBS[
                sub_id
            ].setdefault(
                "link_ids",
                [],
            )

            if uid not in ids:
                ids.append(uid)

    async with LINKS_LOCK:

        if uid in LINKS:

            LINKS[
                uid
            ][
                "sub_id"
            ] = sub_id

    await save_state()

    log_activity(
        "link",
        (
            f"کانفیگ "
            f"«{label}» "
            f"{'به گروه اضافه شد' if sub_id else 'از گروه خارج شد'}"
        ),
        "info",
    )

    return True


async def remove_sub_group(
    sub_id: str,
):

    async with SUBS_LOCK:

        if sub_id not in SUBS:
            return None

        name = SUBS[
            sub_id
        ].get(
            "name",
            sub_id,
        )

        del SUBS[sub_id]

    async with LINKS_LOCK:

        for link in LINKS.values():

            if (
                link.get("sub_id")
                == sub_id
            ):
                link["sub_id"] = None

    await save_state()

    log_activity(
        "sub",
        (
            f"گروه "
            f"«{name}» "
            f"حذف شد"
        ),
        "warn",
    )

    return name


# ============================================================
# STARTUP
# ============================================================

@app.on_event("startup")
async def startup():

    global http_client

    limits = httpx.Limits(
        max_connections=500,
        max_keepalive_connections=100,
    )

    timeout = httpx.Timeout(
        30.0,
        connect=10.0,
    )

    http_client = httpx.AsyncClient(
        limits=limits,
        timeout=timeout,
        follow_redirects=True,
    )

    await load_state()

    await ensure_default_categories()
    await ensure_default_link()

    log_activity(
        "system",
        (
            f"{APP_NAME} "
            f"v{APP_VERSION} "
            f"راه‌اندازی شد"
        ),
        "ok",
    )

    logger.info(
        "%s v%s started on 0.0.0.0:%s",
        APP_NAME,
        APP_VERSION,
        PORT,
    )

    logger.info(
        "Data directory: %s",
        DATA_DIR,
    )


@app.on_event("shutdown")
async def shutdown():

    await save_state()

    if http_client:
        await http_client.aclose()


# ============================================================
# LANDING
# ============================================================

LANDING_HTML = Path("static/landing/index.html").read_text(encoding="utf-8") if Path("static/landing/index.html").exists() else ""



@app.get(
    "/",
    response_class=HTMLResponse,
)
async def root(
    request: Request,
):

    if await is_valid_session(
        request.cookies.get(
            SESSION_COOKIE
        )
    ):
        return RedirectResponse(
            "/dashboard"
        )

    if not (AUTH.get("password_configured") and AUTH.get("password_hash")):
        return RedirectResponse("/setup")
    return HTMLResponse(
        LANDING_HTML
    )


# ============================================================
# HEALTH
# ============================================================

@app.get("/health")
async def health():

    return {
        "status": "ok",
        "service": APP_NAME,
        "version": APP_VERSION,
        "connections": len(connections),
        "uptime": uptime(),
    }


# ============================================================
# LOGIN
# ============================================================

LOGIN_HTML = Path("static/login/index.html").read_text(encoding="utf-8") if Path("static/login/index.html").exists() else ""
SETUP_HTML = Path("static/setup/index.html").read_text(encoding="utf-8") if Path("static/setup/index.html").exists() else ""





def login_error_html(
    message: str,
):
    safe_message = escape_html(
        message
    )

    return LOGIN_HTML.replace(
        "</form>",
        (
            f"""
            <div class="error">
                {safe_message}
            </div>
            </form>
            """
        ),
    )



# ============================================================
# FIRST-RUN SETUP
# ============================================================


@app.get("/api/system")
async def api_system(token=Depends(require_auth)):
    """CPU / RAM / Disk / Network stats for dashboard."""
    out = {
        "cpu_percent": None,
        "ram_percent": None,
        "ram_used_fmt": None,
        "ram_total_fmt": None,
        "disk_percent": None,
        "disk_used_fmt": None,
        "net_sent_fmt": None,
        "net_recv_fmt": None,
        "uptime": uptime(),
        "connections": len(connections),
        "links": len(LINKS),
    }
    try:
        import psutil
        out["cpu_percent"] = float(psutil.cpu_percent(interval=0.0))
        vm = psutil.virtual_memory()
        out["ram_percent"] = float(vm.percent)
        out["ram_used_fmt"] = fmt_bytes(int(vm.used))
        out["ram_total_fmt"] = fmt_bytes(int(vm.total))
        try:
            du = psutil.disk_usage("/")
            out["disk_percent"] = float(du.percent)
            out["disk_used_fmt"] = fmt_bytes(int(du.used)) + " / " + fmt_bytes(int(du.total))
        except Exception:
            pass
        try:
            nio = psutil.net_io_counters()
            out["net_sent_fmt"] = fmt_bytes(int(nio.bytes_sent))
            out["net_recv_fmt"] = fmt_bytes(int(nio.bytes_recv))
        except Exception:
            pass
    except Exception:
        # fallback without psutil
        total_bytes = int(stats.get("total_bytes") or 0)
        out["net_recv_fmt"] = fmt_bytes(total_bytes)
        out["net_sent_fmt"] = "—"
        out["cpu_percent"] = 0.0
        out["ram_percent"] = 0.0
        out["ram_used_fmt"] = "—"
        out["disk_used_fmt"] = "—"
        out["disk_percent"] = 0.0
    return out


@app.get("/api/setup/status")
async def setup_status():
    return {
        "password_configured": bool(AUTH.get("password_configured") and AUTH.get("password_hash")),
        "needs_setup": not bool(AUTH.get("password_configured") and AUTH.get("password_hash")),
    }


@app.post("/api/setup/password")
async def setup_password(request: Request):
    if AUTH.get("password_configured") and AUTH.get("password_hash"):
        raise HTTPException(status_code=400, detail="رمز قبلاً تنظیم شده است")
    try:
        body = await request.json()
    except Exception:
        raise HTTPException(status_code=400, detail="اطلاعات نامعتبر")
    pw = str(body.get("password") or "")
    rp = str(body.get("repeat_password") or body.get("confirm") or "")
    if len(pw) < 6:
        raise HTTPException(status_code=400, detail="رمز باید حداقل ۶ کاراکتر باشد")
    if pw != rp:
        raise HTTPException(status_code=400, detail="تکرار رمز یکسان نیست")
    AUTH["password_hash"] = hash_password(pw)
    AUTH["password_configured"] = True
    await save_state()
    token = await create_session()
    response = JSONResponse({"ok": True, "message": "رمز تنظیم شد"})
    set_auth_cookie(response, request, token)
    log_activity("auth", "رمز اولیه پنل تنظیم شد", "ok")
    return response


@app.get(
    "/login",
    response_class=HTMLResponse,
)
async def login_page(
    request: Request,
):

    if await is_valid_session(
        request.cookies.get(
            SESSION_COOKIE
        )
    ):
        return RedirectResponse(
            "/dashboard"
        )

    if not (AUTH.get("password_configured") and AUTH.get("password_hash")):
        return RedirectResponse("/setup")

    # always read fresh file so UI edits apply without redeploy of constants
    html = Path("static/login/index.html").read_text(encoding="utf-8") if Path("static/login/index.html").exists() else LOGIN_HTML
    return HTMLResponse(html)


@app.get("/setup", response_class=HTMLResponse)
async def setup_page(request: Request):
    if AUTH.get("password_configured") and AUTH.get("password_hash"):
        return RedirectResponse("/login")
    if await is_valid_session(request.cookies.get(SESSION_COOKIE)):
        return RedirectResponse("/dashboard")
    p = Path("static/setup/index.html")
    html = p.read_text(encoding="utf-8") if p.exists() else (SETUP_HTML or "<h1>setup missing</h1>")
    return HTMLResponse(html)


@app.post("/login")
async def login_form(
    request: Request,
):
    if not (AUTH.get("password_configured") and AUTH.get("password_hash")):
        return RedirectResponse("/setup")


    try:

        content_type = (
            request.headers
            .get(
                "content-type",
                "",
            )
            .lower()
        )

        if "application/json" in content_type:

            body = await request.json()

            password = str(
                body.get(
                    "password",
                    "",
                )
            ).strip()

        else:

            raw = await request.body()

            parsed = parse_qs(
                raw.decode(
                    "utf-8",
                    errors="ignore",
                )
            )

            password = (
                parsed.get(
                    "password",
                    [""],
                )[0]
                .strip()
            )

    except Exception as exc:

        logger.exception(
            "Login parser error: %s",
            exc,
        )

        return HTMLResponse(
            login_error_html(
                "خطا در پردازش اطلاعات ورود."
            ),
            status_code=400,
        )

    ip = client_ip(request)

    blocked, retry_after = login_is_blocked(ip)
    if blocked:
        minutes = max(1, (retry_after + 59) // 60)
        return HTMLResponse(
            login_error_html(
                f"به دلیل تلاش‌های ناموفق متعدد، ورود موقتاً مسدود شده است. حدود {minutes} دقیقه دیگر دوباره تلاش کنید."
            ),
            status_code=429,
            headers={"Retry-After": str(retry_after)},
        )

    if not password:
        register_login_failure(ip)
        return HTMLResponse(
            login_error_html(
                "رمز عبور را وارد کنید."
            ),
            status_code=400,
        )

    if (
        hash_password(password)
        != AUTH["password_hash"]
    ):

        locked, value = register_login_failure(ip)
        if locked:
            return HTMLResponse(
                login_error_html(
                    "تعداد تلاش‌های ناموفق بیش از حد مجاز بود. این IP برای ۱۵ دقیقه مسدود شد."
                ),
                status_code=429,
                headers={"Retry-After": str(LOGIN_LOCKOUT_SECONDS)},
            )

        remaining = value
        log_activity(
            "auth",
            (
                f"تلاش ورود ناموفق از {ip}؛ "
                f"{remaining} تلاش باقی مانده"
            ),
            "err",
        )

        return HTMLResponse(
            login_error_html(
                f"رمز عبور اشتباه است. {remaining} تلاش دیگر باقی مانده است."
            ),
            status_code=401,
        )

    clear_login_failures(ip)

    token = await create_session()

    response = RedirectResponse(
        "/dashboard?login=1",
        status_code=303,
    )

    set_auth_cookie(
        response,
        request,
        token,
    )

    log_activity(
        "auth",
        (
            f"ورود موفق به پنل "
            f"از {client_ip(request)}"
        ),
        "ok",
    )

    return response


@app.post("/api/login")
async def api_login(request: Request):
    if not (AUTH.get("password_configured") and AUTH.get("password_hash")):
        raise HTTPException(status_code=400, detail="ابتدا به /setup بروید و رمز اولیه را تنظیم کنید")
    try:
        body = await request.json()
    except Exception:
        raise HTTPException(status_code=400, detail="JSON نامعتبر است")
    password = str(body.get("password", "")).strip()
    username = str(body.get("username", "")).strip().lower()
    ip = client_ip(request)
    blocked, retry_after = login_is_blocked(ip)
    if blocked:
        raise HTTPException(status_code=429, detail=f"ورود موقتاً مسدود است. حدود {max(1, (retry_after + 59) // 60)} دقیقه دیگر تلاش کنید.", headers={"Retry-After": str(retry_after)})
    if not password:
        register_login_failure(ip)
        raise HTTPException(status_code=400, detail="رمز عبور الزامی است")
    meta = {"role": "owner", "admin_id": None, "username": "owner"}
    ok = False
    if username and username not in ("owner", "admin", "root"):
        aid, admin = find_admin_by_username(username)
        if admin and admin.get("password_hash") == hash_password(password):
            if not admin_is_valid(admin):
                raise HTTPException(status_code=403, detail="حساب مسدود یا منقضی شده است")
            ok = True
            meta = {"role": "admin", "admin_id": aid, "username": username}
    else:
        if hash_password(password) == AUTH["password_hash"]:
            ok = True
    if not ok:
        locked, value = register_login_failure(ip)
        if locked:
            raise HTTPException(status_code=429, detail="تعداد تلاش بیش از حد. ۱۵ دقیقه صبر کنید.", headers={"Retry-After": str(LOGIN_LOCKOUT_SECONDS)})
        raise HTTPException(status_code=401, detail=f"نام کاربری یا رمز اشتباه است. {value} تلاش باقی‌مانده")
    clear_login_failures(ip)
    token = await create_session(meta)
    response = JSONResponse({"ok": True, "role": meta["role"], "username": meta["username"]})
    set_auth_cookie(response, request, token)
    log_activity("auth", f"ورود موفق ({meta['username']}) از {ip}", "ok")
    return response


@app.post("/api/logout")
async def api_logout(
    request: Request,
):

    await destroy_session(
        request.cookies.get(
            SESSION_COOKIE
        )
    )

    response = JSONResponse(
        {
            "ok": True
        }
    )

    # clear cookie with same attributes as set
    response.delete_cookie(
        SESSION_COOKIE,
        path="/",
        samesite="lax",
    )
    response.set_cookie(
        SESSION_COOKIE,
        value="",
        max_age=0,
        path="/",
        httponly=True,
        samesite="lax",
    )

    return response





# ============================================================
# CHANGE PASSWORD
# ============================================================

@app.post("/api/change-password")
async def api_change_password(
    request: Request,
    token=Depends(require_auth),
):

    try:
        body = await request.json()
    except Exception:
        raise HTTPException(
            status_code=400,
            detail="اطلاعات نامعتبر است",
        )

    current_password = str(
        body.get(
            "current_password",
            "",
        )
    )

    if (
        hash_password(current_password)
        != AUTH["password_hash"]
    ):
        raise HTTPException(
            status_code=400,
            detail="رمز فعلی اشتباه است",
        )

    new_password = str(
        body.get(
            "new_password",
            "",
        )
    )

    repeat_password = str(
        body.get(
            "repeat_password",
            "",
        )
    )

    if len(new_password) < 6:
        raise HTTPException(
            status_code=400,
            detail="رمز جدید باید حداقل ۶ کاراکتر باشد",
        )

    if new_password != repeat_password:
        raise HTTPException(
            status_code=400,
            detail="تکرار رمز عبور یکسان نیست",
        )

    AUTH[
        "password_hash"
    ] = hash_password(
        new_password
    )

    async with SESSIONS_LOCK:

        SESSIONS.clear()

        SESSIONS[token] = (
            time.time()
            + SESSION_TTL
        )

    await save_state()

    log_activity(
        "auth",
        "رمز عبور پنل تغییر کرد",
        "ok",
    )

    return {
        "ok": True
    }


# ============================================================
# CREATE LINK
# ============================================================

@app.post("/api/links")
async def create_link_api(
    request: Request,
    _=Depends(require_auth),
):

    try:
        body = await request.json()

        if not isinstance(body, dict):
            raise ValueError(
                "body is not object"
            )

    except Exception as exc:

        logger.exception(
            "Create link JSON error: %s",
            exc,
        )

        raise HTTPException(
            status_code=400,
            detail="اطلاعات ارسال‌شده معتبر نیست.",
        )

    limit_value = safe_float(
        body.get(
            "limit_value",
            0,
        )
    )

    limit_unit = str(
        body.get(
            "limit_unit",
            "GB",
        )
        or "GB"
    ).upper()

    limit_bytes = (
        0
        if limit_value <= 0
        else parse_size_to_bytes(
            limit_value,
            limit_unit,
        )
    )

    expires_days = safe_int(
        body.get(
            "expires_days",
            0,
        ),
        minimum=0,
    )

    expires_at = (
        (
            datetime.now()
            + timedelta(
                days=expires_days
            )
        ).isoformat()
        if expires_days > 0
        else None
    )

    port = safe_int(
        body.get(
            "port",
            DEFAULT_PORT,
        ),
        default=DEFAULT_PORT,
        minimum=MIN_PORT,
        maximum=MAX_PORT,
    )

    ip_limit = safe_int(
        body.get(
            "ip_limit",
            0,
        ),
        minimum=0,
    )

    speed_value = safe_float(
        body.get(
            "speed_limit_value",
            0,
        )
    )

    speed_unit = str(
        body.get(
            "speed_limit_unit",
            "MBIT",
        )
        or "MBIT"
    ).upper()

    speed_bytes = (
        0
        if speed_value <= 0
        else parse_speed_to_bytes(
            speed_value,
            speed_unit,
        )
    )

    connection_limit = safe_int(
        body.get(
            "connection_limit",
            0,
        ),
        minimum=0,
    )

    protocol = str(
        body.get(
            "protocol",
            DEFAULT_PROTOCOL,
        )
        or DEFAULT_PROTOCOL
    ).strip()

    if protocol not in PROTOCOLS:
        protocol = DEFAULT_PROTOCOL

    fingerprint = str(
        body.get(
            "fingerprint",
            DEFAULT_FINGERPRINT,
        )
        or DEFAULT_FINGERPRINT
    ).strip().lower()

    if fingerprint not in FINGERPRINTS:
        fingerprint = DEFAULT_FINGERPRINT

    fragment = str(
        body.get(
            "fragment",
            "off",
        )
        or "off"
    ).strip().lower()

    allowed_fragments = {
        "off",
        "safe",
        "balanced",
        "aggressive",
    }

    if fragment not in allowed_fragments:
        fragment = "off"

    raw_clean = body.get("clean_ips") or body.get("clean_ip") or ""
    if isinstance(raw_clean, list):
        clean_ips = [str(x).strip() for x in raw_clean if str(x).strip()]
    else:
        clean_ips = [x.strip() for x in str(raw_clean).replace(",", "\n").splitlines() if x.strip()]
    alarm_enabled = bool(body.get("alarm_enabled", False))
    category_id = str(body.get("category_id") or "0")
    if category_id not in CATEGORIES:
        category_id = "0"
    config_count = safe_int(body.get("config_count", 1), minimum=1, maximum=40)
    cat = CATEGORIES.get(category_id) or {}
    if cat.get("limit_bytes") and limit_bytes <= 0:
        limit_bytes = int(cat["limit_bytes"])
    if cat.get("expires_days") and expires_days <= 0:
        expires_days = int(cat["expires_days"])
        expires_at = (datetime.now() + timedelta(days=expires_days)).isoformat() if expires_days > 0 else None
    if cat.get("connection_limit") and connection_limit <= 0:
        connection_limit = int(cat["connection_limit"])
    if cat.get("speed_limit_bytes") and speed_bytes <= 0:
        speed_bytes = int(cat["speed_limit_bytes"])
    if cat.get("ip_limit") and ip_limit <= 0:
        ip_limit = int(cat["ip_limit"])
    if cat.get("clean_ips") and not clean_ips:
        clean_ips = list(cat["clean_ips"])
    if cat.get("single_user"):
        if ip_limit == 0: ip_limit = 1
        if connection_limit == 0: connection_limit = 1
    label_val = body.get("label", "")
    if cat.get("random_name") or not str(label_val).strip():
        label_val = random_config_name()
    else:
        label_val = sanitize_config_name(str(label_val))

    uid, link = await make_link(
        label=label_val,
        limit_bytes=limit_bytes,
        expires_at=expires_at,
        note=body.get(
            "note",
            "",
        ),
        sub_id=body.get(
            "sub_id"
        ),
        protocol=protocol,
        fingerprint=fingerprint,
        alpn=body.get(
            "alpn",
            DEFAULT_ALPN_BY_PROTOCOL.get(
                protocol,
                "http/1.1",
            ),
        ),
        port=port,
        ip_limit=ip_limit,
        speed_limit_bytes=speed_bytes,
        connection_limit=connection_limit,
        fragment=fragment,
        clean_ips=clean_ips,
        alarm_enabled=alarm_enabled,
        category_id=category_id,
        config_count=config_count,
    )

    host = get_host(request)

    result = {
        **get_link_info(
            link,
            uid,
            host,
        ),
        "ok": True,
    }

    return result


# ============================================================
# AUTO CREATE
# ============================================================

@app.post("/api/links/auto")
async def create_auto_link(
    request: Request,
    _=Depends(require_auth),
):
    try:
        body = await request.json()
    except Exception:
        body = {}
    if not isinstance(body, dict): body = {}
    host = get_host(request)
    protocol = normalize_protocol(body.get("protocol", DEFAULT_PROTOCOL))
    profile = str(body.get("profile", "balanced")).strip().lower()
    profiles = {
        "normal": {"ip":0,"conn":0,"speed":0,"fp":"chrome","fragment":"off"},
        "balanced": {"ip":2,"conn":4,"speed":0,"fp":"chrome","fragment":"safe"},
        "gaming": {"ip":1,"conn":2,"speed":0,"fp":"chrome","fragment":"safe"},
        "maximum": {"ip":0,"conn":0,"speed":0,"fp":"randomized","fragment":"safe"},
    }
    cfg = profiles.get(profile, profiles["balanced"])
    config_count = safe_int(body.get("config_count", 1), minimum=1, maximum=40)
    uid, link = await make_link(
        label=auto_config_name(), limit_bytes=0, expires_at=None,
        ip_limit=cfg["ip"], speed_limit_bytes=cfg["speed"], connection_limit=cfg["conn"],
        note=f"Auto generated by PXPanel | profile={profile}",
        protocol=protocol, fingerprint=cfg["fp"],
        alpn=DEFAULT_ALPN_BY_PROTOCOL.get(protocol, ""), port=443, fragment=cfg["fragment"],
        config_count=config_count,
    )
    link["security_profile"] = profile
    result = {**get_link_info(link, uid, host), "ok": True, "profile": profile}
    log_activity("link", f"کانفیگ خودکار «{link['label']}» با {PROTOCOL_LABELS.get(protocol, protocol)} ساخته شد", "ok")
    return result


# ============================================================
# LIST LINKS
# ============================================================

@app.get("/api/protocols")
async def api_protocols(request: Request):
    require_auth(request)
    return {"protocols": [{"id": p, "label": PROTOCOL_LABELS.get(p, p)} for p in PROTOCOLS], "default": DEFAULT_PROTOCOL}


@app.get("/api/links")
async def list_links(
    request: Request,
    _=Depends(require_auth),
):

    host = get_host(request)

    async with LINKS_LOCK:
        snapshot = dict(LINKS)

    result = []

    for uid, link in snapshot.items():

        info = get_link_info(
            link,
            uid,
            host,
        )

        result.append(
            {
                **info,

                "created_at":
                    link.get(
                        "created_at"
                    ),

                "expired":
                    is_link_expired(
                        link
                    ),

                "sub_url":
                    f"https://{host}/sub/{uid}",

                "info_url":
                    f"https://{host}/info/{uid}",

                "connected_ips":
                    len(
                        unique_ips_for_uuid(
                            uid
                        )
                    ),
            }
        )

    result = sorted(
        result,
        key=lambda item: (
            -int(item.get("sort_order") or 0),
            str(item.get("created_at") or ""),
        ),
    )

    return {
        "links": result
    }


# ============================================================
# LINK INFO API
# ============================================================

@app.get("/api/links/{uid}/info")
async def link_info_api(
    uid: str,
    request: Request,
    _=Depends(require_auth),
):

    async with LINKS_LOCK:

        link = LINKS.get(uid)

        if not link:
            raise HTTPException(
                status_code=404,
                detail="link not found",
            )

        snapshot = dict(link)

    host = get_host(request)

    return {
        "ok": True,
        **get_link_info(
            snapshot,
            uid,
            host,
        ),
    }


# ============================================================
# UPDATE LINK
# ============================================================



@app.post("/api/links/reorder")
async def reorder_links(request: Request, _=Depends(require_auth)):
    try:
        body = await request.json()
    except Exception:
        raise HTTPException(400, detail="JSON نامعتبر")
    order = body.get("order") or body.get("ids") or []
    if not isinstance(order, list):
        raise HTTPException(400, detail="order باید آرایه باشد")
    # first item = highest priority
    n = len(order)
    async with LINKS_LOCK:
        for i, uid in enumerate(order):
            uid = str(uid)
            if uid in LINKS:
                LINKS[uid]["sort_order"] = n - i
    await save_state()
    return {"ok": True, "count": n}


@app.post("/api/links/bulk-delete")
async def bulk_delete_links(request: Request, _=Depends(require_auth)):
    try:
        body = await request.json()
    except Exception:
        raise HTTPException(400, detail="JSON نامعتبر")
    ids = body.get("ids") or []
    if not isinstance(ids, list) or not ids:
        raise HTTPException(400, detail="ids خالی است")
    deleted = []
    for uid in ids:
        uid = str(uid)
        if uid in LINKS:
            await remove_link(uid)
            deleted.append(uid)
    log_activity("link", f"حذف گروهی {len(deleted)} کانفیگ", "warn")
    return {"ok": True, "deleted": len(deleted)}


@app.post("/api/links/bulk-category")
async def bulk_category(request: Request, _=Depends(require_auth)):
    try:
        body = await request.json()
    except Exception:
        raise HTTPException(400, detail="JSON نامعتبر")
    ids = body.get("ids") or []
    cid = str(body.get("category_id") or "0")
    if cid not in CATEGORIES:
        cid = "0"
    n = 0
    async with LINKS_LOCK:
        for uid in ids:
            uid = str(uid)
            if uid in LINKS:
                LINKS[uid]["category_id"] = cid
                n += 1
    await save_state()
    return {"ok": True, "updated": n}


@app.patch("/api/links/{uid}")
async def update_link(
    uid: str,
    request: Request,
    _=Depends(require_auth),
):

    try:
        body = await request.json()
    except Exception:
        raise HTTPException(
            status_code=400,
            detail="اطلاعات نامعتبر است",
        )

    if not isinstance(body, dict):
        raise HTTPException(
            status_code=400,
            detail="اطلاعات نامعتبر است",
        )

    async with LINKS_LOCK:

        if uid not in LINKS:
            raise HTTPException(
                status_code=404,
                detail="link not found",
            )

        link = LINKS[uid]

        old_sub = link.get(
            "sub_id"
        )

        label = link.get(
            "label",
            uid,
        )

        if "active" in body:
            link["active"] = bool(
                body["active"]
            )

        if "category_id" in body:
            cid = str(body.get("category_id") or "0")
            if cid not in CATEGORIES:
                cid = "0"
            link["category_id"] = cid

        if "sort_order" in body:
            try:
                link["sort_order"] = int(body.get("sort_order") or 0)
            except Exception:
                pass

        if "label" in body:

            value = str(
                body["label"]
            ).strip()

            if value:
                link["label"] = value[:60]

        if "note" in body:

            link["note"] = str(
                body.get(
                    "note",
                    "",
                )
            )[:500]

        if "reset_usage" in body:

            if body.get(
                "reset_usage"
            ):
                link[
                    "used_bytes"
                ] = 0


        if "limit_value" in body:

            value = safe_float(
                body.get(
                    "limit_value",
                    0,
                )
            )

            unit = str(
                body.get(
                    "limit_unit",
                    "GB",
                )
                or "GB"
            )

            link[
                "limit_bytes"
            ] = (
                0
                if value <= 0
                else parse_size_to_bytes(
                    value,
                    unit,
                )
            )

        if "expires_days" in body:

            days = safe_int(
                body.get(
                    "expires_days",
                    0,
                ),
                minimum=0,
            )

            link[
                "expires_at"
            ] = (
                (
                    datetime.now()
                    + timedelta(
                        days=days
                    )
                ).isoformat()
                if days > 0
                else None
            )

        if "fingerprint" in body:

            fingerprint = str(
                body.get(
                    "fingerprint",
                    DEFAULT_FINGERPRINT,
                )
            ).strip().lower()

            link[
                "fingerprint"
            ] = (
                fingerprint
                if fingerprint in FINGERPRINTS
                else DEFAULT_FINGERPRINT
            )

        if "alpn" in body:

            link["alpn"] = str(
                body.get(
                    "alpn",
                    "",
                )
            )[:100]

        if "port" in body:

            p = safe_int(
                body.get(
                    "port",
                    DEFAULT_PORT,
                ),
                default=DEFAULT_PORT,
                minimum=MIN_PORT,
                maximum=MAX_PORT,
            )

            link["port"] = p

        if "ip_limit" in body:

            link["ip_limit"] = safe_int(
                body.get(
                    "ip_limit",
                    0,
                ),
                minimum=0,
            )

        if "connection_limit" in body:

            link[
                "connection_limit"
            ] = safe_int(
                body.get(
                    "connection_limit",
                    0,
                ),
                minimum=0,
            )

        if "speed_limit_value" in body:

            speed_value = safe_float(
                body.get(
                    "speed_limit_value",
                    0,
                )
            )

            speed_unit = str(
                body.get(
                    "speed_limit_unit",
                    "MBIT",
                )
                or "MBIT"
            )

            link[
                "speed_limit_bytes"
            ] = (
                0
                if speed_value <= 0
                else parse_speed_to_bytes(
                    speed_value,
                    speed_unit,
                )
            )

        if "protocol" in body:

            protocol = str(
                body.get(
                    "protocol",
                    DEFAULT_PROTOCOL,
                )
            ).strip()

            link["protocol"] = (
                protocol
                if protocol in PROTOCOLS
                else DEFAULT_PROTOCOL
            )

        if "fragment" in body:

            fragment = str(
                body.get(
                    "fragment",
                    "off",
                )
                or "off"
            ).strip().lower()

            if fragment not in {
                "off",
                "safe",
                "balanced",
                "aggressive",
            }:
                fragment = "off"

            link["fragment"] = fragment

        if "sub_id" in body:

            link[
                "sub_id"
            ] = (
                body.get(
                    "sub_id"
                )
                or None
            )

        new_sub = body.get(
            "sub_id",
            "UNCHANGED",
        )

    if new_sub != "UNCHANGED":

        async with SUBS_LOCK:

            if (
                old_sub
                and old_sub in SUBS
            ):

                ids = SUBS[
                    old_sub
                ].get(
                    "link_ids",
                    [],
                )

                if uid in ids:
                    ids.remove(uid)

            if (
                new_sub
                and new_sub in SUBS
            ):

                ids = SUBS[
                    new_sub
                ].setdefault(
                    "link_ids",
                    [],
                )

                if uid not in ids:
                    ids.append(uid)

    await save_state()

    log_activity(
        "link",
        (
            f"کانفیگ "
            f"«{label}» "
            f"ویرایش شد"
        ),
        "info",
    )

    return {
        "ok": True
    }


# ============================================================
# RESET USAGE
# ============================================================

@app.post(
    "/api/links/{uid}/reset-usage"
)
async def reset_link_usage(
    uid: str,
    _=Depends(require_auth),
):

    async with LINKS_LOCK:

        link = LINKS.get(uid)

        if not link:
            raise HTTPException(
                status_code=404,
                detail="link not found",
            )

        link["used_bytes"] = 0

        label = link.get(
            "label",
            uid,
        )

    await save_state()

    log_activity(
        "link",
        (
            f"مصرف کانفیگ "
            f"«{label}» ریست شد"
        ),
        "info",
    )

    return {
        "ok": True,
        "uuid": uid,
        "used_bytes": 0,
    }


# ============================================================
# LINK ACTION
# ============================================================

@app.post(
    "/api/links/{uid}/action"
)
async def link_action(
    uid: str,
    request: Request,
    _=Depends(require_auth),
):

    try:
        body = await request.json()
    except Exception:
        raise HTTPException(
            status_code=400,
            detail="JSON نامعتبر است",
        )

    action = str(
        body.get(
            "action",
            "",
        )
    ).strip().lower()

    if action == "reset":

        await reset_link_usage(
            uid,
            _
        )

        return {
            "ok": True,
            "action": "reset",
        }

    if action == "enable":

        result = await set_link_active(
            uid,
            True,
        )

        if result is None:
            raise HTTPException(
                status_code=404,
                detail="link not found",
            )

        return {
            "ok": True,
            "action": "enable",
        }

    if action == "disable":

        result = await set_link_active(
            uid,
            False,
        )

        if result is None:
            raise HTTPException(
                status_code=404,
                detail="link not found",
            )

        return {
            "ok": True,
            "action": "disable",
        }

    raise HTTPException(
        status_code=400,
        detail="unknown action",
    )


# ============================================================
# DELETE LINK
# ============================================================

@app.delete("/api/links/{uid}")
async def delete_link(
    uid: str,
    _=Depends(require_auth),
):

    label = await remove_link(uid)

    if label is None:
        raise HTTPException(
            status_code=404,
            detail="link not found",
        )

    return {
        "ok": True,
        "deleted": uid,
    }




def subscription_metadata_headers(used_bytes: int, limit_bytes: int, expires_at, host: str, info_url: str, title: str):
    """Standard subscription headers understood by v2rayNG/v2rayN/Hiddify and similar clients."""
    used_bytes = max(0, int(used_bytes or 0))
    limit_bytes = max(0, int(limit_bytes or 0))

    expire_unix = 0
    if expires_at:
        try:
            dt = datetime.fromisoformat(str(expires_at))
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=IRAN_TZ) if IRAN_TZ else dt
            expire_unix = max(0, int(dt.timestamp()))
        except Exception:
            expire_unix = 0

    userinfo = f"upload=0; download={used_bytes}; total={limit_bytes}; expire={expire_unix}"

    return {
        "profile-title": quote(title, safe=""),
        "profile-web-page-url": info_url,
        "support-url": SUPPORT_URL,
        "profile-update-interval": "12",
        "subscription-userinfo": userinfo,
        "content-disposition": 'inline; filename="subscription.txt"',
    }

# ============================================================
# SINGLE SUB
# ============================================================

@app.get("/sub/{uuid}")
async def subscription_single(
    uuid: str,
    request: Request,
):

    async with LINKS_LOCK:
        link = LINKS.get(uuid)

    if not is_link_allowed(link):
        raise HTTPException(
            status_code=404,
            detail="not found or inactive",
        )

    host = get_host(request)
    clean_ips = link.get("clean_ips") or []
    used = int(link.get("used_bytes", 0) or 0)
    limit = int(link.get("limit_bytes", 0) or 0)
    remaining = max(0, limit - used) if limit > 0 else 0
    volume_text = f"{fmt_bytes(used)}/{fmt_bytes(limit)} (باقی {fmt_bytes(remaining)})" if limit > 0 else f"{fmt_bytes(used)}/∞"
    expires_at = link.get("expires_at")
    if expires_at:
        try:
            exp_dt = datetime.fromisoformat(str(expires_at))
            now_dt = datetime.now(exp_dt.tzinfo) if getattr(exp_dt, "tzinfo", None) else datetime.now()
            secs = int((exp_dt - now_dt).total_seconds())
            if secs <= 0:
                time_text = "منقضی"
            else:
                days, rem = divmod(secs, 86400)
                hours, rem = divmod(rem, 3600)
                mins = rem // 60
                time_text = f"{days}د {hours}س" if days else (f"{hours}س {mins}د" if hours else f"{mins}د")
        except Exception:
            time_text = str(expires_at)[:16]
    else:
        time_text = "∞"
    label = str(link.get("label") or "Config")
    stats_remark = f"{label} | {volume_text} | {time_text}"
    stats_line = generate_vless_link(uuid, "0.0.0.0", remark=stats_remark, protocol=link.get("protocol", DEFAULT_PROTOCOL), fingerprint=link.get("fingerprint", DEFAULT_FINGERPRINT), alpn=link.get("alpn"), port=link.get("port", DEFAULT_PORT))
    lines = [stats_line]
    used_names = set()
    cfg_count = max(1, min(40, int(link.get("config_count") or 1)))
    if clean_ips:
        hosts = list(clean_ips)
        while len(hosts) < cfg_count:
            hosts.extend(clean_ips)
        hosts = hosts[:cfg_count]
        for cip in hosts:
            name = random_config_name(used_names)
            used_names.add(name)
            lines.append(generate_vless_link(uuid, cip, remark=name, protocol=link.get("protocol", DEFAULT_PROTOCOL), fingerprint=link.get("fingerprint", DEFAULT_FINGERPRINT), alpn=link.get("alpn"), port=link.get("port", DEFAULT_PORT)))
    else:
        for i in range(cfg_count):
            name = random_config_name(used_names)
            used_names.add(name)
            lines.append(generate_vless_link(uuid, host, remark=name, protocol=link.get("protocol", DEFAULT_PROTOCOL), fingerprint=link.get("fingerprint", DEFAULT_FINGERPRINT), alpn=link.get("alpn"), port=link.get("port", DEFAULT_PORT)))
    content = base64.b64encode("\n".join(lines).encode()).decode()
    profile_title = f"0.0.0.0 | {stats_remark}"
    headers = subscription_metadata_headers(
        used,
        limit,
        link.get("expires_at"),
        host,
        f"https://{host}/info/{uuid}",
        profile_title,
    )

    return Response(
        content=content,
        media_type="text/plain; charset=utf-8",
        headers=headers,
    )

# ============================================================
# SUB ALL
# ============================================================

@app.get("/sub-all")
async def subscription_all(
    request: Request,
    _=Depends(require_auth),
):

    host = get_host(request)

    async with LINKS_LOCK:

        lines = [
            vless_link_for_link(
                link,
                uid,
                host,
            )

            for uid, link
            in LINKS.items()

            if is_link_allowed(link)
        ]

    content = (
        base64
        .b64encode(
            "\n".join(
                lines
            ).encode()
        )
        .decode()
    )

    return Response(
        content=content,
        media_type="text/plain",
    )


# ============================================================
# INFO PAGE
# ============================================================

@app.get(
    "/info/{uid}",
    response_class=HTMLResponse,
)
async def info_page(
    uid: str,
    request: Request,
):
    async with LINKS_LOCK:
        link = LINKS.get(uid)
        if not link:
            return HTMLResponse("<html lang=\"fa\" dir=\"rtl\"><body style=\"margin:0;background:#07070a;color:#fff;font-family:sans-serif;padding:40px\"><h2>کانفیگ پیدا نشد</h2></body></html>", status_code=404)
        snapshot = dict(link)

    host = get_host(request)
    vless_url = vless_link_for_link(snapshot, uid, host)
    sub_url = f"https://{host}/sub/{uid}"
    used = int(snapshot.get("used_bytes", 0) or 0)
    limit = int(snapshot.get("limit_bytes", 0) or 0)
    if limit > 0:
        usage_percent = max(0, min(100, round((used / limit) * 100, 1)))
        usage_value = f"{fmt_bytes(used)} / {fmt_bytes(limit)}"
        remaining_value = fmt_bytes(max(0, limit - used))
    else:
        usage_percent = 0
        usage_value = f"{fmt_bytes(used)} / نامحدود"
        remaining_value = "نامحدود"

    expires_at = snapshot.get("expires_at")
    if expires_at:
        try:
            expiry_dt = datetime.fromisoformat(str(expires_at))
            now_dt = datetime.now(expiry_dt.tzinfo) if expiry_dt.tzinfo else datetime.now()
            seconds = int((expiry_dt - now_dt).total_seconds())
            if seconds <= 0:
                expiry_remaining = "منقضی شده"
            else:
                days, rem = divmod(seconds, 86400)
                hours, rem = divmod(rem, 3600)
                minutes, _ = divmod(rem, 60)
                expiry_remaining = f"{days} روز و {hours} ساعت" if days else (f"{hours} ساعت و {minutes} دقیقه" if hours else f"{minutes} دقیقه")
        except Exception:
            expiry_remaining = "نامشخص"
        expiry_display = str(expires_at)
    else:
        expiry_remaining = "نامحدود"
        expiry_display = "نامحدود"

    status_text = "فعال" if is_link_allowed(snapshot) else "غیرفعال"
    status_class = "good" if status_text == "فعال" else "bad"
    ip_limit = "نامحدود" if not snapshot.get("ip_limit", 0) else str(snapshot.get("ip_limit"))
    connection_limit = "نامحدود" if not snapshot.get("connection_limit", 0) else str(snapshot.get("connection_limit"))
    speed_limit = "نامحدود" if not snapshot.get("speed_limit_bytes", 0) else fmt_bytes(snapshot.get("speed_limit_bytes", 0)) + "/s"

    usage_history = snapshot.get("usage_history", [])
    svg_points = "0,50 300,50"
    if usage_history and len(usage_history) > 1:
        max_hist = max(usage_history) if max(usage_history) > 0 else 1
        pts = []
        step = 300 / (len(usage_history) - 1)
        for i, val in enumerate(usage_history):
            x = i * step
            y = 60 - min(60, max(4, (val / max_hist) * 52))
            pts.append(f"{x:.1f},{y:.1f}")
        svg_points = " ".join(pts)
    elif usage_history and len(usage_history) == 1:
        svg_points = f"0,50 300,{60 - min(60, max(4, (usage_history[0] / (limit if limit > 0 else max(used, 1))) * 52)):.1f}"

    status_badge_html = 'text-emerald-300 border border-emerald-400/25 bg-emerald-400/10' if status_class == 'good' else 'text-rose-300 border border-rose-400/25 bg-rose-400/10'
    label_escaped = escape_html(snapshot.get("label", "PXpanel"))
    uid_escaped = escape_html(uid)
    app_version_str = escape_html(str(APP_VERSION))
    used_bytes_str = escape_html(fmt_bytes(used))
    limit_bytes_str = escape_html(fmt_bytes(limit)) if limit > 0 else '∞'
    remaining_value_escaped = escape_html(remaining_value)
    expiry_remaining_escaped = escape_html(expiry_remaining)
    expiry_display_escaped = escape_html(expiry_display)
    ip_limit_escaped = escape_html(ip_limit)
    connection_limit_escaped = escape_html(connection_limit)
    speed_limit_escaped = escape_html(speed_limit)
    protocol_escaped = escape_html(snapshot.get("protocol", "vless-ws"))
    fingerprint_escaped = escape_html(snapshot.get("fingerprint", "chrome"))
    vless_url_escaped = escape_html(vless_url)
    sub_url_escaped = escape_html(sub_url)
    dash_calc_offset = f"{339.29 - (339.29 * min(usage_percent, 100) / 100):.1f}"

    info_html = f"""<!DOCTYPE html>
<html lang="fa" dir="rtl">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1,viewport-fit=cover">
<title>{label_escaped} | INFO</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700;800&family=Noto+Sans+Arabic:wght@400;500;600;700;800&display=swap" rel="stylesheet">
<script src="https://cdn.tailwindcss.com"></script>
<script src="https://cdn.jsdelivr.net/npm/qrcode-generator@1.4.4/qrcode.min.js"></script>
<script>
  tailwind.config = {{
    theme: {{
      extend: {{
        fontFamily: {{ sans: ['Noto Sans Arabic','Inter','system-ui','sans-serif'] }}
      }}
    }}
  }}
</script>
<style>
  :root {{
    --bg-main: #05060a;
    --bg-card: rgba(255, 255, 255, 0.04);
    --bg-card-hover: rgba(255, 255, 255, 0.07);
    --border-color: rgba(255, 255, 255, 0.1);
    --text-main: #f1f5f9;
    --text-muted: rgba(255, 255, 255, 0.4);
    --bg-sub-card: rgba(0, 0, 0, 0.2);
    --grad-1: rgba(96,165,250,.16);
    --grad-2: rgba(96,165,250,.13);
    --grad-3: rgba(52,211,153,.08);
  }}

  body.theme-lighter {{
    --bg-main: #131722;
    --bg-card: rgba(255, 255, 255, 0.075);
    --bg-card-hover: rgba(255, 255, 255, 0.115);
    --border-color: rgba(255, 255, 255, 0.16);
    --text-main: #ffffff;
    --text-muted: rgba(255, 255, 255, 0.6);
    --bg-sub-card: rgba(0, 0, 0, 0.35);
    --grad-1: rgba(96,165,250,.24);
    --grad-2: rgba(96,165,250,.20);
    --grad-3: rgba(52,211,153,.13);
  }}

  html,body{{background:var(--bg-main); transition: background 0.3s ease, color 0.3s ease;}}
  body{{
    background:
      radial-gradient(ellipse 80% 50% at 10% -10%, var(--grad-1), transparent 50%),
      radial-gradient(ellipse 60% 40% at 95% 15%, var(--grad-2), transparent 45%),
      radial-gradient(ellipse 55% 35% at 60% 100%, var(--grad-3), transparent 40%),
      var(--bg-main);
  }}
  .status-dot{{box-shadow:0 0 10px currentColor}}
  ::-webkit-scrollbar{{width:8px;height:8px}}
  ::-webkit-scrollbar-thumb{{background:rgba(255,255,255,.12);border-radius:99px}}
  * {{ box-shadow: none !important; }}
  .copy-btn svg{{transition:none}}
  
  .dynamic-card {{
    background-color: var(--bg-card);
    border-color: var(--border-color);
    transition: background-color 0.3s ease, border-color 0.3s ease;
  }}
  .dynamic-card:hover {{
    background-color: var(--bg-card-hover);
  }}
  .sub-box {{
    background-color: var(--bg-sub-card);
  }}
</style>
</head>
<body class="font-sans text-slate-100 antialiased min-h-screen py-8 px-3 sm:px-4 md:py-14">

<div class="w-full max-w-4xl mx-auto space-y-5 sm:space-y-6 md:space-y-8">

  <!-- Top Bar Theme Toggle Button -->
  <div class="flex justify-end">
    <button type="button" onclick="toggleTheme()" class="inline-flex items-center gap-1.5 px-4 py-2 rounded-full text-xs font-extrabold text-amber-300 border border-amber-400/30 bg-amber-400/10 hover:bg-amber-400/20 transition-colors shadow-lg">
      <svg id="themeIcon" xmlns="http://www.w3.org/2000/svg" width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="4"/><path d="M12 2v2M12 20v2M4.93 4.93l1.41 1.41M17.66 17.66l1.41 1.41M2 12h2M20 12h2M6.34 17.66l-1.41 1.41M19.07 4.93l-1.41 1.41"/></svg>
      تغییر تم
    </button>
  </div>

  <!-- Hero -->
  <section class="rounded-[26px] sm:rounded-[28px] border dynamic-card backdrop-blur-2xl p-5 sm:p-6 md:p-8">
    <div class="flex flex-col md:flex-row md:items-center md:justify-between gap-5">
      <div class="flex items-center gap-4">
        <div class="w-13 h-13 sm:w-14 sm:h-14 shrink-0 rounded-2xl grid place-items-center bg-gradient-to-br from-blue-400/20 to-purple-400/10 border border-blue-400/25 text-blue-300">
          <svg xmlns="http://www.w3.org/2000/svg" width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M12 2l8 4v6c0 5.2-3.4 9-8 10-4.6-1-8-4.8-8-10V6l8-4z"/><path d="M9.5 12l1.8 1.8L15 10"/></svg>
        </div>
        <div class="min-w-0">
          <h1 class="text-lg sm:text-xl md:text-2xl font-black tracking-tight truncate">{label_escaped}</h1>
          <p class="mt-1.5 text-[10.5px] sm:text-[11px] text-white/40 break-all">UUID: {uid_escaped} &nbsp;·&nbsp; PXpanel {app_version_str}</p>
        </div>
      </div>
      <div class="flex items-center gap-2.5 self-start md:self-auto flex-wrap">
        <button type="button" onclick="openQrModal()" class="inline-flex items-center gap-1.5 px-3.5 py-2 rounded-full text-xs font-extrabold text-purple-300 border border-purple-400/30 bg-purple-400/10 hover:bg-purple-400/20 transition-colors">
          <svg xmlns="http://www.w3.org/2000/svg" width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round"><rect x="3" y="3" width="7" height="7"/><rect x="14" y="3" width="7" height="7"/><rect x="14" y="14" width="7" height="7"/><rect x="3" y="14" width="7" height="7"/></svg>
          QR Code
        </button>
        <div class="inline-flex items-center gap-2 px-4 py-2 rounded-full text-xs font-extrabold {status_badge_html}">
          <span class="status-dot w-2 h-2 rounded-full bg-current"></span>
          {status_text}
        </div>
      </div>
    </div>
  </section>

  <!-- Usage overview -->
  <section class="grid grid-cols-1 lg:grid-cols-[1.6fr_1fr] gap-5 sm:gap-6">

    <div class="rounded-[22px] border dynamic-card backdrop-blur-2xl p-5 sm:p-6 md:p-7">
      <div class="flex items-center gap-2.5">
        <svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round" class="text-white/35"><path d="M3 3v18h18"/><path d="M7 15l4-6 3 3 4-7"/></svg>
        <div>
          <p class="text-[10px] font-extrabold tracking-widest uppercase text-white/30">Traffic Overview</p>
          <p class="mt-0.5 text-sm font-black">مصرف سرویس</p>
        </div>
      </div>

      <div class="mt-6 flex flex-col sm:flex-row items-center sm:items-start gap-6">
        <div class="relative shrink-0 w-[128px] h-[128px]">
          <svg width="128" height="128" viewBox="0 0 132 132" class="-rotate-90">
            <circle cx="66" cy="66" r="54" fill="none" stroke="rgba(255,255,255,0.07)" stroke-width="10"/>
            <circle cx="66" cy="66" r="54" fill="none" stroke="url(#usageRingGradient)" stroke-width="10" stroke-linecap="round"
              stroke-dasharray="339.29" stroke-dashoffset="{dash_calc_offset}"/>
            <defs>
              <linearGradient id="usageRingGradient" x1="0%" y1="0%" x2="100%" y2="100%">
                <stop offset="0%" stop-color="#34d399"/>
                <stop offset="100%" stop-color="#f59e0b"/>
              </linearGradient>
            </defs>
          </svg>
          <div class="absolute inset-0 grid place-items-center">
            <div class="text-center">
              <p class="text-xl font-black leading-none">{usage_percent}%</p>
              <p class="mt-1.5 text-[10px] text-white/40">مصرف‌شده</p>
            </div>
          </div>
        </div>

        <div class="flex-1 w-full min-w-0">
          <div class="text-xl sm:text-2xl font-black tracking-tight">
            {used_bytes_str}
            <span class="text-sm font-semibold text-white/40"> / {limit_bytes_str}</span>
          </div>

          <div class="mt-4 rounded-xl border border-white/[0.05] sub-box px-3 pt-3 pb-1.5">
            <p class="flex items-center gap-1.5 text-[10px] text-white/35 mb-1">
              <svg xmlns="http://www.w3.org/2000/svg" width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><path d="M3 17l6-6 4 4 8-8"/><path d="M17 7h4v4"/></svg>
              روند مصرف
            </p>
            <svg viewBox="0 0 300 64" class="w-full h-14" preserveAspectRatio="none">
              <defs>
                <linearGradient id="trendFill" x1="0" y1="0" x2="0" y2="1">
                  <stop offset="0%" stop-color="#60a5fa" stop-opacity="0.35"/>
                  <stop offset="100%" stop-color="#60a5fa" stop-opacity="0"/>
                </linearGradient>
              </defs>
              <path d="M0,64 L{svg_points} L300,64 Z" fill="url(#trendFill)"/>
              <path d="M{svg_points}" fill="none" stroke="#60a5fa" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"/>
            </svg>
          </div>

          <div class="mt-4 flex items-center justify-between text-[11px] text-white/40 flex-wrap gap-2">
            <span class="inline-flex items-center gap-1.5">
              <svg xmlns="http://www.w3.org/2000/svg" width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.3" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="9"/><path d="M12 7v5l3 3"/></svg>
              باقی‌مانده: <b class="text-white/70 font-bold">{remaining_value_escaped}</b>
            </span>
            <span class="inline-flex items-center gap-1.5">
              <svg xmlns="http://www.w3.org/2000/svg" width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.3" stroke-linecap="round" stroke-linejoin="round"><rect x="3" y="4" width="18" height="17" rx="2"/><path d="M3 9h18M8 3v3M16 3v3"/></svg>
              زمان: <b class="text-white/70 font-bold">{expiry_remaining_escaped}</b>
            </span>

          </div>
        </div>
      </div>
    </div>

    <div class="rounded-[22px] border dynamic-card backdrop-blur-2xl p-5 sm:p-6 md:p-7">
      <div class="flex items-center gap-2.5">
        <svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round" class="text-white/35"><circle cx="12" cy="12" r="9"/><path d="M12 8v4l3 2"/></svg>
        <p class="text-[10px] font-extrabold tracking-widest uppercase text-white/30">Service</p>
      </div>
      <div class="mt-4 divide-y divide-white/[0.06]">
        <div class="flex items-center justify-between py-3 first:pt-0">
          <span class="inline-flex items-center gap-2 text-[11px] text-white/45">
            <svg xmlns="http://www.w3.org/2000/svg" width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round"><rect x="3" y="4" width="18" height="17" rx="2"/><path d="M3 9h18M8 3v3M16 3v3"/></svg>
            انقضا
          </span>
          <span class="text-xs font-extrabold">{expiry_display_escaped}</span>
        </div>
        <div class="flex items-center justify-between py-3">
          <span class="inline-flex items-center gap-2 text-[11px] text-white/45">
            <svg xmlns="http://www.w3.org/2000/svg" width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round"><path d="M5 12.55a11 11 0 0 1 14 0"/><path d="M8.5 16a6 6 0 0 1 7 0"/><path d="M12 20h.01"/></svg>
            IP Limit
          </span>
          <span class="text-xs font-extrabold">{ip_limit_escaped}</span>
        </div>
        <div class="flex items-center justify-between py-3">
          <span class="inline-flex items-center gap-2 text-[11px] text-white/45">
            <svg xmlns="http://www.w3.org/2000/svg" width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round"><path d="M4 9V7a2 2 0 0 1 2-2h12a2 2 0 0 1 2 2v2"/><rect x="2" y="9" width="20" height="8" rx="2"/><path d="M6 17v2M18 17v2"/></svg>
            Connection
          </span>
          <span class="text-xs font-extrabold">{connection_limit_escaped}</span>
        </div>
        <div class="flex items-center justify-between py-3 last:pb-0">
          <span class="inline-flex items-center gap-2 text-[11px] text-white/45">
            <svg xmlns="http://www.w3.org/2000/svg" width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round"><path d="M13 2L3 14h7l-1 8 10-12h-7l1-8z"/></svg>
            Speed
          </span>
          <span class="text-xs font-extrabold">{speed_limit_escaped}</span>
        </div>
      </div>
    </div>

  </section>

  <!-- Stats -->
  <section class="grid grid-cols-2 md:grid-cols-4 gap-3.5 sm:gap-4 md:gap-5">

    <div class="rounded-2xl border dynamic-card backdrop-blur-xl p-4 sm:p-5 hover:border-emerald-400/20 transition-colors duration-200">
      <div class="w-9 h-9 rounded-xl grid place-items-center bg-emerald-400/10 border border-emerald-400/20 text-emerald-300">
        <svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round"><path d="M3 3v18h18"/><path d="M18 9l-5 5-3-3-4 4"/></svg>
      </div>
      <p class="mt-4 text-[11px] text-white/45">مصرف فعلی</p>
      <p class="mt-1 text-[14px] sm:text-[15px] font-black text-emerald-300 break-words">{used_bytes_str}</p>
    </div>

    <div class="rounded-2xl border dynamic-card backdrop-blur-xl p-4 sm:p-5 hover:border-amber-400/20 transition-colors duration-200">
      <div class="w-9 h-9 rounded-xl grid place-items-center bg-amber-400/10 border border-amber-400/20 text-amber-300">
        <svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="9"/><path d="M12 7v5l3 3"/></svg>
      </div>
      <p class="mt-4 text-[11px] text-white/45">باقی‌مانده</p>
      <p class="mt-1 text-[14px] sm:text-[15px] font-black text-amber-300 break-words">{remaining_value_escaped}</p>
    </div>

    <div class="rounded-2xl border dynamic-card backdrop-blur-xl p-4 sm:p-5 hover:border-blue-400/20 transition-colors duration-200">
      <div class="w-9 h-9 rounded-xl grid place-items-center bg-blue-400/10 border border-blue-400/20 text-blue-300">
        <svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round"><rect x="4" y="4" width="16" height="16" rx="3"/><path d="M9 4v16M4 9h16"/></svg>
      </div>
      <p class="mt-4 text-[11px] text-white/45">اتصالات فعال</p>
      <p class="mt-1 text-[14px] sm:text-[15px] font-black text-blue-300 break-words">{len(unique_ips_for_uuid(uid))}</p>
    </div>

    <div class="rounded-2xl border dynamic-card backdrop-blur-xl p-4 sm:p-5 hover:border-purple-400/20 transition-colors duration-200">
      <div class="w-9 h-9 rounded-xl grid place-items-center bg-purple-400/10 border border-purple-400/20 text-purple-300">
        <svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round"><path d="M12 2l9 4.5v6c0 5-3.6 8.7-9 9.5-5.4-.8-9-4.5-9-9.5v-6L12 2z"/></svg>
      </div>
      <p class="mt-4 text-[11px] text-white/45">زمان باقی‌مانده</p>
      <p class="mt-1 text-[14px] sm:text-[15px] font-black text-purple-300 break-words">{expiry_remaining_escaped}</p>
    </div>

  </section>

  <!-- Technical details -->
  <section class="rounded-[22px] border dynamic-card backdrop-blur-2xl p-5 sm:p-6 md:p-7">
    <div class="flex items-center justify-between gap-3 mb-5">
      <p class="flex items-center gap-2 text-sm font-black">
        <svg xmlns="http://www.w3.org/2000/svg" width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round" class="text-white/40"><path d="M4 21v-7M4 10V3M12 21v-11M12 6V3M20 21v-5M20 12V3"/><path d="M1 14h6M9 8h6M17 16h6"/></svg>
        جزئیات فنی
      </p>
      <p class="text-[11px] text-white/40">Configuration Details</p>
    </div>
    <div class="grid grid-cols-1 sm:grid-cols-2 gap-3.5">
      <div class="rounded-2xl border border-white/[0.06] sub-box p-4">
        <p class="text-[11px] text-white/45">Protocol</p>
        <p class="mt-2 text-[11px] font-medium text-purple-300 tracking-wide" dir="ltr" style="font-family:ui-monospace,Consolas,monospace">{protocol_escaped}</p>
      </div>
      <div class="rounded-2xl border border-white/[0.06] sub-box p-4">
        <p class="text-[11px] text-white/45">Fingerprint</p>
        <p class="mt-2 text-[11px] font-medium text-purple-300 tracking-wide" dir="ltr" style="font-family:ui-monospace,Consolas,monospace">{fingerprint_escaped}</p>
      </div>
      <div class="rounded-2xl border border-white/[0.06] sub-box p-4">
        <p class="text-[11px] text-white/45">IP Limit</p>
        <p class="mt-2 text-xs font-bold text-white/85">{ip_limit_escaped}</p>
      </div>
      <div class="rounded-2xl border border-white/[0.06] sub-box p-4">
        <p class="text-[11px] text-white/45">Connection Limit</p>
        <p class="mt-2 text-xs font-bold text-white/85">{connection_limit_escaped}</p>
      </div>
      <div class="rounded-2xl border border-white/[0.06] sub-box p-4">
        <p class="text-[11px] text-white/45">Speed Limit</p>
        <p class="mt-2 text-xs font-bold text-white/85">{speed_limit_escaped}</p>
      </div>
      <div class="rounded-2xl border border-white/[0.06] sub-box p-4">
        <p class="text-[11px] text-white/45">تاریخ انقضا</p>
        <p class="mt-2 text-xs font-bold text-white/85">{expiry_display_escaped}</p>
      </div>
    </div>
  </section>

  <!-- Links -->
  <section class="rounded-[22px] border dynamic-card backdrop-blur-2xl p-5 sm:p-6 md:p-7">
    <div class="flex items-center justify-between gap-3 mb-5">
      <p class="flex items-center gap-2 text-sm font-black">
        <svg xmlns="http://www.w3.org/2000/svg" width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round" class="text-white/40"><path d="M10 13a5 5 0 0 0 7.07 0l2.83-2.83a5 5 0 0 0-7.07-7.07L11.5 4.5"/><path d="M14 11a5 5 0 0 0-7.07 0l-2.83 2.83a5 5 0 0 0 7.07 7.07l1.41-1.41"/></svg>
        لینک‌های سرویس
      </p>
      <p class="text-[11px] text-white/40">Copy / Import</p>
    </div>

    <div class="space-y-3">
      <div class="flex flex-col sm:flex-row sm:items-center gap-3 sm:gap-4 rounded-2xl border border-white/[0.06] sub-box p-4 hover:border-purple-400/25 transition-colors duration-200">
        <div class="min-w-0 flex-1">
          <p class="text-[11px] font-extrabold text-white/45 tracking-wide">VLESS</p>
          <p id="vlessLinkText" class="mt-1.5 text-[11px] text-purple-300 break-all leading-6" dir="ltr" style="font-family:ui-monospace,Consolas,monospace">{vless_url_escaped}</p>
        </div>
        <button id="vlessCopyBtn" type="button" onclick="pxCopy('vlessLinkText','vlessCopyBtn')"
          class="copy-btn shrink-0 self-start sm:self-center inline-flex items-center gap-1.5 text-[11px] font-bold text-white/60 px-3.5 py-2 rounded-xl bg-white/[0.05] border border-white/10 hover:bg-white/[0.1] hover:text-white transition-colors duration-200">
          <svg xmlns="http://www.w3.org/2000/svg" width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.3" stroke-linecap="round" stroke-linejoin="round"><rect x="9" y="9" width="12" height="12" rx="2"/><path d="M5 15V5a2 2 0 0 1 2-2h10"/></svg>
          <span>کپی</span>
        </button>
      </div>

      <div class="flex flex-col sm:flex-row sm:items-center gap-3 sm:gap-4 rounded-2xl border border-white/[0.06] sub-box p-4 hover:border-purple-400/25 transition-colors duration-200">
        <div class="min-w-0 flex-1">
          <p class="text-[11px] font-extrabold text-white/45 tracking-wide">SUBSCRIPTION</p>
          <p id="subLinkText" class="mt-1.5 text-[11px] text-purple-300 break-all leading-6" dir="ltr" style="font-family:ui-monospace,Consolas,monospace">{sub_url_escaped}</p>
        </div>
        <button id="subCopyBtn" type="button" onclick="pxCopy('subLinkText','subCopyBtn')"
          class="copy-btn shrink-0 self-start sm:self-center inline-flex items-center gap-1.5 text-[11px] font-bold text-white/60 px-3.5 py-2 rounded-xl bg-white/[0.05] border border-white/10 hover:bg-white/[0.1] hover:text-white transition-colors duration-200">
          <svg xmlns="http://www.w3.org/2000/svg" width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.3" stroke-linecap="round" stroke-linejoin="round"><rect x="9" y="9" width="12" height="12" rx="2"/><path d="M5 15V5a2 2 0 0 1 2-2h10"/></svg>
          <span>کپی</span>
        </button>
      </div>
    </div>
  </section>

  <!-- Downloads -->
  <section class="rounded-[22px] border dynamic-card backdrop-blur-2xl p-5 sm:p-6 md:p-7">
    <div class="flex items-center justify-between gap-3 mb-5">
      <p class="flex items-center gap-2 text-sm font-black">
        <svg xmlns="http://www.w3.org/2000/svg" width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round" class="text-white/40"><path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/><path d="M7 10l5 5 5-5"/><path d="M12 15V3"/></svg>
        دانلود برنامه‌ها
      </p>
      <p class="text-[11px] text-white/40">Official Releases</p>
    </div>

    <div class="grid grid-cols-1 sm:grid-cols-3 gap-3.5">
      <a href="https://github.com/2dust/v2rayNG/releases/latest" target="_blank" rel="noopener noreferrer"
         class="flex items-center gap-3 rounded-2xl border border-white/10 sub-box p-4 hover:border-blue-400/25 transition-colors duration-200">
        <div class="w-10 h-10 shrink-0 rounded-xl grid place-items-center bg-blue-400/10 border border-blue-400/20 text-blue-300 font-black text-[11px]">NG</div>
        <div class="min-w-0">
          <p class="text-xs font-extrabold">v2rayNG</p>
          <p class="mt-0.5 text-[10px] text-white/40">Android</p>
        </div>
      </a>
      <a href="https://github.com/2dust/v2rayN/releases/latest" target="_blank" rel="noopener noreferrer"
         class="flex items-center gap-3 rounded-2xl border border-white/10 sub-box p-4 hover:border-blue-400/25 transition-colors duration-200">
        <div class="w-10 h-10 shrink-0 rounded-xl grid place-items-center bg-blue-400/10 border border-blue-400/20 text-blue-300 font-black text-[11px]">N</div>
        <div class="min-w-0">
          <p class="text-xs font-extrabold">v2rayN</p>
          <p class="mt-0.5 text-[10px] text-white/40">Windows / macOS / Linux</p>
        </div>
      </a>
      <a href="https://github.com/hiddify/hiddify-app/releases/latest" target="_blank" rel="noopener noreferrer"
         class="flex items-center gap-3 rounded-2xl border border-white/10 sub-box p-4 hover:border-blue-400/25 transition-colors duration-200">
        <div class="w-10 h-10 shrink-0 rounded-xl grid place-items-center bg-blue-400/10 border border-blue-400/20 text-blue-300 font-black text-[11px]">H</div>
        <div class="min-w-0">
          <p class="text-xs font-extrabold">Hiddify</p>
          <p class="mt-0.5 text-[10px] text-white/40">Android / Windows / macOS / Linux</p>
        </div>
      </a>
    </div>
  </section>

  <!-- Footer -->
  <div class="rounded-2xl border border-emerald-400/15 bg-emerald-400/[0.05] p-4 text-center text-xs text-white/45">
    پشتیبانی و اطلاعیه‌ها &nbsp;·&nbsp; <b class="text-emerald-300">کانال تلگرام: logic_sec</b>
  </div>

</div>

<!-- QR Code Modal Popup -->
<div id="qrModal" class="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/80 backdrop-blur-md hidden">
  <div class="w-full max-w-sm rounded-[24px] border border-white/15 bg-[#0b0c14] p-6 text-center shadow-2xl relative">
    <button type="button" onclick="closeQrModal()" class="absolute top-4 left-4 w-8 h-8 rounded-full bg-white/5 border border-white/10 grid place-items-center text-white/60 hover:text-white">✕</button>
    <p class="text-sm font-black text-white/90 mb-2">QR Code اسکن کانفیگ</p>
    <p class="text-[11px] text-white/40 mb-4">برای اتصال سریع با گوشی موبایل</p>
    <div id="qrcodeContainer" class="bg-white p-4 rounded-2xl inline-block mx-auto mb-4 border border-white/10"></div>
    <p id="qrModalText" class="text-[10px] text-purple-300 break-all max-h-16 overflow-y-auto px-2" dir="ltr"></p>
  </div>
</div>

<script>
const vlessUrlData = "{vless_url}";

// Theme toggle logic with localStorage support (2 themes total)
function toggleTheme() {{
  const body = document.body;
  body.classList.toggle('theme-lighter');
  const isLighter = body.classList.contains('theme-lighter');
  localStorage.setItem('px_theme', isLighter ? 'lighter' : 'dark');
}}

// Initialize saved theme on load
(function() {{
  if (localStorage.getItem('px_theme') === 'lighter') {{
    document.body.classList.add('theme-lighter');
  }}
}})();

function openQrModal() {{
  var modal = document.getElementById('qrModal');
  var container = document.getElementById('qrcodeContainer');
  var txtEl = document.getElementById('qrModalText');
  container.innerHTML = "";
  txtEl.textContent = vlessUrlData;
  modal.classList.remove('hidden');
  try {{
    var typeNumber = 0;
    var errorCorrectionLevel = 'L';
    var qr = qrcode(typeNumber, errorCorrectionLevel);
    qr.addData(vlessUrlData);
    qr.make();
    container.innerHTML = qr.createImgTag(5, 8);
  }} catch (e) {{
    container.innerHTML = "<p class='text-xs text-black'>خطا در تولید QR Code</p>";
  }}
}}

function closeQrModal() {{
  document.getElementById('qrModal').classList.add('hidden');
}}

document.getElementById('qrModal').addEventListener('click', function(e) {{
  if (e.target === this) closeQrModal();
}});

function pxCopy(textId, btnId) {{
  var el = document.getElementById(textId);
  var btn = document.getElementById(btnId);
  if (!el || !btn) return;
  var text = el.textContent.textContext || el.textContent.trim();
  var done = function() {{
    var original = btn.getAttribute('data-original');
    if (!original) {{
      original = btn.innerHTML;
      btn.setAttribute('data-original', original);
    }}
    btn.innerHTML = '<svg xmlns="http://www.w3.org/2000/svg" width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.6" stroke-linecap="round" stroke-linejoin="round"><path d="M20 6L9 17l-5-5"/></svg><span>کپی شد</span>';
    btn.classList.add('text-emerald-300','border-emerald-400/30','bg-emerald-400/10');
    setTimeout(function() {{
      btn.innerHTML = original;
      btn.classList.remove('text-emerald-300','border-emerald-400/30','bg-emerald-400/10');
    }}, 1700);
  }};
  if (navigator.clipboard && navigator.clipboard.writeText) {{
    navigator.clipboard.writeText(text).then(done).catch(function() {{ fallbackCopy(text, done); }});
  }} else {{
    fallbackCopy(text, done);
  }}
}}
function fallbackCopy(text, cb) {{
  var ta = document.createElement('textarea');
  ta.value = text;
  ta.style.position = 'fixed';
  ta.style.opacity = '0';
  document.body.appendChild(ta);
  ta.select();
  try {{ document.execCommand('copy'); }} catch (e) {{}}
  document.body.removeChild(ta);
  if (cb) cb();
}}
</script>
</body>
</html>"""
    return HTMLResponse(info_html)
# ============================================================
# SUB GROUP API
# ============================================================

@app.post("/api/subs")
async def create_sub_api(
    request: Request,
    _=Depends(require_auth),
):

    try:
        body = await request.json()
    except Exception:
        raise HTTPException(
            status_code=400,
            detail="JSON نامعتبر است",
        )

    sub_id, sub = await create_sub_group(
        name=body.get(
            "name",
            "گروه جدید",
        ),
        desc=body.get(
            "desc",
            "",
        ),
        password=body.get(
            "password",
            "",
        ),
    )

    host = get_host(request)

    return {
        "sub_id":
            sub_id,

        **sub,

        "password_hash":
            None,

        "public_url":
            (
                f"https://{host}"
                f"/p/{sub['uuid_key']}"
            ),

        "sub_url":
            (
                f"https://{host}"
                f"/sub-group/{sub['uuid_key']}"
            ),
    }


@app.get("/api/subs")
async def list_subs_api(
    request: Request,
    _=Depends(require_auth),
):

    host = get_host(request)

    async with SUBS_LOCK:
        snapshot_subs = dict(SUBS)

    async with LINKS_LOCK:
        snapshot_links = dict(LINKS)

    result = []

    for sid, sub in snapshot_subs.items():

        link_ids = sub.get(
            "link_ids",
            [],
        )

        active_count = sum(
            1
            for lid in link_ids
            if is_link_allowed(
                snapshot_links.get(
                    lid
                )
            )
        )

        total_used = sum(
            snapshot_links[
                lid
            ].get(
                "used_bytes",
                0,
            )

            for lid in link_ids

            if lid in snapshot_links
        )

        result.append(
            {
                "sub_id":
                    sid,

                **sub,

                "password_hash":
                    None,

                "has_password":
                    sub.get(
                        "password_hash"
                    ) is not None,

                "links_count":
                    len(link_ids),

                "active_count":
                    active_count,

                "total_used_bytes":
                    total_used,

                "total_used_fmt":
                    fmt_bytes(
                        total_used
                    ),

                "public_url":
                    (
                        f"https://{host}"
                        f"/p/{sub['uuid_key']}"
                    ),

                "sub_url":
                    (
                        f"https://{host}"
                        f"/sub-group/{sub['uuid_key']}"
                    ),
            }
        )

    result.sort(
        key=lambda item:
            item.get(
                "created_at",
                "",
            ),
        reverse=True,
    )

    return {
        "subs": result
    }


@app.patch("/api/subs/{sub_id}")
async def update_sub_api(
    sub_id: str,
    request: Request,
    _=Depends(require_auth),
):

    try:
        body = await request.json()
    except Exception:
        raise HTTPException(
            status_code=400,
            detail="JSON نامعتبر است",
        )

    async with SUBS_LOCK:

        if sub_id not in SUBS:
            raise HTTPException(
                status_code=404,
                detail="sub not found",
            )

        sub = SUBS[sub_id]

        if "name" in body:
            sub["name"] = str(
                body["name"]
            )[:60]

        if "desc" in body:
            sub["desc"] = str(
                body["desc"]
            )[:200]

        if "password" in body:

            password = str(
                body.get(
                    "password",
                    "",
                )
            ).strip()

            sub["password_hash"] = (
                hash_password(password)
                if password
                else None
            )

        if "link_ids" in body:

            sub["link_ids"] = list(
                body["link_ids"]
            )

    await save_state()

    return {
        "ok": True
    }


@app.delete("/api/subs/{sub_id}")
async def delete_sub_api(
    sub_id: str,
    _=Depends(require_auth),
):

    name = await remove_sub_group(
        sub_id
    )

    if name is None:
        raise HTTPException(
            status_code=404,
            detail="sub not found",
        )

    return {
        "ok": True,
        "deleted": sub_id,
    }


@app.post("/api/subs/{sub_id}/links")
async def assign_link_to_sub(
    sub_id: str,
    request: Request,
    _=Depends(require_auth),
):

    try:
        body = await request.json()
    except Exception:
        raise HTTPException(
            status_code=400,
            detail="JSON نامعتبر است",
        )

    link_id = str(
        body.get(
            "link_id",
            "",
        )
    )

    action = str(
        body.get(
            "action",
            "add",
        )
    )

    if action == "add":

        success = await set_link_sub(
            link_id,
            sub_id,
        )

    else:

        success = await set_link_sub(
            link_id,
            None,
        )

    if not success:
        raise HTTPException(
            status_code=404,
            detail="link or sub not found",
        )

    return {
        "ok": True
    }


# ============================================================
# GROUP SUB
# ============================================================

@app.get("/sub-group/{uuid_key}")
async def sub_group_subscription(
    uuid_key: str,
    request: Request,
):

    async with SUBS_LOCK:

        sub = next(
            (
                item
                for item
                in SUBS.values()
                if item.get(
                    "uuid_key"
                ) == uuid_key
            ),
            None,
        )

    if not sub:
        raise HTTPException(
            status_code=404,
            detail="not found",
        )

    if sub.get(
        "password_hash"
    ):

        password = (
            request.query_params.get(
                "pw",
                "",
            )
        )

        if (
            hash_password(password)
            != sub["password_hash"]
        ):

            raise HTTPException(
                status_code=403,
                detail="wrong password",
            )

    host = get_host(request)

    async with LINKS_LOCK:

        lines = []

        for link_id in sub.get(
            "link_ids",
            [],
        ):

            link = LINKS.get(
                link_id
            )

            if (
                link
                and is_link_allowed(
                    link
                )
            ):

                lines.append(
                    vless_link_for_link(
                        link,
                        link_id,
                        host,
                    )
                )

    content = (
        base64
        .b64encode(
            "\n".join(
                lines
            ).encode()
        )
        .decode()
    )

    total_used = 0
    total_limit = 0
    expiries = []
    valid_ids = list(sub.get("link_ids", []))

    async with LINKS_LOCK:
        for link_id in valid_ids:
            link = LINKS.get(link_id)
            if not link or not is_link_allowed(link):
                continue
            total_used += int(link.get("used_bytes", 0) or 0)
            total_limit += int(link.get("limit_bytes", 0) or 0)
            if link.get("expires_at"):
                expiries.append(str(link.get("expires_at")))

    # For a group subscription, expose aggregate usage/expiry in standard headers.
    group_limit = total_limit if total_limit > 0 else 0
    group_expiry = None
    if expiries:
        try:
            group_expiry = min(
                expiries,
                key=lambda x: datetime.fromisoformat(x)
            )
        except Exception:
            group_expiry = expiries[0]

    group_volume_text = (
        f"{fmt_bytes(total_used)}/{fmt_bytes(group_limit)}"
        if group_limit > 0
        else f"{fmt_bytes(total_used)}/∞"
    )
    group_expiry_text = group_expiry or "∞"
    group_title = (
        f"0.0.0.0 | {group_volume_text} | {group_expiry_text} | "
        f"{sub['name']} | کانال تلگرام: logic_sec"
    )
    headers = subscription_metadata_headers(
        total_used,
        group_limit,
        group_expiry,
        host,
        f"https://{host}/public-sub/{uuid_key}",
        group_title,
    )

    return Response(
        content=content,
        media_type="text/plain; charset=utf-8",
        headers=headers,
    )


# ============================================================
# PUBLIC GROUP
# ============================================================

PUBLIC_SUB_HTML = Path("static/sub/index.html").read_text(encoding="utf-8") if Path("static/sub/index.html").exists() else ""



@app.get(
    "/p/{uuid_key}",
    response_class=HTMLResponse,
)
async def public_sub_page(
    uuid_key: str,
):

    async with SUBS_LOCK:

        exists = any(
            item.get(
                "uuid_key"
            ) == uuid_key
            for item in SUBS.values()
        )

    if not exists:

        return HTMLResponse(
            """
            <h2
            style="
            font-family:sans-serif;
            padding:40px;
            "
            >
            گروه پیدا نشد
            </h2>
            """,
            status_code=404,
        )

    return HTMLResponse(
        PUBLIC_SUB_HTML
    )


@app.get("/api/public/sub/{uuid_key}")
async def public_sub_data(
    uuid_key: str,
    request: Request,
):

    async with SUBS_LOCK:

        entry = next(
            (
                (
                    sid,
                    item,
                )

                for sid, item
                in SUBS.items()

                if item.get(
                    "uuid_key"
                ) == uuid_key
            ),
            None,
        )

    if not entry:
        raise HTTPException(
            status_code=404,
            detail="not found",
        )

    _, sub = entry

    has_password = (
        sub.get(
            "password_hash"
        ) is not None
    )

    if has_password:

        password = (
            request
            .query_params
            .get(
                "pw",
                "",
            )
        )

        if (
            hash_password(password)
            != sub[
                "password_hash"
            ]
        ):

            return JSONResponse(
                {
                    "locked": True,
                    "name":
                        sub["name"],
                }
            )

    host = get_host(request)

    async with LINKS_LOCK:
        snapshot = dict(LINKS)

    links_out = []

    active_connections = 0

    for link_id in sub.get(
        "link_ids",
        [],
    ):

        link = snapshot.get(
            link_id
        )

        if not link:
            continue

        allowed = is_link_allowed(
            link
        )

        connection_count = sum(
            1
            for item in connections.values()
            if item.get("uuid") == link_id
        )

        active_connections += (
            connection_count
        )

        links_out.append(
            {
                "uuid":
                    link_id,

                "label":
                    link.get(
                        "label"
                    ),

                "active":
                    allowed,

                "protocol":
                    link.get(
                        "protocol",
                        DEFAULT_PROTOCOL,
                    ),

                "used_bytes":
                    link.get(
                        "used_bytes",
                        0,
                    ),

                "used_fmt":
                    fmt_bytes(
                        link.get(
                            "used_bytes",
                            0,
                        )
                    ),

                "limit_bytes":
                    link.get(
                        "limit_bytes",
                        0,
                    ),

                "limit_fmt":
                    (
                        "∞"
                        if not link.get(
                            "limit_bytes",
                            0,
                        )
                        else fmt_bytes(
                            link[
                                "limit_bytes"
                            ]
                        )
                    ),

                "expires_at":
                    link.get(
                        "expires_at"
                    ),

                "vless_link":
                    vless_link_for_link(
                        link,
                        link_id,
                        host,
                    ),

                "sub_url":
                    (
                        f"https://{host}"
                        f"/sub/{link_id}"
                    ),

                "info_url":
                    (
                        f"https://{host}"
                        f"/info/{link_id}"
                    ),

                "connections":
                    connection_count,

                "ip_limit":
                    link.get(
                        "ip_limit",
                        0,
                    ),

                "speed_limit_bytes":
                    link.get(
                        "speed_limit_bytes",
                        0,
                    ),

                "connection_limit":
                    link.get(
                        "connection_limit",
                        0,
                    ),
            }
        )

    total_used = sum(
        item["used_bytes"]
        for item in links_out
    )

    return {
        "locked": False,

        "name":
            sub["name"],

        "desc":
            sub.get(
                "desc",
                "",
            ),

        "sub_url":
            (
                f"https://{host}"
                f"/sub-group/{uuid_key}"
            ),

        "active_connections":
            active_connections,

        "total_used_fmt":
            fmt_bytes(
                total_used
            ),

        "support":
            SUPPORT_USERNAME,

        "links":
            links_out,
    }




@app.post("/api/mix-sub")
async def mix_subscription(request: Request, _=Depends(require_auth)):
    try:
        body = await request.json()
    except Exception:
        raise HTTPException(status_code=400, detail="JSON نامعتبر")
    ids = body.get("link_ids") or []
    if not isinstance(ids, list) or len(ids) < 2:
        raise HTTPException(status_code=400, detail="حداقل ۲ کانفیگ انتخاب کنید")
    if len(ids) > 40:
        raise HTTPException(status_code=400, detail="حداکثر ۴۰ کانفیگ")
    host = get_host(request)
    lines = []
    used_names = set()
    total_used = 0
    total_limit = 0
    labels = []
    async with LINKS_LOCK:
        for lid in ids:
            link = LINKS.get(lid)
            if not link or not is_link_allowed(link):
                continue
            labels.append(str(link.get("label") or lid[:8]))
            total_used += int(link.get("used_bytes", 0) or 0)
            total_limit += int(link.get("limit_bytes", 0) or 0)
            name = random_config_name(used_names)
            used_names.add(name)
            lines.append(generate_vless_link(
                lid, host, remark=name,
                protocol=link.get("protocol", DEFAULT_PROTOCOL),
                fingerprint=link.get("fingerprint", DEFAULT_FINGERPRINT),
                alpn=link.get("alpn"),
                port=link.get("port", DEFAULT_PORT),
            ))
    if not lines:
        raise HTTPException(status_code=400, detail="هیچ کانفیگ معتبری انتخاب نشده")
    # stats first line
    vol = f"{fmt_bytes(total_used)}/{fmt_bytes(total_limit)}" if total_limit > 0 else f"{fmt_bytes(total_used)}/∞"
    mix_label = "Mix-" + random_config_name()[:6]
    stats = f"{mix_label} | {vol} | {len(lines)} configs"
    first = generate_vless_link(ids[0], "127.0.0.1", remark=stats, protocol="vless-ws")
    content = base64.b64encode(("\n".join([first] + lines)).encode()).decode()
    # store as a sub group for reuse
    sub_id, sub = await create_sub_group(name=mix_label, desc="مخلوط‌سازی کانفیگ‌ها")
    async with SUBS_LOCK:
        if sub_id in SUBS:
            SUBS[sub_id]["link_ids"] = list(ids)
    await save_state()
    return {
        "ok": True,
        "sub_url": f"https://{host}/sub-group/{sub['uuid_key']}",
        "name": mix_label,
        "count": len(lines),
        "content_preview": stats,
    }


@app.get("/api/categories")
async def list_categories(_=Depends(require_auth)):
    items = [{**cat, "id": cid} for cid, cat in CATEGORIES.items()]
    items.sort(key=lambda x: int(x.get("number", 0)))
    return {"categories": items}

@app.post("/api/categories")
async def create_category(request: Request, _=Depends(require_auth)):
    if len(CATEGORIES) >= 50:
        raise HTTPException(status_code=400, detail="حداکثر ۵۰ گروه")
    try:
        body = await request.json()
    except Exception:
        raise HTTPException(status_code=400, detail="JSON نامعتبر")
    name = str(body.get("name") or "دسته جدید").strip()[:40]
    used = {int(x.get("number", 0)) for x in CATEGORIES.values()}
    num = 0
    while num in used:
        num += 1
    cid = str(num)
    limit_value = safe_float(body.get("limit_value", 0))
    limit_unit = str(body.get("limit_unit") or "GB").upper()
    limit_bytes = 0 if limit_value <= 0 else parse_size_to_bytes(limit_value, limit_unit)
    speed_value = safe_float(body.get("speed_limit_value", 0))
    speed_bytes = 0 if speed_value <= 0 else parse_speed_to_bytes(speed_value, "MBIT")
    raw_clean = body.get("clean_ips") or ""
    if isinstance(raw_clean, list):
        clean_ips = [str(x).strip() for x in raw_clean if str(x).strip()]
    else:
        clean_ips = [x.strip() for x in str(raw_clean).replace(",", "\n").splitlines() if x.strip()]
    record = {
        "id": cid, "name": name, "number": num,
        "limit_bytes": limit_bytes,
        "expires_days": safe_int(body.get("expires_days", 0), minimum=0),
        "connection_limit": safe_int(body.get("connection_limit", 0), minimum=0),
        "speed_limit_bytes": speed_bytes,
        "ip_limit": safe_int(body.get("ip_limit", 0), minimum=0),
        "clean_ips": clean_ips,
        "random_name": bool(body.get("random_name", False)),
        "single_user": bool(body.get("single_user", False)),
        "created_at": datetime.now().isoformat(),
    }
    CATEGORIES[cid] = record
    await save_state()
    return {"ok": True, **record}


@app.patch("/api/categories/{cid}")
async def update_category(cid: str, request: Request, _=Depends(require_auth)):
    if cid not in CATEGORIES:
        raise HTTPException(status_code=404, detail="یافت نشد")
    try:
        body = await request.json()
    except Exception:
        raise HTTPException(status_code=400, detail="JSON نامعتبر")
    cat = CATEGORIES[cid]
    if "name" in body:
        cat["name"] = str(body.get("name") or cat["name"]).strip()[:40]
    if "limit_value" in body:
        lv = safe_float(body.get("limit_value", 0))
        unit = str(body.get("limit_unit") or "GB").upper()
        cat["limit_bytes"] = 0 if lv <= 0 else parse_size_to_bytes(lv, unit)
    if "expires_days" in body:
        cat["expires_days"] = safe_int(body.get("expires_days", 0), minimum=0)
    if "connection_limit" in body:
        cat["connection_limit"] = safe_int(body.get("connection_limit", 0), minimum=0)
    if "speed_limit_value" in body:
        sv = safe_float(body.get("speed_limit_value", 0))
        cat["speed_limit_bytes"] = 0 if sv <= 0 else parse_speed_to_bytes(sv, "MBIT")
    if "ip_limit" in body:
        cat["ip_limit"] = safe_int(body.get("ip_limit", 0), minimum=0)
    if "clean_ips" in body:
        raw = body.get("clean_ips") or ""
        if isinstance(raw, list):
            cat["clean_ips"] = [str(x).strip() for x in raw if str(x).strip()]
        else:
            cat["clean_ips"] = [x.strip() for x in str(raw).replace(",", "\n").splitlines() if x.strip()]
    if "random_name" in body:
        cat["random_name"] = bool(body.get("random_name"))
    if "single_user" in body:
        cat["single_user"] = bool(body.get("single_user"))
    await save_state()
    return {"ok": True, **cat}

@app.delete("/api/categories/{cid}")
async def delete_category(cid: str, _=Depends(require_auth)):
    if cid not in CATEGORIES:
        raise HTTPException(status_code=404, detail="یافت نشد")
    del CATEGORIES[cid]
    for link in LINKS.values():
        if str(link.get("category_id")) == cid:
            link["category_id"] = "0"
    await save_state()
    return {"ok": True}

# ============================================================
# STATS
# ============================================================

@app.get("/stats")
async def get_stats(
    _=Depends(require_auth),
):

    async with LINKS_LOCK:
        snapshot = dict(LINKS)

    return {
        "service":
            APP_NAME,

        "version":
            APP_VERSION,

        "active_connections":
            len(connections),

        "total_traffic_mb":
            round(
                stats[
                    "total_bytes"
                ]
                / (
                    1024 ** 2
                ),
                2,
            ),

        "total_traffic_bytes":
            stats[
                "total_bytes"
            ],

        "total_requests":
            stats[
                "total_requests"
            ],

        "total_errors":
            stats[
                "total_errors"
            ],

        "uptime":
            uptime(),

        "timestamp":
            datetime.now().isoformat(),

        "hourly":
            dict(
                hourly_traffic
            ),

        "recent_errors":
            list(
                error_logs
            )[-10:],

        "links_count":
            len(snapshot),

        "active_links":
            sum(
                1
                for link
                in snapshot.values()
                if is_link_allowed(
                    link
                )
            ),

        "expired_links":
            sum(
                1
                for link
                in snapshot.values()
                if is_link_expired(
                    link
                )
            ),

        "subs_count":
            len(SUBS),
    }


@app.get("/api/activity")
async def get_activity(
    _=Depends(require_auth),
):

    return {
        "logs":
            list(
                activity_logs
            )[-150:]
    }


# ============================================================
# CONNECTIONS
# ============================================================

@app.get("/api/connections")
async def get_connections(
    _=Depends(require_auth),
):

    async with LINKS_LOCK:
        snapshot = dict(LINKS)

    grouped = {}

    for connection in connections.values():

        ip = connection.get(
            "ip",
            "نامشخص",
        )

        link = snapshot.get(
            connection.get(
                "uuid"
            )
        )

        label = (
            link.get(
                "label"
            )
            if link
            else "نامشخص"
        )

        group = grouped.get(ip)

        if group is None:

            group = {
                "ip":
                    ip,

                "sessions":
                    0,

                "bytes":
                    0,

                "labels":
                    set(),

                "transports":
                    set(),

                "first_connected_at":
                    connection.get(
                        "connected_at"
                    ),

                "last_connected_at":
                    connection.get(
                        "connected_at"
                    ),
            }

            grouped[ip] = group

        group["sessions"] += 1

        group["bytes"] += int(
            connection.get(
                "bytes",
                0,
            )
            or 0
        )

        group["labels"].add(
            label
        )

        group["transports"].add(
            connection.get(
                "transport",
                DEFAULT_PROTOCOL,
            )
        )

    result = []

    for group in grouped.values():

        result.append(
            {
                "ip":
                    group["ip"],

                "sessions":
                    group["sessions"],

                "labels":
                    sorted(
                        group["labels"]
                    ),

                "label":
                    (
                        " · ".join(
                            sorted(
                                group["labels"]
                            )
                        )
                        if group["labels"]
                        else "نامشخص"
                    ),

                "transports":
                    sorted(
                        group["transports"]
                    ),

                "bytes":
                    group["bytes"],

                "bytes_fmt":
                    fmt_bytes(
                        group["bytes"]
                    ),

                "connected_at":
                    group[
                        "first_connected_at"
                    ],

                "last_connected_at":
                    group[
                        "last_connected_at"
                    ],
            }
        )

    result.sort(
        key=lambda item:
            item.get(
                "last_connected_at"
            )
            or "",
        reverse=True,
    )

    return {
        "connections":
            result,

        "count":
            len(result),

        "raw_count":
            len(connections),
    }


# ============================================================
# OPTIONAL EXISTING PROJECT MODULES
# ============================================================

# ============================================================
# IMPORTANT:
# DO NOT REPLACE THIS VLESS CORE.
# ============================================================

try:

    from relay_vless import (
        RELAY_BUF,
        parse_vless_header,
        check_and_use,
        relay_ws_to_tcp,
        relay_tcp_to_ws,
        websocket_tunnel,
    )

    app.add_api_websocket_route(
        "/ws/{uuid}",
        websocket_tunnel,
    )

    logger.info(
        "VLESS relay loaded."
    )

except Exception as exc:

    logger.warning(
        "VLESS relay module unavailable: %s",
        exc,
    )


# ============================================================
# XHTTP
# ============================================================

try:

    from xhttp_siz10 import (
        router as xhttp_router
    )

    app.include_router(
        xhttp_router
    )

    logger.info(
        "XHTTP module loaded."
    )

except Exception as exc:

    logger.warning(
        "XHTTP module unavailable: %s",
        exc,
    )



# ============================================================

@app.get("/api/me")
async def api_me_info(request: Request, token=Depends(require_auth)):
    meta = get_session_meta(token)
    return {
        "ok": True,
        "role": meta.get("role"),
        "username": meta.get("username"),
        "permissions": meta.get("permissions") or {p: True for p in ALL_PERMS},
        "uptime": uptime(),
    }


@app.get("/api/admins")
async def api_admins_list(token=Depends(require_perm("admins"))):
    meta = get_session_meta(token)
    if meta.get("role") != "owner":
        raise HTTPException(403, detail="فقط مالک پنل")
    out = []
    for aid, a in ADMIN_ACCOUNTS.items():
        out.append({
            "id": aid,
            "username": a.get("username"),
            "label": a.get("label"),
            "limit_bytes": int(a.get("limit_bytes") or 0),
            "used_bytes": int(a.get("used_bytes") or 0),
            "expires_at": a.get("expires_at"),
            "active": bool(a.get("active", True)),
            "blocked": bool(a.get("blocked")),
            "permissions": a.get("permissions") or {},
            "created_at": a.get("created_at"),
            "valid": admin_is_valid(a),
        })
    out.sort(key=lambda x: x.get("created_at") or "", reverse=True)
    return {"admins": out}


@app.post("/api/admins")
async def api_admins_create(request: Request, token=Depends(require_perm("admins"))):
    meta = get_session_meta(token)
    if meta.get("role") != "owner":
        raise HTTPException(403, detail="فقط مالک پنل")
    try:
        body = await request.json()
    except Exception:
        raise HTTPException(400, detail="JSON نامعتبر")
    username = str(body.get("username") or "").strip().lower()
    password = str(body.get("password") or "")
    repeat = str(body.get("repeat_password") or body.get("confirm") or "")
    if not username or len(username) < 3:
        raise HTTPException(400, detail="نام کاربری حداقل ۳ کاراکتر")
    if not username.isalnum():
        raise HTTPException(400, detail="نام کاربری فقط حروف و عدد انگلیسی")
    if username in ("owner", "admin", "root"):
        raise HTTPException(400, detail="این نام کاربری رزرو شده است")
    if find_admin_by_username(username)[0]:
        raise HTTPException(400, detail="نام کاربری تکراری است")
    if len(password) < 6:
        raise HTTPException(400, detail="رمز حداقل ۶ کاراکتر")
    if password != repeat:
        raise HTTPException(400, detail="تکرار رمز یکسان نیست")
    limit_value = safe_float(body.get("limit_value", 0))
    limit_unit = str(body.get("limit_unit") or "GB").upper()
    limit_bytes = 0 if limit_value <= 0 else parse_size_to_bytes(limit_value, limit_unit)
    days = safe_int(body.get("expires_days", 0), minimum=0)
    expires_at = (datetime.now() + timedelta(days=days)).isoformat() if days > 0 else None
    perms_in = body.get("permissions") or {}
    permissions = {p: bool(perms_in.get(p, False)) for p in ALL_PERMS}
    rec = default_admin_record(username, password, limit_bytes=limit_bytes, expires_at=expires_at, permissions=permissions, label=body.get("label") or username)
    ADMIN_ACCOUNTS[rec["id"]] = rec
    await save_state()
    log_activity("admin", f"اکانت ادمین «{username}» ساخته شد", "ok")
    return {"ok": True, "id": rec["id"], "username": username}


@app.patch("/api/admins/{aid}")
async def api_admins_patch(aid: str, request: Request, token=Depends(require_perm("admins"))):
    meta = get_session_meta(token)
    if meta.get("role") != "owner":
        raise HTTPException(403, detail="فقط مالک پنل")
    if aid not in ADMIN_ACCOUNTS:
        raise HTTPException(404, detail="یافت نشد")
    body = await request.json()
    a = ADMIN_ACCOUNTS[aid]
    if "blocked" in body:
        a["blocked"] = bool(body["blocked"])
    if "active" in body:
        a["active"] = bool(body["active"])
    if "label" in body:
        a["label"] = str(body["label"])[:40]
    if "permissions" in body and isinstance(body["permissions"], dict):
        a["permissions"] = {p: bool(body["permissions"].get(p, False)) for p in ALL_PERMS}
    if "limit_value" in body:
        lv = safe_float(body.get("limit_value", 0))
        lu = str(body.get("limit_unit") or "GB").upper()
        a["limit_bytes"] = 0 if lv <= 0 else parse_size_to_bytes(lv, lu)
    if "expires_days" in body:
        days = safe_int(body.get("expires_days", 0), minimum=0)
        a["expires_at"] = (datetime.now() + timedelta(days=days)).isoformat() if days > 0 else None
    if body.get("password"):
        pw = str(body["password"])
        if len(pw) < 6:
            raise HTTPException(400, detail="رمز حداقل ۶ کاراکتر")
        a["password_hash"] = hash_password(pw)
    await save_state()
    log_activity("admin", f"اکانت ادمین «{a.get('username')}» ویرایش شد", "ok")
    return {"ok": True}


@app.delete("/api/admins/{aid}")
async def api_admins_delete(aid: str, token=Depends(require_perm("admins"))):
    meta = get_session_meta(token)
    if meta.get("role") != "owner":
        raise HTTPException(403, detail="فقط مالک پنل")
    a = ADMIN_ACCOUNTS.pop(aid, None)
    if not a:
        raise HTTPException(404, detail="یافت نشد")
    await save_state()
    log_activity("admin", f"اکانت ادمین «{a.get('username')}» حذف شد", "warn")
    return {"ok": True}


NEWS_FILE = Path(__file__).resolve().parent / "news.json"


@app.get("/api/news")
async def api_news(token=Depends(require_auth)):
    try:
        if NEWS_FILE.exists():
            data = json.loads(NEWS_FILE.read_text(encoding="utf-8"))
        else:
            data = {"enabled": False, "title": "", "message": "", "updated_at": ""}
        return {"ok": True, **data}
    except Exception as e:
        return {"ok": False, "enabled": False, "title": "", "message": str(e), "updated_at": ""}




# ============================================================
# BACKUP / RESTORE
# ============================================================


@app.get("/api/security/status")
async def security_status(token=Depends(require_auth)):
    meta = get_session_meta(token)
    if meta.get("role") != "owner":
        raise HTTPException(403, detail="فقط مالک")
    now = time.time()
    locked = []
    for ip, until in list(LOGIN_LOCKED_UNTIL.items()):
        if until > now:
            locked.append({"ip": ip, "remaining_sec": int(until - now)})
    return {
        "ok": True,
        "max_attempts": LOGIN_MAX_ATTEMPTS,
        "window_seconds": LOGIN_WINDOW_SECONDS,
        "lockout_seconds": LOGIN_LOCKOUT_SECONDS,
        "locked_ips": locked,
        "tracked_ips": len(LOGIN_FAILURES),
    }


@app.post("/api/security/unlock")
async def security_unlock(request: Request, token=Depends(require_auth)):
    meta = get_session_meta(token)
    if meta.get("role") != "owner":
        raise HTTPException(403, detail="فقط مالک")
    try:
        body = await request.json()
    except Exception:
        body = {}
    ip = str((body or {}).get("ip") or "").strip()
    if ip:
        LOGIN_FAILURES.pop(ip, None)
        LOGIN_LOCKED_UNTIL.pop(ip, None)
    else:
        LOGIN_FAILURES.clear()
        LOGIN_LOCKED_UNTIL.clear()
    log_activity("auth", f"رفع مسدودی brute-force ({ip or 'all'})", "ok")
    return {"ok": True}


@app.get("/api/backup/users")
async def backup_users(token=Depends(require_auth)):
    meta = get_session_meta(token)
    # owner always; admin needs settings perm
    if meta.get("role") != "owner":
        if not (meta.get("permissions") or {}).get("settings"):
            raise HTTPException(403, detail="دسترسی ندارید")
    payload = {
        "type": "pxpanel_users_backup",
        "version": APP_VERSION,
        "created_at": datetime.now().isoformat(),
        "links": dict(LINKS),
        "subs": dict(SUBS),
        "categories": dict(CATEGORIES),
        "admin_accounts": dict(ADMIN_ACCOUNTS),
    }
    body = json.dumps(payload, ensure_ascii=False, indent=2)
    return Response(
        content=body,
        media_type="application/json",
        headers={
            "Content-Disposition": f'attachment; filename="pxpanel-users-{datetime.now().strftime("%Y%m%d-%H%M%S")}.json"'
        },
    )


@app.get("/api/backup/bot")
async def backup_bot(token=Depends(require_auth)):
    meta = get_session_meta(token)
    if meta.get("role") != "owner":
        if not (meta.get("permissions") or {}).get("settings"):
            raise HTTPException(403, detail="دسترسی ندارید")
    data = {}
    try:
        if TG_FILE.exists():
            data = json.loads(TG_FILE.read_text(encoding="utf-8"))
    except Exception:
        data = {}
    payload = {
        "type": "pxpanel_bot_backup",
        "version": APP_VERSION,
        "created_at": datetime.now().isoformat(),
        "telegram": data,
    }
    body = json.dumps(payload, ensure_ascii=False, indent=2)
    return Response(
        content=body,
        media_type="application/json",
        headers={
            "Content-Disposition": f'attachment; filename="pxpanel-bot-{datetime.now().strftime("%Y%m%d-%H%M%S")}.json"'
        },
    )


@app.post("/api/restore/users")
async def restore_users(request: Request, token=Depends(require_auth)):
    meta = get_session_meta(token)
    if meta.get("role") != "owner":
        raise HTTPException(403, detail="فقط مالک پنل")
    try:
        body = await request.json()
    except Exception:
        raise HTTPException(400, detail="فایل JSON نامعتبر")
    if not isinstance(body, dict):
        raise HTTPException(400, detail="فرمت نامعتبر")
    # accept either wrapper or raw state
    links = body.get("links")
    if links is None and body.get("type") == "pxpanel_users_backup":
        raise HTTPException(400, detail="لینک‌ها در بک‌آپ نیست")
    if links is None:
        raise HTTPException(400, detail="فایل بک‌آپ کاربران نیست")
    if not isinstance(links, dict):
        raise HTTPException(400, detail="links نامعتبر")
    mode = str(body.get("mode") or "merge").lower()  # merge | replace
    async with LINKS_LOCK:
        if mode == "replace":
            LINKS.clear()
            SUBS.clear()
            CATEGORIES.clear()
            ADMIN_ACCOUNTS.clear()
        LINKS.update(links)
        if isinstance(body.get("subs"), dict):
            SUBS.update(body["subs"])
        if isinstance(body.get("categories"), dict):
            CATEGORIES.update(body["categories"])
        if isinstance(body.get("admin_accounts"), dict):
            ADMIN_ACCOUNTS.update(body["admin_accounts"])
        for uid, link in list(LINKS.items()):
            if not isinstance(link, dict):
                LINKS.pop(uid, None)
                continue
            link.setdefault("protocol", DEFAULT_PROTOCOL)
            link.setdefault("fingerprint", DEFAULT_FINGERPRINT)
            link.setdefault("used_bytes", 0)
            link.setdefault("active", True)
            link.setdefault("config_count", 1)
    await save_state()
    log_activity("backup", f"بازیابی کاربران ({mode}) — {len(links)} کانفیگ", "ok")
    return {"ok": True, "links": len(LINKS), "subs": len(SUBS), "mode": mode}


@app.post("/api/restore/bot")
async def restore_bot(request: Request, token=Depends(require_auth)):
    meta = get_session_meta(token)
    if meta.get("role") != "owner":
        raise HTTPException(403, detail="فقط مالک پنل")
    try:
        body = await request.json()
    except Exception:
        raise HTTPException(400, detail="فایل JSON نامعتبر")
    tg = body.get("telegram") if isinstance(body, dict) else None
    if tg is None and isinstance(body, dict) and (body.get("token") or body.get("admin_ids") is not None):
        tg = body
    if not isinstance(tg, dict):
        raise HTTPException(400, detail="فایل بک‌آپ ربات نیست")
    # merge with existing
    current = {}
    try:
        if TG_FILE.exists():
            current = json.loads(TG_FILE.read_text(encoding="utf-8"))
    except Exception:
        current = {}
    current.update({k: v for k, v in tg.items() if v is not None})
    TG_FILE.parent.mkdir(parents=True, exist_ok=True)
    TG_FILE.write_text(json.dumps(current, ensure_ascii=False, indent=2), encoding="utf-8")
    # try activate
    try:
        from telegram_bot import configure_bot, start_bot, stop_bot, setup_webhook
        await stop_bot()
        configure_bot(current.get("token") or "", current.get("admin_ids") or "")
        host = get_host(request)
        if current.get("webhook") and host and host != "localhost":
            wh = f"https://{host}/telegram/webhook"
            await setup_webhook(wh)
            await start_bot(mode="webhook")
        else:
            await setup_webhook("")
            await start_bot(mode="polling")
    except Exception as exc:
        logger.warning("restore bot activate: %s", exc)
        log_activity("backup", f"بک‌آپ ربات ذخیره شد (فعال‌سازی: {exc})", "warn")
        return {"ok": True, "warning": str(exc)}
    log_activity("backup", "بازیابی تنظیمات ربات انجام شد", "ok")
    return {"ok": True, "message": "ربات بازیابی و فعال شد"}



# TELEGRAM SETTINGS API
# ============================================================

def load_tg_settings():
    try:
        if TG_FILE.exists():
            return json.loads(TG_FILE.read_text(encoding="utf-8"))
    except Exception:
        pass
    return {
        "token": os.environ.get("TELEGRAM_BOT_TOKEN", "").strip(),
        "admin_ids": os.environ.get("TELEGRAM_ADMIN_IDS", "").strip(),
        "webhook": False,
        "enabled": False,
    }


def save_tg_settings(data: dict):
    TG_FILE.parent.mkdir(parents=True, exist_ok=True)
    TG_FILE.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")




# ============================================================
# USER TELEGRAM BOTS (multi-tenant bot connect)
# ============================================================

@app.get("/api/telegram/user-bots")
async def api_user_bots_list(token=Depends(require_auth)):
    bots = []
    for bid, b in (USER_BOTS or {}).items():
        tok = str(b.get("token") or "")
        masked = (tok[:8] + "…" + tok[-4:]) if len(tok) > 12 else "***"
        bots.append({
            "id": bid,
            "label": b.get("label") or "",
            "token_masked": masked,
            "admin_ids": b.get("admin_ids") or "",
            "protocol": b.get("protocol") or DEFAULT_PROTOCOL,
            "active": bool(b.get("active", True)),
            "created_at": b.get("created_at"),
        })
    return {"bots": bots}


@app.post("/api/telegram/user-bots")
async def api_user_bots_add(request: Request, token=Depends(require_auth)):
    try:
        body = await request.json()
    except Exception:
        raise HTTPException(status_code=400, detail="JSON نامعتبر")
    tok = str(body.get("token") or "").strip()
    admin_ids = str(body.get("admin_ids") or "").strip()
    label = str(body.get("label") or "user-bot").strip() or "user-bot"
    protocol = normalize_protocol(body.get("protocol"))
    if not tok or ":" not in tok:
        raise HTTPException(status_code=400, detail="توکن ربات نامعتبر است")
    if not admin_ids:
        raise HTTPException(status_code=400, detail="آیدی ادمین لازم است")
    bid = secrets.token_hex(6)
    USER_BOTS[bid] = {
        "id": bid,
        "label": label,
        "token": tok,
        "admin_ids": admin_ids,
        "protocol": protocol,
        "active": True,
        "created_at": datetime.now().isoformat(),
    }
    try:
        await save_state()
    except Exception:
        pass
    # best-effort: notify telegram module if available
    try:
        from telegram_bot import register_user_bot
        await register_user_bot(USER_BOTS[bid])
    except Exception:
        pass
    log_activity("telegram", f"ربات کاربر ثبت شد: {label}", "ok")
    return {"ok": True, "id": bid, "message": "ربات کاربر ثبت و آماده اتصال شد"}


@app.delete("/api/telegram/user-bots/{bid}")
async def api_user_bots_del(bid: str, token=Depends(require_auth)):
    if bid not in USER_BOTS:
        raise HTTPException(status_code=404, detail="ربات پیدا نشد")
    USER_BOTS.pop(bid, None)
    try:
        await save_state()
    except Exception:
        pass
    try:
        from telegram_bot import unregister_user_bot
        await unregister_user_bot(bid)
    except Exception:
        pass
    return {"ok": True}


@app.get("/api/telegram/settings")
async def api_tg_get(_=Depends(require_auth)):
    s = load_tg_settings()
    token = s.get("token") or ""
    masked = (token[:8] + "…" + token[-4:]) if len(token) > 14 else ("••••" if token else "")
    return {
        "token_masked": masked,
        "has_token": bool(token),
        "admin_ids": s.get("admin_ids") or "",
        "webhook": bool(s.get("webhook")),
        "enabled": bool(s.get("enabled")),
    }


@app.post("/api/telegram/settings")
async def api_tg_save(request: Request, _=Depends(require_auth)):
    try:
        body = await request.json()
    except Exception:
        raise HTTPException(400, detail="invalid json")
    s = load_tg_settings()
    token = str(body.get("token") or "").strip()
    admin_ids = str(body.get("admin_ids") or "").strip()
    use_webhook = bool(body.get("webhook", True))
    if token:
        s["token"] = token
    if admin_ids is not None:
        s["admin_ids"] = admin_ids
    s["webhook"] = use_webhook
    s["enabled"] = True
    save_tg_settings(s)
    # apply runtime
    try:
        from telegram_bot import configure_bot, start_bot, stop_bot, setup_webhook
        await stop_bot()
        configure_bot(s.get("token") or "", s.get("admin_ids") or "")
        host = get_host(request)
        if use_webhook and host and host != "localhost":
            wh = f"https://{host}/telegram/webhook"
            ok = await setup_webhook(wh)
            s["webhook_url"] = wh
            s["webhook_ok"] = bool(ok)
            save_tg_settings(s)
            await start_bot(mode="webhook")
        else:
            await setup_webhook("")  # delete webhook -> polling
            await start_bot(mode="polling")
        log_activity("telegram", "ربات تلگرام پیکربندی و فعال شد", "ok")
        return {"ok": True, "webhook": use_webhook, "message": "ربات فعال شد"}
    except Exception as exc:
        logger.warning("telegram activate error: %s", exc)
        return {"ok": True, "warning": str(exc), "message": "تنظیمات ذخیره شد"}


@app.post("/telegram/webhook")
async def telegram_webhook(request: Request):
    try:
        from telegram_bot import process_update
        data = await request.json()
        await process_update(data)
    except Exception as exc:
        logger.warning("webhook error: %s", exc)
    return {"ok": True}


# ============================================================
# TELEGRAM
# ============================================================

try:

    from telegram_bot import (
        start_bot as _tg_start_bot,
        stop_bot as _tg_stop_bot,
    )

except Exception:

    async def _tg_start_bot():
        return None

    async def _tg_stop_bot():
        return None


@app.on_event("startup")
async def start_optional_telegram():

    try:

        await _tg_start_bot()

        logger.info(
            "Telegram module initialized."
        )

    except Exception as exc:

        logger.warning(
            "Telegram bot disabled/error: %s",
            exc,
        )


# ============================================================
# HTTP PROXY
# ============================================================

_HOP = {
    "connection",
    "keep-alive",
    "proxy-authenticate",
    "proxy-authorization",
    "te",
    "trailers",
    "transfer-encoding",
    "upgrade",
    "content-encoding",
    "content-length",
}


@app.api_route(
    "/proxy/{target_url:path}",
    methods=[
        "GET",
        "POST",
        "PUT",
        "DELETE",
        "PATCH",
        "HEAD",
        "OPTIONS",
    ],
)
async def http_proxy(
    target_url: str,
    request: Request,
):

    if not target_url.startswith("http"):
        target_url = (
            "https://"
            + target_url
        )

    if http_client is None:
        raise HTTPException(
            status_code=503,
            detail="HTTP client not ready",
        )

    try:

        body = await request.body()

        headers = {
            key: value
            for key, value
            in request.headers.items()
            if (
                key.lower()
                not in _HOP
            )
            and (
                key.lower()
                != "host"
            )
        }

        response = await http_client.request(
            method=request.method,
            url=target_url,
            headers=headers,
            content=body,
        )

        stats["total_bytes"] += len(
            response.content
        )

        stats["total_requests"] += 1

        hourly_traffic[
            now_ir().strftime(
                "%H:00"
            )
        ] += len(
            response.content
        )

        output_headers = {
            key: value
            for key, value
            in response.headers.items()
            if key.lower() not in _HOP
        }

        return Response(
            content=response.content,
            status_code=response.status_code,
            headers=output_headers,
        )

    except Exception as exc:

        stats["total_errors"] += 1

        error_logs.append(
            {
                "error":
                    str(exc),

                "url":
                    target_url,

                "time":
                    datetime.now().isoformat(),
            }
        )

        logger.exception(
            "Proxy error: %s",
            target_url,
        )

        raise HTTPException(
            status_code=502,
            detail=(
                "Proxy error: "
                f"{exc}"
            ),
        )


# ============================================================
# DASHBOARD
# ============================================================

DASHBOARD_HTML = Path("static/dashboard/index.html").read_text(encoding="utf-8") if Path("static/dashboard/index.html").exists() else ""





@app.get(
    "/dashboard",
    response_class=HTMLResponse,
)
async def dashboard(
    request: Request,
):

    if not await is_valid_session(
        request.cookies.get(
            SESSION_COOKIE
        )
    ):
        return RedirectResponse(
            "/login"
        )

    await ensure_default_categories()
    await ensure_default_link()

    return HTMLResponse(
        DASHBOARD_HTML
    )


# ============================================================
# TEST
# ============================================================

@app.get(
    "/test-ws",
    response_class=HTMLResponse,
)
async def test_ws():

    return HTMLResponse(
        """
        <script>
        location.href='/dashboard'
        </script>
        """
    )


# ============================================================
# GLOBAL ERROR HANDLER
# ============================================================

@app.exception_handler(Exception)
async def global_exception_handler(
    request: Request,
    exc: Exception,
):

    stats[
        "total_errors"
    ] += 1

    error_logs.append(
        {
            "error":
                str(exc),

            "path":
                str(request.url),

            "method":
                request.method,

            "time":
                datetime.now().isoformat(),
        }
    )

    logger.exception(
        "Unhandled exception: %s %s",
        request.method,
        request.url,
    )

    # API requests
    if (
        request.url.path.startswith(
            "/api/"
        )
        or request.url.path == "/stats"
    ):

        return JSONResponse(
            {
                "ok": False,
                "error":
                    str(exc)
                or "internal server error",
            },
            status_code=500,
        )

    return HTMLResponse(
        """
        <html lang="fa" dir="rtl">
        <body style="
            background:#07070a;
            color:#fff;
            font-family:sans-serif;
            padding:40px;
        ">
            <h2>
            خطای داخلی PX Panel
            </h2>

            <p>
            لطفاً لاگ Railway را بررسی کنید.
            </p>
        </body>
        </html>
        """,
        status_code=500,
    )


# ============================================================
# MAIN
# ============================================================

if __name__ == "__main__":

    uvicorn.run(
        "main:app",
        host="0.0.0.0",
        port=PORT,
        log_level="info",
        workers=1,
    )
