# -*- coding: utf-8 -*-
"""
LEVEL UP - Professional Web Dashboard & Real-Time EXP Tracker
Includes a protected animated login and a separate admin access-code manager.
"""
import asyncio
import base64
import hashlib
import hmac
import json
import os
import secrets
import time
from typing import Dict, List, Any, Optional
from aiohttp import web


# -------------------- Runtime bot state --------------------
class BotState:
    def __init__(self):
        self.accounts: Dict[str, Dict[str, Any]] = {}
        self.logs: List[Dict[str, Any]] = []
        self.max_logs = 200
        self.total_matches = 0
        self.total_gained_exp = 0
        self.start_time = time.time()
        self.account_workers: Dict[str, asyncio.Task] = {}
        self.refresh_callbacks: Dict[str, Any] = {}
        self.account_credentials: Dict[str, Dict[str, Any]] = {}

    def log(self, message: str, level: str = "info", uid: Optional[str] = None):
        entry = {"time": time.strftime("%H:%M:%S"), "level": level, "message": message, "uid": uid}
        self.logs.append(entry)
        if len(self.logs) > self.max_logs:
            self.logs.pop(0)

    def register_account(self, uid: str, nickname: str, region: str, level: int, exp: int, likes: int = 0):
        uid_str = str(uid)
        if uid_str not in self.accounts:
            self.accounts[uid_str] = {
                "uid": uid_str,
                "nickname": nickname or f"Player_{uid_str[:6]}",
                "region": region or "BD",
                "level": level or 1,
                "initial_exp": exp,
                "current_exp": exp,
                "gained_exp": 0,
                "likes": likes or 0,
                "status": "ONLINE",
                "matches_played": 0,
                "active_matches": 0,
                "last_match_time": None,
                "last_updated": time.strftime("%H:%M:%S")
            }
        else:
            acc = self.accounts[uid_str]
            if nickname: acc["nickname"] = nickname
            if region: acc["region"] = region
            if level: acc["level"] = level
            acc["current_exp"] = exp
            acc["gained_exp"] = max(0, exp - acc["initial_exp"])
            acc["likes"] = likes
            acc["status"] = "ONLINE"
            acc["last_updated"] = time.strftime("%H:%M:%S")
        self.recalc_totals()

    def update_exp(self, uid: str, current_exp: int, level: Optional[int] = None):
        uid_str = str(uid)
        if uid_str in self.accounts:
            acc = self.accounts[uid_str]
            old_exp = acc["current_exp"]
            acc["current_exp"] = current_exp
            if level is not None and level > 0: acc["level"] = level
            acc["gained_exp"] = max(0, current_exp - acc["initial_exp"])
            acc["last_updated"] = time.strftime("%H:%M:%S")
            diff = current_exp - old_exp
            if diff > 0:
                self.log(f"Account {acc['nickname']} ({uid_str}) gained +{diff} EXP! Total Gained: +{acc['gained_exp']}", "success", uid_str)
            self.recalc_totals()

    def update_status(self, uid: str, status: str, active_matches: Optional[int] = None):
        uid_str = str(uid)
        if uid_str in self.accounts:
            self.accounts[uid_str]["status"] = status
            if active_matches is not None: self.accounts[uid_str]["active_matches"] = active_matches
            self.accounts[uid_str]["last_updated"] = time.strftime("%H:%M:%S")

    def increment_match(self, uid: str):
        uid_str = str(uid)
        self.total_matches += 1
        if uid_str in self.accounts:
            self.accounts[uid_str]["matches_played"] += 1
            self.accounts[uid_str]["last_match_time"] = time.strftime("%H:%M:%S")
            self.accounts[uid_str]["last_updated"] = time.strftime("%H:%M:%S")
            self.log(f"Account {self.accounts[uid_str]['nickname']} finished Match #{self.accounts[uid_str]['matches_played']}", "info", uid_str)

    def recalc_totals(self):
        self.total_gained_exp = sum(acc.get("gained_exp", 0) for acc in self.accounts.values())


bot_state = BotState()

# -------------------- Access-code storage --------------------
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
TEMPLATE_PATH = os.path.join(BASE_DIR, "templates", "index.html")
LOGIN_PATH = os.path.join(BASE_DIR, "templates", "login.html")
ADMIN_PATH = os.path.join(BASE_DIR, "templates", "admin.html")
CONFIG_PATH = os.getenv("LEVEL_UP_CONFIG_PATH", os.path.join(BASE_DIR, "level_up_config.json"))
ACCESS_ENV = "LEVEL_UP_ACCESS_CODE"
ADMIN_ENV = "LEVEL_UP_ADMIN_CODE"
SESSION_SECRET_ENV = "LEVEL_UP_SESSION_SECRET"
COOKIE_NAME = "level_up_session"
SESSION_TTL = 60 * 60 * 12


def _hash_code(code: str) -> str:
    return hashlib.sha256(code.encode("utf-8")).hexdigest()


def _load_config() -> dict:
    data = {}
    try:
        if os.path.exists(CONFIG_PATH):
            with open(CONFIG_PATH, "r", encoding="utf-8") as f:
                loaded = json.load(f)
                if isinstance(loaded, dict):
                    data = loaded
    except Exception:
        data = {}

    # Seed each code only when it has not yet been configured. After that,
    # admin changes are stored as hashes in level_up_config.json.
    changed = False
    if not data.get("access_code_hash"):
        initial = os.getenv(ACCESS_ENV, "LEVELUP@2026")
        data["access_code_hash"] = _hash_code(initial)
        changed = True
    if not data.get("admin_code_hash"):
        initial_admin = os.getenv(ADMIN_ENV, "CHANGE-ME-ADMIN")
        data["admin_code_hash"] = _hash_code(initial_admin)
        changed = True
    if changed or not data.get("updated_at"):
        data["updated_at"] = int(time.time())
        _save_config(data)
    return data


def _save_config(data: dict):
    tmp = CONFIG_PATH + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)
    os.replace(tmp, CONFIG_PATH)


def _secret() -> bytes:
    raw = os.getenv(SESSION_SECRET_ENV)
    if not raw:
        # Stable local secret so sessions survive worker requests; set this env var in production.
        raw = "level-up-local-session-secret-change-me"
    return raw.encode("utf-8")


def _make_session(role: str) -> str:
    payload = f"{role}:{int(time.time()) + SESSION_TTL}:{secrets.token_hex(8)}"
    sig = hmac.new(_secret(), payload.encode(), hashlib.sha256).hexdigest()
    return base64.urlsafe_b64encode(f"{payload}:{sig}".encode()).decode()


def _read_session(request: web.Request) -> Optional[str]:
    token = request.cookies.get(COOKIE_NAME)
    if not token:
        return None
    try:
        raw = base64.urlsafe_b64decode(token.encode()).decode()
        role, exp, nonce, sig = raw.rsplit(":", 3)
        payload = f"{role}:{exp}:{nonce}"
        expected = hmac.new(_secret(), payload.encode(), hashlib.sha256).hexdigest()
        if not hmac.compare_digest(sig, expected) or int(exp) < int(time.time()):
            return None
        return role
    except Exception:
        return None


def _set_session(response: web.Response, role: str):
    response.set_cookie(
        COOKIE_NAME, _make_session(role), max_age=SESSION_TTL,
        httponly=True, samesite="Lax", secure=False, path="/"
    )


def _json_error(message: str, status: int = 400):
    return web.json_response({"status": "error", "error": message}, status=status)


# -------------------- Auth pages/API --------------------
async def handle_index(request: web.Request) -> web.Response:
    if not _read_session(request):
        with open(LOGIN_PATH, "r", encoding="utf-8") as f: content = f.read()
        return web.Response(text=content, content_type="text/html", charset="utf-8")
    with open(TEMPLATE_PATH, "r", encoding="utf-8") as f: content = f.read()
    return web.Response(text=content, content_type="text/html", charset="utf-8")


async def handle_login(request: web.Request) -> web.Response:
    try:
        data = await request.json()
        code = str(data.get("access_code", "")).strip()
        cfg = _load_config()
        if not code or not hmac.compare_digest(_hash_code(code), cfg["access_code_hash"]):
            return _json_error("Invalid access code", 401)
        response = web.json_response({"status": "ok"})
        _set_session(response, "user")
        bot_state.log("Web dashboard login accepted", "success")
        return response
    except Exception as e:
        return _json_error(str(e), 400)


async def handle_logout(request: web.Request) -> web.Response:
    response = web.json_response({"status": "ok"})
    response.del_cookie(COOKIE_NAME, path="/")
    return response


async def handle_admin_page(request: web.Request) -> web.Response:
    # A normal user session must not open the admin interface from the dashboard.
    if _read_session(request) == "user":
        raise web.HTTPFound("/")
    with open(ADMIN_PATH, "r", encoding="utf-8") as f: content = f.read()
    return web.Response(text=content, content_type="text/html", charset="utf-8")


async def handle_admin_auth(request: web.Request) -> web.Response:
    if _read_session(request) == "user":
        return _json_error("Log out of the user panel before admin authentication", 403)
    try:
        data = await request.json()
        admin_code = str(data.get("admin_code", "")).strip()
        cfg = _load_config()
        if not admin_code or not hmac.compare_digest(_hash_code(admin_code), cfg["admin_code_hash"]):
            return _json_error("Invalid admin code", 401)
        response = web.json_response({"status": "ok"})
        _set_session(response, "admin")
        return response
    except Exception as e:
        return _json_error(str(e), 400)


async def handle_admin_change_code(request: web.Request) -> web.Response:
    if _read_session(request) != "admin":
        return _json_error("Admin authentication required", 403)
    try:
        data = await request.json()
        new_code = str(data.get("new_access_code", "")).strip()
        if len(new_code) < 6:
            return _json_error("New access code must be at least 6 characters")
        cfg = _load_config()
        cfg["access_code_hash"] = _hash_code(new_code)
        cfg["updated_at"] = int(time.time())
        _save_config(cfg)
        bot_state.log("Dashboard access code changed by admin", "warning")
        return web.json_response({"status": "ok", "message": "Access code updated"})
    except Exception as e:
        return _json_error(str(e), 400)


async def handle_admin_change_admin_code(request: web.Request) -> web.Response:
    if _read_session(request) != "admin":
        return _json_error("Admin authentication required", 403)
    try:
        data = await request.json()
        new_code = str(data.get("new_admin_code", "")).strip()
        confirm_code = str(data.get("confirm_admin_code", "")).strip()
        if len(new_code) < 8:
            return _json_error("New admin code must be at least 8 characters")
        if not hmac.compare_digest(new_code, confirm_code):
            return _json_error("Admin codes do not match")
        cfg = _load_config()
        cfg["admin_code_hash"] = _hash_code(new_code)
        cfg["updated_at"] = int(time.time())
        _save_config(cfg)
        bot_state.log("Admin code changed from the admin panel", "warning")
        return web.json_response({"status": "ok", "message": "Admin code updated"})
    except Exception as e:
        return _json_error(str(e), 400)


# -------------------- Dashboard API --------------------
def _require_user(request: web.Request):
    role = _read_session(request)
    return role if role in ("user", "admin") else None


async def handle_get_stats(request: web.Request) -> web.Response:
    if not _require_user(request): return _json_error("Login required", 401)
    accounts_data = list(bot_state.accounts.values())
    accounts_data.sort(key=lambda x: x.get("gained_exp", 0), reverse=True)
    return web.json_response({
        "total_accounts": len(bot_state.accounts),
        "total_matches": bot_state.total_matches,
        "total_gained_exp": bot_state.total_gained_exp,
        "accounts": accounts_data,
        "logs": bot_state.logs[-60:],
        "uptime": int(time.time() - bot_state.start_time)
    })


async def handle_add_account(request: web.Request) -> web.Response:
    if not _require_user(request): return _json_error("Login required", 401)
    try:
        data = await request.json()
        accounts_file = os.path.join(BASE_DIR, "accounts.json")
        existing = []
        if os.path.exists(accounts_file):
            try:
                with open(accounts_file, "r", encoding="utf-8") as f: existing = json.load(f)
            except Exception: existing = []
        if "uid" in data and "password" in data:
            uid, pwd = str(data["uid"]).strip(), str(data["password"]).strip()
            if not uid or not pwd: return _json_error("UID and Password are required")
            existing = [acc for acc in existing if str(acc.get("uid")) != uid]
            existing.append({"uid": uid, "password": pwd})
        elif "token" in data:
            token = str(data["token"]).strip()
            if not token: return _json_error("Token is required")
            existing = [acc for acc in existing if acc.get("token") != token]
            existing.append({"token": token})
        else: return _json_error("Invalid payload")
        with open(accounts_file, "w", encoding="utf-8") as f: json.dump(existing, f, indent=2)
        bot_state.log(f"New account added: {data.get('uid') or 'Token'}", "success")
        if "on_account_added" in bot_state.refresh_callbacks:
            asyncio.create_task(bot_state.refresh_callbacks["on_account_added"](data))
        return web.json_response({"status": "ok"})
    except Exception as e: return _json_error(str(e))


async def handle_delete_account(request: web.Request) -> web.Response:
    if not _require_user(request): return _json_error("Login required", 401)
    try:
        data = await request.json(); uid = str(data.get("uid", "")).strip()
        accounts_file = os.path.join(BASE_DIR, "accounts.json")
        if os.path.exists(accounts_file):
            with open(accounts_file, "r", encoding="utf-8") as f: existing = json.load(f)
            existing = [acc for acc in existing if str(acc.get("uid")) != uid]
            with open(accounts_file, "w", encoding="utf-8") as f: json.dump(existing, f, indent=2)
        if uid in bot_state.accounts: del bot_state.accounts[uid]
        if uid in bot_state.account_workers:
            bot_state.account_workers[uid].cancel(); del bot_state.account_workers[uid]
        bot_state.log(f"Account {uid} removed from rotation.", "warning", uid)
        return web.json_response({"status": "ok"})
    except Exception as e: return _json_error(str(e))


async def handle_refresh_account(request: web.Request) -> web.Response:
    if not _require_user(request): return _json_error("Login required", 401)
    try:
        data = await request.json(); uid = str(data.get("uid", "")).strip()
        if "on_refresh_account" in bot_state.refresh_callbacks:
            asyncio.create_task(bot_state.refresh_callbacks["on_refresh_account"](uid))
        return web.json_response({"status": "ok"})
    except Exception as e: return _json_error(str(e))


@web.middleware
async def auth_middleware(request: web.Request, handler):
    # Public endpoints
    if request.path in ("/login", "/logout", "/admin", "/admin/auth", "/admin/change-code") or request.path.startswith("/assets/"):
        return await handler(request)
    # Main page and APIs are protected by their own checks/redirect behavior.
    return await handler(request)


async def start_web_dashboard(host: str = "0.0.0.0", port: int = 5000):
    _load_config()
    app = web.Application(middlewares=[auth_middleware])
    assets_path = os.path.join(BASE_DIR, "assets")
    if os.path.isdir(assets_path): app.router.add_static("/assets", assets_path, show_index=False)
    app.router.add_get("/", handle_index)
    app.router.add_post("/login", handle_login)
    app.router.add_post("/logout", handle_logout)
    app.router.add_get("/admin", handle_admin_page)
    app.router.add_post("/admin/auth", handle_admin_auth)
    app.router.add_post("/admin/change-code", handle_admin_change_code)
    app.router.add_post("/admin/change-admin-code", handle_admin_change_admin_code)
    app.router.add_get("/api/stats", handle_get_stats)
    app.router.add_post("/api/account/add", handle_add_account)
    app.router.add_post("/api/account/delete", handle_delete_account)
    app.router.add_post("/api/account/refresh", handle_refresh_account)
    runner = web.AppRunner(app)
    await runner.setup()
    site = web.TCPSite(runner, host, port)
    await site.start()
    print(f"\033[92m[+] LEVEL UP Web Dashboard running on http://{host}:{port}\033[0m")
    print("[+] User access code: LEVEL_UP_ACCESS_CODE environment variable or level_up_config.json")
    print("[+] Admin code: configured hash in level_up_config.json (initial seed: LEVEL_UP_ADMIN_CODE)")
