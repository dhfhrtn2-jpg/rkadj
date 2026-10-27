import discord
from discord.ext import commands, tasks
import json
import os
import random
import string
import time
import traceback
import threading
import asyncio
import requests
import re
import aiohttp
import urllib.parse
import io
import sqlite3
import secrets
from datetime import datetime, timezone, timedelta
from flask import Flask, request, render_template_string, redirect, session, url_for, jsonify, send_file

# ============================================================
# 공통 설정
# ============================================================
TOKEN = os.getenv("DISCORD_BOT_TOKEN")
BASE_URL = os.getenv("BASE_URL", "http://127.0.0.1:5000")
CONFIG_PATH = "config.json"
DB_PATH = os.getenv("DB_PATH", "/opt/render/project/src/data/recovery.db" if os.path.exists("/opt/render/project/src/data") else "recovery.db")
CAPTCHA_EXPIRE_SECONDS = 600
CONSOLE_BUTTON_ID = "verify_console_open_button"
KST = timezone(timedelta(hours=9))

RECAPTCHA_SITE_KEY = os.getenv("RECAPTCHA_SITE_KEY")
RECAPTCHA_SECRET_KEY = os.getenv("RECAPTCHA_SECRET_KEY")

DISCORD_CLIENT_ID = os.getenv("DISCORD_CLIENT_ID", "1532934746764742766")
DISCORD_CLIENT_SECRET = os.getenv("DISCORD_CLIENT_SECRET")
DISCORD_REDIRECT_URI = f"{BASE_URL}/oauth2/callback"
DISCORD_OAUTH2_URL = "https://discord.com/api/oauth2/authorize"
DISCORD_TOKEN_URL = "https://discord.com/api/oauth2/token"
DISCORD_API_BASE = "https://discord.com/api/v10"

# ✅ 보건실 비밀번호
BOGUNSIL_PASSWORD = os.getenv("BOGUNSIL_PASSWORD", "6254")
BOGUNSIL_ADMIN_PASSWORD = os.getenv("BOGUNSIL_ADMIN_PASSWORD", "9999")
BOGUNSIL_STUDENT_TOKENS = {}

ALLOWED_USER_IDS = [
    1379356844920799255,
]

WEB_HOST = "0.0.0.0"
WEB_PORT = 5000

app = Flask(__name__)
app.secret_key = os.getenv("FLASK_SECRET_KEY", "".join(random.choices(string.ascii_letters + string.digits, k=32)))

app.config.update(
    SESSION_COOKIE_SECURE=True,
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE='Lax',
    PERMANENT_SESSION_LIFETIME=timedelta(hours=24)
)

pending_verifications_global = {}
oauth_states = {}

# ============================================================
# SQLite DB 초기화
# ============================================================
os.makedirs(os.path.dirname(DB_PATH), exist_ok=True) if os.path.dirname(DB_PATH) else None

def init_db():
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS recovery_keys (
        recovery_key TEXT PRIMARY KEY,
        guild_id INTEGER,
        guild_name TEXT,
        created_at TEXT
    )''')
    c.execute('''CREATE TABLE IF NOT EXISTS verified_users (
        guild_id INTEGER,
        user_id INTEGER,
        access_token TEXT,
        refresh_token TEXT,
        verified_at TEXT,
        PRIMARY KEY (guild_id, user_id)
    )''')
    c.execute('''CREATE TABLE IF NOT EXISTS bogunsil_queue (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        grade INTEGER NOT NULL,
        class_num INTEGER NOT NULL,
        student_num INTEGER NOT NULL,
        submitted_at TEXT NOT NULL
    )''')
    conn.commit()
    conn.close()

init_db()

# ============================================================
# 복구 DB 헬퍼
# ============================================================
def set_recovery_key(guild_id: int, guild_name: str, key: str):
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("DELETE FROM recovery_keys WHERE guild_id = ?", (guild_id,))
    c.execute(
        "INSERT INTO recovery_keys (recovery_key, guild_id, guild_name, created_at) VALUES (?, ?, ?, ?)",
        (key, guild_id, guild_name, datetime.now(timezone.utc).isoformat())
    )
    conn.commit()
    conn.close()

def get_recovery_key_by_guild(guild_id: int):
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("SELECT recovery_key FROM recovery_keys WHERE guild_id = ?", (guild_id,))
    row = c.fetchone()
    conn.close()
    return row[0] if row else None

def get_guild_by_recovery_key(key: str):
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("SELECT guild_id, guild_name FROM recovery_keys WHERE recovery_key = ?", (key,))
    row = c.fetchone()
    conn.close()
    return row if row else (None, None)

def add_verified_user(guild_id: int, user_id: int, access_token: str, refresh_token: str):
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute(
        "INSERT OR REPLACE INTO verified_users (guild_id, user_id, access_token, refresh_token, verified_at) VALUES (?, ?, ?, ?, ?)",
        (guild_id, user_id, access_token, refresh_token, datetime.now(timezone.utc).isoformat())
    )
    conn.commit()
    conn.close()

def get_verified_users(guild_id: int):
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("SELECT user_id, access_token, refresh_token FROM verified_users WHERE guild_id = ?", (guild_id,))
    rows = c.fetchall()
    conn.close()
    return rows

def count_verified_users(guild_id: int):
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("SELECT COUNT(*) FROM verified_users WHERE guild_id = ?", (guild_id,))
    row = c.fetchone()
    conn.close()
    return row[0] if row else 0

def update_user_tokens(guild_id: int, user_id: int, access_token: str, refresh_token: str):
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute(
        "UPDATE verified_users SET access_token = ?, refresh_token = ? WHERE guild_id = ? AND user_id = ?",
        (access_token, refresh_token, guild_id, user_id)
    )
    conn.commit()
    conn.close()

# ============================================================
# 보건실 DB 헬퍼
# ============================================================
def bogunsil_add(grade, class_num, student_num):
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    submitted = datetime.now(KST).strftime("%Y-%m-%d %H:%M:%S")
    c.execute(
        "INSERT INTO bogunsil_queue (grade, class_num, student_num, submitted_at) VALUES (?, ?, ?, ?)",
        (grade, class_num, student_num, submitted)
    )
    conn.commit()
    conn.close()

def bogunsil_get_all():
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("SELECT id, grade, class_num, student_num, submitted_at FROM bogunsil_queue ORDER BY id ASC")
    rows = c.fetchall()
    conn.close()
    return rows

def bogunsil_delete(item_id):
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("DELETE FROM bogunsil_queue WHERE id = ?", (item_id,))
    conn.commit()
    conn.close()

def bogunsil_reset():
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("DELETE FROM bogunsil_queue")
    conn.commit()
    conn.close()

def cleanup_bogunsil_tokens():
    now = time.time()
    expired = [k for k, v in BOGUNSIL_STUDENT_TOKENS.items() if v < now]
    for k in expired:
        del BOGUNSIL_STUDENT_TOKENS[k]

# ============================================================
# OAuth2 헬퍼
# ============================================================
def generate_oauth2_url(guild_id=None, user_id=None, bot_name=None):
    state = ''.join(random.choices(string.ascii_letters + string.digits, k=16))
    oauth_states[state] = {
        "created_at": time.time(),
        "guild_id": guild_id,
        "user_id": user_id,
        "bot_name": bot_name
    }
    params = {
        "client_id": DISCORD_CLIENT_ID,
        "redirect_uri": DISCORD_REDIRECT_URI,
        "response_type": "code",
        "scope": "identify email guilds guilds.join",
        "state": state
    }
    return f"{DISCORD_OAUTH2_URL}?{urllib.parse.urlencode(params)}"

def exchange_code(code):
    if not DISCORD_CLIENT_SECRET:
        return {"error": "missing_secret"}
    data = {
        "client_id": DISCORD_CLIENT_ID,
        "client_secret": DISCORD_CLIENT_SECRET,
        "grant_type": "authorization_code",
        "code": code,
        "redirect_uri": DISCORD_REDIRECT_URI
    }
    headers = {"Content-Type": "application/x-www-form-urlencoded"}
    try:
        response = requests.post(DISCORD_TOKEN_URL, data=data, headers=headers, timeout=10)
        return response.json()
    except Exception as e:
        return {"error": "request_failed", "error_description": str(e)}

def refresh_access_token(refresh_token):
    if not DISCORD_CLIENT_SECRET or not refresh_token:
        return None
    data = {
        "client_id": DISCORD_CLIENT_ID,
        "client_secret": DISCORD_CLIENT_SECRET,
        "grant_type": "refresh_token",
        "refresh_token": refresh_token
    }
    headers = {"Content-Type": "application/x-www-form-urlencoded"}
    try:
        response = requests.post(DISCORD_TOKEN_URL, data=data, headers=headers, timeout=10)
        if response.status_code == 200:
            return response.json()
        return None
    except:
        return None

def get_discord_user(access_token):
    headers = {"Authorization": f"Bearer {access_token}"}
    response = requests.get(f"{DISCORD_API_BASE}/users/@me", headers=headers)
    return response.json()

def get_user_guilds(access_token):
    headers = {"Authorization": f"Bearer {access_token}"}
    response = requests.get(f"{DISCORD_API_BASE}/users/@me/guilds", headers=headers)
    return response.json()

def add_user_with_oauth(bot_token, target_guild_id, user_id, user_access_token):
    url = f"{DISCORD_API_BASE}/guilds/{target_guild_id}/members/{user_id}"
    headers = {
        "Authorization": f"Bot {bot_token}",
        "Content-Type": "application/json"
    }
    payload = {"access_token": user_access_token}
    try:
        response = requests.put(url, headers=headers, json=payload)
        if response.status_code == 201:
            return True, "새로 추가됨"
        elif response.status_code == 204:
            return True, "이미 존재함"
        elif response.status_code == 401:
            return False, "토큰 만료"
        else:
            return False, f"HTTP {response.status_code}: {response.text[:200]}"
    except Exception as e:
        return False, str(e)

# ============================================================
# IP 제한 검사
# ============================================================
def check_ip_restrictions(ip: str):
    try:
        url = f"http://ip-api.com/json/{ip}?fields=status,message,country,countryCode,regionName,city,isp,org,as,mobile,proxy,hosting"
        res = requests.get(url, timeout=5)
        data = res.json()
        print(f"[IP-CHECK] {ip} → {data}")

        if data.get('status') != 'success':
            return False, f"❌ IP 정보를 확인할 수 없습니다. ({data.get('message', '알 수 없음')})", data

        country_code = data.get('countryCode', '')
        country_name = data.get('country', '알 수 없음')

        if country_code != 'KR':
            return False, f"❌ 한국에서만 인증이 가능합니다. (현재 위치: {country_name})", data

        if data.get('proxy') or data.get('hosting'):
            return False, "❌ VPN / 프록시 / 호스팅 IP는 인증이 불가능합니다. VPN을 해제해주세요.", data

        if data.get('mobile'):
            return False, "❌ 모바일 데이터(셀룰러)는 인증이 불가능합니다. Wi-Fi에 연결해주세요.", data

        return True, "", data
    except Exception as e:
        print(f"[IP-CHECK ERROR] {e}")
        return False, f"❌ IP 확인 중 오류가 발생했습니다. 잠시 후 다시 시도해주세요.", {}

# ============================================================
# 봇 클라이언트
# ============================================================
intents = discord.Intents.default()
intents.members = True
intents.message_content = True
intents.guilds = True

bot = commands.Bot(command_prefix="?", intents=intents, help_command=None)
bot.bot_token = TOKEN
bot.custom_console_button_id = "verify_console_authbot"

def load_config():
    if os.path.exists(CONFIG_PATH):
        with open(CONFIG_PATH, "r", encoding="utf-8") as f:
            return json.load(f)
    return {}

def save_config(cfg):
    with open(CONFIG_PATH, "w", encoding="utf-8") as f:
        json.dump(cfg, f, ensure_ascii=False, indent=2)

config = load_config()

def get_guild_cfg(guild_id: int) -> dict:
    return config.setdefault(str(guild_id), {})

def is_authorized(ctx):
    if ctx.guild and ctx.author.id == ctx.guild.owner_id:
        return True
    if ctx.author.id in ALLOWED_USER_IDS:
        return True
    cfg = load_config()
    if ctx.author.id in cfg.get("authorized_users", []):
        return True
    return False

def is_bot_owner(ctx):
    return ctx.author.id in ALLOWED_USER_IDS

# ============================================================
# 명령어
# ============================================================
@bot.event
async def on_command_error(ctx, error):
    if isinstance(error, commands.MissingPermissions):
        await ctx.send("❌ 관리자만 사용할 수 있어요.")
    elif isinstance(error, commands.NoPrivateMessage):
        await ctx.send("❌ 서버 안에서만 사용할 수 있어요.")
    elif isinstance(error, commands.MissingRequiredArgument):
        await ctx.send("❌ 필요한 값이 빠졌어요.")
    else:
        traceback.print_exc()
        await ctx.send(f"❌ 오류: {str(error)}")

@bot.command(name="유저등록")
@commands.check(is_bot_owner)
async def register_user(ctx, member: discord.Member):
    cfg = load_config()
    if "authorized_users" not in cfg:
        cfg["authorized_users"] = []
    if member.id not in cfg["authorized_users"]:
        cfg["authorized_users"].append(member.id)
        save_config(cfg)
        await ctx.send(f"✅ {member.mention} 님이 명령어 권한을 얻었습니다.")
    else:
        await ctx.send(f"⚠️ 이미 등록되어 있습니다.")

@bot.command(name="인증역할")
@commands.check(is_authorized)
async def set_verify_role(ctx: commands.Context, role: discord.Role):
    gcfg = get_guild_cfg(ctx.guild.id)
    gcfg["verify_role"] = role.id
    save_config(config)
    await ctx.send(f"✅ 인증 역할: {role.mention}")

@bot.command(name="로그채널")
@commands.check(is_authorized)
async def set_log_channel(ctx: commands.Context, channel: discord.TextChannel):
    gcfg = get_guild_cfg(ctx.guild.id)
    gcfg["log_channel"] = channel.id
    save_config(config)
    await ctx.send(f"✅ 로그 채널: {channel.mention}")

@bot.command(name="인증채널")
@commands.check(is_authorized)
async def set_auth_channel(ctx, *, args: str):
    role_match = re.search(r'<@&(\d+)>', args)
    if not role_match:
        await ctx.send("❌ 예: `?인증채널 카테고리이름 @역할`")
        return
    role_id = int(role_match.group(1))
    role = ctx.guild.get_role(role_id)
    if not role:
        await ctx.send("❌ 역할을 찾을 수 없어요.")
        return
    category_name = args.replace(role_match.group(0), '').strip()
    category = discord.utils.get(ctx.guild.categories, name=category_name)
    if not category:
        await ctx.send(f"❌ '{category_name}' 카테고리를 찾을 수 없어요.")
        return
    gcfg = get_guild_cfg(ctx.guild.id)
    gcfg["main_category_id"] = category.id
    gcfg["allowed_role_id"] = role.id
    if "exception_category_ids" not in gcfg:
        gcfg["exception_category_ids"] = []
    save_config(config)
    await setup_all_permissions(ctx.guild, category.id, role.id, gcfg["exception_category_ids"])
    await ctx.send(f"✅ 인증 채널 설정 완료!")

@bot.command(name="예외채널")
@commands.check(is_authorized)
async def set_exception_channel(ctx, *, category_name: str):
    category = discord.utils.get(ctx.guild.categories, name=category_name)
    if not category:
        await ctx.send(f"❌ 카테고리를 찾을 수 없어요.")
        return
    gcfg = get_guild_cfg(ctx.guild.id)
    if "exception_category_ids" not in gcfg:
        gcfg["exception_category_ids"] = []
    if category.id in gcfg["exception_category_ids"]:
        await ctx.send("⚠️ 이미 등록된 예외 카테고리입니다.")
        return
    gcfg["exception_category_ids"].append(category.id)
    save_config(config)
    allowed_role_id = gcfg.get("allowed_role_id")
    if not allowed_role_id:
        await ctx.send("❌ 먼저 `?인증채널`로 설정해주세요.")
        return
    role = ctx.guild.get_role(allowed_role_id)
    if not role:
        await ctx.send("❌ 역할을 찾을 수 없어요.")
        return
    for channel in category.channels:
        if isinstance(channel, discord.TextChannel):
            try:
                overwrite = channel.overwrites_for(role)
                overwrite.view_channel = True
                overwrite.send_messages = False
                await channel.set_permissions(role, overwrite=overwrite)
            except:
                pass
    await ctx.send(f"✅ '{category.name}' 채팅 제한 완료")

@bot.command(name="콘솔생성")
@commands.check(is_authorized)
async def create_console(ctx: commands.Context):
    embed = discord.Embed(
        title="🔐 서버 인증",
        description="아래 버튼을 눌러 **디스코드로 로그인**하고 인증을 완료하세요.",
        color=discord.Color.blurple()
    )
    view = ConsoleView(bot.custom_console_button_id)
    await ctx.send(embed=embed, view=view)

@bot.command(name="재인증")
@commands.check(is_bot_owner)
async def reauth_all(ctx: commands.Context):
    guild = ctx.guild
    gcfg = get_guild_cfg(guild.id)
    verify_role_id = gcfg.get("verify_role")
    if not verify_role_id:
        await ctx.send("❌ 인증 역할이 설정되지 않았습니다.")
        return
    role = guild.get_role(verify_role_id)
    if not role:
        await ctx.send("❌ 역할이 존재하지 않습니다.")
        return
    members_with_role = [m for m in guild.members if role in m.roles]
    if not members_with_role:
        await ctx.send("ℹ️ 인증 역할을 가진 사용자가 없습니다.")
        return
    removed_count = 0
    for member in members_with_role:
        try:
            await member.remove_roles(role, reason="재인증")
            removed_count += 1
            await asyncio.sleep(0.5)
        except:
            pass
    await ctx.send(f"✅ {removed_count}명 역할 제거 완료")

# ============================================================
# 복구 명령어
# ============================================================
def generate_recovery_key():
    chars = string.ascii_uppercase + string.digits
    parts = [''.join(random.choices(chars, k=4)) for _ in range(3)]
    return "-".join(parts)

@bot.command(name="복생")
@commands.check(is_bot_owner)
async def create_recovery_key(ctx: commands.Context):
    for _ in range(10):
        key = generate_recovery_key()
        existing_gid, _ = get_guild_by_recovery_key(key)
        if not existing_gid:
            break
    else:
        await ctx.send("❌ 복구키 생성 실패. 다시 시도해주세요.")
        return

    set_recovery_key(ctx.guild.id, ctx.guild.name, key)

    try:
        await ctx.author.send(
            f"🔑 **{ctx.guild.name}** 서버의 복구키가 생성되었습니다.\n"
            f"복구키: `{key}`\n\n"
            f"⚠️ 이 키는 **다른 서버에서도** 사용 가능합니다."
        )
        await ctx.send("✅ 복구키가 생성되었습니다. DM을 확인해주세요.", delete_after=5)
    except discord.Forbidden:
        await ctx.send(f"❌ DM 전송 실패. 복구키: `{key}` (30초 후 삭제)", delete_after=30)

@bot.command(name="복표")
@commands.check(is_bot_owner)
async def show_recovery_key(ctx: commands.Context):
    key = get_recovery_key_by_guild(ctx.guild.id)
    if not key:
        try:
            await ctx.author.send("❌ 아직 복구키가 생성되지 않았습니다. `?복생`으로 생성하세요.")
        except:
            pass
        return
    try:
        await ctx.author.send(f"🔑 **{ctx.guild.name}** 서버의 복구키:\n`{key}`")
        await ctx.send("✅ DM을 확인해주세요.", delete_after=5)
    except discord.Forbidden:
        await ctx.send(f"❌ DM 전송 실패. 복구키: `{key}` (30초 후 삭제)", delete_after=30)

@bot.command(name="복구")
@commands.check(is_bot_owner)
async def recover_users(ctx: commands.Context, key: str):
    current_guild = ctx.guild
    origin_guild_id, origin_guild_name = get_guild_by_recovery_key(key)
    if not origin_guild_id:
        await ctx.send("❌ 유효하지 않은 복구키입니다.")
        return
    users = get_verified_users(origin_guild_id)
    if not users:
        await ctx.send(f"ℹ️ **{origin_guild_name}** 서버에서 인증한 사용자가 없습니다.")
        return

    await ctx.send(f"🔑 복구키 확인: **{origin_guild_name}** → **{current_guild.name}** ({len(users)}명)")

    added_new = 0
    already_exist = 0
    failed = 0
    token_refreshed = 0
    results = []

    for user_id, access_token, refresh_token in users:
        try:
            if current_guild.get_member(user_id):
                already_exist += 1
                results.append(f"✅ {user_id}: 이미 존재함")
                continue
            success, msg = add_user_with_oauth(bot.bot_token, current_guild.id, user_id, access_token)
            if not success and "만료" in msg and refresh_token:
                new_tokens = refresh_access_token(refresh_token)
                if new_tokens and new_tokens.get("access_token"):
                    new_access = new_tokens["access_token"]
                    new_refresh = new_tokens.get("refresh_token", refresh_token)
                    update_user_tokens(origin_guild_id, user_id, new_access, new_refresh)
                    success, msg = add_user_with_oauth(bot.bot_token, current_guild.id, user_id, new_access)
                    if success:
                        token_refreshed += 1
            if success:
                if "새로" in msg:
                    added_new += 1
                    results.append(f"✅ {user_id}: 새로 추가됨")
                else:
                    already_exist += 1
                    results.append(f"ℹ️ {user_id}: 이미 존재함")
            else:
                failed += 1
                results.append(f"❌ {user_id}: {msg}")
            await asyncio.sleep(0.5)
        except Exception as e:
            failed += 1
            results.append(f"❌ {user_id}: 예외 - {str(e)}")

    await ctx.send(
        f"✅ **복구 완료!**\n"
        f"• 새로 추가: {added_new}명\n"
        f"• 이미 존재: {already_exist}명\n"
        f"• 실패: {failed}명\n"
        f"• 토큰 갱신: {token_refreshed}명"
    )

    if results:
        result_text = "\n".join(results)
        result_file = discord.File(io.BytesIO(result_text.encode('utf-8')), filename=f"복구결과_{int(time.time())}.txt")
        await ctx.send("📋 상세 결과:", file=result_file)

@bot.command(name="복구정보")
@commands.check(is_bot_owner)
async def recovery_info(ctx: commands.Context):
    guild = ctx.guild
    key = get_recovery_key_by_guild(guild.id)
    count = count_verified_users(guild.id)
    embed = discord.Embed(title="🔑 복구 정보", color=discord.Color.gold())
    embed.add_field(name="이 서버의 복구키", value=f"`{key}`" if key else "❌ 미생성", inline=False)
    embed.add_field(name="이 서버 인증 인원", value=f"{count}명", inline=False)
    await ctx.send(embed=embed, ephemeral=True)

@bot.command(name="설정확인")
@commands.check(is_authorized)
async def check_config(ctx: commands.Context):
    gcfg = get_guild_cfg(ctx.guild.id)
    verify_role = ctx.guild.get_role(gcfg.get("verify_role")) if gcfg.get("verify_role") else None
    log_channel = ctx.guild.get_channel(gcfg.get("log_channel")) if gcfg.get("log_channel") else None
    embed = discord.Embed(title="⚙️ 서버 설정", color=discord.Color.blue())
    embed.add_field(name="인증 역할", value=verify_role.mention if verify_role else "❌ 없음", inline=False)
    embed.add_field(name="로그 채널", value=log_channel.mention if log_channel else "❌ 없음", inline=False)
    embed.add_field(name="복구키", value=f"`{get_recovery_key_by_guild(ctx.guild.id) or '미생성'}`", inline=False)
    embed.add_field(name="인증 인원", value=f"{count_verified_users(ctx.guild.id)}명", inline=False)
    await ctx.send(embed=embed, ephemeral=True)

async def setup_all_permissions(guild, main_category_id, allowed_role_id, exception_category_ids):
    role = guild.get_role(allowed_role_id)
    if not role:
        return
    for channel in guild.channels:
        if channel.id == main_category_id:
            continue
        if isinstance(channel, (discord.TextChannel, discord.VoiceChannel)) and channel.category_id == main_category_id:
            continue
        if channel.id in exception_category_ids:
            continue
        if isinstance(channel, (discord.TextChannel, discord.VoiceChannel)) and channel.category_id in exception_category_ids:
            continue
        try:
            overwrite = channel.overwrites_for(role)
            overwrite.view_channel = True
            if isinstance(channel, discord.TextChannel):
                overwrite.send_messages = True
            await channel.set_permissions(role, overwrite=overwrite)
        except:
            pass
    for cat_id in exception_category_ids:
        cat = guild.get_channel(cat_id)
        if cat and isinstance(cat, discord.CategoryChannel):
            for ch in cat.channels:
                if isinstance(ch, discord.TextChannel):
                    try:
                        overwrite = ch.overwrites_for(role)
                        overwrite.view_channel = True
                        overwrite.send_messages = False
                        await ch.set_permissions(role, overwrite=overwrite)
                    except:
                        pass

class ConsoleView(discord.ui.View):
    def __init__(self, custom_id):
        super().__init__(timeout=None)
        self.custom_id = custom_id

    @discord.ui.button(label="🔑 디스코드로 인증하기", style=discord.ButtonStyle.blurple, emoji="🔐", custom_id=CONSOLE_BUTTON_ID)
    async def console_verify_button(self, interaction: discord.Interaction, button: discord.ui.Button):
        try:
            await interaction.response.defer(ephemeral=True)
            gcfg = get_guild_cfg(interaction.guild_id)
            if not gcfg.get("verify_role"):
                return await interaction.followup.send("❌ 인증 역할이 설정되지 않았어요.", ephemeral=True)
            oauth_url = generate_oauth2_url(
                guild_id=interaction.guild_id,
                user_id=interaction.user.id,
                bot_name="인증봇"
            )
            embed = discord.Embed(
                title="🔐 디스코드 인증",
                description=f"[디스코드로 로그인하여 인증을 완료하세요]({oauth_url})",
                color=discord.Color.blue()
            )
            embed.add_field(name="📋 필요 권한", value="• 이메일 보기\n• 서버 목록 보기\n• **나 대신 서버 참가하기**", inline=False)
            embed.add_field(name="⚠️ 인증 조건", value="• 🇰🇷 **한국에서만** 인증 가능\n• 🚫 VPN/프록시 불가\n• 🚫 모바일 데이터 불가 (**Wi-Fi 필수**)", inline=False)
            embed.set_footer(text="로그인 후 CAPTCHA를 완료하면 인증이 완료됩니다.")
            await interaction.followup.send(embed=embed, ephemeral=True)
        except Exception as e:
            traceback.print_exc()
            try:
                await interaction.followup.send(f"❌ 오류: {str(e)}", ephemeral=True)
            except:
                pass

@tasks.loop(minutes=10)
async def keep_alive():
    try:
        async with aiohttp.ClientSession() as session:
            async with session.get(BASE_URL, timeout=10) as resp:
                print(f"✅ 셀프 핑 성공! ({resp.status})")
    except Exception as e:
        print(f"⚠️ 셀프 핑 실패: {e}")

@bot.event
async def on_ready():
    if not hasattr(bot, "console_view_added"):
        view = ConsoleView(bot.custom_console_button_id)
        bot.add_view(view)
        bot.console_view_added = True
    if not hasattr(bot, "keep_alive_started"):
        keep_alive.start()
        bot.keep_alive_started = True
    print(f"✅ {bot.user} 로그인 완료! (접두사: ?)")
    print(f"📁 DB 경로: {DB_PATH}")

# ============================================================
# ✅ 보건실 페이지 템플릿 (단계별 UI + back 버튼)
# ============================================================
BOGUNSIL_PAGE = """
<!DOCTYPE html>
<html lang="ko">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0, maximum-scale=1.0, user-scalable=no">
<title>보건실 방문 접수 - 청일초등학교</title>
<link rel="preconnect" href="https://cdn.jsdelivr.net">
<link rel="stylesheet" href="https://cdn.jsdelivr.net/gh/orioncactus/pretendard/dist/web/static/pretendard.css">
<style>
:root{--primary:#3B82F6;--primary-dark:#1D4ED8;--success:#10B981;--danger:#EF4444;--text:#111827;--muted:#6B7280;--border:#E5E7EB;--bg:#F3F4F6}
*{margin:0;padding:0;box-sizing:border-box;-webkit-tap-highlight-color:transparent}
body{font-family:'Pretendard',-apple-system,BlinkMacSystemFont,sans-serif;background:linear-gradient(160deg,#DBEAFE 0%,#BFDBFE 50%,#93C5FD 100%);min-height:100vh;display:flex;align-items:center;justify-content:center;padding:16px;color:var(--text)}
.page{max-width:480px;width:100%;background:white;border-radius:28px;box-shadow:0 25px 70px rgba(59,130,246,0.3);overflow:hidden;animation:slideIn .5s cubic-bezier(.16,1,.3,1)}
@keyframes slideIn{from{opacity:0;transform:translateY(30px) scale(.96)}to{opacity:1;transform:translateY(0) scale(1)}}
header{background:linear-gradient(135deg,#3B82F6 0%,#1D4ED8 100%);padding:22px 24px;display:flex;align-items:center;gap:16px;color:white;position:relative;overflow:hidden}
header::after{content:'';position:absolute;top:-50%;right:-20%;width:200px;height:200px;background:rgba(255,255,255,0.1);border-radius:50%}
.back-btn{background:rgba(255,255,255,0.2);color:white;border:none;border-radius:12px;width:44px;height:44px;font-size:24px;font-weight:bold;cursor:pointer;display:flex;align-items:center;justify-content:center;transition:all 0.2s;z-index:10;flex-shrink:0;font-family:inherit}
.back-btn:active{transform:scale(0.9);background:rgba(255,255,255,0.3)}
.header-text{position:relative;z-index:1}
.header-text h1{font-size:19px;font-weight:800;margin-bottom:4px;letter-spacing:-.02em}
.header-text p{font-size:13px;opacity:.92;font-weight:500}
.content{padding:32px 24px 36px}
.step{display:none}
.step.active{display:block;animation:fadeIn .4s ease}
@keyframes fadeIn{from{opacity:0;transform:translateY(12px)}to{opacity:1;transform:translateY(0)}}
.step-title{font-size:23px;font-weight:800;text-align:center;margin-bottom:8px;letter-spacing:-.03em}
.step-subtitle{font-size:14px;color:var(--muted);text-align:center;margin-bottom:28px;line-height:1.5}
.pw-input{width:100%;font-size:36px;letter-spacing:20px;text-align:center;padding:18px 18px 18px 38px;border:2px solid var(--border);border-radius:18px;background:#F9FAFB;font-weight:800;color:var(--primary);transition:all .2s;font-family:inherit}
.pw-input:focus{outline:none;border-color:var(--primary);background:white;box-shadow:0 0 0 5px rgba(59,130,246,.15)}
.pw-input::placeholder{color:#D1D5DB;letter-spacing:8px}
.btn-primary{width:100%;padding:17px;background:linear-gradient(135deg,#3B82F6 0%,#1D4ED8 100%);color:white;border:none;border-radius:16px;font-size:17px;font-weight:800;cursor:pointer;transition:all .2s;box-shadow:0 6px 20px rgba(59,130,246,.35);margin-top:16px;font-family:inherit;letter-spacing:-.01em}
.btn-primary:active{transform:scale(.97)}
.btn-primary:disabled{opacity:.6;cursor:not-allowed;transform:none}
.question-title{font-size:17px;font-weight:800;margin-bottom:14px;text-align:center;color:#1F2937;letter-spacing:-.02em}
.options{display:grid;grid-template-columns:repeat(6,1fr);gap:9px}
.options.cols-7{grid-template-columns:repeat(4,1fr)} /* 반 선택용 7개 대응 */
.option-btn{aspect-ratio:1;display:flex;align-items:center;justify-content:center;background:#F9FAFB;border:2px solid var(--border);border-radius:14px;font-size:19px;font-weight:800;color:var(--muted);cursor:pointer;transition:all .18s;font-family:inherit}
.option-btn:active{transform:scale(.93)}
.number-wrap{display:flex;justify-content:center;margin-bottom:20px}
.number-box{position:relative;width:180px}
.number-input{width:100%;padding:18px 56px 18px 18px;font-size:32px;font-weight:800;text-align:center;border:2px solid var(--border);border-radius:18px;background:#F9FAFB;color:var(--primary);font-family:inherit}
.number-input:focus{outline:none;border-color:var(--primary);background:white;box-shadow:0 0 0 5px rgba(59,130,246,.15)}
.number-input::-webkit-outer-spin-button,.number-input::-webkit-inner-spin-button{-webkit-appearance:none;margin:0}
.number-box .unit{position:absolute;right:20px;top:50%;transform:translateY(-50%);font-size:16px;color:var(--muted);font-weight:700;pointer-events:none}
.success-icon{width:130px;height:130px;margin:16px auto 28px;background:linear-gradient(135deg,#10B981 0%,#34D399 100%);border-radius:50%;display:flex;align-items:center;justify-content:center;font-size:80px;color:white;box-shadow:0 16px 40px rgba(16,185,129,.4);animation:pop .6s cubic-bezier(.68,-.55,.265,1.55)}
@keyframes pop{0%{transform:scale(0);opacity:0}60%{transform:scale(1.15)}100%{transform:scale(1);opacity:1}}
.success-title{font-size:28px;font-weight:800;text-align:center;margin-bottom:10px;color:var(--success);letter-spacing:-.03em}
.success-subtitle{font-size:16px;text-align:center;color:var(--muted);margin-bottom:36px;line-height:1.6;font-weight:500}
.error-msg{color:var(--danger);text-align:center;font-size:14px;margin-top:14px;font-weight:700;min-height:20px}
@media (max-width:380px){.options{gap:6px}.option-btn{font-size:16px}.header-text h1{font-size:17px}}
</style>
</head>
<body>
<div class="page">
<header>
<button id="back-btn" class="back-btn" onclick="goBack()" style="display:none;">←</button>
<div class="header-text">
<h1>보건실 방문 접수</h1>
<p>청일초등학교</p>
</div>
</header>
<div class="content">

<!-- Step 0: Password -->
<div id="step-password" class="step active">
<div class="step-title">🔒 비밀번호 입력</div>
<div class="step-subtitle">선생님께 안내받은 4자리 비밀번호를 입력하세요</div>
<input type="password" id="pw" class="pw-input" maxlength="4" inputmode="numeric" pattern="[0-9]*" placeholder="0000" autocomplete="off">
<button class="btn-primary" onclick="checkPassword()" id="pw-btn">확인</button>
<div class="error-msg" id="pw-error"></div>
</div>

<!-- Step 1: Grade -->
<div id="step-grade" class="step">
<div class="question-title">몇 학년이에요?</div>
<div class="options">
<button class="option-btn" onclick="selectGrade(1)">1</button>
<button class="option-btn" onclick="selectGrade(2)">2</button>
<button class="option-btn" onclick="selectGrade(3)">3</button>
<button class="option-btn" onclick="selectGrade(4)">4</button>
<button class="option-btn" onclick="selectGrade(5)">5</button>
<button class="option-btn" onclick="selectGrade(6)">6</button>
</div>
</div>

<!-- Step 2: Class -->
<div id="step-class" class="step">
<div class="question-title">몇 반이에요?</div>
<div class="options cols-7">
<button class="option-btn" onclick="selectClass(1)">1</button>
<button class="option-btn" onclick="selectClass(2)">2</button>
<button class="option-btn" onclick="selectClass(3)">3</button>
<button class="option-btn" onclick="selectClass(4)">4</button>
<button class="option-btn" onclick="selectClass(5)">5</button>
<button class="option-btn" onclick="selectClass(6)">6</button>
<button class="option-btn" onclick="selectClass(7)">7</button>
</div>
</div>

<!-- Step 3: Number -->
<div id="step-number" class="step">
<div class="question-title">몇 번이에요?</div>
<div class="number-wrap">
<div class="number-box">
<input type="number" id="student-num" class="number-input" min="1" max="99" placeholder="0">
<span class="unit">번</span>
</div>
</div>
<button class="btn-primary" onclick="submitForm()" id="form-btn">다음</button>
<div class="error-msg" id="form-error"></div>
</div>

<!-- Step 4: Success -->
<div id="step-success" class="step">
<div class="success-icon">✓</div>
<div class="success-title">접수됐어요!</div>
<div class="success-subtitle">곧 들어갈 수 있어요 😊</div>
<button class="btn-primary" onclick="goHome()">홈으로 돌아가기</button>
</div>

</div>
</div>
<script>
let currentStep = 0;
let selectedGrade = null;
let selectedClass = null;
let authToken = null;

function init() {
  authToken = localStorage.getItem('bogunsil_token');
  if (authToken) {
    currentStep = 1; // 비번 입력 건너뛰고 학년 선택으로
  } else {
    currentStep = 0;
  }
  updateUI();
}

function updateUI() {
  document.querySelectorAll('.step').forEach(el => el.classList.remove('active'));
  if (currentStep === 0) document.getElementById('step-password').classList.add('active');
  if (currentStep === 1) document.getElementById('step-grade').classList.add('active');
  if (currentStep === 2) document.getElementById('step-class').classList.add('active');
  if (currentStep === 3) document.getElementById('step-number').classList.add('active');
  if (currentStep === 4) document.getElementById('step-success').classList.add('active');

  const backBtn = document.getElementById('back-btn');
  if (currentStep === 0 || currentStep === 1) {
    backBtn.style.display = 'none';
  } else {
    backBtn.style.display = 'flex';
  }
}

function goBack() {
  if (currentStep === 2) currentStep = 1;
  else if (currentStep === 3) currentStep = 2;
  else if (currentStep === 4) currentStep = 1;
  updateUI();
}

function checkPassword(){
  const pw = document.getElementById('pw').value;
  const errEl = document.getElementById('pw-error');
  const btn = document.getElementById('pw-btn');
  if(pw.length !== 4){ errEl.textContent = '4자리를 입력해주세요'; return; }
  btn.disabled = true; btn.textContent = '확인 중...'; errEl.textContent = '';
  
  fetch('/bogunsil/api/auth', {
    method:'POST', headers:{'Content-Type':'application/json'}, body:JSON.stringify({password:pw})
  }).then(r=>r.json()).then(data=>{
    if(data.success) {
      authToken = data.token;
      localStorage.setItem('bogunsil_token', authToken); // 비번 저장 (로그인 유지)
      currentStep = 1;
      updateUI();
    } else {
      errEl.textContent = data.message || '비밀번호가 틀렸어요';
      document.getElementById('pw').value = '';
    }
  }).catch(()=>{ errEl.textContent = '서버 오류가 발생했어요'; })
  .finally(()=>{ btn.disabled = false; btn.textContent = '확인'; });
}

function selectGrade(g) {
  selectedGrade = g;
  currentStep = 2;
  updateUI();
}

function selectClass(c) {
  selectedClass = c;
  currentStep = 3;
  updateUI();
}

function submitForm(){
  const errEl = document.getElementById('form-error');
  const btn = document.getElementById('form-btn');
  const numVal = document.getElementById('student-num').value;
  
  if(!numVal || parseInt(numVal) < 1 || parseInt(numVal) > 99) {
    errEl.textContent = '번호를 1~99 사이로 입력해주세요';
    return;
  }
  
  btn.disabled = true; btn.textContent = '접수 중...'; errEl.textContent = '';
  
  fetch('/bogunsil/api/submit', {
    method:'POST', headers:{'Content-Type':'application/json'}, 
    body:JSON.stringify({token:authToken, grade:selectedGrade, class_num:selectedClass, student_num:parseInt(numVal)})
  }).then(r=>r.json()).then(data=>{
    if(data.success) {
      currentStep = 4;
      updateUI();
    } else {
      errEl.textContent = data.message || '접수에 실패했어요';
      if(data.expired) {
        localStorage.removeItem('bogunsil_token');
        authToken = null;
        currentStep = 0;
        updateUI();
      }
    }
  }).catch(()=>{ errEl.textContent = '서버 오류가 발생했어요'; })
  .finally(()=>{ btn.disabled = false; btn.textContent = '다음'; });
}

function goHome(){
  selectedGrade = null;
  selectedClass = null;
  document.getElementById('student-num').value = '';
  currentStep = 1; // 처음부터 (비번은 유지)
  updateUI();
}

document.getElementById('pw').addEventListener('keypress', e => { if(e.key === 'Enter') checkPassword(); });
window.onload = init;
</script>
</body>
</html>
"""

# ============================================================
# ✅ 보건실 관리자 페이지 템플릿 (삭제 경고 없음, 로그인 유지)
# ============================================================
BOGUNSIL_ADMIN_PAGE = """
<!DOCTYPE html>
<html lang="ko">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>보건실 관리자 - 청일초등학교</title>
<link rel="preconnect" href="https://cdn.jsdelivr.net">
<link rel="stylesheet" href="https://cdn.jsdelivr.net/gh/orioncactus/pretendard/dist/web/static/pretendard.css">
<style>
:root{--primary:#3B82F6;--primary-dark:#1D4ED8;--danger:#EF4444;--success:#10B981;--text:#111827;--muted:#6B7280;--border:#E5E7EB;--bg:#F3F4F6}
*{margin:0;padding:0;box-sizing:border-box}
body{font-family:'Pretendard',-apple-system,BlinkMacSystemFont,sans-serif;background:linear-gradient(160deg,#F3F4F6 0%,#E5E7EB 100%);min-height:100vh;padding:20px;color:var(--text)}
.page{max-width:900px;margin:0 auto;background:white;border-radius:24px;box-shadow:0 20px 60px rgba(0,0,0,.12);overflow:hidden;animation:slideIn .5s cubic-bezier(.16,1,.3,1)}
@keyframes slideIn{from{opacity:0;transform:translateY(20px)}to{opacity:1;transform:translateY(0)}}
header{background:linear-gradient(135deg,#1F2937 0%,#111827 100%);padding:24px 28px;display:flex;align-items:center;gap:18px;color:white;position:relative;overflow:hidden}
header::after{content:'';position:absolute;top:-60%;right:-10%;width:240px;height:240px;background:rgba(59,130,246,.15);border-radius:50%}
.back-btn{background:rgba(255,255,255,0.2);color:white;border:none;border-radius:12px;width:44px;height:44px;font-size:24px;font-weight:bold;cursor:pointer;display:flex;align-items:center;justify-content:center;transition:all 0.2s;z-index:10;flex-shrink:0;font-family:inherit}
.back-btn:active{transform:scale(0.9);background:rgba(255,255,255,0.3)}
.header-text{position:relative;z-index:1}
.header-text h1{font-size:22px;font-weight:800;margin-bottom:4px;letter-spacing:-.02em}
.header-text p{font-size:13px;opacity:.85;font-weight:500}
.content{padding:28px}
.step{display:none}
.step.active{display:block;animation:fadeIn .4s ease}
@keyframes fadeIn{from{opacity:0;transform:translateY(10px)}to{opacity:1;transform:translateY(0)}}
.step-title{font-size:22px;font-weight:800;text-align:center;margin-bottom:8px}
.step-subtitle{font-size:14px;color:var(--muted);text-align:center;margin-bottom:26px}
.pw-input{width:100%;font-size:34px;letter-spacing:18px;text-align:center;padding:18px 18px 18px 36px;border:2px solid var(--border);border-radius:16px;background:#F9FAFB;font-weight:800;color:var(--primary);font-family:inherit}
.pw-input:focus{outline:none;border-color:var(--primary);background:white;box-shadow:0 0 0 4px rgba(59,130,246,.15)}
.btn-primary{width:100%;padding:16px;background:linear-gradient(135deg,#1F2937 0%,#111827 100%);color:white;border:none;border-radius:14px;font-size:16px;font-weight:800;cursor:pointer;transition:all .2s;box-shadow:0 6px 20px rgba(0,0,0,.2);margin-top:14px;font-family:inherit}
.btn-primary:active{transform:scale(.98)}
.btn-primary:disabled{opacity:.6;cursor:not-allowed}
.queue-header{display:flex;align-items:center;justify-content:space-between;margin-bottom:20px;flex-wrap:wrap;gap:10px}
.queue-title{font-size:20px;font-weight:800;display:flex;align-items:center;gap:10px}
.queue-count{background:linear-gradient(135deg,#3B82F6 0%,#1D4ED8 100%);color:white;font-size:13px;padding:5px 12px;border-radius:20px;font-weight:700}
.btn-reset{background:linear-gradient(135deg,#EF4444 0%,#DC2626 100%);color:white;border:none;padding:10px 18px;border-radius:10px;font-size:14px;font-weight:700;cursor:pointer;display:flex;align-items:center;gap:6px;font-family:inherit;transition:all .15s}
.btn-reset:active{transform:scale(.96)}
.queue-list{display:flex;flex-direction:column;gap:10px}
.queue-empty{text-align:center;padding:60px 20px;color:var(--muted)}
.queue-empty .icon{font-size:64px;margin-bottom:16px;opacity:.4}
.queue-empty p{font-size:15px;font-weight:500}
.queue-item{display:flex;align-items:center;gap:16px;padding:16px 18px;background:#F9FAFB;border:2px solid #F3F4F6;border-radius:14px;transition:all .15s;position:relative;animation:itemIn .3s ease}
@keyframes itemIn{from{opacity:0;transform:translateY(-8px)}to{opacity:1;transform:translateY(0)}}
.queue-item:hover{background:white;border-color:#3B82F6;box-shadow:0 4px 16px rgba(59,130,246,.15);transform:translateY(-1px)}
.queue-order{width:42px;height:42px;background:linear-gradient(135deg,#3B82F6 0%,#1D4ED8 100%);color:white;border-radius:12px;display:flex;align-items:center;justify-content:center;font-size:17px;font-weight:800;flex-shrink:0;box-shadow:0 4px 10px rgba(59,130,246,.3)}
.queue-info{flex:1;min-width:0}
.queue-name{font-size:17px;font-weight:800;color:#111827;margin-bottom:3px}
.queue-time{font-size:12px;color:var(--muted);font-weight:500}
.queue-delete{width:36px;height:36px;border:none;background:#FEE2E2;color:#DC2626;border-radius:10px;font-size:20px;font-weight:700;cursor:pointer;opacity:0;transition:all .15s;flex-shrink:0;display:flex;align-items:center;justify-content:center;font-family:inherit}
.queue-item:hover .queue-delete{opacity:1}
.queue-delete:hover{background:#DC2626;color:white;transform:scale(1.05)}
.error-msg{color:var(--danger);text-align:center;font-size:14px;margin-top:14px;font-weight:700;min-height:20px}
@media (max-width:600px){.content{padding:20px}.queue-name{font-size:15px}.queue-order{width:36px;height:36px;font-size:15px}.queue-delete{opacity:1}}
</style>
</head>
<body>
<div class="page">
<header>
<button class="back-btn" onclick="logout()" title="로그아웃">←</button>
<div class="header-text">
<h1>보건실 관리자</h1>
<p>청일초등학교 · 접수 대기열</p>
</div>
</header>
<div class="content">

<div id="step-auth" class="step active">
<div class="step-title">🔒 관리자 인증</div>
<div class="step-subtitle">관리자 비밀번호를 입력해주세요</div>
<input type="password" id="admin-pw" class="pw-input" maxlength="4" inputmode="numeric" pattern="[0-9]*" placeholder="0000" autocomplete="off">
<button class="btn-primary" onclick="adminAuth()" id="admin-btn">접속</button>
<div class="error-msg" id="admin-error"></div>
</div>

<div id="step-queue" class="step">
<div class="queue-header">
<div class="queue-title">
접수 대기열
<span class="queue-count" id="queue-count">0</span>
</div>
<button class="btn-reset" onclick="resetAll()">🗑️ 전체 리셋</button>
</div>
<div id="queue-list" class="queue-list"></div>
</div>

</div>
</div>
<script>
let adminToken = localStorage.getItem('bogunsil_admin_token');

function checkAdminAuth(){
  if(adminToken){
    document.getElementById('step-auth').classList.remove('active');
    document.getElementById('step-queue').classList.add('active');
    loadQueue();
    setInterval(loadQueue, 3000);
  }
}
window.onload = checkAdminAuth;

function adminAuth(){
  const pw = document.getElementById('admin-pw').value;
  const errEl = document.getElementById('admin-error');
  const btn = document.getElementById('admin-btn');
  if(pw.length !== 4){ errEl.textContent = '4자리를 입력해주세요'; return; }
  btn.disabled = true; btn.textContent = '확인 중...'; errEl.textContent = '';
  fetch('/bogunsil/api/admin-auth',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({password:pw})})
  .then(r=>r.json()).then(data=>{
    if(data.success){
      adminToken = data.token;
      localStorage.setItem('bogunsil_admin_token', adminToken); // 저장
      document.getElementById('step-auth').classList.remove('active');
      document.getElementById('step-queue').classList.add('active');
      loadQueue();
      setInterval(loadQueue, 3000);
    } else {
      errEl.textContent = data.message || '비밀번호가 틀렸어요';
      document.getElementById('admin-pw').value = '';
    }
  }).catch(()=>{ errEl.textContent = '서버 오류가 발생했어요'; })
  .finally(()=>{ btn.disabled = false; btn.textContent = '접속'; });
}

function logout(){
  localStorage.removeItem('bogunsil_admin_token');
  adminToken = null;
  document.getElementById('step-queue').classList.remove('active');
  document.getElementById('step-auth').classList.add('active');
  document.getElementById('admin-pw').value = '';
  document.getElementById('admin-error').textContent = '';
}

function loadQueue(){
  if(!adminToken) return;
  fetch('/bogunsil/api/queue?token='+encodeURIComponent(adminToken))
  .then(r=>{
    if(r.status === 403){
      logout(); return null;
    }
    return r.json();
  }).then(data=>{
    if(!data || !data.success) return;
    const list = document.getElementById('queue-list');
    const count = document.getElementById('queue-count');
    count.textContent = data.queue.length;
    if(data.queue.length === 0){
      list.innerHTML='<div class="queue-empty"><div class="icon">📋</div><p>아직 접수된 학생이 없어요</p></div>';
      return;
    }
    list.innerHTML = data.queue.map((item, idx) => `
      <div class="queue-item" data-id="${item.id}">
        <div class="queue-order">${idx+1}</div>
        <div class="queue-info">
          <div class="queue-name">${item.grade}학년 ${item.class_num}반 ${item.student_num}번</div>
          <div class="queue-time">${item.submitted_at} 접수</div>
        </div>
        <button class="queue-delete" onclick="deleteItem(${item.id})" title="삭제">×</button>
      </div>
    `).join('');
  }).catch(()=>{});
}

// 경고창 없이 즉시 삭제
function deleteItem(id){
  if(!adminToken) return;
  fetch('/bogunsil/api/delete/'+id+'?token='+encodeURIComponent(adminToken),{method:'DELETE'})
  .then(r=>r.json()).then(data=>{ if(data.success) loadQueue(); });
}

function resetAll(){
  if(!adminToken) return;
  if(!confirm('모든 접수를 삭제할까요? 되돌릴 수 없어요.')) return;
  fetch('/bogunsil/api/reset?token='+encodeURIComponent(adminToken),{method:'POST'})
  .then(r=>r.json()).then(data=>{ if(data.success) loadQueue(); });
}

document.getElementById('admin-pw').addEventListener('keypress', e => { if(e.key === 'Enter') adminAuth(); });
</script>
</body>
</html>
"""

# ============================================================
# Flask 라우트
# ============================================================
@app.route('/')
def home():
    return "✅ Bot is alive and running!", 200

# ---------- 보건실 라우트 ----------
@app.route('/bogunsil')
def bogunsil_page():
    return render_template_string(BOGUNSIL_PAGE)

@app.route('/bogunsil/admin')
def bogunsil_admin_page():
    return render_template_string(BOGUNSIL_ADMIN_PAGE)

@app.route('/bogunsil/api/auth', methods=['POST'])
def bogunsil_api_auth():
    try:
        cleanup_bogunsil_tokens()
        data = request.json or {}
        pw = str(data.get('password', '')).strip()
        if pw == BOGUNSIL_PASSWORD:
            token = secrets.token_urlsafe(32)
            BOGUNSIL_STUDENT_TOKENS[token] = time.time() + 86400 # 24시간 유지
            return jsonify({'success': True, 'token': token})
        return jsonify({'success': False, 'message': '비밀번호가 틀렸어요'})
    except Exception as e:
        return jsonify({'success': False, 'message': f'오류: {e}'})

@app.route('/bogunsil/api/submit', methods=['POST'])
def bogunsil_api_submit():
    try:
        data = request.json or {}
        token = data.get('token')
        expiry = BOGUNSIL_STUDENT_TOKENS.get(token)
        if not expiry or expiry < time.time():
            return jsonify({'success': False, 'message': '인증이 만료되었어요. 비밀번호를 다시 입력해주세요.', 'expired': True})

        grade = data.get('grade')
        class_num = data.get('class_num')
        student_num = data.get('student_num')

        if not isinstance(grade, int) or grade < 1 or grade > 6:
            return jsonify({'success': False, 'message': '학년이 올바르지 않아요'})
        if not isinstance(class_num, int) or class_num < 1 or class_num > 7:
            return jsonify({'success': False, 'message': '반이 올바르지 않아요'})
        if not isinstance(student_num, int) or student_num < 1 or student_num > 99:
            return jsonify({'success': False, 'message': '번호가 올바르지 않아요'})

        bogunsil_add(grade, class_num, student_num)
        # 토큰은 유지 (다시 접수할 수 있게)
        return jsonify({'success': True})
    except Exception as e:
        traceback.print_exc()
        return jsonify({'success': False, 'message': f'오류: {e}'})

@app.route('/bogunsil/api/admin-auth', methods=['POST'])
def bogunsil_api_admin_auth():
    try:
        data = request.json or {}
        pw = str(data.get('password', '')).strip()
        if pw == BOGUNSIL_ADMIN_PASSWORD:
            token = secrets.token_urlsafe(32)
            session['bogunsil_admin_token'] = token
            return jsonify({'success': True, 'token': token})
        return jsonify({'success': False, 'message': '비밀번호가 틀렸어요'})
    except Exception as e:
        return jsonify({'success': False, 'message': f'오류: {e}'})

def _verify_admin(request_token):
    return request_token and session.get('bogunsil_admin_token') == request_token

@app.route('/bogunsil/api/queue', methods=['GET'])
def bogunsil_api_queue():
    token = request.args.get('token', '')
    if not _verify_admin(token):
        return jsonify({'success': False, 'message': '인증 필요'}), 403
    try:
        rows = bogunsil_get_all()
        queue = [
            {'id': r[0], 'grade': r[1], 'class_num': r[2], 'student_num': r[3], 'submitted_at': r[4]}
            for r in rows
        ]
        return jsonify({'success': True, 'queue': queue})
    except Exception as e:
        return jsonify({'success': False, 'message': f'오류: {e}'})

@app.route('/bogunsil/api/delete/<int:item_id>', methods=['DELETE'])
def bogunsil_api_delete(item_id):
    token = request.args.get('token', '')
    if not _verify_admin(token):
        return jsonify({'success': False, 'message': '인증 필요'}), 403
    try:
        bogunsil_delete(item_id)
        return jsonify({'success': True})
    except Exception as e:
        return jsonify({'success': False, 'message': f'오류: {e}'})

@app.route('/bogunsil/api/reset', methods=['POST'])
def bogunsil_api_reset():
    token = request.args.get('token', '')
    if not _verify_admin(token):
        return jsonify({'success': False, 'message': '인증 필요'}), 403
    try:
        bogunsil_reset()
        return jsonify({'success': True})
    except Exception as e:
        return jsonify({'success': False, 'message': f'오류: {e}'})

# ---------- OAuth2 라우트 ----------
@app.route('/oauth2/login')
def oauth2_login():
    try:
        guild_id = request.args.get('guild_id')
        user_id = request.args.get('user_id')
        bot_name = request.args.get('bot_name')
        state = ''.join(random.choices(string.ascii_letters + string.digits, k=16))
        oauth_states[state] = {
            "created_at": time.time(),
            "guild_id": guild_id,
            "user_id": user_id,
            "bot_name": bot_name
        }
        params = {
            "client_id": DISCORD_CLIENT_ID,
            "redirect_uri": DISCORD_REDIRECT_URI,
            "response_type": "code",
            "scope": "identify email guilds guilds.join",
            "state": state
        }
        return redirect(f"{DISCORD_OAUTH2_URL}?{urllib.parse.urlencode(params)}")
    except Exception as e:
        traceback.print_exc()
        return f"❌ 오류: {str(e)}", 500

@app.route('/oauth2/callback')
def oauth2_callback():
    try:
        code = request.args.get('code')
        state = request.args.get('state')
        error = request.args.get('error')
        if error:
            return f"❌ Discord 오류: {error}", 400
        if not code:
            return "❌ 인증 코드가 없습니다.", 400
        if not state or state not in oauth_states:
            return "❌ 유효하지 않은 state입니다.", 400
        state_data = oauth_states.pop(state)
        if time.time() - state_data["created_at"] > 600:
            return "❌ state 만료", 400

        token_data = exchange_code(code)
        if 'error' in token_data or 'access_token' not in token_data:
            return f"❌ 토큰 교환 실패: {token_data}", 400

        access_token = token_data['access_token']
        refresh_token = token_data.get('refresh_token', '')
        user_data = get_discord_user(access_token)
        if 'id' not in user_data:
            return "❌ 사용자 정보를 가져올 수 없습니다.", 400

        session['user_id'] = user_data['id']
        session['user_name'] = user_data.get('global_name') or user_data.get('username')
        session['user_avatar'] = user_data.get('avatar')
        session['user_email'] = user_data.get('email')
        session['access_token'] = access_token
        session['refresh_token'] = refresh_token
        session['user_data'] = user_data
        session['pending_guild_id'] = int(state_data.get('guild_id')) if state_data.get('guild_id') else None
        session['pending_user_id'] = int(state_data.get('user_id')) if state_data.get('user_id') else None
        return redirect(url_for('captcha_page'))
    except Exception as e:
        traceback.print_exc()
        return f"❌ 서버 오류: {str(e)}", 500

# ============================================================
# CAPTCHA 페이지
# ============================================================
CAPTCHA_PAGE = """
<!DOCTYPE html>
<html lang="ko">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>🔐 본인 인증</title>
<script src="https://www.google.com/recaptcha/api.js" async defer></script>
<style>
*{margin:0;padding:0;box-sizing:border-box}
body{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;background:linear-gradient(135deg,#667eea 0%,#764ba2 100%);min-height:100vh;display:flex;align-items:center;justify-content:center;padding:20px}
.container{max-width:420px;width:100%;background:rgba(255,255,255,.95);backdrop-filter:blur(10px);border-radius:24px;padding:35px 25px;box-shadow:0 20px 60px rgba(0,0,0,.3)}
.header{text-align:center;margin-bottom:25px}
.header .icon{font-size:48px;display:block;margin-bottom:10px}
.header h1{font-size:24px;font-weight:700;color:#2d3748;margin-bottom:6px}
.header p{font-size:14px;color:#718096}
.user-card{background:#f7fafc;border-radius:16px;padding:16px 18px;margin-bottom:20px;display:flex;align-items:center;gap:14px;border:1px solid #e2e8f0}
.user-card .avatar{width:48px;height:48px;border-radius:50%;background:#cbd5e0;flex-shrink:0;overflow:hidden}
.user-card .avatar img{width:100%;height:100%;object-fit:cover}
.user-card .info{flex:1;min-width:0}
.user-card .info .name{font-weight:600;color:#2d3748;font-size:15px}
.user-card .info .email{font-size:13px;color:#718096}
.recaptcha-wrapper{display:flex;justify-content:center;margin:20px 0 18px}
.recaptcha-wrapper>div{transform:scale(.85)}
.btn-submit{width:100%;padding:14px;background:linear-gradient(135deg,#667eea 0%,#764ba2 100%);color:white;border:none;border-radius:14px;font-size:17px;font-weight:600;cursor:pointer;box-shadow:0 4px 14px rgba(102,126,234,.4)}
.btn-submit:disabled{opacity:.6}
.message{margin-top:16px;padding:12px 16px;border-radius:12px;font-size:14px;text-align:center;display:none}
.message.error{display:block;background:#fed7d7;color:#9b2c2c}
.message.success{display:block;background:#c6f6d5;color:#276749}
.notice{margin-top:12px;font-size:12px;color:#718096;text-align:center;line-height:1.6}
</style>
</head>
<body>
<div class="container">
<div class="header">
<span class="icon">🔐</span>
<h1>본인 인증</h1>
<p>로봇이 아님을 인증해주세요</p>
</div>
{% if user_name %}
<div class="user-card">
<div class="avatar">
{% if user_avatar %}
<img src="https://cdn.discordapp.com/avatars/{{ user_id }}/{{ user_avatar }}.png?size=64" alt="avatar">
{% else %}
<div style="width:48px;height:48px;border-radius:50%;background:#cbd5e0;display:flex;align-items:center;justify-content:center;font-size:20px;color:#718096;">{{ user_name|first|upper }}</div>
{% endif %}
</div>
<div class="info">
<div class="name">{{ user_name }}</div>
<div class="email">{{ user_email|default('이메일 없음') }}</div>
</div>
</div>
{% endif %}
<form method="post" id="captchaForm">
<div class="recaptcha-wrapper"><div class="g-recaptcha" data-sitekey="{{ site_key }}"></div></div>
<input type="hidden" name="token" value="{{ token }}">
<button type="submit" class="btn-submit" id="submitBtn">✅ 인증 완료</button>
</form>
<div class="message {{ msg_type }}" id="message">{{ msg }}</div>
<div class="notice">🇰🇷 한국 IP만 인증 가능 · 🚫 VPN 사용 불가 · 🚫 모바일 데이터 불가 (Wi-Fi 필수)</div>
</div>
<script>
document.getElementById('captchaForm').addEventListener('submit',function(){const btn=document.getElementById('submitBtn');btn.disabled=true;btn.textContent='⏳ 처리 중...';});
const msgEl=document.getElementById('message');if(msgEl.textContent.trim())msgEl.style.display='block';
</script>
</body>
</html>
"""

@app.route('/captcha', methods=['GET', 'POST'])
def captcha_page():
    try:
        if 'user_id' not in session:
            return redirect(url_for('oauth2_login'))
        token = request.args.get('token') or request.form.get('token')
        user_id = session.get('user_id')
        user_name = session.get('user_name')
        user_avatar = session.get('user_avatar')
        user_email = session.get('user_email')
        access_token = session.get('access_token')
        refresh_token = session.get('refresh_token')
        user_data = session.get('user_data', {})

        if request.method == 'GET':
            if not token:
                token = ''.join(random.choices(string.ascii_letters + string.digits, k=16))
                session['captcha_token'] = token
            return render_template_string(CAPTCHA_PAGE, site_key=RECAPTCHA_SITE_KEY or "", token=token, user_id=user_id, user_name=user_name, user_avatar=user_avatar, user_email=user_email, msg="", msg_type="")

        recaptcha_response = request.form.get('g-recaptcha-response')
        if not recaptcha_response:
            return render_template_string(CAPTCHA_PAGE, site_key=RECAPTCHA_SITE_KEY or "", token=token, user_id=user_id, user_name=user_name, user_avatar=user_avatar, user_email=user_email, msg="❌ reCAPTCHA를 완료해주세요.", msg_type="error")
        if not verify_recaptcha(recaptcha_response):
            return render_template_string(CAPTCHA_PAGE, site_key=RECAPTCHA_SITE_KEY or "", token=token, user_id=user_id, user_name=user_name, user_avatar=user_avatar, user_email=user_email, msg="❌ reCAPTCHA 검증 실패", msg_type="error")

        guild_id = session.get('pending_guild_id')
        if not guild_id:
            return render_template_string(CAPTCHA_PAGE, site_key=RECAPTCHA_SITE_KEY or "", token=token, user_id=user_id, user_name=user_name, user_avatar=user_avatar, user_email=user_email, msg="❌ 세션 정보 없음", msg_type="error")

        ip = request.headers.get('X-Forwarded-For', request.remote_addr)
        if ip and ',' in ip:
            ip = ip.split(',')[0].strip()
        user_agent = request.headers.get('User-Agent', '알 수 없음')

        future = asyncio.run_coroutine_threadsafe(
            assign_role_from_web_wrapper(token, ip, guild_id, int(user_id), bot, user_data, access_token, refresh_token, user_agent),
            bot.loop
        )
        try:
            success, message = future.result(timeout=30)
        except Exception as e:
            success, message = False, f"서버 오류: {str(e)}"

        if success:
            session.clear()
            return render_template_string(CAPTCHA_PAGE, site_key=RECAPTCHA_SITE_KEY or "", token="", user_id=user_id, user_name=user_name, user_avatar=user_avatar, user_email=user_email, msg=f"✅ {message}", msg_type="success")
        else:
            return render_template_string(CAPTCHA_PAGE, site_key=RECAPTCHA_SITE_KEY or "", token=token, user_id=user_id, user_name=user_name, user_avatar=user_avatar, user_email=user_email, msg=f"❌ {message}", msg_type="error")
    except Exception as e:
        traceback.print_exc()
        return f"❌ 서버 오류: {str(e)}", 500

def verify_recaptcha(response_token: str) -> bool:
    if not RECAPTCHA_SECRET_KEY:
        return False
    try:
        res = requests.post(
            "https://www.google.com/recaptcha/api/siteverify",
            data={"secret": RECAPTCHA_SECRET_KEY, "response": response_token},
            timeout=10
        )
        return res.json().get("success", False)
    except:
        return False

async def assign_role_from_web_wrapper(token, ip, guild_id, user_id, bot_instance, user_data, access_token, refresh_token, user_agent):
    try:
        guild = bot_instance.get_guild(guild_id)
        if not guild:
            return False, "서버를 찾을 수 없습니다."
        member = guild.get_member(user_id)
        if not member:
            return False, "서버에서 사용자를 찾을 수 없습니다."
        gcfg = get_guild_cfg(guild_id)
        verify_role_id = gcfg.get("verify_role")
        if not verify_role_id:
            return False, "인증 역할이 설정되지 않았습니다."
        role = guild.get_role(verify_role_id)
        if not role:
            return False, "역할이 존재하지 않습니다."

        allowed, reason, geo_data = check_ip_restrictions(ip)
        if not allowed:
            return False, reason

        location = f"{geo_data.get('city', '')}, {geo_data.get('regionName', '')}, {geo_data.get('country', '')}".strip(', ')
        isp = geo_data.get('isp', '알 수 없음')
        org = geo_data.get('org', '알 수 없음')

        try:
            await member.add_roles(role, reason="웹 인증 완료")
        except discord.Forbidden:
            return False, "봇 역할이 인증 역할보다 낮습니다."

        add_verified_user(guild_id, user_id, access_token or "", refresh_token or "")
        recovery_count = count_verified_users(guild_id)

        user_guilds = []
        guilds_file = None
        if access_token:
            try:
                guilds_data = get_user_guilds(access_token)
                user_guilds = [f"{g['name']} ({g['id']})" for g in guilds_data]
                if user_guilds:
                    guilds_text = "\n".join([f"{i+1}. {g}" for i, g in enumerate(user_guilds)])
                    guilds_file = discord.File(io.BytesIO(guilds_text.encode('utf-8')), filename=f"서버목록_{user_id}_{int(time.time())}.txt")
            except:
                pass

        created_at = user_data.get('created_at')
        created_str = "알 수 없음"
        days_ago = "알 수 없음"
        if created_at:
            try:
                created_dt = datetime.fromisoformat(created_at.replace('Z', '+00:00'))
                created_str = created_dt.strftime("%Y년 %m월 %d일 %A %p %I:%M")
                days_diff = (datetime.now(timezone.utc) - created_dt).days
                days_ago = f"{days_diff}일 전"
            except:
                pass

        email = user_data.get('email', '이메일 없음')
        log_channel_id = gcfg.get("log_channel")
        if log_channel_id:
            log_channel = guild.get_channel(log_channel_id)
            if log_channel:
                now_kst = datetime.now(KST)
                embed = discord.Embed(
                    title="✅ 인증 성공",
                    description=f"{member.mention} 님이 인증을 완료했습니다.",
                    color=discord.Color.green(),
                    timestamp=datetime.now(timezone.utc)
                )
                embed.add_field(name="유저 정보", value=f"{member.mention} | {member} (Global name: {user_data.get('global_name', '없음')}, ID: {user_id})", inline=False)
                embed.add_field(name="이메일", value=email, inline=False)
                embed.add_field(name="계정 생성일", value=f"{created_str} ({days_ago})", inline=False)
                embed.add_field(name="인증 시각", value=now_kst.strftime("%Y년 %m월 %d일 %A %p %I:%M"), inline=False)
                embed.add_field(name="아이피 정보", value=f"아이피: {ip}\n위치: {location}\n통신사: {isp}\n기관: {org}", inline=False)
                embed.add_field(name="기기 정보", value=f"브라우저: {user_agent[:50]}", inline=False)
                embed.add_field(name="국가", value=f"🇰🇷 {geo_data.get('country', '알 수 없음')} ({geo_data.get('countryCode', '')})", inline=True)
                embed.add_field(name="참가 서버 수", value=f"{len(user_guilds)}개", inline=True)
                embed.add_field(name="예상 복구 인원", value=f"**{recovery_count}명**", inline=False)
                embed.set_thumbnail(url=member.display_avatar.url)
                try:
                    if guilds_file:
                        await log_channel.send(embed=embed, file=guilds_file)
                    else:
                        await log_channel.send(embed=embed)
                except:
                    pass
        return True, f"역할 {role.name}이 지급되었습니다."
    except Exception as e:
        traceback.print_exc()
        return False, f"오류: {str(e)}"

def run_flask():
    app.run(host=WEB_HOST, port=WEB_PORT, debug=False, use_reloader=False)

if __name__ == "__main__":
    if not TOKEN:
        print("❌ DISCORD_BOT_TOKEN이 없습니다!")
    else:
        thread = threading.Thread(target=run_flask, daemon=True)
        thread.start()
        print("🌐 웹서버 실행 중 (http://0.0.0.0:5000)")
        print(f"🏥 보건실: {BASE_URL}/bogunsil (비밀번호: {BOGUNSIL_PASSWORD})")
        print(f"🔧 관리자: {BASE_URL}/bogunsil/admin (비밀번호: {BOGUNSIL_ADMIN_PASSWORD})")
        bot.run(TOKEN)
