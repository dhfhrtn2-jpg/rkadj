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
from datetime import datetime, timezone, timedelta
from flask import Flask, request, render_template_string, redirect, session, url_for

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
    conn.commit()
    conn.close()

init_db()

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
# ✅ IP 제한 검사 (한국만 + VPN차단 + 모바일차단)
# ============================================================
def check_ip_restrictions(ip: str):
    """
    ip-api.com의 정확한 필드를 사용해서 검사
    - countryCode == 'KR' (한국만)
    - proxy / hosting == False (VPN/프록시/호스팅 차단)
    - mobile == False (모바일 데이터 차단)
    
    반환: (allowed: bool, reason: str, geo_data: dict)
    """
    try:
        url = f"http://ip-api.com/json/{ip}?fields=status,message,country,countryCode,regionName,city,isp,org,as,mobile,proxy,hosting"
        res = requests.get(url, timeout=5)
        data = res.json()
        
        print(f"[IP-CHECK] {ip} → {data}")
        
        if data.get('status') != 'success':
            return False, f"❌ IP 정보를 확인할 수 없습니다. ({data.get('message', '알 수 없음')})", data
        
        country_code = data.get('countryCode', '')
        country_name = data.get('country', '알 수 없음')
        
        # 1. 한국만 허용
        if country_code != 'KR':
            return False, f"❌ 한국에서만 인증이 가능합니다. (현재 위치: {country_name})", data
        
        # 2. VPN / 프록시 / 호스팅 차단
        if data.get('proxy') or data.get('hosting'):
            return False, "❌ VPN / 프록시 / 호스팅 IP는 인증이 불가능합니다. VPN을 해제해주세요.", data
        
        # 3. 모바일 데이터 차단
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
            f"⚠️ 이 키는 **다른 서버에서도** 사용 가능합니다.\n"
            f"`?복구 {key}`를 입력하면 이 서버에서 인증한 사람들을 다른 서버로 복구할 수 있어요."
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
        await ctx.author.send(
            f"🔑 **{ctx.guild.name}** 서버의 복구키입니다.\n"
            f"복구키: `{key}`"
        )
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

    if origin_guild_id == current_guild.id:
        await ctx.send(
            f"🔑 이 복구키는 **현재 서버**의 키입니다.\n"
            f"→ **{origin_guild_name}** 에서 인증한 {len(users)}명을 현재 서버로 복구합니다."
        )
    else:
        await ctx.send(
            f"🔑 복구키 확인됨: **{origin_guild_name}**\n"
            f"→ **{origin_guild_name}** 에서 인증한 **{len(users)}명**을 **{current_guild.name}** 서버로 복구합니다..."
        )

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

    summary = (
        f"✅ **복구 완료!** (원본: **{origin_guild_name}** → 대상: **{current_guild.name}**)\n"
        f"• 새로 추가: {added_new}명\n"
        f"• 이미 존재: {already_exist}명\n"
        f"• 실패: {failed}명\n"
        f"• 토큰 자동 갱신: {token_refreshed}명"
    )
    await ctx.send(summary)

    if results:
        result_text = "\n".join(results)
        result_file = discord.File(
            io.BytesIO(result_text.encode('utf-8')),
            filename=f"복구결과_{int(time.time())}.txt"
        )
        await ctx.send("📋 상세 결과:", file=result_file)

    gcfg = get_guild_cfg(current_guild.id)
    log_channel_id = gcfg.get("log_channel")
    if log_channel_id:
        log_channel = current_guild.get_channel(log_channel_id)
        if log_channel:
            embed = discord.Embed(
                title="📨 복구 실행됨",
                description=f"복구키로 **{origin_guild_name}** 인증자들을 복구했습니다.",
                color=discord.Color.blue(),
                timestamp=datetime.now(timezone.utc)
            )
            embed.add_field(name="실행자", value=ctx.author.mention, inline=False)
            embed.add_field(name="원본 서버", value=origin_guild_name, inline=True)
            embed.add_field(name="대상 서버", value=current_guild.name, inline=True)
            embed.add_field(name="새로 추가", value=str(added_new), inline=True)
            embed.add_field(name="이미 존재", value=str(already_exist), inline=True)
            embed.add_field(name="실패", value=str(failed), inline=True)
            try:
                await log_channel.send(embed=embed)
            except:
                pass

@bot.command(name="복구정보")
@commands.check(is_bot_owner)
async def recovery_info(ctx: commands.Context):
    guild = ctx.guild
    key = get_recovery_key_by_guild(guild.id)
    count = count_verified_users(guild.id)

    embed = discord.Embed(
        title="🔑 복구 정보",
        color=discord.Color.gold(),
        timestamp=datetime.now(timezone.utc)
    )
    embed.add_field(name="이 서버의 복구키", value=f"`{key}`" if key else "❌ 생성되지 않음", inline=False)
    embed.add_field(name="이 서버에서 인증한 인원", value=f"{count}명", inline=False)
    embed.set_footer(text="이 복구키로 다른 서버에서도 이 서버 인증자들을 복구할 수 있습니다.")
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

# ============================================================
# 권한 설정 헬퍼
# ============================================================
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

# ============================================================
# ConsoleView
# ============================================================
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
            embed.add_field(
                name="^위에 있는 하이퍼링크를 클릭하여 인증을 완료하세요",
                value="인증을 완료할시 역할이 지급됩니다.",
                inline=False
            )
            embed.add_field(
                name="인증이 안되면 donthaf_94721 dm",
                value="사진과 함께",
                inline=False
            )
            embed.set_footer(text="로그인 후 CAPTCHA를 완료하면 인증이 완료됩니다.")
            await interaction.followup.send(embed=embed, ephemeral=True)
        except Exception as e:
            traceback.print_exc()
            try:
                await interaction.followup.send(f"❌ 오류: {str(e)}", ephemeral=True)
            except:
                pass

# ============================================================
# 셀프 핑
# ============================================================
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
# Flask 라우트
# ============================================================
@app.route('/')
def home():
    return "✅ Bot is alive and running!", 200

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
        oauth_url = f"{DISCORD_OAUTH2_URL}?{urllib.parse.urlencode(params)}"
        return redirect(oauth_url)
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
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); min-height: 100vh; display: flex; align-items: center; justify-content: center; padding: 20px; }
        .container { max-width: 420px; width: 100%; background: rgba(255,255,255,0.95); backdrop-filter: blur(10px); border-radius: 24px; padding: 35px 25px; box-shadow: 0 20px 60px rgba(0,0,0,0.3); animation: slideUp 0.5s ease-out; }
        @keyframes slideUp { from { opacity: 0; transform: translateY(30px); } to { opacity: 1; transform: translateY(0); } }
        .header { text-align: center; margin-bottom: 25px; }
        .header .icon { font-size: 48px; display: block; margin-bottom: 10px; }
        .header h1 { font-size: 24px; font-weight: 700; color: #2d3748; margin-bottom: 6px; }
        .header p { font-size: 14px; color: #718096; }
        .user-card { background: #f7fafc; border-radius: 16px; padding: 16px 18px; margin-bottom: 20px; display: flex; align-items: center; gap: 14px; border: 1px solid #e2e8f0; }
        .user-card .avatar { width: 48px; height: 48px; border-radius: 50%; background: #cbd5e0; flex-shrink: 0; overflow: hidden; }
        .user-card .avatar img { width: 100%; height: 100%; object-fit: cover; }
        .user-card .info { flex: 1; min-width: 0; }
        .user-card .info .name { font-weight: 600; color: #2d3748; font-size: 15px; }
        .user-card .info .email { font-size: 13px; color: #718096; }
        .recaptcha-wrapper { display: flex; justify-content: center; margin: 20px 0 18px; }
        .recaptcha-wrapper > div { transform: scale(0.85); transform-origin: center; }
        @media (max-width: 420px) { .recaptcha-wrapper > div { transform: scale(0.75); } }
        .btn-submit { width: 100%; padding: 14px; background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; border: none; border-radius: 14px; font-size: 17px; font-weight: 600; cursor: pointer; box-shadow: 0 4px 14px rgba(102, 126, 234, 0.4); }
        .btn-submit:active { transform: scale(0.97); }
        .btn-submit:disabled { opacity: 0.6; cursor: not-allowed; }
        .message { margin-top: 16px; padding: 12px 16px; border-radius: 12px; font-size: 14px; text-align: center; display: none; }
        .message.error { display: block; background: #fed7d7; color: #9b2c2c; }
        .message.success { display: block; background: #c6f6d5; color: #276749; }
        .notice { margin-top: 12px; font-size: 12px; color: #718096; text-align: center; line-height: 1.6; }
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
            <div class="recaptcha-wrapper">
                <div class="g-recaptcha" data-sitekey="{{ site_key }}"></div>
            </div>
            <input type="hidden" name="token" value="{{ token }}">
            <button type="submit" class="btn-submit" id="submitBtn">✅ 인증 완료</button>
        </form>
        <div class="message {{ msg_type }}" id="message">{{ msg }}</div>
        <div class="notice">
            🇰🇷 한국 IP만 인증 가능 · 🚫 VPN 사용 불가 · 🚫 모바일 데이터 불가 (Wi-Fi 필수)
        </div>
    </div>
    <script>
        document.getElementById('captchaForm').addEventListener('submit', function() {
            const btn = document.getElementById('submitBtn');
            btn.disabled = true;
            btn.textContent = '⏳ 처리 중...';
        });
        const msgEl = document.getElementById('message');
        if (msgEl.textContent.trim()) msgEl.style.display = 'block';
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

# ============================================================
# 웹 인증 처리 (새로운 IP 제한 로직)
# ============================================================
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

        # ============================================================
        # ✅ IP 제한 검사 (한국 + VPN차단 + 모바일차단)
        # ============================================================
        allowed, reason, geo_data = check_ip_restrictions(ip)
        if not allowed:
            print(f"[인증 차단] {user_id} - {reason}")
            return False, reason

        # 위치/통신사 정보
        location = f"{geo_data.get('city', '')}, {geo_data.get('regionName', '')}, {geo_data.get('country', '')}".strip(', ')
        isp = geo_data.get('isp', '알 수 없음')
        org = geo_data.get('org', '알 수 없음')

        # 역할 지급
        try:
            await member.add_roles(role, reason="웹 인증 완료")
        except discord.Forbidden:
            return False, "봇 역할이 인증 역할보다 낮습니다."

        # DB 저장
        add_verified_user(guild_id, user_id, access_token or "", refresh_token or "")
        recovery_count = count_verified_users(guild_id)

        # 서버 목록 파일
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

# ============================================================
# Flask 실행
# ============================================================
def run_flask():
    app.run(host=WEB_HOST, port=WEB_PORT, debug=False, use_reloader=False)

if __name__ == "__main__":
    if not TOKEN:
        print("❌ DISCORD_BOT_TOKEN이 없습니다!")
    else:
        thread = threading.Thread(target=run_flask, daemon=True)
        thread.start()
        print("🌐 웹서버 실행 중 (http://0.0.0.0:5000)")
        bot.run(TOKEN)
