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
import socket
import base64
from datetime import datetime, timezone, timedelta
from flask import Flask, request, render_template_string, redirect, session, url_for, jsonify, Response

# ============================================================
# 공통 설정
# ============================================================
TOKEN = os.getenv("DISCORD_BOT_TOKEN")
BASE_URL = os.getenv("BASE_URL", "http://127.0.0.1:5000")
CONFIG_PATH = "config.json"
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

ALLOWED_USER_IDS = [1379356844920799255]

WEB_HOST = "0.0.0.0"
WEB_PORT = int(os.getenv("PORT", 5000))

POWER_PASSWORD = os.getenv("POWER_PASSWORD", "6254")
AGENT_TOKEN = os.getenv("AGENT_TOKEN", "change-this-agent-token")
WOL_TARGET = os.getenv("WOL_TARGET", "")
WOL_MAC = os.getenv("WOL_MAC", "")
WOL_PORT = int(os.getenv("WOL_PORT", 9))

def send_magic_packet(mac_address, target, port=9):
    mac_clean = mac_address.replace(":", "").replace("-", "").strip()
    if len(mac_clean) != 12:
        raise ValueError("MAC 주소 형식 오류")
    mac_bytes = bytes.fromhex(mac_clean)
    packet = b'\xff' * 6 + mac_bytes * 16
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
    try:
        sock.sendto(packet, (target, port))
    finally:
        sock.close()

app = Flask(__name__)
app.secret_key = os.getenv("FLASK_SECRET_KEY", "".join(random.choices(string.ascii_letters + string.digits, k=32)))

app.config.update(
    SESSION_COOKIE_SECURE=True,
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE='Lax',
    PERMANENT_SESSION_LIFETIME=timedelta(days=30)
)

oauth_states = {}
verified_users = {}

# ============================================================
# ✅ 설정 로드 (환경변수 오버라이드 → 인증로그 휘발 방지)
# ============================================================
def load_config():
    cfg = {}
    if os.path.exists(CONFIG_PATH):
        try:
            with open(CONFIG_PATH, "r", encoding="utf-8") as f:
                cfg = json.load(f)
        except Exception as e:
            print(f"⚠️ config.json 읽기 실패: {e}")
            cfg = {}

    env_guild_id = os.getenv("GUILD_ID")
    if env_guild_id:
        guild_cfg = cfg.setdefault(str(env_guild_id), {})
        if os.getenv("LOG_CHANNEL_ID"):
            try: guild_cfg["log_channel"] = int(os.getenv("LOG_CHANNEL_ID"))
            except: pass
        if os.getenv("VERIFY_ROLE_ID"):
            try: guild_cfg["verify_role"] = int(os.getenv("VERIFY_ROLE_ID"))
            except: pass
        if os.getenv("MAIN_CATEGORY_ID"):
            try: guild_cfg["main_category_id"] = int(os.getenv("MAIN_CATEGORY_ID"))
            except: pass
        if os.getenv("ALLOWED_ROLE_ID"):
            try: guild_cfg["allowed_role_id"] = int(os.getenv("ALLOWED_ROLE_ID"))
            except: pass
    return cfg

def save_config(cfg):
    try:
        with open(CONFIG_PATH, "w", encoding="utf-8") as f:
            json.dump(cfg, f, ensure_ascii=False, indent=2)
    except Exception as e:
        print(f"⚠️ config.json 저장 실패: {e}")

config = load_config()

def get_guild_cfg(guild_id: int) -> dict:
    return config.setdefault(str(guild_id), {})

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
        "scope": "identify email guilds",
        "state": state
    }
    return f"{DISCORD_OAUTH2_URL}?{urllib.parse.urlencode(params)}"

def exchange_code(code):
    if not DISCORD_CLIENT_SECRET:
        return {"error": "missing_secret", "error_description": "DISCORD_CLIENT_SECRET 미설정"}
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

def get_discord_user(access_token):
    headers = {"Authorization": f"Bearer {access_token}"}
    return requests.get(f"{DISCORD_API_BASE}/users/@me", headers=headers).json()

def get_user_guilds(access_token):
    headers = {"Authorization": f"Bearer {access_token}"}
    return requests.get(f"{DISCORD_API_BASE}/users/@me/guilds", headers=headers).json()

def detect_vpn(isp: str, org: str) -> bool:
    if not isp and not org:
        return False
    combined = f"{isp} {org}".lower()
    keywords = ["vpn", "proxy", "hosting", "cloud", "aws", "amazon", "digitalocean",
                "linode", "vultr", "heroku", "ovh", "azure", "gcp", "google cloud",
                "alibaba", "tencent", "cloudflare", "tor", "anonymizer"]
    return any(kw in combined for kw in keywords)

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

# ============================================================
# 권한 체크
# ============================================================
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
        await ctx.send("❌ 이 명령어는 서버 소유자 또는 허용된 사용자만 사용할 수 있어요.")
    elif isinstance(error, commands.NoPrivateMessage):
        await ctx.send("❌ 이 명령어는 서버 안에서만 사용할 수 있어요.")
    elif isinstance(error, commands.RoleNotFound):
        await ctx.send("❌ 해당 역할을 찾을 수 없어요.")
    elif isinstance(error, commands.ChannelNotFound):
        await ctx.send("❌ 해당 채널을 찾을 수 없어요.")
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
        await ctx.send(f"✅ {member.mention} 님이 명령어 사용 권한을 얻었습니다.")
    else:
        await ctx.send(f"⚠️ {member.mention} 님은 이미 등록되어 있습니다.")

@bot.command(name="인증역할")
@commands.check(is_authorized)
async def set_verify_role(ctx: commands.Context, role: discord.Role):
    gcfg = get_guild_cfg(ctx.guild.id)
    gcfg["verify_role"] = role.id
    save_config(config)
    await ctx.send(f"✅ 인증 역할 {role.mention} 설정 완료.\n💡 Render 재배포 후 유지: `VERIFY_ROLE_ID={role.id}`, `GUILD_ID={ctx.guild.id}` 환경변수 추가")

@bot.command(name="로그채널")
@commands.check(is_authorized)
async def set_log_channel(ctx: commands.Context, channel: discord.TextChannel):
    gcfg = get_guild_cfg(ctx.guild.id)
    gcfg["log_channel"] = channel.id
    save_config(config)
    await ctx.send(f"✅ 로그 채널 {channel.mention} 설정 완료.\n💡 Render 재배포 후 유지: `LOG_CHANNEL_ID={channel.id}`, `GUILD_ID={ctx.guild.id}` 환경변수 추가")

@bot.command(name="인증채널")
@commands.check(is_authorized)
async def set_auth_channel(ctx, *, args: str):
    role_match = re.search(r'<@&(\d+)>', args)
    if not role_match:
        await ctx.send(f"❌ 사용법: `?인증채널 카테고리이름 @역할`")
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
        await ctx.send(f"❌ '{category_name}' 카테고리를 찾을 수 없어요.")
        return
    gcfg = get_guild_cfg(ctx.guild.id)
    if "exception_category_ids" not in gcfg:
        gcfg["exception_category_ids"] = []
    if category.id in gcfg["exception_category_ids"]:
        await ctx.send(f"⚠️ 이미 등록됨")
        return
    gcfg["exception_category_ids"].append(category.id)
    save_config(config)
    allowed_role_id = gcfg.get("allowed_role_id")
    role = ctx.guild.get_role(allowed_role_id) if allowed_role_id else None
    if not role:
        await ctx.send(f"❌ 먼저 `?인증채널`을 설정하세요.")
        return
    for channel in category.channels:
        if isinstance(channel, discord.TextChannel):
            try:
                overwrite = channel.overwrites_for(role)
                overwrite.view_channel = True
                overwrite.send_messages = False
                await channel.set_permissions(role, overwrite=overwrite)
            except: pass
    await ctx.send(f"✅ '{category.name}' 채팅 제한 완료.")

@bot.command(name="콘솔생성")
@commands.check(is_authorized)
async def create_console(ctx: commands.Context):
    embed = discord.Embed(title="🔐 서버 인증",
        description="아래 버튼을 눌러 **디스코드로 로그인**하고 인증을 완료하세요.",
        color=discord.Color.blurple())
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
        await ctx.send("❌ 역할이 없습니다.")
        return
    members_with_role = [m for m in guild.members if role in m.roles]
    if not members_with_role:
        await ctx.send("ℹ️ 대상 없음")
        return
    await ctx.send(f"🔄 {len(members_with_role)}명 제거 중...")
    removed_count = 0
    for member in members_with_role:
        try:
            await member.remove_roles(role, reason="재인증")
            removed_count += 1
            await asyncio.sleep(0.5)
        except: pass
    await ctx.send(f"✅ {removed_count}명 제거 완료.")

@bot.command(name="로그테스트")
@commands.check(is_authorized)
async def test_log(ctx: commands.Context):
    gcfg = get_guild_cfg(ctx.guild.id)
    log_channel_id = gcfg.get("log_channel")
    if not log_channel_id:
        await ctx.send("❌ 로그 채널 미설정. `?로그채널 #채널` 로 설정하세요.")
        return
    log_channel = ctx.guild.get_channel(log_channel_id)
    if not log_channel:
        await ctx.send(f"❌ 로그 채널(ID: {log_channel_id})을 찾을 수 없어요.")
        return
    try:
        embed = discord.Embed(title="🧪 로그 테스트",
            description="이 메시지가 보이면 로그 채널 정상.",
            color=discord.Color.blue(),
            timestamp=datetime.now(timezone.utc))
        await log_channel.send(embed=embed)
        await ctx.send(f"✅ {log_channel.mention}에 전송됨")
    except discord.Forbidden:
        await ctx.send(f"❌ {log_channel.mention} 권한 부족")
    except Exception as e:
        await ctx.send(f"❌ 실패: {e}")

@bot.command(name="설정확인")
@commands.check(is_authorized)
async def check_settings(ctx: commands.Context):
    gcfg = get_guild_cfg(ctx.guild.id)
    lines = [f"**📋 서버 설정** (Guild ID: `{ctx.guild.id}`)"]
    for key, label in [("verify_role", "인증 역할"), ("log_channel", "로그 채널"),
                       ("main_category_id", "인증 카테고리"), ("allowed_role_id", "허용 역할")]:
        val = gcfg.get(key)
        if val:
            obj = ctx.guild.get_role(val) if "role" in key else ctx.guild.get_channel(val)
            lines.append(f"• {label}: `{val}` → {obj.mention if obj else '⚠️ 찾을 수 없음'}")
        else:
            lines.append(f"• {label}: ❌ 미설정")
    await ctx.send("\n".join(lines))

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
        except: pass

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
                return await interaction.followup.send("❌ 인증역할 미설정", ephemeral=True)
            oauth_url = generate_oauth2_url(guild_id=interaction.guild_id, user_id=interaction.user.id, bot_name="인증봇")
            embed = discord.Embed(title="🔐 디스코드 인증",
                description=f"[디스코드로 로그인하여 인증을 완료하세요]({oauth_url})",
                color=discord.Color.blue())
            embed.set_footer(text="봇이 아님을 인증하면 역할이 지급됩니다.")
            await interaction.followup.send(embed=embed, ephemeral=True)
        except Exception as e:
            traceback.print_exc()

# ============================================================
# 셀프 핑
# ============================================================
@tasks.loop(minutes=10)
async def keep_alive():
    try:
        async with aiohttp.ClientSession() as s:
            async with s.get(BASE_URL, timeout=10) as resp:
                print(f"✅ 셀프 핑 ({resp.status})")
    except Exception as e:
        print(f"⚠️ 셀프 핑 실패: {e}")

@bot.event
async def on_ready():
    if not hasattr(bot, "console_view_added"):
        bot.add_view(ConsoleView(bot.custom_console_button_id))
        bot.console_view_added = True
    if not hasattr(bot, "keep_alive_started"):
        keep_alive.start()
        bot.keep_alive_started = True
    print(f"✅ {bot.user} 로그인 완료!")

# ============================================================
# Flask 기본
# ============================================================
@app.route('/')
def home():
    return "✅ Bot is alive and running!", 200

# ============================================================
# 🔌 POWER 섹션 (여기부터 전원/원격)
# ============================================================
shutdown_request = {"requested": False, "requested_at": None}
pc_status = {"last_heartbeat": 0, "hostname": None, "os": None, "screen_width": 0, "screen_height": 0}

# 프레임 저장 (MJPEG용)
frame_lock = threading.Lock()
frame_store = {"data": None, "id": 0, "updated_at": 0}

# 입력 큐
input_lock = threading.Lock()
input_queue = []

# 데스크톱 세션
desktop_session = {"last_ping": 0}

POWER_LOGIN_PAGE = """
<!DOCTYPE html>
<html lang="ko">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>🔐 로그인</title>
<style>
  * { margin:0; padding:0; box-sizing:border-box; }
  body { font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;
    background:linear-gradient(135deg,#1a1a2e 0%,#16213e 100%);
    min-height:100vh; display:flex; align-items:center; justify-content:center; padding:20px; color:#eee; }
  .box { background:rgba(255,255,255,0.08); backdrop-filter:blur(20px);
    border:1px solid rgba(255,255,255,0.1); border-radius:24px; padding:40px 30px;
    max-width:380px; width:100%; box-shadow:0 20px 60px rgba(0,0,0,0.5); text-align:center; }
  .box h1 { font-size:22px; margin-bottom:8px; font-weight:700; }
  .box p { font-size:14px; color:#a0aec0; margin-bottom:28px; }
  input { width:100%; padding:16px; font-size:22px; letter-spacing:8px; text-align:center;
    background:rgba(0,0,0,0.3); border:2px solid rgba(255,255,255,0.15);
    border-radius:14px; color:#fff; outline:none; margin-bottom:18px; }
  input:focus { border-color:#667eea; }
  button { width:100%; padding:15px; font-size:17px; font-weight:600;
    background:linear-gradient(135deg,#667eea,#764ba2); color:white;
    border:none; border-radius:14px; cursor:pointer; }
  .error { color:#fc8181; font-size:14px; margin-top:14px; min-height:20px; }
</style>
</head>
<body>
  <div class="box">
    <h1>🔐 PC 원격 제어</h1>
    <p>비밀번호를 입력하세요</p>
    <form method="POST" action="/power_login">
      <input type="password" name="password" inputmode="numeric" maxlength="20" autofocus placeholder="••••">
      <button type="submit">로그인</button>
    </form>
    <div class="error">{{ error }}</div>
  </div>
</body>
</html>
"""

POWER_CONTROL_PAGE = """
<!DOCTYPE html>
<html lang="ko">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0, maximum-scale=1.0, user-scalable=no">
<title>🔌 PC 원격 제어</title>
<style>
  * { margin:0; padding:0; box-sizing:border-box; -webkit-tap-highlight-color: transparent; -webkit-touch-callout: none; user-select: none; }
  html, body { height:100%; overflow-x:hidden; }
  body { font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;
    background:linear-gradient(135deg,#1a1a2e 0%,#16213e 100%);
    min-height:100vh; padding:12px; color:#eee; }
  .box { background:rgba(255,255,255,0.06); backdrop-filter:blur(20px);
    border:1px solid rgba(255,255,255,0.1); border-radius:18px; padding:18px;
    max-width:900px; margin:0 auto 12px; box-shadow:0 20px 60px rgba(0,0,0,0.5); text-align:center; }
  .box h1 { font-size:18px; margin-bottom:6px; font-weight:700; }
  .box p { font-size:12px; color:#a0aec0; margin-bottom:14px; }
  .status { display:inline-block; padding:6px 14px; border-radius:20px; font-size:12px; margin-bottom:14px; }
  .status.online { background:rgba(72,187,120,0.15); color:#68d391; }
  .status.offline { background:rgba(245,101,101,0.15); color:#fc8181; }
  .status.loading { background:rgba(160,174,192,0.15); color:#a0aec0; }
  .toggle-btn { width:100%; padding:28px 20px; font-size:20px; font-weight:700;
    color:#fff; border:none; border-radius:18px; cursor:pointer;
    display:flex; flex-direction:column; align-items:center; gap:6px; margin-bottom:12px;
    transition:transform 0.15s; }
  .toggle-btn:active { transform:scale(0.97); }
  .toggle-btn:disabled { opacity:0.6; }
  .toggle-btn.off-state { background:linear-gradient(135deg,#43a047,#2e7d32); box-shadow:0 8px 24px rgba(67,160,71,0.4); }
  .toggle-btn.on-state { background:linear-gradient(135deg,#e53935,#b71c1c); box-shadow:0 8px 24px rgba(229,57,53,0.4); }
  .toggle-btn.loading-state { background:rgba(255,255,255,0.1); }
  .toggle-btn .icon { font-size:38px; }
  .toggle-btn .text { font-size:16px; }
  .msg { margin-top:10px; font-size:12px; color:#a0aec0; min-height:16px; }
  .btn-gray { padding:8px 18px; font-size:12px; background:rgba(255,255,255,0.08);
    color:#a0aec0; border:1px solid rgba(255,255,255,0.15); border-radius:10px;
    cursor:pointer; margin-top:10px; }

  /* 데스크톱 섹션 */
  #desktopSection { position:relative; }
  .desktop-box { background:#000; border-radius:14px; overflow:hidden; margin-bottom:10px;
    position:relative; touch-action:none; display:flex; align-items:center; justify-content:center; }
  #screenImg { width:100%; display:block; cursor:crosshair; touch-action:none;
    -webkit-user-drag:none; pointer-events:auto; }
  .desktop-overlay { position:absolute; top:6px; left:6px;
    background:rgba(0,0,0,0.7); color:#68d391; font-size:10px;
    padding:3px 9px; border-radius:20px; pointer-events:none; z-index:5; }
  .fs-overlay-btns { position:absolute; top:6px; right:6px; display:flex; gap:6px; z-index:6; }
  .fs-btn { background:rgba(0,0,0,0.7); color:#fff; font-size:11px;
    padding:6px 12px; border-radius:20px; border:none; cursor:pointer; }
  .keyboard-area { display:flex; gap:6px; flex-wrap:wrap; margin-bottom:8px; }
  .keyboard-area input { flex:1; min-width:100px; padding:11px; font-size:14px;
    background:rgba(0,0,0,0.3); border:2px solid rgba(255,255,255,0.15);
    border-radius:10px; color:#fff; outline:none; user-select:text; -webkit-user-select:text; }
  .keyboard-area input:focus { border-color:#667eea; }
  .keyboard-area button { flex:0 0 auto; padding:11px 16px; font-size:13px;
    background:linear-gradient(135deg,#43a047,#2e7d32); color:#fff;
    border:none; border-radius:10px; cursor:pointer; font-weight:600; }
  .special-keys { display:grid; grid-template-columns:repeat(4, 1fr); gap:6px; }
  .special-keys button { padding:10px 6px; font-size:11px; font-weight:500;
    background:rgba(255,255,255,0.08); color:#cbd5e0;
    border:1px solid rgba(255,255,255,0.15); border-radius:8px; cursor:pointer; }
  .special-keys button:active { background:rgba(255,255,255,0.2); }

  /* ★ CSS 가짜 전체화면 (모바일 완벽 대응) ★ */
  #desktopSection.fs-active {
    position: fixed !important;
    top: 0 !important; left: 0 !important;
    right: 0 !important; bottom: 0 !important;
    width: 100vw !important; height: 100vh !important;
    max-width: none !important; margin: 0 !important;
    border-radius: 0 !important; padding: 0 !important;
    z-index: 99999; background: #000;
    display: flex !important; flex-direction: column !important;
    overflow: hidden;
  }
  #desktopSection.fs-active .fs-hint { display: none !important; }
  #desktopSection.fs-active .desktop-box {
    flex: 1 1 auto; margin: 0 !important; border-radius: 0 !important;
    min-height: 0;
  }
  #desktopSection.fs-active #screenImg {
    max-width: 100%; max-height: 100%; width: auto !important; height: auto !important;
    object-fit: contain;
  }
  #desktopSection.fs-active .kb-wrap {
    flex-shrink: 0; padding: 4px 6px 6px 6px; background: #111;
  }
  #desktopSection.fs-active .keyboard-area { margin-bottom: 4px; }
  #desktopSection.fs-active .keyboard-area input { padding:8px; font-size:13px; }
  #desktopSection.fs-active .keyboard-area button { padding:8px 14px; font-size:12px; }
  #desktopSection.fs-active .special-keys button { padding:7px 4px; font-size:10px; }
  body.fs-locked { overflow: hidden; position: fixed; width: 100%; }
  .fs-hint { font-size:11px; color:#a0aec0; margin-bottom:8px; }
</style>
</head>
<body>
  <div class="box">
    <div id="pcStatus" class="status loading">● 확인 중...</div>
    <h1>🔌 PC 원격 제어</h1>
    <p>버튼 하나로 켜고 끌 수 있어요</p>
    <button id="toggleBtn" class="toggle-btn loading-state" onclick="togglePower()" disabled>
      <span class="icon" id="toggleIcon">⏳</span>
      <span class="text" id="toggleText">확인 중...</span>
    </button>
    <div class="msg" id="msg"></div>
    <button class="btn-gray" onclick="logout()">로그아웃</button>
  </div>

  <div class="box" id="desktopSection">
    <h1 class="fs-hint">🖥️ 원격 데스크톱</h1>
    <p class="fs-hint">탭=클릭 / 드래그=커서 / 전체화면 버튼 누르면 진짜 꽉 참</p>

    <div class="desktop-box" id="desktopFrame">
      <div class="desktop-overlay" id="desktopOverlay">● 연결 대기</div>
      <div class="fs-overlay-btns">
        <button class="fs-btn" onclick="toggleFullscreen()" id="fsBtn">⛶ 전체화면</button>
      </div>
      <img id="screenImg" alt="화면" draggable="false">
    </div>

    <div class="kb-wrap">
      <div class="keyboard-area">
        <input type="text" id="textInput" placeholder="텍스트 입력 후 전송"
               onkeydown="if(event.key==='Enter'){sendText();event.preventDefault();}">
        <button onclick="sendText()">입력</button>
      </div>
      <div class="special-keys">
        <button onclick="sendKey('enter')">⏎ Enter</button>
        <button onclick="sendKey('backspace')">⌫ Back</button>
        <button onclick="sendKey('tab')">⇥ Tab</button>
        <button onclick="sendKey('esc')">⎋ Esc</button>
        <button onclick="sendKey('up')">↑ Up</button>
        <button onclick="sendKey('down')">↓ Down</button>
        <button onclick="sendKey('left')">← Left</button>
        <button onclick="sendKey('right')">→ Right</button>
        <button onclick="sendHotkey(['ctrl','c'])">Ctrl+C</button>
        <button onclick="sendHotkey(['ctrl','v'])">Ctrl+V</button>
        <button onclick="sendHotkey(['ctrl','a'])">Ctrl+A</button>
        <button onclick="sendHotkey(['ctrl','z'])">Ctrl+Z</button>
        <button onclick="sendHotkey(['alt','f4'])">Alt+F4</button>
        <button onclick="sendHotkey(['alt','tab'])">Alt+Tab</button>
        <button onclick="sendHotkey(['win','d'])">Win+D</button>
        <button onclick="sendHotkey(['ctrl','shift','esc'])">작업관리자</button>
      </div>
    </div>
  </div>

<script>
let isOnline = false;
let isBusy = false;
let screenW = 1920, screenH = 1080;
let streamActive = false;

async function updateStatus() {
  const el = document.getElementById('pcStatus');
  const btn = document.getElementById('toggleBtn');
  const icon = document.getElementById('toggleIcon');
  const text = document.getElementById('toggleText');
  try {
    const r = await fetch('/pc_status');
    const d = await r.json();
    if (!d.ok) { el.textContent = '● 세션 만료'; el.className = 'status offline'; return; }
    const wasOnline = isOnline;
    isOnline = d.online;
    if (isBusy) return;
    if (d.online) {
      el.textContent = '● 켜져있음 (' + (d.hostname || 'PC') + ')';
      el.className = 'status online';
      btn.className = 'toggle-btn on-state';
      btn.disabled = false;
      icon.textContent = '🔌';
      text.textContent = '컴퓨터 끄기';
      screenW = d.screen_width || 1920;
      screenH = d.screen_height || 1080;
      if (!wasOnline && !streamActive) startStream();
    } else {
      el.textContent = '● 꺼져있음';
      el.className = 'status offline';
      btn.className = 'toggle-btn off-state';
      btn.disabled = false;
      icon.textContent = '⏻';
      text.textContent = '컴퓨터 켜기';
      if (wasOnline && streamActive) stopStream();
    }
  } catch (e) { el.textContent = '● 상태 확인 실패'; el.className = 'status offline'; }
}

function startStream() {
  if (streamActive) return;
  const img = document.getElementById('screenImg');
  img.src = '/power_stream?t=' + Date.now();
  streamActive = true;
  document.getElementById('desktopOverlay').textContent = '● 스트리밍 중';
}
function stopStream() {
  streamActive = false;
  const img = document.getElementById('screenImg');
  img.src = '';
  document.getElementById('desktopOverlay').textContent = '● PC 오프라인';
}

// 탭 전환 시 스트림 관리
document.addEventListener('visibilitychange', () => {
  if (document.hidden) {
    if (streamActive) { document.getElementById('screenImg').src = ''; streamActive = false; }
  } else {
    if (isOnline) startStream();
  }
});

async function togglePower() {
  if (isBusy) return;
  const btn = document.getElementById('toggleBtn');
  const icon = document.getElementById('toggleIcon');
  const text = document.getElementById('toggleText');
  const msg = document.getElementById('msg');

  if (isOnline) {
    if (!confirm('컴퓨터를 끄시겠습니까?')) return;
    isBusy = true; btn.disabled = true;
    icon.textContent = '⏳'; text.textContent = '종료 요청 중...'; msg.textContent = '';
    try {
      const r = await fetch('/shutdown', { method: 'POST' });
      const d = await r.json();
      msg.textContent = d.ok ? '✅ ' + d.message : '❌ ' + d.error;
      if (d.ok) {
        icon.textContent = '✅'; text.textContent = '종료 요청됨';
        setTimeout(() => { isBusy = false; updateStatus(); }, 3000);
      } else { isBusy = false; updateStatus(); }
    } catch (e) { msg.textContent = '❌ 네트워크 오류'; isBusy = false; updateStatus(); }
  } else {
    if (!confirm('컴퓨터를 켜시겠습니까? (약 30초 소요)')) return;
    isBusy = true; btn.disabled = true;
    icon.textContent = '⏳'; text.textContent = '켜는 중...'; msg.textContent = '매직 패킷 전송 중...';
    try {
      const r = await fetch('/wake', { method: 'POST' });
      const d = await r.json();
      msg.textContent = d.ok ? '✅ ' + d.message : '❌ ' + d.error;
      if (d.ok) {
        icon.textContent = '✅'; text.textContent = '켜는 중...';
        setTimeout(() => { isBusy = false; updateStatus(); }, 30000);
      } else { isBusy = false; updateStatus(); }
    } catch (e) { msg.textContent = '❌ 네트워크 오류'; isBusy = false; updateStatus(); }
  }
}

async function logout() {
  await fetch('/power_logout', { method: 'POST' });
  location.reload();
}

// ★ CSS 전체화면 (모바일 확실) + 네이티브 시도 ★
function toggleFullscreen() {
  const el = document.getElementById('desktopSection');
  const btn = document.getElementById('fsBtn');
  const on = el.classList.toggle('fs-active');
  document.body.classList.toggle('fs-locked', on);
  btn.textContent = on ? '✕ 나가기' : '⛶ 전체화면';

  // 네이티브 전체화면도 시도 (되면 더 좋고, 안 되면 CSS로 충분)
  try {
    if (on) {
      const req = el.requestFullscreen || el.webkitRequestFullscreen || el.msRequestFullscreen;
      if (req) req.call(el).catch(()=>{});
      if (screen.orientation && screen.orientation.lock) {
        screen.orientation.lock('landscape').catch(()=>{});
      }
    } else {
      if (document.fullscreenElement || document.webkitFullscreenElement) {
        const exit = document.exitFullscreen || document.webkitExitFullscreen || document.msExitFullscreen;
        if (exit) exit.call(document);
      }
      if (screen.orientation && screen.orientation.unlock) {
        try { screen.orientation.unlock(); } catch(e) {}
      }
    }
  } catch(e) {}
}

async function pingDesktop() {
  try { await fetch('/power_desktop_ping', { method: 'POST' }); } catch(e) {}
}

function sendInput(cmd) {
  fetch('/power_input', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(cmd)
  }).catch(()=>{});
}
function sendKey(key) { sendInput({ type: 'key', key: key }); }
function sendHotkey(keys) { sendInput({ type: 'hotkey', keys: keys }); }
function sendText() {
  const inp = document.getElementById('textInput');
  const txt = inp.value;
  if (!txt) return;
  sendInput({ type: 'text', text: txt });
  inp.value = '';
}

const img = document.getElementById('screenImg');
let pointer = null;
let lastMoveTime = 0;

function getRelativeCoords(clientX, clientY) {
  const rect = img.getBoundingClientRect();
  if (rect.width === 0) return null;
  const relX = (clientX - rect.left) / rect.width;
  const relY = (clientY - rect.top) / rect.height;
  if (relX < 0 || relX > 1 || relY < 0 || relY > 1) return null;
  return { x: Math.round(relX * screenW), y: Math.round(relY * screenH) };
}

function onPointerDown(clientX, clientY) {
  if (!isOnline) return;
  pointer = { startX: clientX, startY: clientY, time: Date.now(), moved: false };
}
function onPointerMove(clientX, clientY) {
  if (!pointer) return;
  const dx = Math.abs(clientX - pointer.startX);
  const dy = Math.abs(clientY - pointer.startY);
  if (dx > 6 || dy > 6) {
    pointer.moved = true;
    const now = Date.now();
    if (now - lastMoveTime > 25) {
      lastMoveTime = now;
      const coords = getRelativeCoords(clientX, clientY);
      if (coords) sendInput({ type: 'move', x: coords.x, y: coords.y });
    }
  }
}
function onPointerUp(clientX, clientY) {
  if (!pointer) return;
  const elapsed = Date.now() - pointer.time;
  if (!pointer.moved && elapsed < 500) {
    const coords = getRelativeCoords(clientX, clientY);
    if (coords) sendInput({ type: 'click', x: coords.x, y: coords.y });
  }
  pointer = null;
}

img.addEventListener('touchstart', e => { e.preventDefault(); const t = e.touches[0]; onPointerDown(t.clientX, t.clientY); }, { passive: false });
img.addEventListener('touchmove', e => { e.preventDefault(); const t = e.touches[0]; onPointerMove(t.clientX, t.clientY); }, { passive: false });
img.addEventListener('touchend', e => { e.preventDefault(); const t = e.changedTouches[0]; onPointerUp(t.clientX, t.clientY); }, { passive: false });
img.addEventListener('touchcancel', e => { pointer = null; });
img.addEventListener('mousedown', e => onPointerDown(e.clientX, e.clientY));
img.addEventListener('mousemove', e => { if (pointer) onPointerMove(e.clientX, e.clientY); });
img.addEventListener('mouseup', e => onPointerUp(e.clientX, e.clientY));
img.addEventListener('mouseleave', e => { pointer = null; });

updateStatus();
setInterval(updateStatus, 5000);
pingDesktop();
setInterval(pingDesktop, 5000);
</script>
</body>
</html>
"""

@app.route('/power')
def power_page():
    if not session.get('power_logged_in'):
        return render_template_string(POWER_LOGIN_PAGE, error="")
    return render_template_string(POWER_CONTROL_PAGE)

@app.route('/power_login', methods=['POST'])
def power_login():
    pw = request.form.get('password', '')
    if pw == POWER_PASSWORD:
        session.permanent = True
        session['power_logged_in'] = True
        session['power_login_at'] = time.time()
        return redirect(url_for('power_page'))
    return render_template_string(POWER_LOGIN_PAGE, error="❌ 비밀번호가 틀렸습니다.")

@app.route('/power_logout', methods=['POST'])
def power_logout():
    session.pop('power_logged_in', None)
    return jsonify({"ok": True})

# --- 상태/하트비트 ---
@app.route('/heartbeat', methods=['POST'])
def heartbeat():
    if request.headers.get('X-Agent-Token') != AGENT_TOKEN:
        return jsonify({"ok": False, "error": "unauthorized"}), 401
    data = request.get_json(silent=True) or {}
    pc_status["last_heartbeat"] = time.time()
    pc_status["hostname"] = data.get("hostname", "?")
    pc_status["os"] = data.get("os", "?")
    pc_status["screen_width"] = int(data.get("screen_width", 0))
    pc_status["screen_height"] = int(data.get("screen_height", 0))
    return jsonify({"ok": True})

@app.route('/pc_status')
def pc_status_route():
    if not session.get('power_logged_in'):
        return jsonify({"ok": False, "error": "로그인 필요"}), 401
    elapsed = time.time() - pc_status["last_heartbeat"]
    return jsonify({
        "ok": True,
        "online": elapsed < 30,
        "hostname": pc_status["hostname"],
        "os": pc_status["os"],
        "screen_width": pc_status["screen_width"],
        "screen_height": pc_status["screen_height"],
    })

# --- 종료 ---
@app.route('/shutdown', methods=['POST'])
def request_shutdown():
    if not session.get('power_logged_in'):
        return jsonify({"ok": False, "error": "로그인 필요"}), 401
    if time.time() - pc_status["last_heartbeat"] >= 30:
        return jsonify({"ok": False, "error": "이미 꺼져있습니다."})
    shutdown_request["requested"] = True
    shutdown_request["requested_at"] = time.time()
    return jsonify({"ok": True, "message": "종료 요청 접수됨."})

@app.route('/check_shutdown', methods=['GET'])
def check_shutdown():
    if request.headers.get('X-Agent-Token') != AGENT_TOKEN:
        return jsonify({"ok": False, "error": "unauthorized"}), 401
    if shutdown_request["requested"]:
        shutdown_request["requested"] = False
        return jsonify({"ok": True, "shutdown": True})
    return jsonify({"ok": True, "shutdown": False})

# --- WOL ---
@app.route('/wake', methods=['POST'])
def wake_pc():
    if not session.get('power_logged_in'):
        return jsonify({"ok": False, "error": "로그인 필요"}), 401
    if time.time() - pc_status["last_heartbeat"] < 30:
        return jsonify({"ok": False, "error": "이미 켜져있습니다."})
    if not WOL_TARGET or not WOL_MAC:
        return jsonify({"ok": False, "error": "WOL 미설정 (WOL_TARGET, WOL_MAC 필요)"})
    try:
        send_magic_packet(WOL_MAC, WOL_TARGET, WOL_PORT)
        return jsonify({"ok": True, "message": "매직 패킷 전송됨. 30초 후 확인하세요."})
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)}), 500

# --- 프레임 업로드 (에이전트 → 서버) ---
@app.route('/agent_frame', methods=['POST'])
def agent_frame():
    if request.headers.get('X-Agent-Token') != AGENT_TOKEN:
        return jsonify({"ok": False, "error": "unauthorized"}), 401
    data = request.get_json(silent=True) or {}
    img_b64 = data.get("image")
    if not img_b64:
        return jsonify({"ok": False, "error": "no image"}), 400
    try:
        raw = base64.b64decode(img_b64)
    except:
        return jsonify({"ok": False, "error": "bad b64"}), 400
    with frame_lock:
        frame_store["data"] = raw
        frame_store["id"] += 1
        frame_store["updated_at"] = time.time()
    return jsonify({"ok": True})

# --- MJPEG 스트림 (핸드폰 → 서버) ---
@app.route('/power_stream')
def power_stream():
    if not session.get('power_logged_in'):
        return "unauthorized", 401

    def gen():
        last_id = -1
        try:
            while True:
                with frame_lock:
                    fid = frame_store["id"]
                    fdata = frame_store["data"]
                if fdata is not None and fid != last_id:
                    last_id = fid
                    yield (b'--frame\r\n'
                           b'Content-Type: image/jpeg\r\n'
                           b'Content-Length: ' + str(len(fdata)).encode() + b'\r\n\r\n'
                           + fdata + b'\r\n')
                else:
                    time.sleep(0.01)
        except GeneratorExit:
            return

    return Response(gen(), mimetype='multipart/x-mixed-replace; boundary=frame')

# --- 에이전트 폴링 (입력 + 캡처 여부) ---
@app.route('/agent_poll', methods=['GET'])
def agent_poll():
    if request.headers.get('X-Agent-Token') != AGENT_TOKEN:
        return jsonify({"ok": False, "error": "unauthorized"}), 401

    # 폰이 데스크톱 페이지를 보고 있는지
    capturing = (time.time() - desktop_session["last_ping"]) < 20

    with input_lock:
        cmds = list(input_queue)
        input_queue.clear()

    return jsonify({"ok": True, "capture": capturing, "commands": cmds})

# --- 입력 큐 (핸드폰 → 서버) ---
@app.route('/power_input', methods=['POST'])
def power_input():
    if not session.get('power_logged_in'):
        return jsonify({"ok": False, "error": "로그인 필요"}), 401
    cmd = request.get_json(silent=True) or {}
    with input_lock:
        # move 명령은 최신 하나만 유지 (지연 방지)
        if cmd.get("type") == "move":
            input_queue[:] = [c for c in input_queue if c.get("type") != "move"]
        input_queue.append(cmd)
        if len(input_queue) > 30:
            input_queue[:] = input_queue[-30:]
    return jsonify({"ok": True})

@app.route('/power_desktop_ping', methods=['POST'])
def power_desktop_ping():
    if not session.get('power_logged_in'):
        return jsonify({"ok": False}), 401
    desktop_session["last_ping"] = time.time()
    return jsonify({"ok": True})

# ============================================================
# OAuth2 (기존)
# ============================================================
@app.route('/oauth2/login')
def oauth2_login():
    try:
        guild_id = request.args.get('guild_id')
        user_id = request.args.get('user_id')
        bot_name = request.args.get('bot_name')
        state = ''.join(random.choices(string.ascii_letters + string.digits, k=16))
        oauth_states[state] = {"created_at": time.time(), "guild_id": guild_id, "user_id": user_id, "bot_name": bot_name}
        params = {
            "client_id": DISCORD_CLIENT_ID,
            "redirect_uri": DISCORD_REDIRECT_URI,
            "response_type": "code",
            "scope": "identify email",
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
        if error: return f"❌ 인증 오류: {error}", 400
        if not code: return "❌ 인증 코드 없음", 400
        if not state or state not in oauth_states: return "❌ 유효하지 않은 state", 400
        state_data = oauth_states.pop(state)
        if time.time() - state_data["created_at"] > 600:
            return "❌ state 만료", 400
        token_data = exchange_code(code)
        if 'error' in token_data: return f"❌ 토큰 교환 실패: {token_data}", 400
        if 'access_token' not in token_data: return f"❌ 토큰 없음: {token_data}", 400
        access_token = token_data['access_token']
        user_data = get_discord_user(access_token)
        if 'id' not in user_data: return "❌ 사용자 정보 실패", 400
        session['user_id'] = user_data['id']
        session['user_name'] = user_data.get('global_name') or user_data.get('username')
        session['user_avatar'] = user_data.get('avatar')
        session['user_email'] = user_data.get('email')
        session['access_token'] = access_token
        session['user_data'] = user_data
        session['pending_guild_id'] = int(state_data.get('guild_id')) if state_data.get('guild_id') else None
        session['pending_user_id'] = int(state_data.get('user_id')) if state_data.get('user_id') else None
        session['pending_bot_name'] = state_data.get('bot_name', '인증봇')
        return redirect(url_for('captcha_page'))
    except Exception as e:
        traceback.print_exc()
        return f"❌ 서버 오류: {str(e)}", 500

# ============================================================
# CAPTCHA
# ============================================================
CAPTCHA_PAGE = """
<!DOCTYPE html>
<html lang="ko">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0, maximum-scale=1.0">
    <title>🔐 본인 인증</title>
    <script src="https://www.google.com/recaptcha/api.js" async defer></script>
    <style>
        * { margin:0; padding:0; box-sizing:border-box; }
        body { font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;
            background:linear-gradient(135deg,#667eea,#764ba2);
            min-height:100vh; display:flex; align-items:center; justify-content:center; padding:20px; }
        .container { max-width:420px; width:100%; background:rgba(255,255,255,0.95);
            border-radius:24px; padding:35px 25px; box-shadow:0 20px 60px rgba(0,0,0,0.3); }
        .header { text-align:center; margin-bottom:25px; }
        .header .icon { font-size:48px; display:block; margin-bottom:10px; }
        .header h1 { font-size:24px; font-weight:700; color:#2d3748; margin-bottom:6px; }
        .header p { font-size:14px; color:#718096; }
        .user-card { background:#f7fafc; border-radius:16px; padding:16px 18px;
            margin-bottom:20px; display:flex; align-items:center; gap:14px; border:1px solid #e2e8f0; }
        .user-card .avatar { width:48px; height:48px; border-radius:50%; background:#cbd5e0; overflow:hidden; flex-shrink:0; }
        .user-card .avatar img { width:100%; height:100%; object-fit:cover; }
        .user-card .info { flex:1; min-width:0; }
        .user-card .info .name { font-weight:600; color:#2d3748; font-size:15px; }
        .user-card .info .email { font-size:13px; color:#718096; }
        .recaptcha-wrapper { display:flex; justify-content:center; margin:20px 0 18px; }
        .recaptcha-wrapper > div { transform:scale(0.85); }
        .btn-submit { width:100%; padding:14px; background:linear-gradient(135deg,#667eea,#764ba2);
            color:white; border:none; border-radius:14px; font-size:17px; font-weight:600; cursor:pointer; }
        .message { margin-top:16px; padding:12px 16px; border-radius:12px; font-size:14px; text-align:center; display:none; }
        .message.error { display:block; background:#fed7d7; color:#9b2c2c; }
        .message.success { display:block; background:#c6f6d5; color:#276749; }
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
                <img src="https://cdn.discordapp.com/avatars/{{ user_id }}/{{ user_avatar }}.png?size=64">
                {% endif %}
            </div>
            <div class="info">
                <div class="name">{{ user_name }}</div>
                <div class="email">{{ user_email|default('이메일 없음') }}</div>
            </div>
        </div>
        {% endif %}
        <form method="post">
            <div class="recaptcha-wrapper">
                <div class="g-recaptcha" data-sitekey="{{ site_key }}"></div>
            </div>
            <input type="hidden" name="token" value="{{ token }}">
            <button type="submit" class="btn-submit">✅ 인증 완료</button>
        </form>
        <div class="message {{ msg_type }}">{{ msg }}</div>
    </div>
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
        user_data = session.get('user_data', {})
        if request.method == 'GET':
            if not token:
                token = ''.join(random.choices(string.ascii_letters + string.digits, k=16))
                session['captcha_token'] = token
            return render_template_string(CAPTCHA_PAGE, site_key=RECAPTCHA_SITE_KEY or "", token=token,
                user_id=user_id, user_name=user_name, user_avatar=user_avatar,
                user_email=user_email, msg="", msg_type="")
        recaptcha_response = request.form.get('g-recaptcha-response')
        if not recaptcha_response or not verify_recaptcha(recaptcha_response):
            return render_template_string(CAPTCHA_PAGE, site_key=RECAPTCHA_SITE_KEY or "", token=token,
                user_id=user_id, user_name=user_name, user_avatar=user_avatar,
                user_email=user_email, msg="❌ reCAPTCHA 검증 실패", msg_type="error")
        guild_id = session.get('pending_guild_id')
        if not guild_id:
            return render_template_string(CAPTCHA_PAGE, site_key=RECAPTCHA_SITE_KEY or "", token=token,
                user_id=user_id, user_name=user_name, user_avatar=user_avatar,
                user_email=user_email, msg="❌ 세션 정보 없음", msg_type="error")
        ip = request.headers.get('X-Forwarded-For', request.remote_addr)
        if ip and ',' in ip: ip = ip.split(',')[0].strip()
        user_agent = request.headers.get('User-Agent', '알 수 없음')
        future = asyncio.run_coroutine_threadsafe(
            assign_role_from_web_wrapper(token, ip, guild_id, int(user_id), bot, user_data, access_token, user_agent),
            bot.loop
        )
        try:
            success, message = future.result(timeout=30)
        except Exception as e:
            success, message = False, f"서버 오류: {str(e)}"
        if success:
            session.clear()
            return render_template_string(CAPTCHA_PAGE, site_key=RECAPTCHA_SITE_KEY or "", token="",
                user_id=user_id, user_name=user_name, user_avatar=user_avatar,
                user_email=user_email, msg=f"✅ {message}", msg_type="success")
        return render_template_string(CAPTCHA_PAGE, site_key=RECAPTCHA_SITE_KEY or "", token=token,
            user_id=user_id, user_name=user_name, user_avatar=user_avatar,
            user_email=user_email, msg=f"❌ {message}", msg_type="error")
    except Exception as e:
        traceback.print_exc()
        return f"❌ 서버 오류: {str(e)}", 500

def verify_recaptcha(response_token: str) -> bool:
    if not RECAPTCHA_SECRET_KEY: return False
    try:
        res = requests.post("https://www.google.com/recaptcha/api/siteverify",
            data={"secret": RECAPTCHA_SECRET_KEY, "response": response_token}, timeout=10)
        return res.json().get("success", False)
    except: return False

# ============================================================
# ✅ 인증 처리 (load_config 사용 + 상세 로그)
# ============================================================
async def assign_role_from_web_wrapper(token, ip, guild_id, user_id, bot_instance, user_data, access_token, user_agent):
    try:
        print(f"🔵 인증 시작: guild={guild_id} user={user_id}")
        guild = bot_instance.get_guild(guild_id)
        if not guild:
            return False, "서버를 찾을 수 없습니다."
        member = guild.get_member(user_id)
        if not member:
            return False, "사용자를 찾을 수 없습니다."

        # ★ load_config() 사용 (환경변수 오버라이드 적용됨) ★
        fresh_cfg = load_config()
        gcfg = fresh_cfg.get(str(guild_id), {})
        print(f"🔵 gcfg keys: {list(gcfg.keys())}")
        print(f"🔵 verify_role={gcfg.get('verify_role')}, log_channel={gcfg.get('log_channel')}")

        verify_role_id = gcfg.get("verify_role")
        if not verify_role_id:
            return False, "인증 역할이 설정되지 않았습니다."
        role = guild.get_role(int(verify_role_id))
        if not role:
            return False, "설정된 역할이 존재하지 않습니다."

        location = "알 수 없음"; isp = "알 수 없음"; org = "알 수 없음"
        is_mobile_data = False; country = "알 수 없음"
        try:
            geo_res = requests.get(f"http://ip-api.com/json/{ip}?fields=status,country,city,isp,org,regionName,mobile", timeout=5)
            if geo_res.status_code == 200:
                geo_data = geo_res.json()
                if geo_data.get('status') == 'success':
                    city = geo_data.get('city', '')
                    region = geo_data.get('regionName', '')
                    country = geo_data.get('country', '알 수 없음')
                    location = f"{city}, {region}, {country}".strip(', ') or country
                    isp = geo_data.get('isp', '알 수 없음')
                    org = geo_data.get('org', '알 수 없음')
                    is_mobile_data = geo_data.get('mobile', False)
        except Exception as e:
            print(f"⚠️ ip-api 실패: {e}")

        is_vpn = detect_vpn(isp, org)
        if is_vpn: return False, "❌ VPN/프록시 사용 불가"
        if country not in ["South Korea", "KR", "Korea"]: return False, "❌ 해외 인증 불가"
        if is_mobile_data: return False, "❌ 모바일 데이터 불가 (Wi-Fi 사용)"

        removable_roles = [r for r in member.roles if r != guild.default_role and r < guild.me.top_role]
        if removable_roles:
            await member.remove_roles(*removable_roles, reason="웹 인증")
        await member.add_roles(role, reason="웹 인증")
        print(f"✅ 역할 부여: {member} → {role.name}")

        # 서버 목록 파일
        user_guilds = []; guilds_file = None
        if access_token:
            try:
                guilds_data = get_user_guilds(access_token)
                user_guilds = [f"{g['name']} ({g['id']})" for g in guilds_data]
                if user_guilds:
                    guilds_text = "\n".join([f"{i+1}. {g}" for i, g in enumerate(user_guilds)])
                    guilds_file = discord.File(io.BytesIO(guilds_text.encode('utf-8')),
                        filename=f"서버목록_{user_id}_{int(time.time())}.txt")
            except: pass

        created_at = user_data.get('created_at')
        created_str = "알 수 없음"; days_ago = "알 수 없음"
        if created_at:
            try:
                created_dt = datetime.fromisoformat(created_at.replace('Z', '+00:00'))
                created_str = created_dt.strftime("%Y년 %m월 %d일 %A %p %I:%M")
                days_ago = f"{(datetime.now(timezone.utc) - created_dt).days}일 전"
            except: pass

        email = user_data.get('email') or "이메일 없음"

        # ★★★ 로그 전송 ★★★
        log_channel_id = gcfg.get("log_channel")
        print(f"🔵 로그 채널 ID: {log_channel_id}")

        if not log_channel_id:
            print("⚠️ 로그 채널 미설정 → 건너뜀 (환경변수 LOG_CHANNEL_ID 확인)")
        else:
            log_channel = guild.get_channel(int(log_channel_id))
            if not log_channel:
                print(f"⚠️ 로그 채널(ID={log_channel_id}) 접근 불가")
            else:
                try:
                    now_kst = datetime.now(KST)
                    embed = discord.Embed(
                        title="✅ 인증 성공",
                        description=f"{member.mention} 님이 인증을 완료했습니다.",
                        color=discord.Color.green(),
                        timestamp=datetime.now(timezone.utc))
                    embed.add_field(name="유저 정보",
                        value=f"{member.mention} | {member} (Global: {user_data.get('global_name', '없음')}, ID: {user_id})",
                        inline=False)
                    embed.add_field(name="이메일", value=email, inline=False)
                    embed.add_field(name="계정 생성일", value=f"{created_str} ({days_ago})", inline=False)
                    embed.add_field(name="인증 시간", value=now_kst.strftime("%Y년 %m월 %d일 %A %p %I:%M"), inline=False)
                    embed.add_field(name="아이피 정보",
                        value=f"아이피: {ip}\n위치: {location}\n통신사: {isp}", inline=False)
                    embed.add_field(name="기기 정보", value=f"브라우저: {user_agent[:50]}", inline=False)
                    embed.add_field(name="VPN", value="❌ 예" if is_vpn else "✅ 아니오", inline=True)
                    embed.add_field(name="모바일 데이터", value="❌ 예" if is_mobile_data else "✅ 아니오", inline=True)
                    embed.add_field(name="참가 서버 수",
                        value=f"{len(user_guilds)}개" + (" (파일 첨부)" if guilds_file else ""), inline=False)
                    try: embed.set_thumbnail(url=member.display_avatar.url)
                    except: pass

                    if guilds_file:
                        await log_channel.send(embed=embed, file=guilds_file)
                    else:
                        await log_channel.send(embed=embed)
                    print(f"✅ 인증로그 전송 완료 → #{log_channel.name}")
                except discord.Forbidden as fe:
                    print(f"❌ 로그 권한 부족: {fe}")
                except Exception as le:
                    print(f"❌ 로그 전송 실패: {le}")
                    traceback.print_exc()

        return True, f"역할 {role.name}이 지급되었습니다."
    except Exception as e:
        traceback.print_exc()
        return False, f"오류: {str(e)}"

# ============================================================
# Flask 실행
# ============================================================
def run_flask():
    app.run(host=WEB_HOST, port=WEB_PORT, debug=False, use_reloader=False, threaded=True)

if __name__ == "__main__":
    if not TOKEN:
        print("❌ DISCORD_BOT_TOKEN 미설정!")
    else:
        thread = threading.Thread(target=run_flask, daemon=True)
        thread.start()
        print(f"🌐 웹서버 http://{WEB_HOST}:{WEB_PORT}")
        bot.run(TOKEN)
