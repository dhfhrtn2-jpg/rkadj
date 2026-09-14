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
from datetime import datetime, timezone, timedelta
from flask import Flask, request, render_template_string, redirect, session, url_for, jsonify

# ============================================================
# 공통 설정 (환경변수)
# ============================================================
TOKEN = os.getenv("DISCORD_BOT_TOKEN")
BASE_URL = os.getenv("BASE_URL", "https://rkadj.onrender.com")
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

ALLOWED_USER_IDS = [
    1379356844920799255,
]

WEB_HOST = "0.0.0.0"
WEB_PORT = int(os.getenv("PORT", 5000))

# ============================================================
# 전원 제어 설정
# ============================================================
POWER_PASSWORD = os.getenv("POWER_PASSWORD", "6254")
AGENT_TOKEN = os.getenv("AGENT_TOKEN", "change-this-agent-token")
WOL_TARGET = os.getenv("WOL_TARGET", "")      # 공유기 DDNS 주소
WOL_MAC = os.getenv("WOL_MAC", "")            # PC MAC 주소
WOL_PORT = int(os.getenv("WOL_PORT", 9))
REMOTE_DESKTOP_URL = os.getenv("REMOTE_DESKTOP_URL", "https://remotedesktop.google.com/access")

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

shutdown_request = {
    "requested": False,
    "requested_at": None,
}

pc_status = {
    "last_heartbeat": 0,
    "hostname": None,
    "os": None,
}

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
    response = requests.get(f"{DISCORD_API_BASE}/users/@me", headers=headers)
    return response.json()

def get_user_guilds(access_token):
    headers = {"Authorization": f"Bearer {access_token}"}
    response = requests.get(f"{DISCORD_API_BASE}/users/@me/guilds", headers=headers)
    return response.json()

# ============================================================
# VPN 감지
# ============================================================
def detect_vpn(isp: str, org: str) -> bool:
    if not isp and not org:
        return False
    combined = f"{isp} {org}".lower()
    keywords = ["vpn", "proxy", "hosting", "cloud", "aws", "amazon", "digitalocean",
                "linode", "vultr", "heroku", "ovh", "azure", "gcp", "google cloud",
                "alibaba", "tencent", "cloudflare", "tor", "anonymizer"]
    for kw in keywords:
        if kw in combined:
            return True
    return False

# ============================================================
# Wake-on-LAN 매직 패킷
# ============================================================
def send_magic_packet(mac_address: str, target: str, port: int = 9):
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
# 설정 저장/로드
# ============================================================
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

# ============================================================
# 권한 체크
# ============================================================
def is_authorized(ctx):
    if ctx.guild and ctx.author.id == ctx.guild.owner_id:
        return True
    if ctx.author.id in ALLOWED_USER_IDS:
        return True
    cfg = load_config()
    authorized_list = cfg.get("authorized_users", [])
    if ctx.author.id in authorized_list:
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
        await ctx.send("❌ 권한이 없어요.")
    elif isinstance(error, commands.NoPrivateMessage):
        await ctx.send("❌ 서버 안에서만 사용할 수 있어요.")
    elif isinstance(error, commands.RoleNotFound):
        await ctx.send("❌ 역할을 찾을 수 없어요.")
    elif isinstance(error, commands.ChannelNotFound):
        await ctx.send("❌ 채널을 찾을 수 없어요.")
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
    await ctx.send(f"✅ 인증 역할을 {role.mention} 로 설정했어요.")

@bot.command(name="로그채널")
@commands.check(is_authorized)
async def set_log_channel(ctx: commands.Context, channel: discord.TextChannel):
    gcfg = get_guild_cfg(ctx.guild.id)
    gcfg["log_channel"] = channel.id
    save_config(config)
    await ctx.send(f"✅ 로그 채널을 {channel.mention} 로 설정했어요.")

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
    if not category_name:
        await ctx.send("❌ 카테고리 이름을 입력해주세요.")
        return
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
        await ctx.send(f"⚠️ 이미 등록된 카테고리입니다.")
        return
    gcfg["exception_category_ids"].append(category.id)
    save_config(config)
    allowed_role_id = gcfg.get("allowed_role_id")
    if not allowed_role_id:
        await ctx.send(f"❌ 먼저 `?인증채널`을 설정해주세요.")
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
    await ctx.send(f"✅ '{category.name}' 카테고리 채팅 제한 완료.")

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
    await ctx.send(f"✅ {removed_count}명 역할 제거 완료.")

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
                return await interaction.followup.send("❌ 인증역할이 설정되지 않았어요.", ephemeral=True)
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
        async with aiohttp.ClientSession() as session:
            async with session.get(BASE_URL, timeout=10) as resp:
                print(f"✅ 셀프 핑 성공 ({resp.status})")
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
    print(f"✅ {bot.user} 로그인 완료!")

# ============================================================
# Flask 라우트
# ============================================================
@app.route('/')
def home():
    return "✅ Bot is alive and running!", 200

# ---------------- PC 상태 / 제어 ----------------
@app.route('/heartbeat', methods=['POST'])
def heartbeat():
    agent_token = request.headers.get('X-Agent-Token')
    if agent_token != AGENT_TOKEN:
        return jsonify({"ok": False, "error": "unauthorized"}), 401
    data = request.get_json(silent=True) or {}
    pc_status["last_heartbeat"] = time.time()
    pc_status["hostname"] = data.get("hostname", "알 수 없음")
    pc_status["os"] = data.get("os", "알 수 없음")
    return jsonify({"ok": True})

@app.route('/pc_status')
def pc_status_route():
    if not session.get('power_logged_in'):
        return jsonify({"ok": False, "error": "로그인 필요"}), 401
    elapsed = time.time() - pc_status["last_heartbeat"]
    is_online = elapsed < 30
    return jsonify({
        "ok": True,
        "online": is_online,
        "hostname": pc_status["hostname"],
        "os": pc_status["os"],
        "last_seen_seconds": int(elapsed) if pc_status["last_heartbeat"] > 0 else None,
    })

@app.route('/check_shutdown', methods=['GET'])
def check_shutdown():
    agent_token = request.headers.get('X-Agent-Token')
    if agent_token != AGENT_TOKEN:
        return jsonify({"ok": False, "error": "unauthorized"}), 401
    if shutdown_request["requested"]:
        shutdown_request["requested"] = False
        return jsonify({"ok": True, "shutdown": True, "requested_at": shutdown_request["requested_at"]})
    return jsonify({"ok": True, "shutdown": False})

@app.route('/shutdown', methods=['POST'])
def request_shutdown():
    if not session.get('power_logged_in'):
        return jsonify({"ok": False, "error": "로그인이 필요합니다."}), 401
    elapsed = time.time() - pc_status["last_heartbeat"]
    if elapsed >= 30:
        return jsonify({"ok": False, "error": "이미 꺼져있습니다."})
    shutdown_request["requested"] = True
    shutdown_request["requested_at"] = time.time()
    return jsonify({"ok": True, "message": "종료 요청이 접수되었습니다."})

@app.route('/wake', methods=['POST'])
def wake_pc():
    if not session.get('power_logged_in'):
        return jsonify({"ok": False, "error": "로그인이 필요합니다."}), 401
    elapsed = time.time() - pc_status["last_heartbeat"]
    if elapsed < 30:
        return jsonify({"ok": False, "error": "이미 켜져있습니다."})
    if not WOL_TARGET or not WOL_MAC:
        return jsonify({"ok": False, "error": "WOL 설정이 되어있지 않습니다. (WOL_TARGET, WOL_MAC 환경변수 필요)"})
    try:
        send_magic_packet(WOL_MAC, WOL_TARGET, WOL_PORT)
        return jsonify({"ok": True, "message": "매직 패킷 전송됨. 30초 후 상태를 확인하세요."})
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)}), 500

# ---------------- /power 페이지 ----------------
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
    background:rgba(0,0,0,0.3); border:2px solid rgba(255,255,255,0.15); border-radius:14px;
    color:#fff; outline:none; margin-bottom:18px; }
  input:focus { border-color:#667eea; }
  button { width:100%; padding:15px; font-size:17px; font-weight:600;
    background:linear-gradient(135deg,#667eea,#764ba2); color:white; border:none;
    border-radius:14px; cursor:pointer; }
  button:active { transform:scale(0.97); }
  .error { color:#fc8181; font-size:14px; margin-top:14px; min-height:20px; }
</style>
</head>
<body>
  <div class="box">
    <h1>🔐 PC 원격 전원</h1>
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
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>🔌 PC 원격 전원</title>
<style>
  * { margin:0; padding:0; box-sizing:border-box; }
  body { font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;
    background:linear-gradient(135deg,#1a1a2e 0%,#16213e 100%);
    min-height:100vh; display:flex; align-items:center; justify-content:center;
    padding:20px; color:#eee; }
  .box { background:rgba(255,255,255,0.08); backdrop-filter:blur(20px);
    border:1px solid rgba(255,255,255,0.1); border-radius:24px; padding:30px 24px;
    max-width:420px; width:100%; box-shadow:0 20px 60px rgba(0,0,0,0.5); text-align:center; }
  .box h1 { font-size:22px; margin-bottom:6px; font-weight:700; }
  .box p { font-size:13px; color:#a0aec0; margin-bottom:22px; }
  .status { display:inline-block; padding:8px 16px; border-radius:20px; font-size:13px;
    margin-bottom:22px; transition:all 0.3s; }
  .status.online { background:rgba(72,187,120,0.15); color:#68d391; }
  .status.offline { background:rgba(245,101,101,0.15); color:#fc8181; }
  .status.loading { background:rgba(160,174,192,0.15); color:#a0aec0; }
  button, a.btn {
    width:100%; padding:22px; font-size:19px; font-weight:700;
    border:none; border-radius:16px; cursor:pointer; display:block;
    text-decoration:none; text-align:center; transition:transform 0.15s, box-shadow 0.15s;
    margin-bottom:14px;
  }
  button:active, a.btn:active { transform:scale(0.97); }
  button:disabled { opacity:0.5; cursor:not-allowed; }
  .btn-on { background:linear-gradient(135deg,#43a047,#2e7d32); color:#fff;
    box-shadow:0 8px 24px rgba(67,160,71,0.35); }
  .btn-off { background:linear-gradient(135deg,#e53935,#b71c1c); color:#fff;
    box-shadow:0 8px 24px rgba(229,57,53,0.35); }
  .btn-remote { background:linear-gradient(135deg,#1a73e8,#0d47a1); color:#fff;
    box-shadow:0 8px 24px rgba(26,115,232,0.35); }
  .btn-logout { padding:10px 16px; font-size:13px; font-weight:400;
    background:rgba(255,255,255,0.08); color:#a0aec0; border:1px solid rgba(255,255,255,0.15);
    border-radius:10px; margin-top:10px; width:auto; display:inline-block; }
  #msg { margin-top:16px; font-size:14px; color:#a0aec0; min-height:20px; }
</style>
</head>
<body>
  <div class="box">
    <div id="pcStatus" class="status loading">● 확인 중...</div>
    <h1>PC 원격 전원</h1>
    <p>컴퓨터를 켜거나 끌 수 있어요</p>

    <button class="btn-on" id="btnWake" onclick="wakePC()">⏻ 컴퓨터 켜기</button>
    <button class="btn-off" id="btnShutdown" onclick="sendShutdown()">🔌 컴퓨터 끄기</button>
    <a class="btn btn-remote" href="{{ remote_url }}" target="_blank">🖥️ 원격 데스크톱 (가로 모드)</a>

    <div id="msg"></div>
    <button class="btn-logout" onclick="logout()">로그아웃</button>
  </div>

<script>
let isOnline = false;

async function updateStatus() {
  const el = document.getElementById('pcStatus');
  try {
    const r = await fetch('/pc_status');
    const d = await r.json();
    if (!d.ok) { el.textContent = '● 세션 만료'; el.className = 'status offline'; return; }
    isOnline = d.online;
    if (d.online) {
      el.textContent = `● 켜져있음 (${d.hostname || 'PC'})`;
      el.className = 'status online';
      document.getElementById('btnShutdown').disabled = false;
      document.getElementById('btnWake').disabled = true;
    } else {
      el.textContent = '● 꺼져있음';
      el.className = 'status offline';
      document.getElementById('btnShutdown').disabled = true;
      document.getElementById('btnWake').disabled = false;
    }
  } catch (e) {
    el.textContent = '● 상태 확인 실패';
    el.className = 'status offline';
  }
}

async function wakePC() {
  if (isOnline) { document.getElementById('msg').textContent = '⚠️ 이미 켜져있습니다.'; return; }
  if (!confirm('컴퓨터를 켜시겠습니까? (약 30초 소요)')) return;
  document.getElementById('msg').textContent = '⏳ 매직 패킷 전송 중...';
  try {
    const r = await fetch('/wake', { method: 'POST' });
    const d = await r.json();
    document.getElementById('msg').textContent = d.ok ? '✅ ' + d.message : '❌ ' + d.error;
    if (d.ok) setTimeout(updateStatus, 30000);
  } catch (e) {
    document.getElementById('msg').textContent = '❌ 네트워크 오류';
  }
}

async function sendShutdown() {
  if (!isOnline) { document.getElementById('msg').textContent = '❌ 이미 꺼져있습니다.'; return; }
  if (!confirm('정말로 컴퓨터를 끄시겠습니까?')) return;
  const btn = document.getElementById('btnShutdown');
  btn.disabled = true;
  btn.textContent = '⏳ 요청 중...';
  try {
    const r = await fetch('/shutdown', { method: 'POST' });
    const d = await r.json();
    document.getElementById('msg').textContent = d.ok ? '✅ ' + d.message : '❌ ' + d.error;
    if (d.ok) { btn.textContent = '✅ 요청됨'; setTimeout(updateStatus, 15000); }
    else { btn.disabled = false; btn.textContent = '🔌 컴퓨터 끄기'; }
  } catch (e) {
    document.getElementById('msg').textContent = '❌ 네트워크 오류';
    btn.disabled = false;
    btn.textContent = '🔌 컴퓨터 끄기';
  }
}

async function logout() {
  await fetch('/power_logout', { method: 'POST' });
  location.reload();
}

updateStatus();
setInterval(updateStatus, 5000);
</script>
</body>
</html>
"""

@app.route('/power')
def power_page():
    if not session.get('power_logged_in'):
        return render_template_string(POWER_LOGIN_PAGE, error="")
    return render_template_string(POWER_CONTROL_PAGE, remote_url=REMOTE_DESKTOP_URL)

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
    session.pop('power_login_at', None)
    return jsonify({"ok": True})

# ---------------- 기존 OAuth2 ----------------
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
            "scope": "identify email",
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
            return f"❌ 인증 오류: {error}", 400
        if not code or not state or state not in oauth_states:
            return "❌ 유효하지 않은 요청", 400
        state_data = oauth_states.pop(state)
        if time.time() - state_data["created_at"] > 600:
            return "❌ state 만료", 400
        token_data = exchange_code(code)
        if 'error' in token_data or 'access_token' not in token_data:
            return f"❌ 토큰 교환 실패: {token_data}", 400
        access_token = token_data['access_token']
        user_data = get_discord_user(access_token)
        if 'id' not in user_data:
            return "❌ 사용자 정보 실패", 400
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

# ---------------- CAPTCHA 페이지 ----------------
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
    <script>
        document.querySelector('form').addEventListener('submit', function() {
            const btn = document.querySelector('.btn-submit');
            btn.disabled = true; btn.textContent = '⏳ 처리 중...';
        });
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
        user_data = session.get('user_data', {})
        if request.method == 'GET':
            if not token:
                token = ''.join(random.choices(string.ascii_letters + string.digits, k=16))
                session['captcha_token'] = token
            return render_template_string(
                CAPTCHA_PAGE, site_key=RECAPTCHA_SITE_KEY or "", token=token,
                user_id=user_id, user_name=user_name, user_avatar=user_avatar,
                user_email=user_email, msg="", msg_type=""
            )
        recaptcha_response = request.form.get('g-recaptcha-response')
        if not recaptcha_response or not verify_recaptcha(recaptcha_response):
            return render_template_string(
                CAPTCHA_PAGE, site_key=RECAPTCHA_SITE_KEY or "", token=token,
                user_id=user_id, user_name=user_name, user_avatar=user_avatar,
                user_email=user_email, msg="❌ reCAPTCHA 검증 실패", msg_type="error"
            )
        guild_id = session.get('pending_guild_id')
        if not guild_id:
            return render_template_string(
                CAPTCHA_PAGE, site_key=RECAPTCHA_SITE_KEY or "", token=token,
                user_id=user_id, user_name=user_name, user_avatar=user_avatar,
                user_email=user_email, msg="❌ 세션 정보 없음", msg_type="error"
            )
        target_bot = bot
        ip = request.headers.get('X-Forwarded-For', request.remote_addr)
        if ip and ',' in ip:
            ip = ip.split(',')[0].strip()
        user_agent = request.headers.get('User-Agent', '알 수 없음')
        future = asyncio.run_coroutine_threadsafe(
            assign_role_from_web_wrapper(
                token, ip, guild_id, int(user_id), target_bot,
                user_data, access_token, user_agent
            ),
            target_bot.loop
        )
        try:
            success, message = future.result(timeout=30)
        except Exception as e:
            success, message = False, f"서버 오류: {str(e)}"
        if success:
            session.clear()
            return render_template_string(
                CAPTCHA_PAGE, site_key=RECAPTCHA_SITE_KEY or "", token="",
                user_id=user_id, user_name=user_name, user_avatar=user_avatar,
                user_email=user_email, msg=f"✅ {message}", msg_type="success"
            )
        return render_template_string(
            CAPTCHA_PAGE, site_key=RECAPTCHA_SITE_KEY or "", token=token,
            user_id=user_id, user_name=user_name, user_avatar=user_avatar,
            user_email=user_email, msg=f"❌ {message}", msg_type="error"
        )
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
# 웹 인증 처리
# ============================================================
async def assign_role_from_web_wrapper(token, ip, guild_id, user_id, bot_instance, user_data, access_token, user_agent):
    try:
        guild = bot_instance.get_guild(guild_id)
        if not guild:
            return False, "서버를 찾을 수 없습니다."
        member = guild.get_member(user_id)
        if not member:
            return False, "사용자를 찾을 수 없습니다."
        with open(CONFIG_PATH, "r", encoding="utf-8") as f:
            config = json.load(f)
        gcfg = config.get(str(guild_id), {})
        verify_role_id = gcfg.get("verify_role")
        if not verify_role_id:
            return False, "인증 역할이 설정되지 않았습니다."
        role = guild.get_role(verify_role_id)
        if not role:
            return False, "역할이 존재하지 않습니다."
        location = "알 수 없음"
        isp = "알 수 없음"
        org = "알 수 없음"
        is_mobile_data = False
        country = "알 수 없음"
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
        except:
            pass
        is_vpn = detect_vpn(isp, org)
        if is_vpn:
            return False, "❌ VPN/프록시 사용 불가"
        if country not in ["South Korea", "KR", "Korea"]:
            return False, "❌ 해외에서는 인증 불가"
        if is_mobile_data:
            return False, "❌ 모바일 데이터로는 인증 불가 (Wi-Fi 사용)"
        removable_roles = [r for r in member.roles if r != guild.default_role and r < guild.me.top_role]
        if removable_roles:
            await member.remove_roles(*removable_roles, reason="웹 인증")
        await member.add_roles(role, reason="웹 인증")
        log_channel_id = gcfg.get("log_channel")
        if log_channel_id:
            log_channel = guild.get_channel(log_channel_id)
            if log_channel:
                embed = discord.Embed(
                    title="✅ 인증 성공",
                    description=f"{member.mention} 님이 인증을 완료했습니다.",
                    color=discord.Color.green(),
                    timestamp=datetime.now(timezone.utc)
                )
                embed.add_field(name="유저", value=f"{member.mention} ({user_id})", inline=False)
                embed.add_field(name="이메일", value=user_data.get('email', '없음'), inline=False)
                embed.add_field(name="IP", value=f"{ip}\n{location}\n{isp}", inline=False)
                embed.set_thumbnail(url=member.display_avatar.url)
                try:
                    await log_channel.send(embed=embed)
                except:
                    pass
        return True, f"역할 {role.name} 지급 완료"
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
        print("❌ DISCORD_BOT_TOKEN 미설정!")
    else:
        thread = threading.Thread(target=run_flask, daemon=True)
        thread.start()
        print(f"🌐 웹서버 실행 중: http://{WEB_HOST}:{WEB_PORT}")
        bot.run(TOKEN)
