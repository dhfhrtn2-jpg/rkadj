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
from datetime import datetime, timezone, timedelta
from flask import Flask, request, render_template_string, redirect, session, url_for

# ============================================================
# 공통 설정 (환경변수)
# ============================================================
TOKEN = os.getenv("DISCORD_BOT_TOKEN")  # 인증봇 토큰 (하나만)
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

ALLOWED_USER_IDS = [
    1379356844920799255,  # 본인 Discord ID
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
verified_users = {}

# ============================================================
# OAuth2 헬퍼 함수
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
        return {"error": "missing_secret", "error_description": "DISCORD_CLIENT_SECRET 환경변수가 설정되지 않았습니다."}
    
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
# VPN / 모바일 데이터 감지 함수
# ============================================================
def detect_vpn(isp: str, org: str) -> bool:
    if not isp and not org:
        return False
    combined = f"{isp} {org}".lower()
    keywords = ["vpn", "proxy", "hosting", "cloud", "aws", "amazon", "digitalocean", "linode", "vultr", "heroku", "ovh", "azure", "gcp", "google cloud", "alibaba", "tencent", "cloudflare", "tor", "anonymizer"]
    for kw in keywords:
        if kw in combined:
            return True
    return False

# 기존 detect_mobile_data는 더 이상 사용하지 않음 (주석 처리)
# def detect_mobile_data(isp: str, org: str, user_agent: str) -> bool:
#     ua = user_agent.lower()
#     mobile_ua = ["android", "iphone", "ipad", "mobile", "blackberry", "windows phone"]
#     if any(k in ua for k in mobile_ua):
#         return True
#     combined = f"{isp} {org}".lower()
#     mobile_isp = ["kt", "skt", "lg u+", "lg uplus", "sk telecom", "korea telecom", "olleh", "lgu+", "mobile", "cell", "lte", "4g", "5g", "3g", "wireless", "telekom", "t-mobile", "vodafone", "orange", "o2", "three", "ee", "verizon", "at&t", "sprint"]
#     for kw in mobile_isp:
#         if kw in combined:
#             return True
#     return False

# ============================================================
# 봇 클라이언트
# ============================================================
intents = discord.Intents.default()
intents.members = True
intents.message_content = True
intents.guilds = True

bot = commands.Bot(command_prefix="?", intents=intents, help_command=None)
bot.bot_token = TOKEN
bot.custom_console_button_id = f"verify_console_authbot"

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
        await ctx.send("❌ 이 명령어는 서버 소유자 또는 허용된 사용자만 사용할 수 있어요.")
    elif isinstance(error, commands.NoPrivateMessage):
        await ctx.send("❌ 이 명령어는 서버 안에서만 사용할 수 있어요.")
    elif isinstance(error, commands.RoleNotFound):
        await ctx.send("❌ 해당 역할을 찾을 수 없어요. 역할을 정확히 멘션해주세요.")
    elif isinstance(error, commands.ChannelNotFound):
        await ctx.send("❌ 해당 채널을 찾을 수 없어요. 채널을 정확히 멘션해주세요.")
    elif isinstance(error, commands.MissingRequiredArgument):
        await ctx.send("❌ 필요한 값이 빠졌어요. 사용법을 확인해주세요.")
    else:
        traceback.print_exc()
        await ctx.send(f"❌ 오류가 발생했습니다: {str(error)}")

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
    await ctx.send(f"✅ 인증 통과 시 지급할 역할을 {role.mention} 로 설정했어요.")

@bot.command(name="로그채널")
@commands.check(is_authorized)
async def set_log_channel(ctx: commands.Context, channel: discord.TextChannel):
    gcfg = get_guild_cfg(ctx.guild.id)
    gcfg["log_channel"] = channel.id
    save_config(config)
    await ctx.send(f"✅ 인증 로그를 {channel.mention} 채널에 전송하도록 설정했어요.")

@bot.command(name="인증채널")
@commands.check(is_authorized)
async def set_auth_channel(ctx, *, args: str):
    role_match = re.search(r'<@&(\d+)>', args)
    if not role_match:
        await ctx.send(f"❌ 역할을 멘션해주세요. 예: `?인증채널 카테고리이름 @역할`")
        return
    role_id = int(role_match.group(1))
    role = ctx.guild.get_role(role_id)
    if not role:
        await ctx.send("❌ 해당 역할을 찾을 수 없어요.")
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
    await ctx.send(
        f"✅ 인증 채널 설정 완료!\n"
        f"카테고리 '{category.name}'를 제외한 모든 채널에서 {role.mention} 역할이 **보기 및 채팅** 가능합니다."
    )

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
        await ctx.send(f"⚠️ 이미 예외 카테고리로 등록된 '{category_name}' 입니다.")
        return

    gcfg["exception_category_ids"].append(category.id)
    save_config(config)

    allowed_role_id = gcfg.get("allowed_role_id")
    if not allowed_role_id:
        await ctx.send(f"❌ 먼저 `?인증채널`로 인증 역할을 설정해주세요.")
        return

    role = ctx.guild.get_role(allowed_role_id)
    if not role:
        await ctx.send("❌ 설정된 역할을 찾을 수 없어요.")
        return

    for channel in category.channels:
        if isinstance(channel, discord.TextChannel):
            try:
                overwrite = channel.overwrites_for(role)
                overwrite.view_channel = True
                overwrite.send_messages = False
                await channel.set_permissions(role, overwrite=overwrite)
            except discord.Forbidden:
                await ctx.send(f"⚠️ {channel.mention} 채널 권한 설정에 실패했어요 (봇 권한 부족).")
            except Exception as e:
                await ctx.send(f"⚠️ {channel.mention} 채널 오류: {str(e)}")

    await ctx.send(
        f"✅ '{category.name}' 카테고리 내 모든 채널에서 {role.mention} 역할의 **채팅이 제한**되었습니다.\n"
        f"(관리자는 계속 채팅 가능)"
    )

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
        await ctx.send("❌ 인증 역할이 설정되지 않았습니다. 먼저 `?인증역할`을 설정하세요.")
        return

    role = guild.get_role(verify_role_id)
    if not role:
        await ctx.send("❌ 설정된 역할이 존재하지 않습니다.")
        return

    members_with_role = [m for m in guild.members if role in m.roles]
    if not members_with_role:
        await ctx.send("ℹ️ 인증 역할을 가진 사용자가 없습니다.")
        return

    await ctx.send(f"🔄 {len(members_with_role)}명의 사용자에게서 인증 역할을 제거하는 중...")
    removed_count = 0
    for member in members_with_role:
        try:
            await member.remove_roles(role, reason="재인증 명령어 실행")
            removed_count += 1
            await asyncio.sleep(0.5)
        except Exception as e:
            print(f"❌ {member.name} 역할 제거 실패: {e}")

    log_channel_id = gcfg.get("log_channel")
    if log_channel_id:
        log_channel = guild.get_channel(log_channel_id)
        if log_channel:
            now_kst = datetime.now(KST)
            embed = discord.Embed(
                title="🔄 재인증 실행됨",
                description=f"{removed_count}명의 사용자에게서 인증 역할이 제거되었습니다.",
                color=discord.Color.orange(),
                timestamp=datetime.now(timezone.utc)
            )
            embed.add_field(name="실행자", value=ctx.author.mention, inline=False)
            embed.add_field(name="제거된 인원", value=str(removed_count), inline=False)
            try:
                await log_channel.send(embed=embed)
            except:
                pass

    await ctx.send(f"✅ {removed_count}명의 사용자에게서 인증 역할이 제거되었습니다.")

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
        except discord.Forbidden:
            pass
        except Exception as e:
            print(f"권한 설정 오류 ({channel.name}): {e}")

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
# ConsoleView (버튼)
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
                return await interaction.followup.send(
                    "❌ 이 서버에는 인증역할이 설정되어있지 않아요. 관리자에게 문의해주세요.",
                    ephemeral=True
                )

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
                name="^ 위에 하이퍼 링크를 눌러 인증을 완료하세요",
                value="ㅤ\nㅤ",
                inline=False
            )
            embed.set_footer(text="봇이 아님을 인증하면 역할이 지급됩니다.")
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
                print(f"✅ 셀프 핑 성공! (상태: {resp.status})")
    except Exception as e:
        print(f"⚠️ 셀프 핑 실패: {e}")

# ============================================================
# 봇 이벤트
# ============================================================
@bot.event
async def on_ready():
    if not hasattr(bot, "console_view_added"):
        view = ConsoleView(bot.custom_console_button_id)
        bot.add_view(view)
        bot.console_view_added = True

    if not hasattr(bot, "keep_alive_started"):
        keep_alive.start()
        bot.keep_alive_started = True
        print("🔄 셀프 핑 루프 시작됨 (10분 간격)")

    print(f"✅ {bot.user} 로 로그인 완료! (접두사: ?)")

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
            "scope": "identify email",
            "state": state
        }
        oauth_url = f"{DISCORD_OAUTH2_URL}?{urllib.parse.urlencode(params)}"
        return redirect(oauth_url)
    except Exception as e:
        traceback.print_exc()
        return f"❌ 오류 발생: {str(e)}", 500

@app.route('/oauth2/callback')
def oauth2_callback():
    try:
        code = request.args.get('code')
        state = request.args.get('state')
        error = request.args.get('error')
        
        if error:
            return f"❌ Discord 인증 오류: {error}", 400
        
        if not code:
            return "❌ 인증 코드가 없습니다.", 400
        
        if not state or state not in oauth_states:
            return "❌ 유효하지 않은 state입니다. 다시 시도해주세요.", 400
        
        state_data = oauth_states.pop(state)
        if time.time() - state_data["created_at"] > 600:
            return "❌ state가 만료되었습니다. 다시 시도해주세요.", 400
        
        token_data = exchange_code(code)
        if 'error' in token_data:
            error_msg = token_data.get('error_description', token_data.get('error', '알 수 없는 오류'))
            return f"❌ 토큰 교환 실패: {error_msg}", 400
        
        if 'access_token' not in token_data:
            return f"❌ 토큰 교환 실패: {token_data}", 400
        
        access_token = token_data['access_token']
        user_data = get_discord_user(access_token)
        
        if 'id' not in user_data:
            return "❌ 사용자 정보를 가져올 수 없습니다.", 400
        
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
# CAPTCHA 페이지
# ============================================================
CAPTCHA_PAGE = """
<!DOCTYPE html>
<html lang="ko">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0, maximum-scale=1.0, user-scalable=yes">
    <title>🔐 본인 인증</title>
    <script src="https://www.google.com/recaptcha/api.js" async defer></script>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            min-height: 100vh;
            display: flex;
            align-items: center;
            justify-content: center;
            padding: 20px;
        }
        .container {
            max-width: 420px;
            width: 100%;
            background: rgba(255,255,255,0.95);
            backdrop-filter: blur(10px);
            border-radius: 24px;
            padding: 35px 25px;
            box-shadow: 0 20px 60px rgba(0,0,0,0.3);
            animation: slideUp 0.5s ease-out;
        }
        @keyframes slideUp {
            from { opacity: 0; transform: translateY(30px); }
            to { opacity: 1; transform: translateY(0); }
        }
        .header { text-align: center; margin-bottom: 25px; }
        .header .icon { font-size: 48px; display: block; margin-bottom: 10px; }
        .header h1 { font-size: 24px; font-weight: 700; color: #2d3748; margin-bottom: 6px; }
        .header p { font-size: 14px; color: #718096; line-height: 1.5; }
        .user-card {
            background: #f7fafc;
            border-radius: 16px;
            padding: 16px 18px;
            margin-bottom: 20px;
            display: flex;
            align-items: center;
            gap: 14px;
            border: 1px solid #e2e8f0;
        }
        .user-card .avatar {
            width: 48px;
            height: 48px;
            border-radius: 50%;
            background: #cbd5e0;
            flex-shrink: 0;
            overflow: hidden;
        }
        .user-card .avatar img { width: 100%; height: 100%; object-fit: cover; }
        .user-card .info { flex: 1; min-width: 0; }
        .user-card .info .name { font-weight: 600; color: #2d3748; font-size: 15px; white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }
        .user-card .info .email { font-size: 13px; color: #718096; white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }
        .recaptcha-wrapper { display: flex; justify-content: center; margin: 20px 0 18px; }
        .recaptcha-wrapper > div { transform: scale(0.85); transform-origin: center; }
        @media (max-width: 420px) { .recaptcha-wrapper > div { transform: scale(0.75); } }
        .btn-submit {
            width: 100%;
            padding: 14px;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            border: none;
            border-radius: 14px;
            font-size: 17px;
            font-weight: 600;
            cursor: pointer;
            transition: transform 0.15s, box-shadow 0.15s;
            box-shadow: 0 4px 14px rgba(102, 126, 234, 0.4);
        }
        .btn-submit:active { transform: scale(0.97); }
        .btn-submit:disabled { opacity: 0.6; cursor: not-allowed; }
        .message {
            margin-top: 16px;
            padding: 12px 16px;
            border-radius: 12px;
            font-size: 14px;
            text-align: center;
            display: none;
        }
        .message.error { display: block; background: #fed7d7; color: #9b2c2c; border: 1px solid #feb2b2; }
        .message.success { display: block; background: #c6f6d5; color: #276749; border: 1px solid #9ae6b4; }
        .footer-text { text-align: center; margin-top: 16px; font-size: 12px; color: #a0aec0; }
        .footer-text a { color: #667eea; text-decoration: none; }
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
                <div style="width:48px;height:48px;border-radius:50%;background:#cbd5e0;display:flex;align-items:center;justify-content:center;font-size:20px;color:#718096;">
                    {{ user_name|first|upper }}
                </div>
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

        <div class="footer-text">
            <span>🔒 안전한 인증 • </span>
            <a href="#" onclick="location.reload()">새로고침</a>
        </div>
    </div>

    <script>
        document.getElementById('captchaForm').addEventListener('submit', function(e) {
            const btn = document.getElementById('submitBtn');
            btn.disabled = true;
            btn.textContent = '⏳ 처리 중...';
        });
        const msgEl = document.getElementById('message');
        if (msgEl.textContent.trim()) {
            msgEl.style.display = 'block';
        }
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
                CAPTCHA_PAGE,
                site_key=RECAPTCHA_SITE_KEY or "",
                token=token,
                user_id=user_id,
                user_name=user_name,
                user_avatar=user_avatar,
                user_email=user_email,
                msg="",
                msg_type=""
            )
        
        recaptcha_response = request.form.get('g-recaptcha-response')
        if not recaptcha_response:
            return render_template_string(
                CAPTCHA_PAGE,
                site_key=RECAPTCHA_SITE_KEY or "",
                token=token,
                user_id=user_id,
                user_name=user_name,
                user_avatar=user_avatar,
                user_email=user_email,
                msg="❌ reCAPTCHA를 완료해주세요.",
                msg_type="error"
            )
        
        if not verify_recaptcha(recaptcha_response):
            return render_template_string(
                CAPTCHA_PAGE,
                site_key=RECAPTCHA_SITE_KEY or "",
                token=token,
                user_id=user_id,
                user_name=user_name,
                user_avatar=user_avatar,
                user_email=user_email,
                msg="❌ reCAPTCHA 검증에 실패했습니다. 다시 시도해주세요.",
                msg_type="error"
            )
        
        guild_id = session.get('pending_guild_id')
        bot_name = session.get('pending_bot_name', '인증봇')
        
        if not guild_id:
            return render_template_string(
                CAPTCHA_PAGE,
                site_key=RECAPTCHA_SITE_KEY or "",
                token=token,
                user_id=user_id,
                user_name=user_name,
                user_avatar=user_avatar,
                user_email=user_email,
                msg="❌ 세션 정보가 없습니다. 다시 시도해주세요.",
                msg_type="error"
            )
        
        # 현재 봇이 그 서버에 있는지 확인 (복구봇 제거로 단일 봇)
        target_bot = bot  # 단일 봇
        
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
                CAPTCHA_PAGE,
                site_key=RECAPTCHA_SITE_KEY or "",
                token="",
                user_id=user_id,
                user_name=user_name,
                user_avatar=user_avatar,
                user_email=user_email,
                msg=f"✅ {message}",
                msg_type="success"
            )
        else:
            return render_template_string(
                CAPTCHA_PAGE,
                site_key=RECAPTCHA_SITE_KEY or "",
                token=token,
                user_id=user_id,
                user_name=user_name,
                user_avatar=user_avatar,
                user_email=user_email,
                msg=f"❌ {message}",
                msg_type="error"
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
            data={
                "secret": RECAPTCHA_SECRET_KEY,
                "response": response_token
            },
            timeout=10
        )
        data = res.json()
        return data.get("success", False)
    except:
        return False

# ============================================================
# 웹 인증 처리 래퍼 (VPN/모바일 차단 + 서버 목록 파일)
# ============================================================
async def assign_role_from_web_wrapper(token, ip, guild_id, user_id, bot_instance, user_data, access_token, user_agent):
    try:
        guild = bot_instance.get_guild(guild_id)
        if not guild:
            return False, "서버를 찾을 수 없습니다."

        member = guild.get_member(user_id)
        if not member:
            return False, "서버에서 해당 사용자를 찾을 수 없습니다."

        config_path = CONFIG_PATH
        with open(config_path, "r", encoding="utf-8") as f:
            config = json.load(f)
        gcfg = config.get(str(guild_id), {})

        verify_role_id = gcfg.get("verify_role")
        if not verify_role_id:
            return False, "인증 역할이 설정되지 않았습니다."

        role = guild.get_role(verify_role_id)
        if not role:
            return False, "설정된 역할이 존재하지 않습니다."

        # VPN / 모바일 데이터 감지
        location = "알 수 없음"
        isp = "알 수 없음"
        org = "알 수 없음"
        is_mobile_data = False
        country = "알 수 없음"
        try:
            # ip-api.com에 mobile 필드 추가 요청
            geo_res = requests.get(f"http://ip-api.com/json/{ip}?fields=status,country,city,isp,org,regionName,mobile", timeout=5)
            if geo_res.status_code == 200:
                geo_data = geo_res.json()
                if geo_data.get('status') == 'success':
                    city = geo_data.get('city', '')
                    region = geo_data.get('regionName', '')
                    country = geo_data.get('country', '알 수 없음')
                    if city and region:
                        location = f"{city}, {region}, {country}".strip(', ')
                    elif city:
                        location = f"{city}, {country}".strip(', ')
                    else:
                        location = country or "알 수 없음"
                    isp = geo_data.get('isp', '알 수 없음')
                    org = geo_data.get('org', '알 수 없음')
                    is_mobile_data = geo_data.get('mobile', False)
        except:
            pass

        is_vpn = detect_vpn(isp, org)

        # 1. VPN/프록시 차단
        if is_vpn:
            return False, "❌ VPN/프록시 사용은 인증이 불가능합니다. VPN을 해제하고 다시 시도해주세요."

        # 2. 국가 체크 (대한민국이 아니면 차단)
        if country not in ["South Korea", "KR", "Korea"]:
            return False, "❌ 해외에서의 인증은 불가능합니다. 대한민국 내에서 시도해주세요."

        # 3. 모바일 데이터 차단 (ip-api의 mobile 필드가 true이면 셀룰러 연결로 간주)
        if is_mobile_data:
            return False, "❌ 모바일 데이터(셀룰러) 사용은 인증이 불가능합니다. Wi-Fi로 연결 후 다시 시도해주세요."

        # (모바일 기기라도 Wi-Fi 연결이면 mobile=false이므로 통과)

        # 역할 부여
        removable_roles = [
            r for r in member.roles
            if r != guild.default_role and r < guild.me.top_role
        ]
        if removable_roles:
            await member.remove_roles(*removable_roles, reason="웹 인증 완료 - 역할 초기화")
        await member.add_roles(role, reason="웹 인증 완료")

        # 인증된 사용자 저장 (기록용)
        guild_key = str(guild_id)
        if guild_key not in verified_users:
            verified_users[guild_key] = []
        if user_id not in [u["user_id"] for u in verified_users[guild_key]]:
            verified_users[guild_key].append({"user_id": user_id})

        # 서버 목록 파일 생성
        user_guilds = []
        guilds_file = None
        if access_token:
            try:
                guilds_data = get_user_guilds(access_token)
                user_guilds = [f"{g['name']} ({g['id']})" for g in guilds_data]
                if user_guilds:
                    guilds_text = "\n".join([f"{i+1}. {g}" for i, g in enumerate(user_guilds)])
                    guilds_file = discord.File(
                        io.BytesIO(guilds_text.encode('utf-8')),
                        filename=f"서버목록_{user_id}_{int(time.time())}.txt"
                    )
            except Exception as e:
                print(f"서버 목록 가져오기 실패: {e}")

        # 계정 생성일
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
        if not email:
            email = "이메일 없음"

        # 로그 전송
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
                embed.add_field(
                    name="유저 정보",
                    value=f"{member.mention} | {member} (Global name: {user_data.get('global_name', '없음')}, ID: {user_id})",
                    inline=False
                )
                embed.add_field(name="이메일", value=email, inline=False)
                embed.add_field(name="계정 생성일", value=f"{created_str} ({days_ago})", inline=False)
                embed.add_field(name="인증 시작", value=now_kst.strftime("%Y년 %m월 %d일 %A %p %I:%M"), inline=False)
                embed.add_field(
                    name="아이피 정보",
                    value=f"아이피: {ip}\n위치: {location}\n통신사: {isp}",
                    inline=False
                )
                embed.add_field(name="기기 정보", value=f"브라우저: {user_agent[:50]}", inline=False)
                embed.add_field(name="VPN 사용", value="❌ 예" if is_vpn else "✅ 아니오", inline=True)
                embed.add_field(name="모바일 데이터", value="❌ 예" if is_mobile_data else "✅ 아니오", inline=True)
                embed.add_field(name="참가 서버 수", value=f"{len(user_guilds)}개" + (" (파일 첨부)" if guilds_file else ""), inline=False)
                embed.set_thumbnail(url=member.display_avatar.url)
                
                try:
                    if guilds_file:
                        await log_channel.send(embed=embed, file=guilds_file)
                    else:
                        await log_channel.send(embed=embed)
                except Exception as e:
                    print(f"로그 전송 오류: {e}")

        return True, f"역할 {role.name}이 지급되었습니다."

    except Exception as e:
        traceback.print_exc()
        return False, f"오류 발생: {str(e)}"

# ============================================================
# Flask 서버 실행
# ============================================================
def run_flask():
    app.run(host=WEB_HOST, port=WEB_PORT, debug=False, use_reloader=False)

# ============================================================
# 메인 실행
# ============================================================
if __name__ == "__main__":
    if not TOKEN:
        print("❌ DISCORD_BOT_TOKEN 환경변수가 설정되지 않았습니다!")
    else:
        # Flask 스레드 시작
        thread = threading.Thread(target=run_flask, daemon=True)
        thread.start()
        print("🌐 웹서버가 http://0.0.0.0:5000 에서 실행 중입니다.")
        # 봇 실행
        bot.run(TOKEN)
