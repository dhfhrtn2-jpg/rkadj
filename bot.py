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
TOKEN1 = os.getenv("DISCORD_BOT_TOKEN1")
TOKEN2 = os.getenv("DISCORD_BOT_TOKEN2")
BASE_URL = os.getenv("BASE_URL", "https://rkadj.onrender.com")  # ✅ 반드시 https:// 포함!
CONFIG_PATH1 = "config_bot1.json"
CONFIG_PATH2 = "config_bot2.json"
BACKUP_PATH1 = "backup_bot1.json"
BACKUP_PATH2 = "backup_bot2.json"
CAPTCHA_EXPIRE_SECONDS = 600
CONSOLE_BUTTON_ID = "verify_console_open_button"
KST = timezone(timedelta(hours=9))

RECAPTCHA_SITE_KEY = os.getenv("RECAPTCHA_SITE_KEY")
RECAPTCHA_SECRET_KEY = os.getenv("RECAPTCHA_SECRET_KEY")

DISCORD_CLIENT_ID = os.getenv("DISCORD_CLIENT_ID", "1532934746764742766")
DISCORD_CLIENT_SECRET = os.getenv("DISCORD_CLIENT_SECRET")
# ✅ Redirect URI를 정확히 통일 (Discord Developer Portal과 동일해야 함)
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
verified_users = {}

# ============================================================
# OAuth2 헬퍼 함수 (서버 가입용)
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
        "scope": "identify guilds.join",  # ✅ guilds.join 포함!
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
        "redirect_uri": DISCORD_REDIRECT_URI,
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

def add_user_to_guild(bot_token, guild_id, user_id, access_token):
    """
    봇 토큰 + OAuth2 access_token으로 사용자를 서버에 강제 추가
    (import os.txt의 방식)
    """
    url = f"{DISCORD_API_BASE}/guilds/{guild_id}/members/{user_id}"
    headers = {
        "Authorization": f"Bot {bot_token}",
        "Content-Type": "application/json"
    }
    payload = {"access_token": access_token}
    try:
        response = requests.put(url, headers=headers, json=payload)
        print(f"[DEBUG] add_user_to_guild 응답: {response.status_code} - {response.text[:200]}")
        if response.status_code in (201, 204):
            return True, "서버 가입 성공"
        else:
            return False, f"HTTP {response.status_code}: {response.text[:200]}"
    except Exception as e:
        return False, str(e)

# ============================================================
# 봇 팩토리 함수
# ============================================================
def create_bot(token, bot_name, config_path, backup_path, prefix, include_backup=True):
    intents = discord.Intents.default()
    intents.members = True
    intents.message_content = True
    intents.guilds = True

    bot = commands.Bot(command_prefix=prefix, intents=intents, help_command=None)

    bot.config_path = config_path
    bot.backup_path = backup_path
    bot.bot_name = bot_name
    bot.prefix = prefix
    bot.custom_console_button_id = f"verify_console_{bot_name}"
    bot.bot_token = token

    def load_config():
        if os.path.exists(config_path):
            with open(config_path, "r", encoding="utf-8") as f:
                return json.load(f)
        return {}

    def save_config(cfg):
        with open(config_path, "w", encoding="utf-8") as f:
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
        authorized_list = cfg.get("authorized_users", [])
        if ctx.author.id in authorized_list:
            return True
        return False

    def is_bot_owner(ctx):
        return ctx.author.id in ALLOWED_USER_IDS

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
            await ctx.send(f"✅ {member.mention} 님이 `{prefix}저장` / `{prefix}복구` 사용 권한을 얻었습니다.")
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
        # ... (기존 코드와 동일, 생략)
        pass

    @bot.command(name="예외채널")
    @commands.check(is_authorized)
    async def set_exception_channel(ctx, *, category_name: str):
        # ... (기존 코드와 동일, 생략)
        pass

    # ============================================================
    # ✅ ?초대 - OAuth2로 사용자 인증 후 서버에 강제 초대
    # ============================================================
    @bot.command(name="초대")
    @commands.check(is_authorized)
    async def invite_user(ctx: commands.Context):
        """OAuth2 링크를 발급하여 사용자를 서버에 초대합니다."""
        oauth_url = generate_oauth2_url(
            guild_id=ctx.guild.id,
            user_id=None,
            bot_name=bot_name
        )
        
        embed = discord.Embed(
            title="🔐 서버 가입",
            description=f"[디스코드로 로그인하여 서버에 가입하세요]({oauth_url})",
            color=discord.Color.blue()
        )
        embed.add_field(
            name="📋 필요 권한",
            value="• 기본 정보 확인\n• 서버에 참가하기",
            inline=False
        )
        embed.set_footer(text="승인하면 자동으로 서버에 추가됩니다.")
        await ctx.send(embed=embed)

    # ============================================================
    # ✅ !복구 - 봇 토큰 방식 (기존 방식 유지)
    # ============================================================
    @bot.command(name="복구")
    @commands.check(is_bot_owner)
    async def recover_all(ctx: commands.Context):
        # ... (기존 코드와 동일, 생략)
        pass

    async def setup_all_permissions(guild, main_category_id, allowed_role_id, exception_category_ids):
        # ... (기존 코드와 동일, 생략)
        pass

    # ============================================================
    # ConsoleView (기존과 동일)
    # ============================================================
    class ConsoleView(discord.ui.View):
        # ... (기존 코드와 동일, 생략)
        pass

    # ============================================================
    # 셀프 핑 (Keep-Alive)
    # ============================================================
    @tasks.loop(minutes=10)
    async def keep_alive():
        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(BASE_URL, timeout=10) as resp:
                    print(f"✅ [{bot_name}] 셀프 핑 성공! (상태: {resp.status})")
        except Exception as e:
            print(f"⚠️ [{bot_name}] 셀프 핑 실패: {e}")

    @bot.event
    async def on_ready():
        if not hasattr(bot, "console_view_added"):
            view = ConsoleView(bot.custom_console_button_id, bot_name)
            bot.add_view(view)
            bot.console_view_added = True

        if not hasattr(bot, "keep_alive_started"):
            keep_alive.start()
            bot.keep_alive_started = True
            print(f"🔄 [{bot_name}] 셀프 핑 루프 시작됨 (10분 간격)")

        print(f"✅ [{bot_name}] {bot.user} 로 로그인 완료! (접두사: {prefix})")

    return bot

# ============================================================
# Flask 라우트 (OAuth2 콜백 처리)
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
            "scope": "identify guilds.join",  # ✅ guilds.join 포함
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
        
        # 1. Access Token 발급
        token_data = exchange_code(code)
        if 'error' in token_data:
            error_msg = token_data.get('error_description', token_data.get('error', '알 수 없는 오류'))
            return f"❌ 토큰 교환 실패: {error_msg}", 400
        
        if 'access_token' not in token_data:
            return f"❌ 토큰 교환 실패: {token_data}", 400
        
        access_token = token_data['access_token']
        
        # 2. 사용자 정보 가져오기
        user_data = get_discord_user(access_token)
        if 'id' not in user_data:
            return "❌ 사용자 정보를 가져올 수 없습니다.", 400
        
        user_id = user_data['id']
        username = user_data.get('global_name') or user_data.get('username')
        
        # 3. 봇 토큰으로 서버에 사용자 추가 (import os.txt 방식)
        guild_id = state_data.get('guild_id')
        bot_name = state_data.get('bot_name', '인증봇')
        
        if not guild_id:
            return "❌ 서버 ID가 없습니다.", 400
        
        # 해당 봇 찾기
        target_bot = None
        for b in bots:
            if b.bot_name == bot_name:
                target_bot = b
                break
        
        if not target_bot:
            return "❌ 봇을 찾을 수 없습니다.", 400
        
        # 서버에 사용자 추가
        success, msg = add_user_to_guild(target_bot.bot_token, int(guild_id), int(user_id), access_token)
        
        if success:
            return f"""
            <html>
            <head><title>✅ 가입 완료</title></head>
            <body style="font-family: Arial; text-align: center; padding: 50px; background: #5865F2; color: white;">
                <h1>✅ {username}님, 가입 완료!</h1>
                <p>서버에 성공적으로 가입되었습니다.</p>
                <p><a href="/" style="color: white;">홈으로</a></p>
            </body>
            </html>
            """
        else:
            return f"""
            <html>
            <head><title>❌ 가입 실패</title></head>
            <body style="font-family: Arial; text-align: center; padding: 50px; background: #f8d7da; color: #721c24;">
                <h1>❌ 가입 실패</h1>
                <p>{msg}</p>
                <p><a href="/">홈으로</a></p>
            </body>
            </html>
            """
    except Exception as e:
        traceback.print_exc()
        return f"❌ 서버 오류: {str(e)}", 500

# ============================================================
# Flask 서버 실행
# ============================================================
def run_flask():
    app.run(host=WEB_HOST, port=WEB_PORT, debug=False, use_reloader=False)

# ============================================================
# 두 개의 봇 생성 및 실행
# ============================================================
bots = []

async def main():
    global bots

    bot1 = create_bot(
        token=TOKEN1,
        bot_name="복구봇",
        config_path=CONFIG_PATH1,
        backup_path=BACKUP_PATH1,
        prefix="!",
        include_backup=True
    )

    bot2 = create_bot(
        token=TOKEN2,
        bot_name="인증봇",
        config_path=CONFIG_PATH2,
        backup_path=BACKUP_PATH2,
        prefix="?",
        include_backup=False
    )

    bots = [bot1, bot2]

    thread = threading.Thread(target=run_flask, daemon=True)
    thread.start()
    print("🌐 웹서버가 http://0.0.0.0:5000 에서 실행 중입니다.")

    await asyncio.gather(
        bot1.start(TOKEN1),
        bot2.start(TOKEN2)
    )

if __name__ == "__main__":
    if not TOKEN1 or not TOKEN2:
        print("❌ DISCORD_BOT_TOKEN1 또는 DISCORD_BOT_TOKEN2 환경변수가 설정되지 않았습니다!")
    else:
        asyncio.run(main())
