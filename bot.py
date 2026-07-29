import discord
from discord.ext import commands
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
from datetime import datetime, timezone, timedelta

from flask import Flask, request, render_template_string

# ============================================================
# 설정 (환경변수)
# ============================================================
TOKEN = os.getenv("DISCORD_BOT_TOKEN")
BASE_URL = os.getenv("BASE_URL", "http://127.0.0.1:5000")
PREFIX = "!"
CONFIG_PATH = "config.json"
CAPTCHA_EXPIRE_SECONDS = 600
CONSOLE_BUTTON_ID = "verify_console_open_button"
KST = timezone(timedelta(hours=9))

# 🔐 reCAPTCHA 키 (환경변수)
RECAPTCHA_SITE_KEY = os.getenv("RECAPTCHA_SITE_KEY")
RECAPTCHA_SECRET_KEY = os.getenv("RECAPTCHA_SECRET_KEY")

ALLOWED_USER_IDS = [
    1379356844920799255,  # 본인 Discord ID
]

WEB_HOST = "0.0.0.0"
WEB_PORT = 5000

intents = discord.Intents.default()
intents.members = True
intents.message_content = True

bot = commands.Bot(command_prefix=PREFIX, intents=intents, help_command=None)

# ============================================================
# 서버별 설정 저장/로드
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

pending_verifications = {}

# ============================================================
# 권한 체크 (서버 소유자 + 허용된 사용자)
# ============================================================
def owner_or_allowed():
    async def predicate(ctx: commands.Context) -> bool:
        if ctx.guild is None:
            raise commands.NoPrivateMessage("서버 안에서만 사용할 수 있어요.")
        if ctx.author.id == ctx.guild.owner_id:
            return True
        if ctx.author.id in ALLOWED_USER_IDS:
            return True
        raise commands.MissingPermissions(["서버 소유자 또는 허용된 사용자"])
    return commands.check(predicate)

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
        raise error

# ============================================================
# 기존 명령어 (인증역할, 로그채널, 콘솔생성)
# ============================================================
@bot.command(name="인증역할")
@owner_or_allowed()
async def set_verify_role(ctx: commands.Context, role: discord.Role):
    gcfg = get_guild_cfg(ctx.guild.id)
    gcfg["verify_role"] = role.id
    save_config(config)
    await ctx.send(f"✅ 인증 통과 시 지급할 역할을 {role.mention} 로 설정했어요.")

@bot.command(name="로그채널")
@owner_or_allowed()
async def set_log_channel(ctx: commands.Context, channel: discord.TextChannel):
    gcfg = get_guild_cfg(ctx.guild.id)
    gcfg["log_channel"] = channel.id
    save_config(config)
    await ctx.send(f"✅ 인증 로그를 {channel.mention} 채널에 전송하도록 설정했어요.")

# ============================================================
# ✨ 새로운 명령어: 인증채널 (카테고리 제외, 역할에 모든 권한)
# ============================================================
@bot.command(name="인증채널")
@owner_or_allowed()
async def set_auth_channel(ctx, *, args: str):
    """
    사용법: !인증채널 카테고리이름 @역할
    예: !인증채널 일반 @인증된
    """
    # 역할 멘션 추출 (<@&숫자>)
    role_match = re.search(r'<@&(\d+)>', args)
    if not role_match:
        await ctx.send("❌ 역할을 멘션해주세요. 예: `!인증채널 카테고리이름 @역할`")
        return
    role_id = int(role_match.group(1))
    role = ctx.guild.get_role(role_id)
    if not role:
        await ctx.send("❌ 해당 역할을 찾을 수 없어요.")
        return

    # 카테고리 이름 추출 (역할 멘션 제거)
    category_name = args.replace(role_match.group(0), '').strip()
    if not category_name:
        await ctx.send("❌ 카테고리 이름을 입력해주세요.")
        return

    category = discord.utils.get(ctx.guild.categories, name=category_name)
    if not category:
        await ctx.send(f"❌ '{category_name}' 카테고리를 찾을 수 없어요.")
        return

    # 설정 저장
    gcfg = get_guild_cfg(ctx.guild.id)
    gcfg["main_category_id"] = category.id
    gcfg["allowed_role_id"] = role.id
    if "exception_category_ids" not in gcfg:
        gcfg["exception_category_ids"] = []
    save_config(config)

    # 권한 설정 실행
    await setup_all_permissions(ctx.guild, category.id, role.id, gcfg["exception_category_ids"])
    await ctx.send(
        f"✅ 인증 채널 설정 완료!\n"
        f"카테고리 '{category.name}'를 제외한 모든 채널에서 {role.mention} 역할이 **보기 및 채팅** 가능합니다."
    )

# ============================================================
# ✨ 새로운 명령어: 예외채널 (특정 카테고리에서 채팅 금지)
# ============================================================
@bot.command(name="예외채널")
@owner_or_allowed()
async def set_exception_channel(ctx, *, category_name: str):
    """
    사용법: !예외채널 카테고리이름
    예: !예외채널 비밀채널
    """
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
        await ctx.send("❌ 먼저 `!인증채널`로 인증 역할을 설정해주세요.")
        return

    role = ctx.guild.get_role(allowed_role_id)
    if not role:
        await ctx.send("❌ 설정된 역할을 찾을 수 없어요.")
        return

    # 해당 카테고리 내 모든 채널에서 채팅 금지 (보기는 허용)
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

# ============================================================
# 권한 설정 헬퍼 함수
# ============================================================
async def setup_all_permissions(guild, main_category_id, allowed_role_id, exception_category_ids):
    """
    모든 채널/카테고리를 순회하며 권한을 설정합니다.
    - main_category_id와 그 하위 채널은 제외
    - exception_category_ids에 포함된 카테고리와 그 하위 채널은 제외
    - 나머지 모든 채널/카테고리에 allowed_role_id에 view_channel=True, send_messages=True (텍스트 채널인 경우)
    """
    role = guild.get_role(allowed_role_id)
    if not role:
        return

    # 모든 채널(텍스트, 음성, 카테고리)에 대해 처리
    for channel in guild.channels:
        # main_category 자체는 제외
        if channel.id == main_category_id:
            continue
        # main_category의 하위 채널 제외
        if isinstance(channel, (discord.TextChannel, discord.VoiceChannel)) and channel.category_id == main_category_id:
            continue
        # exception 카테고리 자체 제외
        if channel.id in exception_category_ids:
            continue
        # exception 카테고리의 하위 채널 제외
        if isinstance(channel, (discord.TextChannel, discord.VoiceChannel)) and channel.category_id in exception_category_ids:
            continue

        try:
            overwrite = channel.overwrites_for(role)
            overwrite.view_channel = True
            if isinstance(channel, discord.TextChannel):
                overwrite.send_messages = True
            await channel.set_permissions(role, overwrite=overwrite)
        except discord.Forbidden:
            # 봇 권한 부족 시 무시
            pass
        except Exception as e:
            print(f"권한 설정 오류 ({channel.name}): {e}")

    # exception_category_ids에 등록된 카테고리 내 채널들은 따로 처리 (send_messages False)
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
# 웹 인증 관련 (기존 코드 유지)
# ============================================================
def generate_token() -> str:
    return ''.join(random.choices(string.ascii_letters + string.digits, k=16))

def create_verify_link(user_id: int, guild_id: int) -> str:
    token = generate_token()
    expires = time.time() + CAPTCHA_EXPIRE_SECONDS
    pending_verifications[token] = {
        "user_id": user_id,
        "guild_id": guild_id,
        "expires": expires
    }
    return f"{BASE_URL}/verify?token={token}"

async def assign_role_from_web(token: str, ip: str):
    try:
        if token not in pending_verifications:
            return False, "인증 토큰이 존재하지 않습니다."

        data = pending_verifications[token]
        if time.time() > data["expires"]:
            del pending_verifications[token]
            return False, "인증 토큰이 만료되었습니다."

        user_id = data["user_id"]
        guild_id = data["guild_id"]

        guild = bot.get_guild(guild_id)
        if not guild:
            return False, "서버를 찾을 수 없습니다."

        member = guild.get_member(user_id)
        if not member:
            return False, "서버에서 해당 사용자를 찾을 수 없습니다."

        gcfg = get_guild_cfg(guild_id)
        verify_role_id = gcfg.get("verify_role")
        if not verify_role_id:
            return False, "인증 역할이 설정되지 않았습니다."

        role = guild.get_role(verify_role_id)
        if not role:
            return False, "설정된 역할이 존재하지 않습니다."

        removable_roles = [
            r for r in member.roles
            if r != guild.default_role and r < guild.me.top_role
        ]
        if removable_roles:
            await member.remove_roles(*removable_roles, reason="웹 인증 완료 - 역할 초기화")
        await member.add_roles(role, reason="웹 인증 완료")

        del pending_verifications[token]

        log_channel_id = gcfg.get("log_channel")
        if log_channel_id:
            log_channel = guild.get_channel(log_channel_id)
            if log_channel:
                now_kst = datetime.now(KST)
                embed = discord.Embed(
                    title="✅ 웹 인증 완료",
                    description=f"{member.mention} 님이 웹 인증을 완료했어요.",
                    color=discord.Color.green(),
                    timestamp=datetime.now(timezone.utc)
                )
                embed.add_field(name="유저", value=f"{member} ({member.id})", inline=False)
                embed.add_field(name="인증 시각", value=now_kst.strftime("%Y-%m-%d %H:%M:%S (KST)"), inline=False)
                embed.add_field(name="IP 주소", value=ip, inline=False)
                embed.set_thumbnail(url=member.display_avatar.url)
                try:
                    await log_channel.send(embed=embed)
                except:
                    pass

        return True, f"역할 {role.name}이 지급되었습니다."

    except Exception as e:
        traceback.print_exc()
        return False, f"오류 발생: {str(e)}"

# ============================================================
# Flask 웹서버 (reCAPTCHA + 루트 경로)
# ============================================================
app = Flask(__name__)

@app.route('/')
def home():
    return "✅ Bot is alive and running!", 200

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

CAPTCHA_PAGE = """
<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>인증</title>
    <script src="https://www.google.com/recaptcha/api.js" async defer></script>
    <style>
        body { font-family: Arial; text-align: center; padding: 50px; }
        .container { max-width: 400px; margin: 0 auto; border: 1px solid #ccc; padding: 30px; border-radius: 10px; }
        .g-recaptcha { display: inline-block; margin: 20px 0; }
        button { padding: 10px 30px; background: #4CAF50; color: white; border: none; border-radius: 5px; cursor: pointer; }
        .error { color: red; }
        .success { color: green; }
    </style>
</head>
<body>
    <div class="container">
        <h2>🔐 본인 인증</h2>
        <p>로봇이 아님을 인증해주세요.</p>
        <form method="post">
            <div class="g-recaptcha" data-sitekey="{{ site_key }}"></div>
            <input type="hidden" name="token" value="{{ token }}">
            <br>
            <button type="submit">인증하기</button>
        </form>
        {% if error %}
            <p class="error">{{ error }}</p>
        {% endif %}
        {% if success %}
            <p class="success">{{ success }}</p>
        {% endif %}
    </div>
</body>
</html>
"""

@app.route('/verify', methods=['GET', 'POST'])
def verify_page():
    token = request.args.get('token') or request.form.get('token')
    if not token or token not in pending_verifications:
        return "❌ 유효하지 않거나 만료된 인증 링크입니다.", 400

    if request.method == 'GET':
        return render_template_string(
            CAPTCHA_PAGE,
            site_key=RECAPTCHA_SITE_KEY or "",
            token=token,
            error=None,
            success=None
        )

    else:
        recaptcha_response = request.form.get('g-recaptcha-response')
        if not recaptcha_response:
            return render_template_string(
                CAPTCHA_PAGE,
                site_key=RECAPTCHA_SITE_KEY or "",
                token=token,
                error="❌ reCAPTCHA를 완료해주세요.",
                success=None
            )

        if not verify_recaptcha(recaptcha_response):
            return render_template_string(
                CAPTCHA_PAGE,
                site_key=RECAPTCHA_SITE_KEY or "",
                token=token,
                error="❌ reCAPTCHA 검증에 실패했습니다. 다시 시도해주세요.",
                success=None
            )

        ip = request.remote_addr
        future = asyncio.run_coroutine_threadsafe(
            assign_role_from_web(token, ip),
            bot.loop
        )
        try:
            success, message = future.result(timeout=15)
        except Exception as e:
            success, message = False, f"서버 오류: {str(e)}"

        if success:
            return render_template_string(
                CAPTCHA_PAGE,
                site_key=RECAPTCHA_SITE_KEY or "",
                token="",
                error=None,
                success=message
            )
        else:
            return render_template_string(
                CAPTCHA_PAGE,
                site_key=RECAPTCHA_SITE_KEY or "",
                token=token,
                error=message,
                success=None
            )

# ============================================================
# 디스코드 뷰 (콘솔 버튼)
# ============================================================
class ConsoleView(discord.ui.View):
    def __init__(self):
        super().__init__(timeout=None)

    @discord.ui.button(label="인증하기", style=discord.ButtonStyle.green, emoji="✅", custom_id=CONSOLE_BUTTON_ID)
    async def console_verify_button(self, interaction: discord.Interaction, button: discord.ui.Button):
        try:
            await interaction.response.defer(ephemeral=True)

            gcfg = get_guild_cfg(interaction.guild_id)
            if not gcfg.get("verify_role"):
                return await interaction.followup.send(
                    "❌ 이 서버에는 인증역할이 설정되어있지 않아요. 관리자에게 문의해주세요.",
                    ephemeral=True
                )

            link = create_verify_link(interaction.user.id, interaction.guild_id)
            embed = discord.Embed(
                title="🔐 웹 인증",
                description=f"[여기를 클릭하여 인증을 완료하세요]({link})\n\n링크는 {CAPTCHA_EXPIRE_SECONDS//60}분간 유효합니다.",
                color=discord.Color.blue()
            )
            embed.set_footer(text="인증 후 역할이 자동으로 지급됩니다.")
            await interaction.followup.send(embed=embed, ephemeral=True)

        except Exception as e:
            traceback.print_exc()
            try:
                await interaction.followup.send(f"❌ 오류: {str(e)}", ephemeral=True)
            except:
                pass

@bot.command(name="콘솔생성")
@owner_or_allowed()
async def create_console(ctx: commands.Context):
    embed = discord.Embed(
        title="🔐 서버 인증",
        description="아래 버튼을 누르면 인증 링크를 받을 수 있습니다.",
        color=discord.Color.blurple()
    )
    await ctx.send(embed=embed, view=ConsoleView())

# ============================================================
# 실행
# ============================================================
def run_flask():
    app.run(host=WEB_HOST, port=WEB_PORT, debug=False, use_reloader=False)

@bot.event
async def on_ready():
    if not hasattr(bot, "console_view_added"):
        bot.add_view(ConsoleView())
        bot.console_view_added = True

    if not hasattr(bot, "flask_thread"):
        thread = threading.Thread(target=run_flask, daemon=True)
        thread.start()
        bot.flask_thread = thread
        print(f"🌐 웹서버가 http://{WEB_HOST}:{WEB_PORT} 에서 실행 중입니다.")

    print(f"✅ {bot.user} 로 로그인 완료!")

if __name__ == "__main__":
    if TOKEN is None:
        print("❌ DISCORD_BOT_TOKEN 환경변수가 설정되지 않았습니다!")
    else:
        bot.run(TOKEN)
