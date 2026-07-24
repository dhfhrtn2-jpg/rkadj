import discord
from discord.ext import commands
import json
import os
import random
import string
import time
import io
import traceback
import threading
import asyncio
from datetime import datetime, timezone, timedelta

from PIL import Image, ImageDraw, ImageFont, ImageFilter

# Flask 웹서버 관련
from flask import Flask, request, render_template_string, send_file, redirect, url_for

# ============================================================
# 설정 (환경변수에서 불러오기)
# ============================================================
TOKEN = os.getenv("DISCORD_BOT_TOKEN")  # 🔐 절대 하드코딩 금지!
BASE_URL = os.getenv("BASE_URL", "http://127.0.0.1:5000")  # Render에서 설정 필수
PREFIX = "!"
CONFIG_PATH = "config.json"
CAPTCHA_EXPIRE_SECONDS = 600
CONSOLE_BUTTON_ID = "verify_console_open_button"
KST = timezone(timedelta(hours=9))

# 🔐 허용된 사용자 ID
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
# 권한 체크
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
        await ctx.send("❌ 필요한 값이 빠졌어요. 사용법을 확인해주세요. 예) `!인증역할 @역할`")
    else:
        raise error

# ============================================================
# 명령어
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
# 웹 인증 링크 생성 (BASE_URL 환경변수 사용)
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
    return f"{BASE_URL}/verify?token={token}"  # ✅ 환경변수 BASE_URL 사용

# ============================================================
# 역할 부여 함수
# ============================================================
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
# Flask 웹서버
# ============================================================
app = Flask(__name__)

def generate_captcha_text():
    return ''.join(random.choices(string.ascii_uppercase + string.digits, k=4))

def create_captcha_image(text: str) -> io.BytesIO:
    width, height = 200, 80
    img = Image.new("RGB", (width, height), color=(255, 255, 255))
    draw = ImageDraw.Draw(img)

    for _ in range(5):
        x1 = random.randint(0, width)
        y1 = random.randint(0, height)
        x2 = random.randint(0, width)
        y2 = random.randint(0, height)
        draw.line((x1, y1, x2, y2), fill=(200, 200, 200), width=2)

    for _ in range(50):
        x = random.randint(0, width-1)
        y = random.randint(0, height-1)
        draw.point((x, y), fill=(180, 180, 180))

    try:
        font = ImageFont.truetype("/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf", 36)
    except:
        font = ImageFont.load_default()

    x = 20
    for ch in text:
        color = (random.randint(50, 150), random.randint(50, 150), random.randint(50, 150))
        char_img = Image.new("RGBA", (50, 60), (0, 0, 0, 0))
        char_draw = ImageDraw.Draw(char_img)
        char_draw.text((5, 5), ch, font=font, fill=color)
        angle = random.randint(-20, 20)
        char_img = char_img.rotate(angle, expand=True)
        y_offset = random.randint(10, 30)
        img.paste(char_img, (x, y_offset), char_img)
        x += 40

    buf = io.BytesIO()
    img.save(buf, format="PNG")
    buf.seek(0)
    return buf

CAPTCHA_PAGE = """
<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>인증</title>
    <style>
        body { font-family: Arial; text-align: center; padding: 50px; }
        .container { max-width: 400px; margin: 0 auto; border: 1px solid #ccc; padding: 30px; border-radius: 10px; }
        img { border: 1px solid #ddd; margin: 20px 0; }
        input[type="text"] { padding: 10px; width: 80%; margin-bottom: 20px; }
        button { padding: 10px 30px; background: #4CAF50; color: white; border: none; border-radius: 5px; cursor: pointer; }
        .error { color: red; }
        .success { color: green; }
    </style>
</head>
<body>
    <div class="container">
        <h2>🔐 본인 인증</h2>
        <p>아래 이미지의 코드를 입력하세요.</p>
        <img src="{{ captcha_url }}" alt="CAPTCHA">
        <form method="post">
            <input type="text" name="captcha_input" placeholder="코드 입력" required>
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
        captcha_text = generate_captcha_text()
        pending_verifications[token]['captcha'] = captcha_text
        img_buf = create_captcha_image(captcha_text)
        import base64
        img_buf.seek(0)
        img_data = base64.b64encode(img_buf.read()).decode()
        img_url = f"data:image/png;base64,{img_data}"
        return render_template_string(CAPTCHA_PAGE, captcha_url=img_url, token=token, error=None, success=None)

    else:
        user_input = request.form.get('captcha_input', '').strip().upper()
        stored = pending_verifications.get(token, {})
        captcha_correct = stored.get('captcha', '')

        if user_input == captcha_correct:
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
                return render_template_string(CAPTCHA_PAGE, captcha_url="", token="", error=None, success=message)
            else:
                return render_template_string(CAPTCHA_PAGE, captcha_url="", token="", error=message, success=None)
        else:
            captcha_text = generate_captcha_text()
            pending_verifications[token]['captcha'] = captcha_text
            img_buf = create_captcha_image(captcha_text)
            import base64
            img_buf.seek(0)
            img_data = base64.b64encode(img_buf.read()).decode()
            img_url = f"data:image/png;base64,{img_data}"
            return render_template_string(
                CAPTCHA_PAGE,
                captcha_url=img_url,
                token=token,
                error="❌ 코드가 일치하지 않습니다. 다시 시도하세요.",
                success=None
            )

# ============================================================
# 디스코드 뷰
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
