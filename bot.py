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
# 공통 설정 (환경변수)
# ============================================================
TOKEN1 = os.getenv("DISCORD_BOT_TOKEN1")   # 복구봇
TOKEN2 = os.getenv("DISCORD_BOT_TOKEN2")   # 인증봇
BASE_URL = os.getenv("BASE_URL", "http://127.0.0.1:5000")
CONFIG_PATH1 = "config_bot1.json"
CONFIG_PATH2 = "config_bot2.json"
BACKUP_PATH1 = "backup_bot1.json"
BACKUP_PATH2 = "backup_bot2.json"
CAPTCHA_EXPIRE_SECONDS = 600
KST = timezone(timedelta(hours=9))

RECAPTCHA_SITE_KEY = os.getenv("RECAPTCHA_SITE_KEY")
RECAPTCHA_SECRET_KEY = os.getenv("RECAPTCHA_SECRET_KEY")

ALLOWED_USER_IDS = [
    1379356844920799255,  # 본인 Discord ID
]

WEB_HOST = "0.0.0.0"
WEB_PORT = 5000

# ============================================================
# 봇 팩토리 함수 (prefix, 고유 custom_id 지원)
# ============================================================
def create_bot(token, bot_name, config_path, backup_path, prefix, include_backup=True):
    intents = discord.Intents.default()
    intents.members = True
    intents.message_content = True

    bot = commands.Bot(command_prefix=prefix, intents=intents, help_command=None)

    bot.config_path = config_path
    bot.backup_path = backup_path
    bot.bot_name = bot_name
    bot.prefix = prefix

    # 고유한 버튼 custom_id 생성
    bot.custom_console_button_id = f"verify_console_{bot_name}"

    # ============================================================
    # 서버별 설정 저장/로드
    # ============================================================
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
            # 예상치 못한 에러는 로그에 출력하고 사용자에게 알림
            traceback.print_exc()
            await ctx.send(f"❌ 오류가 발생했습니다: {str(error)}")

    # ============================================================
    # 📌 !유저등록 (봇 소유자만)
    # ============================================================
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

    # ============================================================
    # 인증 관련 명령어 (인증역할, 로그채널, 인증채널, 예외채널, 콘솔생성)
    # ============================================================
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
            await ctx.send(f"❌ 역할을 멘션해주세요. 예: `{prefix}인증채널 카테고리이름 @역할`")
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
            await ctx.send(f"❌ 먼저 `{prefix}인증채널`로 인증 역할을 설정해주세요.")
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
                print(f"[{bot_name}] 권한 설정 오류 ({channel.name}): {e}")

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
    # 웹 인증 관련 (봇 이름 저장)
    # ============================================================
    def generate_token() -> str:
        return ''.join(random.choices(string.ascii_letters + string.digits, k=16))

    def create_verify_link(user_id: int, guild_id: int) -> str:
        token = generate_token()
        expires = time.time() + CAPTCHA_EXPIRE_SECONDS
        global pending_verifications_global
        pending_verifications_global[token] = {
            "user_id": user_id,
            "guild_id": guild_id,
            "expires": expires,
            "bot_name": bot_name
        }
        return f"{BASE_URL}/verify?token={token}"

    # ============================================================
    # 📌 !저장 / !복구 (include_backup이 True일 때만)
    # ============================================================
    if include_backup:
        @bot.command(name="저장")
        @commands.check(is_authorized)
        async def save_server(ctx):
            guild = ctx.guild
            backup_data = {}

            roles_data = []
            for role in guild.roles:
                if role.is_default() or role.managed:
                    continue
                roles_data.append({
                    "id": str(role.id),
                    "name": role.name,
                    "color": role.color.value,
                    "hoist": role.hoist,
                    "mentionable": role.mentionable,
                    "permissions": role.permissions.value,
                    "position": role.position
                })
            backup_data["roles"] = roles_data

            categories_data = []
            for cat in guild.categories:
                overwrites = []
                for target, overwrite in cat.overwrites.items():
                    if isinstance(target, discord.Role):
                        if target.is_default() or target.managed:
                            continue
                        overwrites.append({
                            "target_type": "role",
                            "target_id": str(target.id),
                            "allow": overwrite.pair()[0].value,
                            "deny": overwrite.pair()[1].value
                        })
                    elif isinstance(target, discord.Member):
                        overwrites.append({
                            "target_type": "user",
                            "target_id": str(target.id),
                            "allow": overwrite.pair()[0].value,
                            "deny": overwrite.pair()[1].value
                        })
                categories_data.append({
                    "id": str(cat.id),
                    "name": cat.name,
                    "position": cat.position,
                    "overwrites": overwrites
                })
            backup_data["categories"] = categories_data

            channels_data = []
            for ch in guild.channels:
                if isinstance(ch, discord.CategoryChannel):
                    continue
                if isinstance(ch, discord.TextChannel) or isinstance(ch, discord.VoiceChannel):
                    overwrites = []
                    for target, overwrite in ch.overwrites.items():
                        if isinstance(target, discord.Role):
                            if target.is_default() or target.managed:
                                continue
                            overwrites.append({
                                "target_type": "role",
                                "target_id": str(target.id),
                                "allow": overwrite.pair()[0].value,
                                "deny": overwrite.pair()[1].value
                            })
                        elif isinstance(target, discord.Member):
                            overwrites.append({
                                "target_type": "user",
                                "target_id": str(target.id),
                                "allow": overwrite.pair()[0].value,
                                "deny": overwrite.pair()[1].value
                            })
                    channels_data.append({
                        "id": str(ch.id),
                        "name": ch.name,
                        "type": str(ch.type),
                        "position": ch.position,
                        "parent_id": str(ch.category.id) if ch.category else None,
                        "overwrites": overwrites
                    })
            backup_data["channels"] = channels_data

            with open(backup_path, "w", encoding="utf-8") as f:
                json.dump(backup_data, f, indent=4, ensure_ascii=False)

            await ctx.send("✅ 서버 구조가 성공적으로 백업되었습니다.")

        async def safe_delete(obj, delay=0.8):
            while True:
                try:
                    await obj.delete()
                    await asyncio.sleep(delay)
                    return True
                except discord.HTTPException as e:
                    if e.status == 429:
                        retry_after = e.retry_after if hasattr(e, 'retry_after') else 5
                        print(f"[{bot_name}] ⚠️ 레이트리밋 발생! {retry_after}초 대기 후 재시도...")
                        await asyncio.sleep(retry_after + 1)
                    else:
                        print(f"[{bot_name}] ❌ 삭제 실패: {e}")
                        return False
                except Exception as e:
                    print(f"[{bot_name}] ❌ 예상치 못한 오류: {e}")
                    return False

        async def safe_create_role(guild, data, delay=1.0):
            while True:
                try:
                    role = await guild.create_role(
                        name=data["name"],
                        color=discord.Color(data["color"]),
                        hoist=data["hoist"],
                        mentionable=data["mentionable"],
                        permissions=discord.Permissions(data["permissions"])
                    )
                    await role.edit(position=data["position"])
                    await asyncio.sleep(delay)
                    return role
                except discord.HTTPException as e:
                    if e.status == 429:
                        retry_after = e.retry_after if hasattr(e, 'retry_after') else 5
                        print(f"[{bot_name}] ⚠️ 레이트리밋 발생! {retry_after}초 대기 후 재시도...")
                        await asyncio.sleep(retry_after + 1)
                    else:
                        print(f"[{bot_name}] ❌ 역할 생성 실패: {e}")
                        return None

        async def safe_create_channel(guild, data, category=None, delay=0.7):
            while True:
                try:
                    if data["type"] == "text":
                        ch = await guild.create_text_channel(
                            name=data["name"],
                            position=data["position"],
                            category=category
                        )
                    elif data["type"] == "voice":
                        ch = await guild.create_voice_channel(
                            name=data["name"],
                            position=data["position"],
                            category=category
                        )
                    else:
                        return None
                    await asyncio.sleep(delay)
                    return ch
                except discord.HTTPException as e:
                    if e.status == 429:
                        retry_after = e.retry_after if hasattr(e, 'retry_after') else 5
                        print(f"[{bot_name}] ⚠️ 레이트리밋 발생! {retry_after}초 대기 후 재시도...")
                        await asyncio.sleep(retry_after + 1)
                    else:
                        print(f"[{bot_name}] ❌ 채널 생성 실패: {e}")
                        return None

        @bot.command(name="복구")
        @commands.check(is_authorized)
        async def restore_server(ctx):
            guild = ctx.guild
            author = ctx.author

            bot_member = guild.get_member(bot.user.id)
            if not bot_member.guild_permissions.administrator:
                await ctx.author.send("❌ 봇에 `관리자` 권한이 없습니다. 서버 설정에서 권한을 부여해주세요.")
                return

            if not os.path.exists(backup_path):
                await ctx.author.send("❌ 백업 파일이 없습니다. 먼저 `!저장`을 실행하세요.")
                return

            with open(backup_path, "r", encoding="utf-8") as f:
                backup_data = json.load(f)

            if not backup_data:
                await ctx.author.send("❌ 백업 데이터가 비어있습니다.")
                return

            await ctx.send("⚠️ **경고**: 서버의 모든 채널, 카테고리, 역할(관리됨 제외)이 삭제되고 백업된 상태로 복구됩니다.\n"
                           "레이트리밋 방지를 위해 **약 2~5분** 정도 소요될 수 있습니다.\n"
                           "계속하려면 `yes`를 입력하세요. (30초 내)")

            def check(m):
                return m.author == ctx.author and m.channel == ctx.channel and m.content.lower() == "yes"

            try:
                await bot.wait_for("message", check=check, timeout=30.0)
            except asyncio.TimeoutError:
                await ctx.send("복구가 취소되었습니다.")
                return

            await ctx.author.send("🔄 기존 채널 삭제 중... (약 1분 소요)")
            for ch in guild.channels:
                await safe_delete(ch, delay=0.6)

            await ctx.author.send("🔄 기존 역할 삭제 중... (약 1분 소요)")
            for role in guild.roles:
                if role.is_default() or role.managed:
                    continue
                await safe_delete(role, delay=1.0)

            await ctx.author.send("🔄 역할 재생성 중... (약 1~2분 소요)")
            role_map = {}
            roles_data = sorted(backup_data.get("roles", []), key=lambda r: r["position"])
            for rdata in roles_data:
                new_role = await safe_create_role(guild, rdata, delay=1.2)
                if new_role:
                    role_map[rdata["id"]] = new_role

            await ctx.author.send("🔄 카테고리 재생성 중...")
            category_map = {}
            for cdata in backup_data.get("categories", []):
                try:
                    new_cat = await guild.create_category(
                        name=cdata["name"],
                        position=cdata["position"]
                    )
                    await asyncio.sleep(0.7)
                    category_map[cdata["id"]] = new_cat

                    for ow in cdata["overwrites"]:
                        target = None
                        if ow["target_type"] == "role":
                            target = role_map.get(ow["target_id"])
                        elif ow["target_type"] == "user":
                            target = guild.get_member(int(ow["target_id"]))
                        if target:
                            allow = discord.Permissions(ow["allow"])
                            deny = discord.Permissions(ow["deny"])
                            try:
                                await new_cat.set_permissions(
                                    target,
                                    overwrite=discord.PermissionOverwrite.from_pair(allow, deny)
                                )
                                await asyncio.sleep(0.5)
                            except:
                                pass
                except Exception as e:
                    print(f"[{bot_name}] 카테고리 생성 오류: {e}")

            await ctx.author.send("🔄 채널 재생성 중... (약 2~3분 소요)")
            for chdata in backup_data.get("channels", []):
                parent = category_map.get(chdata["parent_id"]) if chdata["parent_id"] else None
                new_ch = await safe_create_channel(guild, chdata, parent, delay=0.7)
                if not new_ch:
                    continue

                for ow in chdata["overwrites"]:
                    target = None
                    if ow["target_type"] == "role":
                        target = role_map.get(ow["target_id"])
                    elif ow["target_type"] == "user":
                        target = guild.get_member(int(ow["target_id"]))
                    if target:
                        allow = discord.Permissions(ow["allow"])
                        deny = discord.Permissions(ow["deny"])
                        try:
                            await new_ch.set_permissions(
                                target,
                                overwrite=discord.PermissionOverwrite.from_pair(allow, deny)
                            )
                            await asyncio.sleep(0.5)
                        except:
                            pass

            try:
                await ctx.author.send("✅ 서버 복구가 완료되었습니다! (레이트리밋을 피하며 안전하게 처리됨)")
            except discord.Forbidden:
                print(f"[{bot_name}] 복구 완료되었으나 DM 전송 실패.")

    # ============================================================
    # 디스코드 뷰 (콘솔 버튼) - 고유 custom_id 사용
    # ============================================================
    class ConsoleView(discord.ui.View):
        def __init__(self, custom_id):
            super().__init__(timeout=None)
            self.custom_id = custom_id

        @discord.ui.button(label="인증하기", style=discord.ButtonStyle.green, emoji="✅", custom_id=CONSOLE_BUTTON_ID)
        async def console_verify_button(self, interaction: discord.Interaction, button: discord.ui.Button):
            try:
                # 먼저 지연 응답 (3초 제한 회피)
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
                    # 이미 defer가 호출되었으므로 followup 사용
                    await interaction.followup.send(f"❌ 오류: {str(e)}", ephemeral=True)
                except:
                    pass

    @bot.command(name="콘솔생성")
    @commands.check(is_authorized)
    async def create_console(ctx: commands.Context):
        embed = discord.Embed(
            title="🔐 서버 인증",
            description=f"아래 버튼을 누르면 인증 링크를 받을 수 있습니다.",
            color=discord.Color.blurple()
        )
        # 고유한 custom_id를 가진 뷰 생성
        view = ConsoleView(bot.custom_console_button_id)
        await ctx.send(embed=embed, view=view)

    # ============================================================
    # 봇 이벤트
    # ============================================================
    @bot.event
    async def on_ready():
        # persistent view 등록 (재시작 후에도 버튼 동작)
        if not hasattr(bot, "console_view_added"):
            view = ConsoleView(bot.custom_console_button_id)
            bot.add_view(view)
            bot.console_view_added = True

        print(f"✅ [{bot_name}] {bot.user} 로 로그인 완료! (접두사: {prefix})")

    return bot

# ============================================================
# Flask 웹서버 (reCAPTCHA + 루트 경로)
# ============================================================
app = Flask(__name__)

pending_verifications_global = {}

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
    if not token or token not in pending_verifications_global:
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

        ip = request.headers.get('X-Forwarded-For', request.remote_addr)
        if ip and ',' in ip:
            ip = ip.split(',')[0].strip()

        data = pending_verifications_global.get(token)
        if not data:
            return "❌ 인증 정보가 없습니다.", 400

        bot_name = data.get("bot_name")
        target_bot = None
        for b in bots:
            if b.bot_name == bot_name:
                target_bot = b
                break

        if not target_bot:
            return "❌ 해당 서버를 관리하는 봇을 찾을 수 없습니다.", 400

        future = asyncio.run_coroutine_threadsafe(
            assign_role_from_web_wrapper(token, ip, data["guild_id"], data["user_id"], target_bot),
            target_bot.loop
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
# 웹 인증 처리 래퍼
# ============================================================
async def assign_role_from_web_wrapper(token: str, ip: str, guild_id: int, user_id: int, bot_instance):
    try:
        if token not in pending_verifications_global:
            return False, "인증 토큰이 존재하지 않습니다."

        data = pending_verifications_global[token]
        if time.time() > data["expires"]:
            del pending_verifications_global[token]
            return False, "인증 토큰이 만료되었습니다."

        guild = bot_instance.get_guild(guild_id)
        if not guild:
            return False, "서버를 찾을 수 없습니다."

        member = guild.get_member(user_id)
        if not member:
            return False, "서버에서 해당 사용자를 찾을 수 없습니다."

        config_path = bot_instance.config_path
        with open(config_path, "r", encoding="utf-8") as f:
            config = json.load(f)
        gcfg = config.get(str(guild_id), {})

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

        del pending_verifications_global[token]

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
                embed.add_field(name="🌐 IP 주소", value=ip, inline=False)
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

    # 복구봇: 접두사 !, 백업 기능 포함
    bot1 = create_bot(
        token=TOKEN1,
        bot_name="복구봇",
        config_path=CONFIG_PATH1,
        backup_path=BACKUP_PATH1,
        prefix="!",
        include_backup=True
    )

    # 인증봇: 접두사 ?, 백업 기능 제외 (오직 인증)
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
