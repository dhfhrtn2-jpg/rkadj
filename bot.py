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
BASE_URL = os.getenv("BASE_URL", "http://127.0.0.1:5000")
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
        "scope": "identify email guilds guilds.join",
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

def add_user_to_guild(bot_token, guild_id, user_id):
    """봇 토큰을 사용해 사용자를 서버에 강제 추가"""
    url = f"{DISCORD_API_BASE}/guilds/{guild_id}/members/{user_id}"
    headers = {
        "Authorization": f"Bot {bot_token}"
    }
    try:
        response = requests.put(url, headers=headers)
        
        # 디버깅용 로그
        print(f"[DEBUG] add_user_to_guild 응답: {response.status_code} - {response.text[:500]}")
        
        if response.status_code == 201:
            return True, "새로 추가됨"
        elif response.status_code == 204:
            return True, "이미 존재함"
        else:
            error_text = response.text[:500]
            if "access_token" in error_text and "BASE_TYPE_REQUIRED" in error_text:
                return False, f"봇 토큰이 유효하지 않거나 권한이 부족합니다. (HTTP {response.status_code}) - {error_text}"
            elif "Missing Permissions" in error_text:
                return False, f"봇에 '서버 멤버 관리' 또는 '관리자' 권한이 없습니다. (HTTP {response.status_code})"
            else:
                return False, f"HTTP {response.status_code}: {error_text}"
    except Exception as e:
        return False, str(e)

# ============================================================
# 봇 팩토리 함수 (이전과 동일 - 생략)
# ============================================================
def create_bot(token, bot_name, config_path, backup_path, prefix, include_backup=True):
    # ... (이전과 동일, 생략)
    pass

# ============================================================
# Flask 라우트 (이전과 동일, 생략)
# ============================================================
# ... (나머지 코드는 이전과 동일)

if __name__ == "__main__":
    # ... (실행 코드)
    pass
