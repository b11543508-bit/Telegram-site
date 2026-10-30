import os
import secrets
import hashlib
import base64
from datetime import timedelta
from urllib.parse import urlencode

import requests
import jwt

from flask import (
    Flask, render_template, redirect, request,
    session, url_for
)
from requests.auth import HTTPBasicAuth
from jwt import PyJWKClient

app = Flask(__name__)

app.secret_key = os.environ.get("SECRET_KEY", "")
app.config.update(
    SESSION_COOKIE_SECURE=True,
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    PERMANENT_SESSION_LIFETIME=timedelta(days=7),
)

CLIENT_ID = os.environ.get("TELEGRAM_CLIENT_ID", "")
CLIENT_SECRET = os.environ.get("TELEGRAM_CLIENT_SECRET", "")
BASE_URL = os.environ.get(
    "BASE_URL", "https://telegram-site-rscj.onrender.com"
).rstrip("/")

REDIRECT_URI = BASE_URL + "/auth/callback"

AUTH_URL = "https://oauth.telegram.org/auth"
TOKEN_URL = "https://oauth.telegram.org/token"
JWKS_URL = "https://oauth.telegram.org/.well-known/jwks.json"
ISSUER = "https://oauth.telegram.org"


def configuration_ok():
    return bool(CLIENT_ID and CLIENT_SECRET and app.secret_key)


@app.route("/")
def home():
    return render_template(
        "index.html",
        user=session.get("user"),
        error=session.pop("login_error", None)
    )


@app.route("/login")
def login():
    if not configuration_ok():
        return "Не настроены переменные Telegram Login в Render.", 503

    state = secrets.token_urlsafe(32)
    nonce = secrets.token_urlsafe(32)
    verifier = secrets.token_urlsafe(64)

    challenge = base64.urlsafe_b64encode(
        hashlib.sha256(verifier.encode()).digest()
    ).rstrip(b"=").decode()

    session["oauth_state"] = state
    session["oauth_nonce"] = nonce
    session["pkce_verifier"] = verifier

    params = {
        "client_id": CLIENT_ID,
        "redirect_uri": REDIRECT_URI,
        "response_type": "code",
        "scope": "openid profile",
        "state": state,
        "nonce": nonce,
        "code_challenge": challenge,
        "code_challenge_method": "S256",
    }

    return redirect(AUTH_URL + "?" + urlencode(params))


@app.route("/auth/callback")
def auth_callback():
    if request.args.get("error"):
        session["login_error"] = "Вход отменён или отклонён в Telegram."
        return redirect(url_for("home"))

    code = request.args.get("code")
    returned_state = request.args.get("state")

    saved_state = session.pop("oauth_state", None)
    nonce = session.pop("oauth_nonce", None)
    verifier = session.pop("pkce_verifier", None)

    if not code or not saved_state or not returned_state:
        session["login_error"] = "Не удалось получить подтверждение входа."
        return redirect(url_for("home"))

    if not secrets.compare_digest(saved_state, returned_state):
        session["login_error"] = "Ошибка проверки безопасности входа."
        return redirect(url_for("home"))

    if not nonce or not verifier:
        session["login_error"] = "Сессия входа истекла. Попробуйте снова."
        return redirect(url_for("home"))

    try:
        token_response = requests.post(
            TOKEN_URL,
            data={
                "grant_type": "authorization_code",
                "code": code,
                "redirect_uri": REDIRECT_URI,
                "client_id": CLIENT_ID,
                "code_verifier": verifier,
            },
            auth=HTTPBasicAuth(CLIENT_ID, CLIENT_SECRET),
            timeout=20,
        )
        token_response.raise_for_status()
        token_data = token_response.json()

        id_token = token_data.get("id_token")
        if not id_token:
            raise ValueError("Telegram не вернул ID token")

        jwks_client = PyJWKClient(JWKS_URL)
        signing_key = jwks_client.get_signing_key_from_jwt(id_token)

        claims = jwt.decode(
            id_token,
            signing_key.key,
            algorithms=["RS256"],
            audience=CLIENT_ID,
            issuer=ISSUER,
            options={"require": ["exp", "iat", "iss", "aud", "sub", "nonce"]},
        )

        if not secrets.compare_digest(str(claims.get("nonce", "")), nonce):
            raise ValueError("Неверная проверка nonce")

        session.clear()
        session.permanent = True
        session["user"] = {
            "id": str(claims.get("id", claims.get("sub", ""))),
            "name": claims.get("name", "Пользователь Telegram"),
            "username": claims.get("preferred_username", ""),
        }

        return redirect(url_for("home"))

    except Exception:
        session.clear()
        session["login_error"] = (
            "Не удалось подтвердить вход. Попробуйте ещё раз."
        )
        return redirect(url_for("home"))


@app.route("/logout", methods=["POST"])
def logout():
    session.clear()
    return redirect(url_for("home"))


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=10000)
