"""
Autenticação Mercado Livre — OAuth 2.0
Gerencia client credentials, troca de código, refresh automático de token.
"""
import json
import os
import time
import requests

_DIR  = os.path.dirname(os.path.abspath(__file__))
_CFG  = os.path.join(_DIR, "ml_config.json")      # client_id + client_secret + redirect_uri
_TOK  = os.path.join(_DIR, "ml_tokens.json")       # access_token + refresh_token

ML_AUTH_URL  = "https://auth.mercadolivre.com.br/authorization"
ML_TOKEN_URL = "https://api.mercadolibre.com/oauth/token"


# ── Config (client_id / secret) ───────────────────────────────────────────────

def salvar_config(client_id: str, client_secret: str, redirect_uri: str):
    with open(_CFG, "w", encoding="utf-8") as f:
        json.dump({"client_id": client_id, "client_secret": client_secret,
                   "redirect_uri": redirect_uri}, f)


def carregar_config() -> dict:
    if not os.path.exists(_CFG):
        return {}
    with open(_CFG, "r", encoding="utf-8") as f:
        return json.load(f)


# ── Tokens ────────────────────────────────────────────────────────────────────

def _salvar_tokens(data: dict):
    data["saved_at"] = int(time.time())
    with open(_TOK, "w", encoding="utf-8") as f:
        json.dump(data, f)


def _carregar_tokens() -> dict:
    if not os.path.exists(_TOK):
        return {}
    with open(_TOK, "r", encoding="utf-8") as f:
        return json.load(f)


def _token_expirado(tokens: dict) -> bool:
    if not tokens.get("access_token"):
        return True
    saved_at  = tokens.get("saved_at", 0)
    expires_in = tokens.get("expires_in", 21600)   # ML padrão = 6h
    # renova com 5 min de folga
    return (time.time() - saved_at) >= (expires_in - 300)


# ── OAuth flow ────────────────────────────────────────────────────────────────

def get_authorization_url(client_id: str, redirect_uri: str) -> str:
    return (
        f"{ML_AUTH_URL}"
        f"?response_type=code"
        f"&client_id={client_id}"
        f"&redirect_uri={redirect_uri}"
    )


def trocar_codigo_por_token(code: str) -> dict | None:
    cfg = carregar_config()
    if not cfg:
        return None
    r = requests.post(ML_TOKEN_URL, data={
        "grant_type":    "authorization_code",
        "client_id":     cfg["client_id"],
        "client_secret": cfg["client_secret"],
        "code":          code,
        "redirect_uri":  cfg["redirect_uri"],
    }, timeout=10)
    if r.status_code == 200:
        data = r.json()
        _salvar_tokens(data)
        return data
    return None


def _renovar_token() -> str | None:
    tokens = _carregar_tokens()
    cfg    = carregar_config()
    if not tokens.get("refresh_token") or not cfg:
        return None
    r = requests.post(ML_TOKEN_URL, data={
        "grant_type":    "refresh_token",
        "client_id":     cfg["client_id"],
        "client_secret": cfg["client_secret"],
        "refresh_token": tokens["refresh_token"],
    }, timeout=10)
    if r.status_code == 200:
        data = r.json()
        _salvar_tokens(data)
        return data["access_token"]
    return None


def get_token() -> str | None:
    """Retorna access_token válido, renovando automaticamente se necessário."""
    tokens = _carregar_tokens()
    if not tokens.get("access_token"):
        return None
    if _token_expirado(tokens):
        return _renovar_token()
    return tokens["access_token"]


def get_user_id(token: str) -> tuple:
    """Retorna (user_id, nickname) do token atual."""
    r = requests.get(
        "https://api.mercadolibre.com/users/me",
        headers={"Authorization": f"Bearer {token}"},
        timeout=5,
    )
    if r.status_code == 200:
        d = r.json()
        return str(d["id"]), d.get("nickname", "")
    return None, None


def esta_conectado() -> bool:
    return bool(get_token())
