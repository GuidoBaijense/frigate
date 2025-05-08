# OIDC authentication endpoints
import os
from fastapi import APIRouter, Request, Response, HTTPException
from fastapi.responses import RedirectResponse
from frigate.config import AuthConfig
from frigate.models import User
from urllib.parse import urlencode
import requests

router = APIRouter()

@router.get("/oidc/login")
def oidc_login(request: Request):
    config: AuthConfig = request.app.frigate_config.auth
    if not config.oidc.enabled:
        raise HTTPException(status_code=404, detail="OIDC not enabled")
    params = {
        "client_id": config.oidc.client_id,
        "response_type": "code",
        "scope": config.oidc.scope,
        "redirect_uri": config.oidc.redirect_uri,
    }
    if config.oidc.extra_params:
        params.update(config.oidc.extra_params)
    url = f"{config.oidc.issuer}/authorize?{urlencode(params)}"
    return RedirectResponse(url)

@router.get("/oidc/callback")
def oidc_callback(request: Request, code: str):
    config: AuthConfig = request.app.frigate_config.auth
    if not config.oidc.enabled:
        raise HTTPException(status_code=404, detail="OIDC not enabled")
    # Exchange code for token
    token_url = f"{config.oidc.issuer}/token"
    data = {
        "grant_type": "authorization_code",
        "code": code,
        "redirect_uri": config.oidc.redirect_uri,
        "client_id": config.oidc.client_id,
        "client_secret": config.oidc.client_secret,
    }
    resp = requests.post(token_url, data=data)
    if not resp.ok:
        raise HTTPException(status_code=400, detail="OIDC token exchange failed")
    tokens = resp.json()
    id_token = tokens.get("id_token")
    if not id_token:
        raise HTTPException(status_code=400, detail="No id_token in OIDC response")
    # Decode id_token (JWT)
    import jwt as pyjwt
    claims = pyjwt.decode(id_token, options={"verify_signature": False})
    username = claims.get("preferred_username") or claims.get("sub")
    mail = claims.get("email")
    if not username:
        raise HTTPException(status_code=400, detail="No username in OIDC token")
    # Create or update user
    user, created = User.get_or_create(username=username, defaults={"role": "viewer", "mail": mail, "notification_tokens": []})
    if not created and mail:
        user.mail = mail
        user.save()
    # Set session/cookie (reuse local login logic)
    from frigate.api.auth import create_encoded_jwt, set_jwt_cookie
    expiration = int(time.time()) + config.session_length
    encoded_jwt = create_encoded_jwt(username, user.role, expiration, request.app.jwt_token)
    response = RedirectResponse("/", status_code=303)
    set_jwt_cookie(response, config.cookie_name, encoded_jwt, expiration, config.cookie_secure)
    return response
