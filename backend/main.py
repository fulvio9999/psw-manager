from __future__ import annotations

import os
import secrets
import time
from pathlib import Path
from typing import Any

from fastapi import Depends, FastAPI, Form, Request
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from sqlalchemy.orm import Session
from sqlalchemy import func

import auth
import crypto
from database import SessionLocal, init_db
from models import AppSettings, User, VaultItem


BASE_DIR = Path(__file__).resolve().parent

SESSION_TTL_MIN = int(os.getenv("SESSION_TTL_MIN", "120"))
COOKIE_SECURE = os.getenv("COOKIE_SECURE", "false").lower() in {"1", "true", "yes"}

app = FastAPI()
templates = Jinja2Templates(directory=str(BASE_DIR / "templates"))
app.mount("/static", StaticFiles(directory=str(BASE_DIR / "static")), name="static")


def get_db() -> Any:
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def _cleanup_store(store: dict[str, dict[str, Any]]) -> None:
    now = time.time()
    expired = [key for key, entry in store.items() if entry["expires_at"] <= now]
    for key in expired:
        del store[key]


def _create_session(user_id: int, key: bytes) -> str:
    session_id = secrets.token_urlsafe(32)
    app.state.sessions[session_id] = {
        "user_id": user_id,
        "key": key,
        "expires_at": time.time() + SESSION_TTL_MIN * 60,
    }
    return session_id


def _get_session(request: Request) -> dict[str, Any] | None:
    _cleanup_store(app.state.sessions)
    session_id = request.cookies.get("session_id")
    if not session_id:
        return None
    session = app.state.sessions.get(session_id)
    if not session:
        return None
    if session["expires_at"] <= time.time():
        del app.state.sessions[session_id]
        return None
    session["expires_at"] = time.time() + SESSION_TTL_MIN * 60
    return session


def _create_setup_token(user_id: int, key: bytes) -> str:
    token = secrets.token_urlsafe(32)
    app.state.setup_tokens[token] = {
        "user_id": user_id,
        "key": key,
        "expires_at": time.time() + 15 * 60,
    }
    return token


def _get_setup_token(request: Request) -> dict[str, Any] | None:
    _cleanup_store(app.state.setup_tokens)
    token = request.cookies.get("setup_token")
    if not token:
        return None
    entry = app.state.setup_tokens.get(token)
    if not entry:
        return None
    if entry["expires_at"] <= time.time():
        del app.state.setup_tokens[token]
        return None
    return entry


def _current_user(request: Request, db: Session) -> tuple[User, bytes] | None:
    session = _get_session(request)
    if not session:
        return None
    user = db.get(User, session["user_id"])
    if not user:
        return None
    return user, session["key"]


def _require_admin(request: Request, db: Session) -> tuple[User, bytes] | None:
    user_session = _current_user(request, db)
    if not user_session:
        return None
    user, key = user_session
    if not user.is_admin:
        return None
    return user, key


def _get_settings(db: Session) -> AppSettings:
    settings = db.query(AppSettings).first()
    if not settings:
        settings = AppSettings(require_2fa=True)
        db.add(settings)
        db.commit()
        db.refresh(settings)
    return settings


@app.on_event("startup")
def startup() -> None:
    app.state.sessions = {}
    app.state.setup_tokens = {}
    init_db()
    with SessionLocal() as db:
        _get_settings(db)


@app.get("/", response_class=HTMLResponse)
def home(request: Request, db: Session = Depends(get_db)) -> HTMLResponse:
    user_session = _current_user(request, db)
    if not user_session:
        return RedirectResponse("/login", status_code=302)

    user, key = user_session
    q = (request.query_params.get("q") or "").strip().lower()
    items = db.query(VaultItem).filter(VaultItem.user_id == user.id).order_by(VaultItem.id.desc()).all()

    view_items = []
    for item in items:
        try:
            name = crypto.decrypt(key, item.name)
            username = crypto.decrypt(key, item.username)
            password = crypto.decrypt(key, item.password)
            url = crypto.decrypt(key, item.url) if item.url else ""
            notes = crypto.decrypt(key, item.notes) if item.notes else ""
        except Exception:
            continue

        haystack = " ".join([name, username, url, notes]).lower()
        if q and q not in haystack:
            continue
        view_items.append(
            {
                "id": item.id,
                "name": name,
                "username": username,
                "password": password,
                "url": url,
                "notes": notes,
            }
        )

    return templates.TemplateResponse(
        "vault.html",
        {"request": request, "user": user, "items": view_items, "q": q},
    )


@app.get("/login", response_class=HTMLResponse)
def login_form(request: Request, db: Session = Depends(get_db)) -> HTMLResponse:
    settings = _get_settings(db)
    return templates.TemplateResponse(
        "login.html",
        {"request": request, "require_2fa": settings.require_2fa},
    )


@app.post("/login", response_class=HTMLResponse)
def login(
    request: Request,
    username: str = Form(...),
    password: str = Form(...),
    code: str = Form(...),
    db: Session = Depends(get_db),
) -> HTMLResponse:
    settings = _get_settings(db)
    if len(password.encode("utf-8")) > 72:
        return templates.TemplateResponse(
            "login.html",
            {"request": request, "error": "Password troppo lunga (max 72 caratteri/byte).", "require_2fa": settings.require_2fa},
        )
    user = db.query(User).filter(User.username == username).first()
    if not user or not auth.verify_password(password, user.password_hash):
        return templates.TemplateResponse(
            "login.html",
            {"request": request, "error": "Credenziali non valide.", "require_2fa": settings.require_2fa},
        )
    if not user.is_active:
        return templates.TemplateResponse(
            "login.html",
            {
                "request": request,
                "error": "Account disattivato. Contatta l'amministratore.",
                "require_2fa": settings.require_2fa,
            },
        )
    key = crypto.derive_key(password, user.salt)

    if user.totp_verified:
        if not code:
            return templates.TemplateResponse(
                "login.html",
                {"request": request, "error": "Inserisci il codice 2FA.", "require_2fa": settings.require_2fa},
            )
        try:
            secret = crypto.decrypt(key, user.totp_secret_enc)
        except Exception:
            return templates.TemplateResponse(
                "login.html",
                {"request": request, "error": "Errore crittografico. Riprovare.", "require_2fa": settings.require_2fa},
            )
        if not auth.verify_totp(secret, code):
            return templates.TemplateResponse(
                "login.html",
                {"request": request, "error": "Codice 2FA non valido.", "require_2fa": settings.require_2fa},
            )
    else:
        if settings.require_2fa:
            setup_token = _create_setup_token(user.id, key)
            response = RedirectResponse("/setup-2fa", status_code=302)
            response.set_cookie(
                "setup_token",
                setup_token,
                httponly=True,
                secure=COOKIE_SECURE,
                samesite="strict",
                max_age=15 * 60,
            )
            return response

    session_id = _create_session(user.id, key)
    response = RedirectResponse("/", status_code=302)
    response.set_cookie(
        "session_id",
        session_id,
        httponly=True,
        secure=COOKIE_SECURE,
        samesite="strict",
        max_age=SESSION_TTL_MIN * 60,
    )
    return response


@app.get("/register", response_class=HTMLResponse)
def register_form(request: Request) -> HTMLResponse:
    return templates.TemplateResponse("register.html", {"request": request})


@app.post("/register", response_class=HTMLResponse)
def register(
    request: Request,
    username: str = Form(...),
    password: str = Form(...),
    password_confirm: str = Form(...),
    db: Session = Depends(get_db),
) -> HTMLResponse:
    if len(password.encode("utf-8")) > 72:
        return templates.TemplateResponse(
            "register.html",
            {"request": request, "error": "Password troppo lunga (max 72 caratteri/byte)."},
        )
    if password != password_confirm:
        return templates.TemplateResponse(
            "register.html",
            {"request": request, "error": "Le password non coincidono."},
        )
    if db.query(User).filter(User.username == username).first():
        return templates.TemplateResponse(
            "register.html",
            {"request": request, "error": "Username già in uso."},
        )

    settings = _get_settings(db)
    salt = crypto.generate_salt()
    key = crypto.derive_key(password, salt)
    secret = auth.generate_totp_secret()
    secret_enc = crypto.encrypt(key, secret)

    is_first_user = db.query(User).count() == 0
    user = User(
        username=username,
        password_hash=auth.hash_password(password),
        salt=salt,
        totp_secret_enc=secret_enc,
        totp_verified=False,
        is_admin=is_first_user,
        is_active=True,
    )
    db.add(user)
    db.commit()
    db.refresh(user)

    if settings.require_2fa:
        setup_token = _create_setup_token(user.id, key)
        response = RedirectResponse("/setup-2fa", status_code=302)
        response.set_cookie(
            "setup_token",
            setup_token,
            httponly=True,
            secure=COOKIE_SECURE,
            samesite="strict",
            max_age=15 * 60,
        )
        return response

    session_id = _create_session(user.id, key)
    response = RedirectResponse("/", status_code=302)
    response.set_cookie(
        "session_id",
        session_id,
        httponly=True,
        secure=COOKIE_SECURE,
        samesite="strict",
        max_age=SESSION_TTL_MIN * 60,
    )
    return response


@app.get("/setup-2fa", response_class=HTMLResponse)
def setup_2fa_form(request: Request, db: Session = Depends(get_db)) -> HTMLResponse:
    entry = _get_setup_token(request)
    setup_token = None
    if not entry:
        user_session = _current_user(request, db)
        if not user_session:
            return RedirectResponse("/login", status_code=302)
        user, key = user_session
        setup_token = _create_setup_token(user.id, key)
        entry = app.state.setup_tokens[setup_token]
    user = db.get(User, entry["user_id"])
    if not user:
        return RedirectResponse("/login", status_code=302)

    if not user.totp_secret_enc:
        secret = auth.generate_totp_secret()
        user.totp_secret_enc = crypto.encrypt(entry["key"], secret)
        db.add(user)
        db.commit()
    else:
        secret = crypto.decrypt(entry["key"], user.totp_secret_enc)
    uri = auth.totp_uri(secret, user.username)
    qr = auth.qr_base64(uri)
    template_response = templates.TemplateResponse(
        "setup_2fa.html",
        {"request": request, "qr": qr, "secret": secret, "username": user.username},
    )
    if setup_token:
        template_response.set_cookie(
            "setup_token",
            setup_token,
            httponly=True,
            secure=COOKIE_SECURE,
            samesite="strict",
            max_age=15 * 60,
        )
    return template_response


@app.post("/setup-2fa", response_class=HTMLResponse)
def setup_2fa(
    request: Request,
    code: str = Form(...),
    db: Session = Depends(get_db),
) -> HTMLResponse:
    entry = _get_setup_token(request)
    if not entry:
        return RedirectResponse("/login", status_code=302)
    user = db.get(User, entry["user_id"])
    if not user:
        return RedirectResponse("/login", status_code=302)

    secret = crypto.decrypt(entry["key"], user.totp_secret_enc)
    if not auth.verify_totp(secret, code):
        uri = auth.totp_uri(secret, user.username)
        qr = auth.qr_base64(uri)
        return templates.TemplateResponse(
            "setup_2fa.html",
            {"request": request, "qr": qr, "secret": secret, "username": user.username, "error": "Codice non valido."},
        )

    user.totp_verified = True
    db.add(user)
    db.commit()

    token = request.cookies.get("setup_token")
    if token and token in app.state.setup_tokens:
        del app.state.setup_tokens[token]
    response = RedirectResponse("/login", status_code=302)
    response.delete_cookie("setup_token")
    return response


@app.post("/logout")
def logout(request: Request) -> RedirectResponse:
    session_id = request.cookies.get("session_id")
    if session_id and session_id in app.state.sessions:
        del app.state.sessions[session_id]
    response = RedirectResponse("/login", status_code=302)
    response.delete_cookie("session_id")
    return response


def _require_user(request: Request, db: Session) -> tuple[User, bytes] | None:
    user_session = _current_user(request, db)
    if not user_session:
        return None
    return user_session


@app.get("/item/new", response_class=HTMLResponse)
def item_new_form(request: Request, db: Session = Depends(get_db)) -> HTMLResponse:
    user_session = _require_user(request, db)
    if not user_session:
        return RedirectResponse("/login", status_code=302)
    user, _ = user_session
    return templates.TemplateResponse(
        "item_form.html",
        {"request": request, "mode": "new", "user": user},
    )


@app.post("/item/new", response_class=HTMLResponse)
def item_new(
    request: Request,
    name: str = Form(...),
    username: str = Form(...),
    password: str = Form(...),
    url: str = Form(""),
    notes: str = Form(""),
    db: Session = Depends(get_db),
) -> HTMLResponse:
    user_session = _require_user(request, db)
    if not user_session:
        return RedirectResponse("/login", status_code=302)
    user, key = user_session

    item = VaultItem(
        user_id=user.id,
        name=crypto.encrypt(key, name),
        username=crypto.encrypt(key, username),
        password=crypto.encrypt(key, password),
        url=crypto.encrypt(key, url) if url else "",
        notes=crypto.encrypt(key, notes) if notes else "",
    )
    db.add(item)
    db.commit()
    return RedirectResponse("/", status_code=302)


@app.get("/item/{item_id}/edit", response_class=HTMLResponse)
def item_edit_form(request: Request, item_id: int, db: Session = Depends(get_db)) -> HTMLResponse:
    user_session = _require_user(request, db)
    if not user_session:
        return RedirectResponse("/login", status_code=302)
    user, key = user_session

    item = db.get(VaultItem, item_id)
    if not item or item.user_id != user.id:
        return RedirectResponse("/", status_code=302)

    view_item = {
        "id": item.id,
        "name": crypto.decrypt(key, item.name),
        "username": crypto.decrypt(key, item.username),
        "password": crypto.decrypt(key, item.password),
        "url": crypto.decrypt(key, item.url) if item.url else "",
        "notes": crypto.decrypt(key, item.notes) if item.notes else "",
    }
    return templates.TemplateResponse(
        "item_form.html",
        {"request": request, "mode": "edit", "item": view_item, "user": user},
    )


@app.post("/item/{item_id}/edit", response_class=HTMLResponse)
def item_edit(
    request: Request,
    item_id: int,
    name: str = Form(...),
    username: str = Form(...),
    password: str = Form(...),
    url: str = Form(""),
    notes: str = Form(""),
    db: Session = Depends(get_db),
) -> HTMLResponse:
    user_session = _require_user(request, db)
    if not user_session:
        return RedirectResponse("/login", status_code=302)
    user, key = user_session

    item = db.get(VaultItem, item_id)
    if not item or item.user_id != user.id:
        return RedirectResponse("/", status_code=302)

    item.name = crypto.encrypt(key, name)
    item.username = crypto.encrypt(key, username)
    item.password = crypto.encrypt(key, password)
    item.url = crypto.encrypt(key, url) if url else ""
    item.notes = crypto.encrypt(key, notes) if notes else ""
    db.add(item)
    db.commit()
    return RedirectResponse("/", status_code=302)


@app.post("/item/{item_id}/delete", response_class=HTMLResponse)
def item_delete(request: Request, item_id: int, db: Session = Depends(get_db)) -> HTMLResponse:
    user_session = _require_user(request, db)
    if not user_session:
        return RedirectResponse("/login", status_code=302)
    user, _ = user_session

    item = db.get(VaultItem, item_id)
    if item and item.user_id == user.id:
        db.delete(item)
        db.commit()
    return RedirectResponse("/", status_code=302)


@app.get("/admin", response_class=HTMLResponse)
def admin_dashboard(request: Request, db: Session = Depends(get_db)) -> HTMLResponse:
    admin_session = _require_admin(request, db)
    if not admin_session:
        return RedirectResponse("/login", status_code=302)
    admin_user, _ = admin_session

    users = db.query(User).order_by(User.id.asc()).all()
    counts = {row[0]: row[1] for row in db.query(VaultItem.user_id, func.count(VaultItem.id)).group_by(VaultItem.user_id).all()}

    view_users = []
    for user in users:
        view_users.append(
            {
                "id": user.id,
                "username": user.username,
                "created_at": user.created_at,
                "totp_verified": user.totp_verified,
                "is_admin": user.is_admin,
                "is_active": user.is_active,
                "items_count": counts.get(user.id, 0),
            }
        )

    settings = _get_settings(db)
    return templates.TemplateResponse(
        "admin.html",
        {"request": request, "user": admin_user, "users": view_users, "settings": settings},
    )


@app.post("/admin/user/{user_id}/toggle-active")
def admin_toggle_active(request: Request, user_id: int, db: Session = Depends(get_db)) -> RedirectResponse:
    admin_session = _require_admin(request, db)
    if not admin_session:
        return RedirectResponse("/login", status_code=302)
    admin_user, _ = admin_session
    if admin_user.id == user_id:
        return RedirectResponse("/admin", status_code=302)
    user = db.get(User, user_id)
    if user:
        user.is_active = not user.is_active
        db.add(user)
        db.commit()
    return RedirectResponse("/admin", status_code=302)


@app.post("/admin/user/{user_id}/reset-2fa")
def admin_reset_2fa(request: Request, user_id: int, db: Session = Depends(get_db)) -> RedirectResponse:
    admin_session = _require_admin(request, db)
    if not admin_session:
        return RedirectResponse("/login", status_code=302)
    user = db.get(User, user_id)
    if user:
        user.totp_verified = False
        user.totp_secret_enc = ""
        db.add(user)
        db.commit()
    return RedirectResponse("/admin", status_code=302)


@app.post("/admin/user/{user_id}/delete")
def admin_delete_user(request: Request, user_id: int, db: Session = Depends(get_db)) -> RedirectResponse:
    admin_session = _require_admin(request, db)
    if not admin_session:
        return RedirectResponse("/login", status_code=302)
    admin_user, _ = admin_session
    if admin_user.id == user_id:
        return RedirectResponse("/admin", status_code=302)
    user = db.get(User, user_id)
    if user:
        db.delete(user)
        db.commit()
    return RedirectResponse("/admin", status_code=302)


@app.post("/admin/settings/require-2fa")
def admin_toggle_require_2fa(request: Request, db: Session = Depends(get_db)) -> RedirectResponse:
    admin_session = _require_admin(request, db)
    if not admin_session:
        return RedirectResponse("/login", status_code=302)
    settings = _get_settings(db)
    settings.require_2fa = not settings.require_2fa
    db.add(settings)
    db.commit()
    return RedirectResponse("/admin", status_code=302)


@app.get("/api/generate-password")
def generate_password(length: int = 16, digits: int = 1, symbols: int = 1) -> JSONResponse:
    alphabet = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
    if digits:
        alphabet += "0123456789"
    if symbols:
        alphabet += "!@#$%&*()-_=+"

    length = max(8, min(length, 64))
    password = "".join(secrets.choice(alphabet) for _ in range(length))
    return JSONResponse({"password": password})
