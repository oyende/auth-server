# server.py
from fastapi import FastAPI, HTTPException, Header
from pydantic import BaseModel
import sqlite3
import time
import hashlib
import os

import bcrypt
import jwt

from pathlib import Path
DB = str(Path(__file__).resolve().parent / "db.sqlite")

APP_SECRET = os.getenv("APP_SECRET", "CHANGE_ME_LONG_RANDOM")  # CHANGE en prod
JWT_ALG = "HS256"
DB = "db.sqlite"

app = FastAPI()


# -----------------------
# DB helpers + migrations
# -----------------------
def _table_columns(conn: sqlite3.Connection, table: str) -> set[str]:
    cur = conn.cursor()
    cur.execute(f"PRAGMA table_info({table})")
    return {row[1] for row in cur.fetchall()}  # row[1] = name


def _add_column_if_missing(conn: sqlite3.Connection, table: str, col_def: str):
    # col_def example: "max_accounts INTEGER NOT NULL DEFAULT 1"
    col_name = col_def.split()[0]
    cols = _table_columns(conn, table)
    if col_name in cols:
        return
    cur = conn.cursor()
    cur.execute(f"ALTER TABLE {table} ADD COLUMN {col_def}")
    conn.commit()


def init_db(conn: sqlite3.Connection):
    cur = conn.cursor()

    # Create tables (latest schema)
    cur.execute("""CREATE TABLE IF NOT EXISTS users(
        email TEXT PRIMARY KEY,
        pw_hash BLOB NOT NULL
    )""")

    cur.execute("""CREATE TABLE IF NOT EXISTS license_keys(
        key_hash TEXT PRIMARY KEY,
        duration_seconds INTEGER NOT NULL,
        plan TEXT NOT NULL,
        max_accounts INTEGER NOT NULL DEFAULT 1,
        used_by TEXT,
        used_at INTEGER
    )""")

    cur.execute("""CREATE TABLE IF NOT EXISTS licenses(
        email TEXT PRIMARY KEY,
        expires_at INTEGER NOT NULL,
        plan TEXT NOT NULL,
        max_accounts INTEGER NOT NULL DEFAULT 1,
        device_id TEXT
    )""")

    # ✅ NEW: active sessions table (anti-bypass instances)
    cur.execute("""CREATE TABLE IF NOT EXISTS active_sessions(
        email TEXT NOT NULL,
        instance_id TEXT NOT NULL,
        last_seen INTEGER NOT NULL,
        PRIMARY KEY (email, instance_id)
    )""")

    conn.commit()

    # Migrations (if old db existed)
    _add_column_if_missing(conn, "license_keys", "max_accounts INTEGER NOT NULL DEFAULT 1")
    _add_column_if_missing(conn, "license_keys", "used_by TEXT")
    _add_column_if_missing(conn, "license_keys", "used_at INTEGER")

    _add_column_if_missing(conn, "licenses", "max_accounts INTEGER NOT NULL DEFAULT 1")
    _add_column_if_missing(conn, "licenses", "device_id TEXT")


def get_db() -> sqlite3.Connection:
    conn = sqlite3.connect(DB)
    init_db(conn)
    return conn


# -----------------------
# Auth helpers
# -----------------------
def sha256(s: str) -> str:
    return hashlib.sha256(s.strip().encode("utf-8")).hexdigest()


def make_token(email: str, ttl_seconds: int = 3600) -> str:
    now = int(time.time())
    payload = {"sub": email, "iat": now, "exp": now + ttl_seconds}
    return jwt.encode(payload, APP_SECRET, algorithm=JWT_ALG)


def email_from_auth(authorization: str) -> str:
    if not authorization.startswith("Bearer "):
        raise HTTPException(401, "Missing token")
    token = authorization.split(" ", 1)[1]
    try:
        payload = jwt.decode(token, APP_SECRET, algorithms=[JWT_ALG])
    except jwt.ExpiredSignatureError:
        raise HTTPException(401, "Expired token")
    except Exception:
        raise HTTPException(401, "Invalid token")

    email = payload.get("sub")
    if not email:
        raise HTTPException(401, "Bad token payload")
    return email


# -----------------------
# Models
# -----------------------
class Creds(BaseModel):
    email: str
    password: str


class Redeem(BaseModel):
    email: str
    password: str
    license_key: str
    device_id: str  # 1 PC lock (optionnel)


# ✅ NEW: Seats models
class SeatReq(BaseModel):
    instance_id: str


# -----------------------
# Routes
# -----------------------
@app.get("/")
def root():
    return {"ok": True}


@app.post("/register")
def register(c: Creds):
    conn = get_db()
    cur = conn.cursor()

    cur.execute("SELECT 1 FROM users WHERE email=?", (c.email,))
    if cur.fetchone():
        conn.close()
        raise HTTPException(400, "Email déjà utilisé")

    pw_hash = bcrypt.hashpw(c.password.encode("utf-8"), bcrypt.gensalt())
    cur.execute("INSERT INTO users(email, pw_hash) VALUES(?,?)", (c.email, pw_hash))
    conn.commit()
    conn.close()
    return {"ok": True}


@app.post("/login")
def login(c: Creds):
    conn = get_db()
    cur = conn.cursor()

    cur.execute("SELECT pw_hash FROM users WHERE email=?", (c.email,))
    row = cur.fetchone()
    conn.close()

    if not row or not bcrypt.checkpw(c.password.encode("utf-8"), row[0]):
        raise HTTPException(401, "Identifiants invalides")

    token = make_token(c.email, ttl_seconds=3600)
    return {"access_token": token, "expires_in": 3600, "email": c.email}


@app.post("/redeem-key")
def redeem(r: Redeem):
    conn = get_db()
    cur = conn.cursor()

    # 1) check user+password
    cur.execute("SELECT pw_hash FROM users WHERE email=?", (r.email,))
    row = cur.fetchone()
    if not row or not bcrypt.checkpw(r.password.encode("utf-8"), row[0]):
        conn.close()
        raise HTTPException(401, "Identifiants invalides")

    # 2) check key exists + unused
    kh = sha256(r.license_key)
    cur.execute(
        "SELECT duration_seconds, plan, max_accounts, used_by FROM license_keys WHERE key_hash=?",
        (kh,)
    )
    row = cur.fetchone()
    if not row:
        conn.close()
        raise HTTPException(404, "Clé inconnue")

    duration_seconds, plan, max_accounts, used_by = row
    if used_by:
        conn.close()
        raise HTTPException(400, "Clé déjà utilisée")

    now = int(time.time())
    expires_at = now + int(duration_seconds)

    # 3) 1 PC lock: refuse si ce compte est déjà lié à un autre device
    cur.execute("SELECT device_id FROM licenses WHERE email=?", (r.email,))
    existing = cur.fetchone()
    if existing and existing[0] and existing[0] != r.device_id:
        conn.close()
        raise HTTPException(403, "Licence déjà liée à un autre PC")

    # 4) mark key used (1 fois) + create/update license
    cur.execute("UPDATE license_keys SET used_by=?, used_at=? WHERE key_hash=?", (r.email, now, kh))

    cur.execute(
        "INSERT INTO licenses(email, expires_at, plan, max_accounts, device_id) VALUES(?,?,?,?,?) "
        "ON CONFLICT(email) DO UPDATE SET "
        "expires_at=excluded.expires_at, "
        "plan=excluded.plan, "
        "max_accounts=excluded.max_accounts, "
        "device_id=COALESCE(licenses.device_id, excluded.device_id)",
        (r.email, expires_at, plan, int(max_accounts), r.device_id)
    )

    conn.commit()
    conn.close()

    token = make_token(r.email, ttl_seconds=3600)
    return {
        "ok": True,
        "access_token": token,
        "expires_in": 3600,
        "email": r.email,
        "plan": plan,
        "license_expires_at": expires_at,
        "max_accounts": int(max_accounts),
        "device_locked": True
    }


@app.get("/verify")
def verify(
    authorization: str = Header(default=""),
    x_device_id: str = Header(default=""),
):
    email = email_from_auth(authorization)

    conn = get_db()
    cur = conn.cursor()
    cur.execute("SELECT expires_at, plan, max_accounts, device_id FROM licenses WHERE email=?", (email,))
    row = cur.fetchone()
    conn.close()

    if not row:
        raise HTTPException(403, "No active license")

    expires_at, plan, max_accounts, device_id = row
    now = int(time.time())

    if now >= int(expires_at):
        raise HTTPException(403, "License expired")

    # Si la licence est verrouillée à un device_id, on exige le header X-Device-Id
# ✅ Mode "souple": si le client envoie X-Device-Id, on vérifie.
    # Sinon, on ne bloque pas /verify (ça évite Missing device id).
    if device_id and x_device_id and device_id != x_device_id:
        raise HTTPException(403, "Wrong device")

    return {
        "ok": True,
        "email": email,
        "plan": plan,
        "expires_at": int(expires_at),
        "seconds_left": int(expires_at) - now,
        "max_accounts": int(max_accounts),
        "device_locked": bool(device_id),
    }


# -----------------------
# ✅ Seats (anti-bypass)
# -----------------------
SEAT_TTL = 90  # seconds: si pas de heartbeat depuis 90s => session considérée morte


def _cleanup_stale_sessions(conn: sqlite3.Connection, email: str):
    now = int(time.time())
    conn.execute(
        "DELETE FROM active_sessions WHERE email=? AND last_seen < ?",
        (email, now - SEAT_TTL)
    )
    conn.commit()


@app.post("/acquire-seat")
def acquire_seat(body: SeatReq, authorization: str = Header(default="")):
    email = email_from_auth(authorization)

    conn = get_db()
    cur = conn.cursor()

    # licence?
    cur.execute("SELECT expires_at, max_accounts FROM licenses WHERE email=?", (email,))
    lic = cur.fetchone()
    if not lic:
        conn.close()
        raise HTTPException(403, "No active license")

    expires_at, max_accounts = lic
    now = int(time.time())
    if now >= int(expires_at):
        conn.close()
        raise HTTPException(403, "License expired")

    # clean stale
    _cleanup_stale_sessions(conn, email)

    # already active?
    cur.execute("SELECT 1 FROM active_sessions WHERE email=? AND instance_id=?", (email, body.instance_id))
    already = cur.fetchone() is not None

    # count active
    cur.execute("SELECT COUNT(*) FROM active_sessions WHERE email=?", (email,))
    active = int(cur.fetchone()[0])

    if (not already) and active >= int(max_accounts):
        conn.close()
        raise HTTPException(403, f"Max instances reached ({int(max_accounts)})")

    # upsert session
    cur.execute(
        "INSERT INTO active_sessions(email, instance_id, last_seen) VALUES(?,?,?) "
        "ON CONFLICT(email, instance_id) DO UPDATE SET last_seen=excluded.last_seen",
        (email, body.instance_id, now)
    )
    conn.commit()
    conn.close()

    return {"ok": True, "active": active if already else active + 1, "max_accounts": int(max_accounts)}


@app.post("/heartbeat")
def heartbeat(body: SeatReq, authorization: str = Header(default="")):
    email = email_from_auth(authorization)
    conn = get_db()
    now = int(time.time())
    conn.execute(
        "UPDATE active_sessions SET last_seen=? WHERE email=? AND instance_id=?",
        (now, email, body.instance_id)
    )
    conn.commit()
    conn.close()
    return {"ok": True}


@app.post("/release-seat")
def release_seat(body: SeatReq, authorization: str = Header(default="")):
    email = email_from_auth(authorization)
    conn = get_db()
    conn.execute("DELETE FROM active_sessions WHERE email=? AND instance_id=?", (email, body.instance_id))
    conn.commit()
    conn.close()
    return {"ok": True}
