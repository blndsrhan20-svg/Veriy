import os
import re
import secrets
import hashlib
import hmac
import base64
from datetime import datetime, timedelta, timezone
from pathlib import Path

from fastapi import FastAPI, HTTPException, Depends, UploadFile, File, Header
from fastapi.responses import HTMLResponse
from pydantic import BaseModel, Field
from sqlalchemy import create_engine, String, Integer, DateTime, ForeignKey, Text, select
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, sessionmaker, Session

APP_NAME = "BOTNEX"
DATABASE_URL = os.getenv("DATABASE_URL", "sqlite:///./botnex.db")
if DATABASE_URL.startswith("postgres://"):
    DATABASE_URL = DATABASE_URL.replace("postgres://", "postgresql+psycopg://", 1)
elif DATABASE_URL.startswith("postgresql://") and "+psycopg" not in DATABASE_URL:
    DATABASE_URL = DATABASE_URL.replace("postgresql://", "postgresql+psycopg://", 1)

engine = create_engine(DATABASE_URL, connect_args={"check_same_thread": False} if DATABASE_URL.startswith("sqlite") else {})
SessionLocal = sessionmaker(bind=engine, autoflush=False, expire_on_commit=False)

class Base(DeclarativeBase):
    pass

class User(Base):
    __tablename__ = "users"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    username: Mapped[str] = mapped_column(String(40), unique=True, index=True)
    password_hash: Mapped[str] = mapped_column(String(256))
    subscription_until: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))

class Bot(Base):
    __tablename__ = "bots"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id"), index=True)
    name: Mapped[str] = mapped_column(String(80))
    entry_file: Mapped[str] = mapped_column(String(255), default="main.py")
    status: Mapped[str] = mapped_column(String(20), default="stopped")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))

Base.metadata.create_all(engine)
app = FastAPI(title=APP_NAME, version="0.1.0")
DATA_DIR = Path(os.getenv("BOTNEX_DATA_DIR", "./bot_data")).resolve()
DATA_DIR.mkdir(parents=True, exist_ok=True)
TOKEN_SECRET = os.getenv("TOKEN_SECRET")
if not TOKEN_SECRET:
    # Development fallback only. Set a long random TOKEN_SECRET in production.
    TOKEN_SECRET = secrets.token_urlsafe(48)

def db():
    session = SessionLocal()
    try:
        yield session
    finally:
        session.close()

def hash_password(password: str) -> str:
    salt = secrets.token_bytes(16)
    digest = hashlib.scrypt(password.encode(), salt=salt, n=2**14, r=8, p=1)
    return base64.b64encode(salt + digest).decode()

def verify_password(password: str, stored: str) -> bool:
    try:
        raw = base64.b64decode(stored.encode())
        salt, expected = raw[:16], raw[16:]
        actual = hashlib.scrypt(password.encode(), salt=salt, n=2**14, r=8, p=1)
        return hmac.compare_digest(actual, expected)
    except Exception:
        return False

def issue_token(user_id: int) -> str:
    expires = str(int((datetime.now(timezone.utc) + timedelta(days=7)).timestamp()))
    payload = f"{user_id}:{expires}".encode()
    sig = hmac.new(TOKEN_SECRET.encode(), payload, hashlib.sha256).digest()
    return base64.urlsafe_b64encode(payload).decode().rstrip("=") + "." + base64.urlsafe_b64encode(sig).decode().rstrip("=")

def current_user(authorization: str | None = Header(default=None), session: Session = Depends(db)):
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(401, "سجّل الدخول أولاً")
    try:
        raw = base64.urlsafe_b64decode(authorization[7:] + "===")
        payload, signature = raw.rsplit(b":", 1)
        expected = hmac.new(TOKEN_SECRET.encode(), payload, hashlib.sha256).digest()
        if not hmac.compare_digest(signature, expected):
            raise ValueError()
        user_id, expires = payload.decode().split(":")
        if int(expires) < int(datetime.now(timezone.utc).timestamp()):
            raise ValueError()
        user = session.get(User, int(user_id))
        if not user:
            raise ValueError()
        return user
    except Exception:
        raise HTTPException(401, "جلسة الدخول غير صالحة")

def require_active(user: User):
    until = user.subscription_until
    if not until or until.replace(tzinfo=timezone.utc) <= datetime.now(timezone.utc):
        raise HTTPException(402, "انتهى الاشتراك. جدّد اشتراكك لتتمكن من إدارة بوتاتك.")

class Credentials(BaseModel):
    username: str = Field(min_length=3, max_length=40, pattern=r"^[a-zA-Z0-9_.-]+$")
    password: str = Field(min_length=8, max_length=128)

class BotCreate(BaseModel):
    name: str = Field(min_length=2, max_length=80)
    entry_file: str = Field(default="main.py", max_length=255)

@app.get("/", response_class=HTMLResponse)
def home():
    return """
<!doctype html><html lang="ar" dir="rtl"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>BOTNEX</title><style>
*{box-sizing:border-box}body{margin:0;background:#0b1020;color:#eef2ff;font-family:Arial,sans-serif;display:grid;min-height:100vh;place-items:center}
main{width:min(92%,560px);background:#141c31;border:1px solid #283552;border-radius:22px;padding:30px;box-shadow:0 20px 70px #0006}
h1{font-size:34px;margin:0;color:#7dd3fc}p{color:#aab7d0;line-height:1.8}.tag{color:#fbbf24;font-weight:bold}
input,button{width:100%;padding:13px;margin:7px 0;border-radius:10px;border:1px solid #34435f;background:#0b1020;color:white;font-size:15px}
button{background:#0ea5e9;border:0;font-weight:bold;cursor:pointer}.tabs{display:flex;gap:8px}.tabs button{background:#25334f}.out{white-space:pre-wrap;color:#a7f3d0;margin-top:12px}
</style><main><h1>BOTNEX</h1><p>منصة إدارة واستضافة بوتات Telegram بلغة Python.</p><p class="tag">لوحة التحكم — نسخة تأسيسية</p>
<div class="tabs"><button onclick="mode='register'">إنشاء حساب</button><button onclick="mode='login'">تسجيل الدخول</button></div>
<input id="u" placeholder="اسم المستخدم"><input id="p" type="password" placeholder="كلمة المرور (8 أحرف على الأقل)">
<button onclick="auth()">متابعة</button><div id="out" class="out"></div>
<script>
let mode='register';
async function auth(){let r=await fetch('/api/'+mode,{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({username:u.value,password:p.value})});let d=await r.json();out.textContent=JSON.stringify(d,null,2);if(d.access_token){localStorage.setItem('botnex_token',d.access_token);out.textContent='تم تسجيل الدخول. يمكنك استخدام واجهات API لإدارة حسابك.'}}
</script></main></html>
"""

@app.get("/health")
def health():
    return {"ok": True, "service": APP_NAME, "version": "0.1.0"}

@app.post("/api/register")
def register(data: Credentials, session: Session = Depends(db)):
    if session.scalar(select(User).where(User.username == data.username)):
        raise HTTPException(409, "اسم المستخدم مستخدم")
    user = User(username=data.username, password_hash=hash_password(data.password))
    session.add(user)
    session.commit()
    session.refresh(user)
    return {"message": "تم إنشاء الحساب. يلزم تفعيل الاشتراك من الإدارة.", "access_token": issue_token(user.id)}

@app.post("/api/login")
def login(data: Credentials, session: Session = Depends(db)):
    user = session.scalar(select(User).where(User.username == data.username))
    if not user or not verify_password(data.password, user.password_hash):
        raise HTTPException(401, "بيانات الدخول غير صحيحة")
    return {"access_token": issue_token(user.id), "username": user.username}

@app.get("/api/me")
def me(user: User = Depends(current_user)):
    active = bool(user.subscription_until and user.subscription_until.replace(tzinfo=timezone.utc) > datetime.now(timezone.utc))
    return {"username": user.username, "subscription_active": active, "subscription_until": user.subscription_until}

@app.get("/api/bots")
def list_bots(user: User = Depends(current_user), session: Session = Depends(db)):
    require_active(user)
    bots = session.scalars(select(Bot).where(Bot.user_id == user.id)).all()
    return [{"id": b.id, "name": b.name, "entry_file": b.entry_file, "status": b.status} for b in bots]

@app.post("/api/bots")
def create_bot(data: BotCreate, user: User = Depends(current_user), session: Session = Depends(db)):
    require_active(user)
    if not re.fullmatch(r"[\w .-]{2,80}", data.name):
        raise HTTPException(400, "اسم البوت غير صالح")
    if len(session.scalars(select(Bot).where(Bot.user_id == user.id)).all()) >= 5:
        raise HTTPException(403, "وصلت إلى الحد الحالي: 5 بوتات لكل حساب")
    bot = Bot(user_id=user.id, name=data.name, entry_file=data.entry_file)
    session.add(bot)
    session.commit()
    session.refresh(bot)
    (DATA_DIR / str(user.id) / str(bot.id)).mkdir(parents=True, exist_ok=True)
    return {"id": bot.id, "name": bot.name, "status": bot.status}

def owned_bot(bot_id: int, user: User, session: Session) -> Bot:
    bot = session.scalar(select(Bot).where(Bot.id == bot_id, Bot.user_id == user.id))
    if not bot:
        raise HTTPException(404, "البوت غير موجود")
    return bot

@app.post("/api/bots/{bot_id}/files")
async def upload_file(bot_id: int, file: UploadFile = File(...), user: User = Depends(current_user), session: Session = Depends(db)):
    require_active(user)
    bot = owned_bot(bot_id, user, session)
    name = Path(file.filename or "").name
    if not name or name.startswith(".") or not name.endswith(".py"):
        raise HTTPException(400, "ارفع ملفات Python بامتداد .py فقط")
    content = await file.read(1_000_001)
    if len(content) > 1_000_000:
        raise HTTPException(413, "الحد الأقصى للملف 1 ميغابايت")
    folder = (DATA_DIR / str(user.id) / str(bot.id)).resolve()
    folder.mkdir(parents=True, exist_ok=True)
    target = (folder / name).resolve()
    if folder not in target.parents:
        raise HTTPException(400, "مسار الملف غير صالح")
    target.write_bytes(content)
    return {"message": "تم رفع الملف", "filename": name}

@app.get("/api/bots/{bot_id}/files")
def list_files(bot_id: int, user: User = Depends(current_user), session: Session = Depends(db)):
    require_active(user)
    owned_bot(bot_id, user, session)
    folder = DATA_DIR / str(user.id) / str(bot_id)
    return {"files": sorted(p.name for p in folder.glob("*.py")) if folder.exists() else []}

@app.get("/api/bots/{bot_id}/files/{filename}")
def read_file(bot_id: int, filename: str, user: User = Depends(current_user), session: Session = Depends(db)):
    require_active(user)
    owned_bot(bot_id, user, session)
    if Path(filename).name != filename or not filename.endswith(".py"):
        raise HTTPException(400, "اسم الملف غير صالح")
    target = DATA_DIR / str(user.id) / str(bot_id) / filename
    if not target.is_file():
        raise HTTPException(404, "الملف غير موجود")
    return {"filename": filename, "content": target.read_text(encoding="utf-8")}

@app.put("/api/bots/{bot_id}/files/{filename}")
def edit_file(bot_id: int, filename: str, payload: dict, user: User = Depends(current_user), session: Session = Depends(db)):
    require_active(user)
    owned_bot(bot_id, user, session)
    if Path(filename).name != filename or not filename.endswith(".py") or not isinstance(payload.get("content"), str):
        raise HTTPException(400, "بيانات الملف غير صالحة")
    content = payload["content"]
    if len(content.encode()) > 1_000_000:
        raise HTTPException(413, "الحد الأقصى للملف 1 ميغابايت")
    target = DATA_DIR / str(user.id) / str(bot_id) / filename
    if not target.is_file():
        raise HTTPException(404, "الملف غير موجود")
    target.write_text(content, encoding="utf-8")
    return {"message": "تم حفظ التعديلات"}

@app.post("/api/admin/users/{user_id}/activate")
def activate_subscription(user_id: int, days: int = 30, x_admin_key: str | None = Header(default=None), session: Session = Depends(db)):
    admin_key = os.getenv("ADMIN_KEY")
    if not admin_key or not x_admin_key or not hmac.compare_digest(x_admin_key, admin_key):
        raise HTTPException(403, "غير مصرح")
    if days < 1 or days > 365:
        raise HTTPException(400, "عدد الأيام يجب أن يكون بين 1 و365")
    user = session.get(User, user_id)
    if not user:
        raise HTTPException(404, "المستخدم غير موجود")
    now = datetime.now(timezone.utc)
    current = user.subscription_until
    if current and current.replace(tzinfo=timezone.utc) > now:
        current = current.replace(tzinfo=timezone.utc)
    else:
        current = now
    user.subscription_until = current + timedelta(days=days)
    session.commit()
    return {"message": "تم تفعيل الاشتراك", "subscription_until": user.subscription_until}

# IMPORTANT: User-uploaded Python code is NOT executed by this API process.
# Bot start/stop requires a separate isolated worker/container runtime before production use.
