from fastapi import FastAPI, APIRouter, HTTPException, Header
from dotenv import load_dotenv
from starlette.middleware.cors import CORSMiddleware
from motor.motor_asyncio import AsyncIOMotorClient
import os, logging, uuid, secrets, re
from pathlib import Path
from pydantic import BaseModel, Field, EmailStr
from typing import List, Optional
from datetime import datetime, timezone, timedelta
import httpx, bcrypt, jwt
import json as _json
from pywebpush import webpush, WebPushException

ROOT = Path(__file__).parent
load_dotenv(ROOT / ".env")

client = AsyncIOMotorClient(
    os.environ["MONGO_URL"],
    serverSelectionTimeoutMS=10000,
    connectTimeoutMS=10000,
    socketTimeoutMS=20000,
    retryWrites=True,
)
db = client[os.environ["DB_NAME"]]
JWT_SECRET = os.environ["JWT_SECRET"]

# Supabase server-side (service-role) configuration — used ONLY for the one-time
# CMS seed import endpoint. These are optional: when absent, the seed-from-mongo
# endpoint returns a friendly 503 instead of crashing.
SUPABASE_URL = (os.environ.get("SUPABASE_URL") or "").rstrip("/")
SUPABASE_SERVICE_ROLE_KEY = os.environ.get("SUPABASE_SERVICE_ROLE_KEY") or ""

# ---- SMS / OTP provider configuration ----------------------------------------
# DEMO MODE (default): SMS_PROVIDER empty/none → the OTP code is returned in the
# API response (`dev_code`) and logged, so the flow is fully testable without a
# real SMS gateway. To activate real SMS LATER without any code change or APK
# rebuild, simply set SMS_PROVIDER ("twilio" | "ovh") and the matching creds in
# the backend .env, then restart the backend.
SMS_PROVIDER = (os.environ.get("SMS_PROVIDER") or "").strip().lower()
OTP_DEMO_MODE = (os.environ.get("OTP_DEMO_MODE", "true").strip().lower() in ("1", "true", "yes"))


def _sms_is_live() -> bool:
    """True when a real SMS provider is fully configured."""
    if SMS_PROVIDER == "twilio":
        return bool(os.environ.get("TWILIO_ACCOUNT_SID") and os.environ.get("TWILIO_AUTH_TOKEN")
                    and os.environ.get("TWILIO_FROM_NUMBER"))
    if SMS_PROVIDER == "ovh":
        return bool(os.environ.get("OVH_APP_KEY") and os.environ.get("OVH_APP_SECRET")
                    and os.environ.get("OVH_CONSUMER_KEY") and os.environ.get("OVH_SMS_SERVICE"))
    return False


async def _send_sms_otp(phone: str, code: str) -> bool:
    """Send the OTP via the configured provider. Returns True if a real SMS was sent.

    In demo mode (no provider configured) this is a no-op returning False — the
    caller then exposes the code via `dev_code`. The Twilio / OVH branches are
    fully wired and only need credentials to go live.
    """
    if not _sms_is_live():
        return False
    body = f"Pizza Denfert — votre code de connexion: {code}"
    try:
        if SMS_PROVIDER == "twilio":
            sid = os.environ["TWILIO_ACCOUNT_SID"]
            token = os.environ["TWILIO_AUTH_TOKEN"]
            sender = os.environ["TWILIO_FROM_NUMBER"]
            async with httpx.AsyncClient(timeout=15) as cx:
                r = await cx.post(
                    f"https://api.twilio.com/2010-04-01/Accounts/{sid}/Messages.json",
                    data={"From": sender, "To": phone, "Body": body},
                    auth=(sid, token),
                )
                r.raise_for_status()
            return True
        if SMS_PROVIDER == "ovh":
            # OVH SMS REST API (signed request).
            import hashlib, time as _time
            app_key = os.environ["OVH_APP_KEY"]
            app_secret = os.environ["OVH_APP_SECRET"]
            consumer_key = os.environ["OVH_CONSUMER_KEY"]
            service = os.environ["OVH_SMS_SERVICE"]
            sender = os.environ.get("OVH_SMS_SENDER") or "PizzaDenfert"
            endpoint = "https://eu.api.ovh.com/1.0"
            url = f"{endpoint}/sms/{service}/jobs"
            payload = _json.dumps({
                "message": body, "senderForResponse": False, "sender": sender,
                "receivers": [phone],
            })
            ts = str(int(_time.time()))
            to_sign = f"{app_secret}+{consumer_key}+POST+{url}+{payload}+{ts}"
            sig = "$1$" + hashlib.sha1(to_sign.encode()).hexdigest()
            headers = {
                "X-Ovh-Application": app_key, "X-Ovh-Consumer": consumer_key,
                "X-Ovh-Timestamp": ts, "X-Ovh-Signature": sig,
                "Content-Type": "application/json",
            }
            async with httpx.AsyncClient(timeout=15) as cx:
                r = await cx.post(url, content=payload, headers=headers)
                r.raise_for_status()
            return True
    except Exception as e:
        log.warning(f"SMS send failed via {SMS_PROVIDER}: {e}")
        return False
    return False

app = FastAPI(title="Pizza Denfert API")
api = APIRouter(prefix="/api")
logging.basicConfig(level=logging.INFO)
log = logging.getLogger("denfert")


# ---- Health-check endpoints (Kubernetes liveness / readiness probes) ----
# These are mounted at the app level (NOT under /api) so that probes hitting
# the root path receive 200 OK instead of 404. The repeated container restart
# loop observed in production was caused by K8s marking the pod unhealthy when
# `GET /` returned 404. The /api/* routes are unchanged and still proxy through
# Nginx for browser traffic.
@app.get("/")
async def root():
    return {"status": "ok", "service": "Pizza Denfert API"}


@app.get("/healthz")
async def healthz():
    return {"status": "ok"}


@app.get("/api/healthz")
async def api_healthz():
    return {"status": "ok"}

def now(): return datetime.now(timezone.utc)
def hp(p): return bcrypt.hashpw(p.encode(), bcrypt.gensalt()).decode()
def cp(p, h):
    try: return bcrypt.checkpw(p.encode(), h.encode())
    except: return False
def mkjwt(uid): return jwt.encode({"sub": uid, "exp": now() + timedelta(days=30)}, JWT_SECRET, algorithm="HS256")

class RegIn(BaseModel):
    email: EmailStr; password: str; name: str
class LogIn(BaseModel):
    email: EmailStr; password: str
class GSession(BaseModel):
    session_id: str
class OtpRequestIn(BaseModel):
    phone: str
    name: Optional[str] = None
class OtpVerifyIn(BaseModel):
    phone: str
    code: str
    name: Optional[str] = None
class ResIn(BaseModel):
    date: str; time: str; guests: int; name: str; phone: str; notes: Optional[str] = None
    zone: str = "indoor"  # "indoor" | "terrace"
class CapacityIn(BaseModel):
    indoor: int
    terrace: int
    tables_indoor: Optional[int] = None
    tables_terrace: Optional[int] = None
    seats_per_table: Optional[int] = None

class UpdateReservationIn(BaseModel):
    status: Optional[str] = None      # pending | confirmed | cancelled | completed
    table_no: Optional[str] = None    # "I-3" or "I-1,I-2" for combined
    guests: Optional[int] = None
    date: Optional[str] = None
    time: Optional[str] = None
    zone: Optional[str] = None
    notes: Optional[str] = None
    name: Optional[str] = None
    phone: Optional[str] = None
class PurchaseIn(BaseModel):
    pizza_count: int = 1  # admin records pizza purchase for loyalty
class RedeemIn(BaseModel):
    reward: str  # "coffee" | "dessert" | "margherita"
class ScanIn(BaseModel):
    qr_data: str  # PIZZA-DENFERT:{user_id}:{qr_token}
class AdminPizzaIn(BaseModel):
    user_id: str
    qr_token: str
    pizza_count: int = 1
class AdminRedeemIn(BaseModel):
    user_id: str
    qr_token: str
    reward: str
class AdminSearchIn(BaseModel):
    query: str  # phone or name
class CreateStaffIn(BaseModel):
    phone: str
    name: str
    role: str = "staff"  # owner | manager | cashier | staff
class UpdateRoleIn(BaseModel):
    role: str
class DisableIn(BaseModel):
    disabled: bool
class AdminPizzaInExt(BaseModel):
    user_id: str
    qr_token: str
    pizza_count: int = 1
    pizza_id: Optional[str] = None  # optional reference to menu.id for popularity tracking


# ---- Kiosk / Advertising Management ----
AD_SECTIONS = ("loyalty", "experience", "ingredients")


class AdSlideIn(BaseModel):
    section: str  # "loyalty" | "experience" | "ingredients"
    order: Optional[int] = None
    title: str
    subtitle: Optional[str] = ""
    image_url: Optional[str] = ""
    duration_ms: int = 5000
    active: bool = True


class AdSlideUpdateIn(BaseModel):
    section: Optional[str] = None
    order: Optional[int] = None
    title: Optional[str] = None
    subtitle: Optional[str] = None
    image_url: Optional[str] = None
    duration_ms: Optional[int] = None
    active: Optional[bool] = None


class AdReorderIn(BaseModel):
    ids: List[str]   # ordered list of slide IDs (whole-collection order, irrespective of section)


class KioskSettingsIn(BaseModel):
    idle_seconds: Optional[int] = None
    loop: Optional[bool] = None
    default_duration_ms: Optional[int] = None
    show_section_titles: Optional[bool] = None

async def cu(authorization: Optional[str] = Header(None)) -> dict:
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(401, "Missing token")
    tok = authorization.replace("Bearer ", "", 1)
    s = await db.user_sessions.find_one({"session_token": tok}, {"_id": 0})
    if s:
        exp = s.get("expires_at")
        if exp and exp.tzinfo is None: exp = exp.replace(tzinfo=timezone.utc)
        if exp and exp > now():
            u = await db.users.find_one({"user_id": s["user_id"]}, {"_id": 0, "password": 0})
            if u:
                if u.get("disabled"):
                    raise HTTPException(403, "Account disabled")
                return u
    try:
        p = jwt.decode(tok, JWT_SECRET, algorithms=["HS256"])
        u = await db.users.find_one({"user_id": p["sub"]}, {"_id": 0, "password": 0})
        if u:
            if u.get("disabled"):
                raise HTTPException(403, "Account disabled")
            return u
    except HTTPException:
        raise
    except Exception:
        pass
    raise HTTPException(401, "Invalid token")

# Menu: pizzas have prices_by_size, others have single price
SEED = [
    # Pizzas
    {"id": "p-margherita", "category": "pizzas", "name": "Margherita", "desc_fr": "Notre signature, simple et raffinée", "desc_en": "Our signature, simple and refined", "ingredients_fr": "Tomate San Marzano, mozzarella fior di latte, basilic frais, huile d'olive", "ingredients_en": "San Marzano tomato, fior di latte mozzarella, fresh basil, olive oil", "prices": {"26": 10.90, "31": 13.90}, "image": "https://images.pexels.com/photos/4109111/pexels-photo-4109111.jpeg?auto=compress&cs=tinysrgb&w=900"},
    {"id": "p-reine", "category": "pizzas", "name": "Reine", "desc_fr": "Le classique italien revisité", "desc_en": "The Italian classic revisited", "ingredients_fr": "Tomate, mozzarella, jambon de Savoie, champignons frais, origan", "ingredients_en": "Tomato, mozzarella, Savoie ham, fresh mushrooms, oregano", "prices": {"26": 13.50, "31": 16.50}, "image": "https://images.pexels.com/photos/2762942/pexels-photo-2762942.jpeg?auto=compress&cs=tinysrgb&w=900"},
    {"id": "p-diavola", "category": "pizzas", "name": "Diavola", "desc_fr": "Piquante et généreuse", "desc_en": "Spicy and generous", "ingredients_fr": "Tomate, mozzarella, salami piquant, oignons rouges, huile pimentée", "ingredients_en": "Tomato, mozzarella, spicy salami, red onions, chilli oil", "prices": {"26": 14.50, "31": 17.50}, "image": "https://images.pexels.com/photos/803290/pexels-photo-803290.jpeg?auto=compress&cs=tinysrgb&w=900"},
    {"id": "p-quatre", "category": "pizzas", "name": "Quatre Fromages", "desc_fr": "Un voyage fromager", "desc_en": "A cheese journey", "ingredients_fr": "Mozzarella, gorgonzola, parmesan, tomme du Rhône, basilic", "ingredients_en": "Mozzarella, gorgonzola, parmesan, Rhône tomme, basil", "prices": {"26": 14.90, "31": 17.90}, "image": "https://images.pexels.com/photos/315755/pexels-photo-315755.jpeg?auto=compress&cs=tinysrgb&w=900"},
    {"id": "p-denfert", "category": "pizzas", "name": "La Denfert", "desc_fr": "Notre création signature", "desc_en": "Our signature creation", "ingredients_fr": "Crème truffe, burrata, jambon San Daniele, roquette, parmesan", "ingredients_en": "Truffle cream, burrata, San Daniele ham, arugula, parmesan", "prices": {"26": 18.90, "31": 21.90}, "image": "https://images.pexels.com/photos/1146760/pexels-photo-1146760.jpeg?auto=compress&cs=tinysrgb&w=900"},
    {"id": "p-rhone", "category": "pizzas", "name": "Rhône-Alpes", "desc_fr": "Inspiration locale", "desc_en": "Local inspiration", "ingredients_fr": "Reblochon AOP, lardons fumés, oignons confits, pommes de terre, crème", "ingredients_en": "Reblochon AOP, smoked bacon, caramelised onions, potato, cream", "prices": {"26": 15.90, "31": 18.90}, "image": "https://images.pexels.com/photos/1049620/pexels-photo-1049620.jpeg?auto=compress&cs=tinysrgb&w=900"},
    {"id": "p-bufala", "category": "pizzas", "name": "Bufala d'Oro", "desc_fr": "L'élégance italienne", "desc_en": "Italian elegance", "ingredients_fr": "Tomate datterino jaune, mozzarella di bufala DOP, basilic, huile Ligure", "ingredients_en": "Yellow datterino tomato, buffalo mozzarella DOP, basil, Ligurian oil", "prices": {"26": 15.50, "31": 18.50}, "image": "https://images.pexels.com/photos/2619967/pexels-photo-2619967.jpeg?auto=compress&cs=tinysrgb&w=900"},
    # Focaccias
    {"id": "f-romarin", "category": "focaccias", "name": "Focaccia Romarin", "desc_fr": "Moelleuse et parfumée", "desc_en": "Soft and fragrant", "ingredients_fr": "Pâte artisanale, romarin frais, fleur de sel, huile d'olive", "ingredients_en": "Artisan dough, fresh rosemary, sea salt flakes, olive oil", "price": 6.50, "image": "https://images.pexels.com/photos/4109996/pexels-photo-4109996.jpeg?auto=compress&cs=tinysrgb&w=900"},
    {"id": "f-burrata", "category": "focaccias", "name": "Focaccia Burrata", "desc_fr": "Crémeuse à souhait", "desc_en": "Beautifully creamy", "ingredients_fr": "Focaccia, burrata, tomates cerises confites, basilic, huile d'olive", "ingredients_en": "Focaccia, burrata, candied cherry tomatoes, basil, olive oil", "price": 11.90, "image": "https://images.pexels.com/photos/1148086/pexels-photo-1148086.jpeg?auto=compress&cs=tinysrgb&w=900"},
    # Gratins
    {"id": "g-dauphinois", "category": "gratins", "name": "Gratin Dauphinois", "desc_fr": "L'âme du terroir", "desc_en": "The soul of terroir", "ingredients_fr": "Pommes de terre, crème, ail, muscade, gruyère AOP", "ingredients_en": "Potato, cream, garlic, nutmeg, gruyère AOP", "price": 9.90, "image": "https://images.pexels.com/photos/8629103/pexels-photo-8629103.jpeg?auto=compress&cs=tinysrgb&w=900"},
    {"id": "g-aubergines", "category": "gratins", "name": "Gratin d'Aubergines", "desc_fr": "Parmigiana italienne", "desc_en": "Italian parmigiana", "ingredients_fr": "Aubergines, tomate San Marzano, mozzarella, parmesan, basilic", "ingredients_en": "Aubergine, San Marzano tomato, mozzarella, parmesan, basil", "price": 11.50, "image": "https://images.pexels.com/photos/6940961/pexels-photo-6940961.jpeg?auto=compress&cs=tinysrgb&w=900"},
    # Salads
    {"id": "s-cesar", "category": "salades", "name": "César au Poulet", "desc_fr": "Le grand classique", "desc_en": "The grand classic", "ingredients_fr": "Romaine, poulet fermier, parmesan, croûtons, sauce César maison", "ingredients_en": "Romaine, free-range chicken, parmesan, croutons, house Caesar", "price": 13.50, "image": "https://images.pexels.com/photos/2097090/pexels-photo-2097090.jpeg?auto=compress&cs=tinysrgb&w=900"},
    {"id": "s-burrata", "category": "salades", "name": "Burrata & Tomates", "desc_fr": "Fraîche et raffinée", "desc_en": "Fresh and refined", "ingredients_fr": "Burrata, tomates anciennes, basilic, balsamique de Modène, fleur de sel", "ingredients_en": "Burrata, heirloom tomatoes, basil, Modena balsamic, sea salt", "price": 14.50, "image": "https://images.pexels.com/photos/8929185/pexels-photo-8929185.jpeg?auto=compress&cs=tinysrgb&w=900"},
    # Desserts
    {"id": "d-tiramisu", "category": "desserts", "name": "Tiramisu Classico", "desc_fr": "Recette traditionnelle italienne", "desc_en": "Traditional Italian recipe", "ingredients_fr": "Mascarpone, biscuits savoiardi, café espresso, cacao", "ingredients_en": "Mascarpone, savoiardi biscuits, espresso, cocoa", "price": 7.50, "image": "https://images.pexels.com/photos/6133302/pexels-photo-6133302.jpeg?auto=compress&cs=tinysrgb&w=900"},
    {"id": "d-panna", "category": "desserts", "name": "Panna Cotta Vanille", "desc_fr": "Douceur onctueuse", "desc_en": "Silky sweetness", "ingredients_fr": "Crème, vanille de Madagascar, coulis fruits rouges du Beaujolais", "ingredients_en": "Cream, Madagascar vanilla, Beaujolais red berry coulis", "price": 7.00, "image": "https://images.pexels.com/photos/4040692/pexels-photo-4040692.jpeg?auto=compress&cs=tinysrgb&w=900"},
    # Drinks
    {"id": "b-pellegrino", "category": "boissons", "name": "San Pellegrino 50cl", "desc_fr": "Eau gazeuse italienne", "desc_en": "Italian sparkling water", "ingredients_fr": "Eau minérale gazeuse", "ingredients_en": "Sparkling mineral water", "price": 4.50, "image": "https://images.pexels.com/photos/2995299/pexels-photo-2995299.jpeg?auto=compress&cs=tinysrgb&w=900"},
    {"id": "b-limonata", "category": "boissons", "name": "Limonata Sicilienne", "desc_fr": "Citrons de Sicile", "desc_en": "Sicilian lemons", "ingredients_fr": "Citrons de Sicile, sucre de canne, eau pétillante", "ingredients_en": "Sicilian lemons, cane sugar, sparkling water", "price": 4.00, "image": "https://images.pexels.com/photos/1232152/pexels-photo-1232152.jpeg?auto=compress&cs=tinysrgb&w=900"},
    {"id": "b-espresso", "category": "boissons", "name": "Espresso", "desc_fr": "Café italien single origin", "desc_en": "Italian single-origin coffee", "ingredients_fr": "Arabica 100%, torréfaction artisanale", "ingredients_en": "100% arabica, artisan roasted", "price": 2.50, "image": "https://images.pexels.com/photos/302899/pexels-photo-302899.jpeg?auto=compress&cs=tinysrgb&w=900"},
    # Wines
    {"id": "w-cotes", "category": "vins", "name": "Côtes du Rhône AOP", "desc_fr": "Rouge fruité et épicé", "desc_en": "Fruity and spicy red", "ingredients_fr": "Grenache, syrah, mourvèdre — 75cl", "ingredients_en": "Grenache, syrah, mourvèdre — 750ml", "price": 28.00, "image": "https://images.pexels.com/photos/1407846/pexels-photo-1407846.jpeg?auto=compress&cs=tinysrgb&w=900"},
    {"id": "w-chianti", "category": "vins", "name": "Chianti Classico DOCG", "desc_fr": "Toscane élégante", "desc_en": "Elegant Tuscany", "ingredients_fr": "Sangiovese 90%, Toscane — 75cl", "ingredients_en": "90% sangiovese, Tuscany — 750ml", "price": 34.00, "image": "https://images.pexels.com/photos/1407847/pexels-photo-1407847.jpeg?auto=compress&cs=tinysrgb&w=900"},
    {"id": "w-prosecco", "category": "vins", "name": "Prosecco DOC", "desc_fr": "Bulles fines de Vénétie", "desc_en": "Fine Veneto bubbles", "ingredients_fr": "Glera 100%, Vénétie — 75cl", "ingredients_en": "100% glera, Veneto — 750ml", "price": 26.00, "image": "https://images.pexels.com/photos/2664149/pexels-photo-2664149.jpeg?auto=compress&cs=tinysrgb&w=900"},
]

@app.on_event("startup")
async def startup():
    # Ensure email index is partial so multiple users with email=None / missing are allowed (phone-only OTP users).
    # NOTE: a plain `sparse` index still indexes explicit null values; only documents missing the field are
    # skipped. We need a partialFilterExpression to actually exclude null/non-string emails.
    # All of this is wrapped in broad try/except so a transient Atlas connectivity blip at boot does
    # NOT crash the process — that would trigger Kubernetes restart loops and health-probe failures.
    try:
        existing = await db.users.index_information()
        if "email_1" in existing:
            opts = existing["email_1"]
            has_partial = "partialFilterExpression" in opts
            if not has_partial:
                try:
                    await db.users.drop_index("email_1")
                except Exception as _drop_err:
                    log.warning(f"could not drop legacy email_1 index: {_drop_err}")
    except Exception as _e:
        log.warning(f"index check failed: {_e}")
    for _name, _coro in (
        ("email", db.users.create_index("email", unique=True, partialFilterExpression={"email": {"$type": "string"}})),
        ("user_id", db.users.create_index("user_id", unique=True)),
        ("phone", db.users.create_index("phone", sparse=True)),
        ("session_token", db.user_sessions.create_index("session_token", unique=True)),
    ):
        try:
            await _coro
        except Exception as _idx_err:
            log.warning(f"create_index({_name}) skipped: {_idx_err}")
    # Menu seed: ONLY insert if collection is empty. Supabase is now the source
    # of truth for the customer menu (see /app/supabase/setup.sql + /admin-cms),
    # but we keep this local copy as a fallback for the legacy /api/menu route
    # and to resolve pizza_id → name in admin stats. Idempotent on restart.
    try:
        existing_menu = await db.menu.count_documents({})
        if existing_menu == 0:
            await db.menu.insert_many([dict(m) for m in SEED])
            log.info(f"Seeded {len(SEED)} menu items (fallback set)")
        else:
            log.info(f"Menu already has {existing_menu} items — skipping seed (Supabase owns the live menu)")
    except Exception as _seed_err:
        log.warning(f"menu seed skipped: {_seed_err}")
    if not await db.users.find_one({"email": "admin@pizzadenfert.fr"}):
        await db.users.insert_one({
            "user_id": "admin_" + secrets.token_hex(6),
            "email": "admin@pizzadenfert.fr", "password": hp("Admin1234!"),
            "name": "Admin", "is_admin": True,
            "pizza_count": 0, "qr_token": secrets.token_hex(12),
            "rewards_redeemed": [], "rewards_history": [],
            "created_at": now(),
        })

# Auth
@api.post("/auth/otp/request")
async def otp_request(b: OtpRequestIn):
    """Generate a 6-digit OTP for the phone. DEV MODE: returns the code in response."""
    phone = b.phone.strip().replace(" ", "")
    if len(phone) < 6:
        raise HTTPException(400, "Invalid phone")
    code = f"{secrets.randbelow(900000) + 100000}"
    await db.otp_codes.update_one(
        {"phone": phone},
        {"$set": {"phone": phone, "code": code, "expires_at": now() + timedelta(minutes=10), "created_at": now()}},
        upsert=True,
    )
    log.info(f"OTP for {phone}: {code}")
    # Try to send a real SMS if a provider is configured; otherwise demo mode.
    sent = await _send_sms_otp(phone, code)
    resp = {"ok": True, "phone": phone, "expires_in": 600, "demo_mode": not sent}
    if not sent:
        # DEMO MODE: expose the code so the flow works without an SMS gateway.
        resp["dev_code"] = code
    return resp


@api.post("/auth/otp/verify")
async def otp_verify(b: OtpVerifyIn):
    """Verify OTP, login existing user or create new account."""
    phone = b.phone.strip().replace(" ", "")
    rec = await db.otp_codes.find_one({"phone": phone}, {"_id": 0})
    if not rec:
        raise HTTPException(400, "No code requested for this phone")
    exp = rec.get("expires_at")
    if exp and exp.tzinfo is None: exp = exp.replace(tzinfo=timezone.utc)
    if exp < now():
        raise HTTPException(400, "Code expired")
    if rec["code"] != b.code.strip():
        raise HTTPException(401, "Invalid code")
    await db.otp_codes.delete_one({"phone": phone})

    user = await db.users.find_one({"phone": phone})
    if not user:
        uid = "user_" + secrets.token_hex(6)
        user = {
            "user_id": uid, "phone": phone, "name": (b.name or phone),
            "email": None, "is_admin": False, "pizza_count": 0,
            "qr_token": secrets.token_hex(12),
            "rewards_redeemed": [], "rewards_history": [],
            "created_at": now(),
        }
        await db.users.insert_one(user)
    user.pop("_id", None); user.pop("password", None)
    return {"token": mkjwt(user["user_id"]), "user": user}


@api.post("/auth/register")
async def register(b: RegIn):
    if await db.users.find_one({"email": b.email.lower()}):
        raise HTTPException(400, "Email already registered")
    uid = "user_" + secrets.token_hex(6)
    u = {"user_id": uid, "email": b.email.lower(), "password": hp(b.password), "name": b.name,
         "is_admin": False, "pizza_count": 0, "qr_token": secrets.token_hex(12),
         "rewards_redeemed": [], "rewards_history": [], "created_at": now()}
    await db.users.insert_one(u)
    u.pop("_id", None); u.pop("password", None)
    return {"token": mkjwt(uid), "user": u}

@api.post("/auth/login")
async def login(b: LogIn):
    u = await db.users.find_one({"email": b.email.lower()})
    if not u or not cp(b.password, u.get("password", "")):
        raise HTTPException(401, "Invalid credentials")
    u.pop("_id", None); u.pop("password", None)
    return {"token": mkjwt(u["user_id"]), "user": u}

@api.post("/auth/google/session")
async def gsession(b: GSession):
    async with httpx.AsyncClient(timeout=15) as cx:
        r = await cx.get("https://demobackend.emergentagent.com/auth/v1/env/oauth/session-data",
                         headers={"X-Session-ID": b.session_id})
    if r.status_code != 200: raise HTTPException(401, "Invalid session")
    d = r.json()
    email = d["email"].lower()
    u = await db.users.find_one({"email": email})
    if not u:
        uid = "user_" + secrets.token_hex(6)
        u = {"user_id": uid, "email": email, "name": d.get("name", email.split("@")[0]),
             "picture": d.get("picture"), "is_admin": False, "pizza_count": 0,
             "qr_token": secrets.token_hex(12), "rewards_redeemed": [], "rewards_history": [],
             "created_at": now()}
        await db.users.insert_one(u)
    await db.user_sessions.update_one(
        {"session_token": d["session_token"]},
        {"$set": {"session_token": d["session_token"], "user_id": u["user_id"],
                  "expires_at": now() + timedelta(days=7), "created_at": now()}},
        upsert=True,
    )
    u.pop("_id", None); u.pop("password", None)
    return {"token": d["session_token"], "user": u}

@api.get("/auth/me")
async def me(authorization: Optional[str] = Header(None)):
    u = await cu(authorization)
    u.pop("_id", None); u.pop("password", None)
    return u

@api.post("/auth/logout")
async def logout(authorization: Optional[str] = Header(None)):
    if authorization and authorization.startswith("Bearer "):
        await db.user_sessions.delete_one({"session_token": authorization.replace("Bearer ", "", 1)})
    return {"ok": True}

# Menu (public)
@api.get("/menu")
async def menu():
    return await db.menu.find({}, {"_id": 0}).to_list(500)


async def _bump_menu_rev() -> int:
    """Increment the menu revision so clients can cheaply detect CMS changes."""
    doc = await db.meta.find_one_and_update(
        {"_id": "menu"},
        {"$inc": {"rev": 1}, "$set": {"updated_at": now().isoformat()}},
        upsert=True, return_document=True,
    )
    return int((doc or {}).get("rev", 1))


@api.get("/menu/version")
async def menu_version():
    """Tiny endpoint the customer apps poll to know when to refetch the menu.
    Returns a monotonically increasing `rev` (bumped on every CMS menu write)
    plus the live item count, so a changed value = the menu changed."""
    meta = await db.meta.find_one({"_id": "menu"}, {"_id": 0})
    count = await db.menu.count_documents({})
    return {"rev": int((meta or {}).get("rev", 0)), "count": count,
            "updated_at": (meta or {}).get("updated_at")}


# ---- Admin menu management (MongoDB-backed CMS) ----
MENU_CATEGORIES = ("pizzas", "focaccias", "gratins", "salades", "desserts", "boissons", "vins")


class MenuItemIn(BaseModel):
    category: str
    name: str
    desc_fr: Optional[str] = ""
    desc_en: Optional[str] = ""
    ingredients_fr: Optional[str] = ""
    ingredients_en: Optional[str] = ""
    price: Optional[float] = None
    prices: Optional[dict] = None  # e.g. {"26": 10.9, "31": 13.9} for pizzas
    image: Optional[str] = ""


class MenuItemUpdate(BaseModel):
    category: Optional[str] = None
    name: Optional[str] = None
    desc_fr: Optional[str] = None
    desc_en: Optional[str] = None
    ingredients_fr: Optional[str] = None
    ingredients_en: Optional[str] = None
    price: Optional[float] = None
    prices: Optional[dict] = None
    image: Optional[str] = None


@api.get("/admin/menu")
async def admin_list_menu(authorization: Optional[str] = Header(None)):
    await _require_admin(authorization)
    return await db.menu.find({}, {"_id": 0}).to_list(500)


@api.post("/admin/menu", status_code=201)
async def admin_create_menu_item(b: MenuItemIn, authorization: Optional[str] = Header(None)):
    await _require_admin(authorization)
    if b.category not in MENU_CATEGORIES:
        raise HTTPException(400, f"Invalid category. Allowed: {', '.join(MENU_CATEGORIES)}")
    if not b.name.strip():
        raise HTTPException(400, "Name required")
    doc = {
        "id": f"m-{secrets.token_hex(5)}",
        "category": b.category,
        "name": b.name.strip(),
        "desc_fr": b.desc_fr or "", "desc_en": b.desc_en or "",
        "ingredients_fr": b.ingredients_fr or "", "ingredients_en": b.ingredients_en or "",
        "image": b.image or "",
        "created_at": now(),
    }
    if b.prices:
        doc["prices"] = {str(k): float(v) for k, v in b.prices.items()}
    elif b.price is not None:
        doc["price"] = float(b.price)
    await db.menu.insert_one(dict(doc))
    await _bump_menu_rev()
    doc.pop("_id", None)
    doc.pop("created_at", None)
    return doc


@api.patch("/admin/menu/{item_id}")
async def admin_update_menu_item(item_id: str, b: MenuItemUpdate, authorization: Optional[str] = Header(None)):
    await _require_admin(authorization)
    existing = await db.menu.find_one({"id": item_id}, {"_id": 0})
    if not existing:
        raise HTTPException(404, "Menu item not found")
    update: dict = {}
    if b.category is not None:
        if b.category not in MENU_CATEGORIES:
            raise HTTPException(400, "Invalid category")
        update["category"] = b.category
    for fld in ("name", "desc_fr", "desc_en", "ingredients_fr", "ingredients_en", "image"):
        v = getattr(b, fld)
        if v is not None:
            update[fld] = v
    # Pricing: if prices map provided, set it and drop single price; if single price provided, set it and drop map.
    unset: dict = {}
    if b.prices is not None:
        update["prices"] = {str(k): float(v) for k, v in b.prices.items()}
        unset["price"] = ""
    elif b.price is not None:
        update["price"] = float(b.price)
        unset["prices"] = ""
    ops: dict = {}
    if update:
        ops["$set"] = update
    if unset:
        # Only unset keys that actually exist to avoid no-op churn
        ops["$unset"] = {k: v for k, v in unset.items() if k in existing}
    if ops:
        await db.menu.update_one({"id": item_id}, ops)
        await _bump_menu_rev()
    fresh = await db.menu.find_one({"id": item_id}, {"_id": 0})
    return fresh


@api.delete("/admin/menu/{item_id}")
async def admin_delete_menu_item(item_id: str, authorization: Optional[str] = Header(None)):
    await _require_admin(authorization)
    r = await db.menu.delete_one({"id": item_id})
    if r.deleted_count == 0:
        raise HTTPException(404, "Menu item not found")
    await _bump_menu_rev()
    return {"deleted": True, "id": item_id}

# Reservations
DEFAULT_CAPACITY = {"indoor": 30, "terrace": 20}
DEFAULT_TABLES = {"tables_indoor": 8, "tables_terrace": 5, "seats_per_table": 4}
VALID_ZONES = ("indoor", "terrace")
VALID_STATUSES = ("pending", "confirmed", "cancelled", "completed")
ACTIVE_STATUSES = ("pending", "confirmed")  # statuses that "hold" a table


# ============================================================================
# PUSH NOTIFICATIONS — Web Push (VAPID) + Emergent native relay (future builds)
# ============================================================================
VAPID_PUBLIC_KEY = os.environ.get("VAPID_PUBLIC_KEY") or ""
VAPID_PRIVATE_KEY = os.environ.get("VAPID_PRIVATE_KEY") or ""
VAPID_CONTACT = os.environ.get("VAPID_CONTACT") or "mailto:contact@pizzadenfert.fr"
EMERGENT_PUSH_KEY = os.environ.get("EMERGENT_PUSH_KEY") or "placeholder"
EMERGENT_PUSH_BASE = "https://integrations.emergentagent.com"


class WebPushSubscriptionIn(BaseModel):
    endpoint: str
    keys: dict  # {"p256dh": "...", "auth": "..."}


class RegisterDevicePushIn(BaseModel):
    user_id: str
    platform: str        # "android" | "ios"
    device_token: str


async def _save_web_subscription(user_id: str, sub: dict) -> None:
    """Upsert a web push subscription keyed by (user_id, endpoint) so re-subscribing same browser is idempotent."""
    await db.push_subscriptions.update_one(
        {"user_id": user_id, "endpoint": sub["endpoint"]},
        {"$set": {
            "user_id": user_id, "endpoint": sub["endpoint"],
            "keys": sub.get("keys", {}), "kind": "web",
            "updated_at": now(),
        }, "$setOnInsert": {"created_at": now()}},
        upsert=True,
    )


def _send_one_web_push(sub: dict, payload: dict) -> tuple[bool, Optional[int]]:
    """Send to one subscription. Returns (ok, status_code). Caller logs failures."""
    if not VAPID_PRIVATE_KEY or not VAPID_PUBLIC_KEY:
        return False, None
    try:
        webpush(
            subscription_info={"endpoint": sub["endpoint"], "keys": sub.get("keys", {})},
            data=_json.dumps(payload),
            vapid_private_key=VAPID_PRIVATE_KEY,
            vapid_claims={"sub": VAPID_CONTACT},
            ttl=3600,
        )
        return True, 201
    except WebPushException as e:
        code = getattr(e.response, "status_code", None) if hasattr(e, "response") and e.response is not None else None
        return False, code
    except Exception:
        return False, None


async def _send_emergent_native_push(user_ids: List[str], payload: dict) -> None:
    """Relay to Emergent push (SuprSend). Silently no-ops if PUSH_KEY is placeholder."""
    if not user_ids or EMERGENT_PUSH_KEY == "placeholder":
        return
    try:
        async with httpx.AsyncClient(timeout=8.0, headers={"X-Push-Key": EMERGENT_PUSH_KEY}) as cx:
            await cx.post(f"{EMERGENT_PUSH_BASE}/api/v1/push/trigger",
                          json={"recipients": user_ids,
                                "data": {"title": payload.get("title", ""),
                                         "message": payload.get("body", payload.get("message", "")),
                                         "action_url": payload.get("url")}})
    except Exception as e:
        log.warning(f"Emergent push relay failed: {e}")


async def push_to_user_ids(user_ids: List[str], payload: dict) -> int:
    """Fan-out push to all subscriptions for a list of user IDs (BOTH web + native).
    Returns the number of web pushes that succeeded (best-effort)."""
    if not user_ids:
        return 0
    ok_count = 0
    # ---- Web push ----
    if VAPID_PRIVATE_KEY:
        cur = db.push_subscriptions.find(
            {"user_id": {"$in": user_ids}, "kind": "web"},
            {"_id": 0, "endpoint": 1, "keys": 1, "user_id": 1},
        )
        dead: List[str] = []
        async for sub in cur:
            ok, code = _send_one_web_push(sub, payload)
            if ok:
                ok_count += 1
            elif code in (404, 410):
                # Subscription is gone / expired — purge it
                dead.append(sub["endpoint"])
            else:
                log.info(f"web push failed (code={code}) for user={sub.get('user_id')}")
        if dead:
            await db.push_subscriptions.delete_many({"endpoint": {"$in": dead}})
    # ---- Native push (Emergent relay) ----
    await _send_emergent_native_push(user_ids, payload)
    return ok_count


async def notify_admins(payload: dict) -> int:
    admin_ids = [u["user_id"] async for u in db.users.find(
        {"is_admin": True, "disabled": {"$ne": True}}, {"_id": 0, "user_id": 1}
    )]
    return await push_to_user_ids(admin_ids, payload)


async def notify_user(user_id: Optional[str], payload: dict) -> int:
    if not user_id:
        return 0
    return await push_to_user_ids([user_id], payload)


# ============================================================================
# Reservations
# ============================================================================


async def _get_capacity() -> dict:
    """Return current per-zone seat + table configuration, seeding defaults on first call."""
    doc = await db.app_settings.find_one({"key": "capacity"}, {"_id": 0})
    if not doc:
        await db.app_settings.update_one(
            {"key": "capacity"},
            {"$set": {"key": "capacity", **DEFAULT_CAPACITY, **DEFAULT_TABLES, "updated_at": now()}},
            upsert=True,
        )
        return {**DEFAULT_CAPACITY, **DEFAULT_TABLES}
    return {
        "indoor": int(doc.get("indoor", DEFAULT_CAPACITY["indoor"])),
        "terrace": int(doc.get("terrace", DEFAULT_CAPACITY["terrace"])),
        "tables_indoor": int(doc.get("tables_indoor", DEFAULT_TABLES["tables_indoor"])),
        "tables_terrace": int(doc.get("tables_terrace", DEFAULT_TABLES["tables_terrace"])),
        "seats_per_table": int(doc.get("seats_per_table", DEFAULT_TABLES["seats_per_table"])),
    }


def _zone_table_ids(zone: str, count: int) -> List[str]:
    """Generate canonical table identifiers for a zone (e.g. I-1, I-2, T-1, T-2)."""
    prefix = "I" if zone == "indoor" else "T"
    return [f"{prefix}-{i}" for i in range(1, count + 1)]


def _parse_tables(table_no: Optional[str]) -> List[str]:
    """Split a comma-separated table id string into individual ids."""
    if not table_no:
        return []
    return [t.strip() for t in table_no.split(",") if t.strip()]


async def _occupied_tables(date: str, time: str, zone: str, exclude_id: Optional[str] = None) -> set:
    """Set of table ids already assigned for (date, time, zone) by active reservations."""
    q = {"date": date, "time": time, "zone": zone,
         "status": {"$in": list(ACTIVE_STATUSES)},
         "table_no": {"$ne": None}}
    if exclude_id:
        q["id"] = {"$ne": exclude_id}
    occupied: set = set()
    async for r in db.reservations.find(q, {"_id": 0, "table_no": 1}):
        for t in _parse_tables(r.get("table_no")):
            occupied.add(t)
    return occupied


async def _assign_tables_for(date: str, time: str, zone: str, guests: int,
                             exclude_id: Optional[str] = None) -> Optional[str]:
    """Try to assign one or more tables in `zone` at (date, time) for `guests`.
    Returns the assignment string ("I-3" or "I-1,I-2") or None if not enough free tables.
    Larger parties get combined adjacent table ids (lowest numbers first)."""
    cap = await _get_capacity()
    seats = max(1, cap["seats_per_table"])
    needed = max(1, (guests + seats - 1) // seats)
    total_tables = cap["tables_indoor"] if zone == "indoor" else cap["tables_terrace"]
    all_ids = _zone_table_ids(zone, total_tables)
    occupied = await _occupied_tables(date, time, zone, exclude_id=exclude_id)
    free = [t for t in all_ids if t not in occupied]
    if len(free) < needed:
        return None
    return ",".join(free[:needed])


async def _ensure_can_book(date: str, time: str, zone: str, guests: int) -> dict:
    """Validate base inputs + return current capacity. Table allocation is done separately."""
    if zone not in VALID_ZONES:
        raise HTTPException(400, "Invalid zone")
    if guests < 1 or guests > 20:
        raise HTTPException(400, "Invalid guests")
    return await _get_capacity()


async def _zone_booked(date: str, time: str, zone: str) -> int:
    """Total guests booked (active statuses only) for (date, time, zone) — used by public availability."""
    agg = await db.reservations.aggregate([
        {"$match": {"date": date, "time": time, "zone": zone, "status": {"$in": list(ACTIVE_STATUSES)}}},
        {"$group": {"_id": None, "total": {"$sum": "$guests"}}},
    ]).to_list(1)
    return int(agg[0]["total"]) if agg else 0


async def _create_reservation_record(user_id: Optional[str], user_name: Optional[str],
                                      user_email: Optional[str], b: "ResIn") -> dict:
    """Shared logic: try to auto-assign a table → confirmed; else → pending (waiting list)."""
    await _ensure_can_book(b.date, b.time, b.zone, b.guests)
    table_no = await _assign_tables_for(b.date, b.time, b.zone, b.guests)
    status = "confirmed" if table_no else "pending"
    r = {"id": str(uuid.uuid4()),
         "user_id": user_id, "user_name": user_name or b.name, "user_email": user_email,
         "date": b.date, "time": b.time, "guests": b.guests, "zone": b.zone,
         "name": b.name, "phone": b.phone, "notes": b.notes or "",
         "table_no": table_no, "status": status,
         "created_at": now()}
    await db.reservations.insert_one(dict(r))
    r.pop("_id", None)
    # ---- Push notifications (best-effort, never blocks the response) ----
    try:
        zone_label = "Intérieur" if b.zone == "indoor" else "Terrasse"
        if status == "confirmed":
            await notify_admins({
                "title": "Nouvelle réservation",
                "body": f"{b.name} · {b.date} {b.time} · {b.guests}p · {zone_label} · Table {table_no}",
                "url": "/admin-reservations",
                "tag": f"res-{r['id']}",
            })
            if user_id:
                await notify_user(user_id, {
                    "title": "Réservation confirmée",
                    "body": f"Table {table_no} · {b.date} {b.time} · {b.guests} couvert{'s' if b.guests>1 else ''}",
                    "url": "/account",
                    "tag": f"res-{r['id']}",
                })
        else:
            await notify_admins({
                "title": "Nouvelle demande (liste d'attente)",
                "body": f"{b.name} · {b.date} {b.time} · {b.guests}p · {zone_label} · à confirmer",
                "url": "/admin-reservations",
                "tag": f"res-{r['id']}",
            })
            if user_id:
                await notify_user(user_id, {
                    "title": "En liste d'attente",
                    "body": f"Toutes les tables sont prises à {b.time}. Vous serez confirmé(e) dès qu'une se libère.",
                    "url": "/account",
                    "tag": f"res-{r['id']}",
                })
    except Exception as e:
        log.warning(f"reservation push notification failed (non-blocking): {e}")
    return r


async def _promote_waitlist(date: str, time: str, zone: str, limit: int = 5) -> List[dict]:
    """DISABLED — by product decision, waitlist entries must be manually confirmed by admins,
    never auto-promoted. Kept as a no-op so existing callers don't break."""
    return []


@api.get("/reservations/availability")
async def reservations_availability(date: str, time: str):
    """Per-zone availability for a (date, time) slot. Public — used by the reservation form."""
    cap = await _get_capacity()
    out: dict = {"date": date, "time": time, "zones": {}}
    for z in VALID_ZONES:
        total_tables = cap["tables_indoor"] if z == "indoor" else cap["tables_terrace"]
        occupied = await _occupied_tables(date, time, z)
        free_tables = max(0, total_tables - len(occupied))
        booked = await _zone_booked(date, time, z)
        available = max(0, cap[z] - booked)
        out["zones"][z] = {
            "capacity": cap[z], "booked": booked, "available": available,
            "tables_total": total_tables, "tables_free": free_tables,
            "full": free_tables <= 0,
        }
    return out


@api.post("/reservations")
async def create_res(b: ResIn, authorization: Optional[str] = Header(None)):
    u = await cu(authorization)
    return await _create_reservation_record(u["user_id"], u.get("name"), u.get("email"), b)


@api.post("/reservations/guest")
async def guest_res(b: ResIn):
    return await _create_reservation_record(None, b.name, None, b)


@api.get("/admin/settings/capacity")
async def admin_get_capacity(authorization: Optional[str] = Header(None)):
    await _require_admin(authorization)
    return await _get_capacity()


@api.put("/admin/settings/capacity")
async def admin_update_capacity(b: CapacityIn, authorization: Optional[str] = Header(None)):
    me_admin = await _require_admin(authorization)
    _check_can_manage(me_admin)
    if b.indoor < 0 or b.indoor > 500 or b.terrace < 0 or b.terrace > 500:
        raise HTTPException(400, "Capacity must be between 0 and 500")
    update: dict = {"key": "capacity", "indoor": int(b.indoor),
                    "terrace": int(b.terrace), "updated_at": now()}
    if b.tables_indoor is not None:
        if b.tables_indoor < 1 or b.tables_indoor > 100:
            raise HTTPException(400, "tables_indoor must be between 1 and 100")
        update["tables_indoor"] = int(b.tables_indoor)
    if b.tables_terrace is not None:
        if b.tables_terrace < 1 or b.tables_terrace > 100:
            raise HTTPException(400, "tables_terrace must be between 1 and 100")
        update["tables_terrace"] = int(b.tables_terrace)
    if b.seats_per_table is not None:
        if b.seats_per_table < 1 or b.seats_per_table > 20:
            raise HTTPException(400, "seats_per_table must be between 1 and 20")
        update["seats_per_table"] = int(b.seats_per_table)
    await db.app_settings.update_one({"key": "capacity"}, {"$set": update}, upsert=True)
    return await _get_capacity()


# ---- Admin: Reservations management ----

def _serialise_res(r: dict) -> dict:
    r = dict(r); r.pop("_id", None)
    ca = r.get("created_at")
    if isinstance(ca, datetime):
        r["created_at"] = ca.isoformat()
    pa = r.get("promoted_at")
    if isinstance(pa, datetime):
        r["promoted_at"] = pa.isoformat()
    return r


@api.get("/admin/reservations")
async def admin_list_reservations(
    authorization: Optional[str] = Header(None),
    period: Optional[str] = None,     # today | upcoming | past | range | all
    from_date: Optional[str] = None,  # YYYY-MM-DD
    to_date: Optional[str] = None,
    status: Optional[str] = None,     # comma-separated: pending,confirmed,cancelled,completed
    q: Optional[str] = None,          # search name or phone
    zone: Optional[str] = None,
    limit: int = 500,
):
    await _require_admin(authorization)
    today_str = now().date().isoformat()
    query: dict = {}

    if period == "today":
        query["date"] = today_str
    elif period == "upcoming":
        query["date"] = {"$gte": today_str}
    elif period == "past":
        query["date"] = {"$lt": today_str}
    elif period == "range" or from_date or to_date:
        dq: dict = {}
        if from_date: dq["$gte"] = from_date
        if to_date: dq["$lte"] = to_date
        if dq: query["date"] = dq

    if status:
        statuses = [s.strip() for s in status.split(",") if s.strip() in VALID_STATUSES]
        if statuses:
            query["status"] = {"$in": statuses}

    if zone in VALID_ZONES:
        query["zone"] = zone

    if q:
        rx = re.escape(q.strip())
        if rx:
            query["$or"] = [
                {"name": {"$regex": rx, "$options": "i"}},
                {"phone": {"$regex": rx, "$options": "i"}},
                {"user_name": {"$regex": rx, "$options": "i"}},
            ]

    cur = db.reservations.find(query, {"_id": 0}).sort([("date", 1), ("time", 1), ("created_at", 1)])
    items = [_serialise_res(r) for r in await cur.to_list(limit)]
    return {"items": items, "count": len(items), "filter": {
        "period": period, "from_date": from_date, "to_date": to_date,
        "status": status, "q": q, "zone": zone,
    }}


@api.get("/admin/reservations/day")
async def admin_reservations_day(date: str, authorization: Optional[str] = Header(None)):
    """Full day overview: timeslot grid showing per-zone table occupancy. Used by the timeline view."""
    await _require_admin(authorization)
    cap = await _get_capacity()
    timeslots = []
    # Service slots: 12:00-14:30 lunch, 19:00-22:30 dinner (every 30 min)
    for h in [12, 12.5, 13, 13.5, 14, 19, 19.5, 20, 20.5, 21, 21.5, 22]:
        hh = int(h); mm = 30 if h % 1 else 0
        timeslots.append(f"{hh:02d}:{mm:02d}")

    reservations = await db.reservations.find(
        {"date": date, "status": {"$in": list(ACTIVE_STATUSES)}},
        {"_id": 0},
    ).sort("time", 1).to_list(1000)

    grid = []
    for t in timeslots:
        slot = {"time": t, "zones": {}}
        for z in VALID_ZONES:
            total = cap["tables_indoor"] if z == "indoor" else cap["tables_terrace"]
            ids = _zone_table_ids(z, total)
            slot["zones"][z] = {"tables": []}
            for tid in ids:
                # find any active res at this slot occupying this table
                holder = next((r for r in reservations
                               if r["time"] == t and r["zone"] == z and tid in _parse_tables(r.get("table_no"))),
                              None)
                slot["zones"][z]["tables"].append({
                    "id": tid,
                    "occupied": bool(holder),
                    "reservation_id": holder["id"] if holder else None,
                    "name": holder["name"] if holder else None,
                    "guests": holder["guests"] if holder else None,
                    "status": holder["status"] if holder else None,
                })
        grid.append(slot)

    pending_today = [_serialise_res(r) for r in reservations if r.get("status") == "pending"]
    return {"date": date, "capacity": cap, "grid": grid, "pending_at_day": pending_today}


@api.patch("/admin/reservations/{rid}")
async def admin_update_reservation(rid: str, b: UpdateReservationIn,
                                    authorization: Optional[str] = Header(None)):
    """Update fields, including status. Handles table re-assignment and waiting list promotion."""
    await _require_admin(authorization)
    existing = await db.reservations.find_one({"id": rid}, {"_id": 0})
    if not existing:
        raise HTTPException(404, "Reservation not found")

    update: dict = {}
    new_date = b.date or existing["date"]
    new_time = b.time or existing["time"]
    new_zone = b.zone or existing["zone"]
    new_guests = int(b.guests) if b.guests is not None else int(existing["guests"])
    new_status = b.status or existing["status"]

    if b.zone is not None and b.zone not in VALID_ZONES:
        raise HTTPException(400, "Invalid zone")
    if b.status is not None and b.status not in VALID_STATUSES:
        raise HTTPException(400, "Invalid status")
    if b.guests is not None and (new_guests < 1 or new_guests > 20):
        raise HTTPException(400, "Invalid guests")

    schedule_changed = (new_date != existing["date"] or new_time != existing["time"]
                        or new_zone != existing["zone"] or new_guests != int(existing.get("guests", 0)))

    was_active = existing.get("status") in ACTIVE_STATUSES
    will_be_active = new_status in ACTIVE_STATUSES

    # Handle table assignment
    new_table = existing.get("table_no")
    needs_reassign = False
    if b.table_no is not None:
        # Manual table override — validate it doesn't conflict
        if b.table_no.strip() == "":
            new_table = None
        else:
            cap = await _get_capacity()
            total = cap["tables_indoor"] if new_zone == "indoor" else cap["tables_terrace"]
            valid_ids = set(_zone_table_ids(new_zone, total))
            requested = _parse_tables(b.table_no)
            unknown = [t for t in requested if t not in valid_ids]
            if unknown:
                raise HTTPException(400, f"Unknown table(s): {', '.join(unknown)}")
            occupied = await _occupied_tables(new_date, new_time, new_zone, exclude_id=rid)
            clash = [t for t in requested if t in occupied]
            if clash and will_be_active:
                raise HTTPException(409, f"Table(s) already occupied: {', '.join(clash)}")
            new_table = ",".join(requested)
    elif will_be_active and (schedule_changed or not was_active or not new_table):
        # Re-assign in these cases:
        #  - schedule changed → old table no longer applies
        #  - reservation was inactive (cancelled/completed) and is being re-activated
        #  - reservation has no table yet (e.g. pending → confirmed: needs a table now)
        needs_reassign = True
        new_table = None

    if needs_reassign:
        new_table = await _assign_tables_for(new_date, new_time, new_zone, new_guests, exclude_id=rid)
        if not new_table:
            # No table available → if requesting "confirmed", flip to pending instead of error
            if new_status == "confirmed":
                new_status = "pending"

    # If status moving to cancelled/completed, free the table
    if new_status in ("cancelled", "completed"):
        new_table = None

    update.update({
        "date": new_date, "time": new_time, "zone": new_zone, "guests": new_guests,
        "status": new_status, "table_no": new_table, "updated_at": now(),
    })
    if b.notes is not None: update["notes"] = b.notes
    if b.name is not None: update["name"] = b.name
    if b.phone is not None: update["phone"] = b.phone

    await db.reservations.update_one({"id": rid}, {"$set": update})

    # Notify owner customer on status changes from admin action
    if existing.get("status") != new_status and existing.get("user_id"):
        try:
            messages_fr = {
                "confirmed": ("Réservation confirmée", f"Table {new_table or '—'} · {new_date} {new_time}"),
                "cancelled": ("Réservation annulée", f"Votre réservation du {new_date} {new_time} a été annulée"),
                "completed": ("Merci de votre visite !", f"À bientôt à Pizza Denfert"),
                "pending":   ("En liste d'attente", f"Votre réservation est en liste d'attente pour {new_date} {new_time}"),
            }
            title, body = messages_fr.get(new_status, ("Mise à jour réservation", ""))
            await notify_user(existing["user_id"], {
                "title": title, "body": body, "url": "/account", "tag": f"res-{rid}",
            })
        except Exception as e:
            log.warning(f"status-change push failed: {e}")

    # If status transitioned away from active OR table freed up → promote waitlist
    promoted: List[dict] = []
    freed_slot_changed = (existing.get("status") in ACTIVE_STATUSES and
                         (new_status not in ACTIVE_STATUSES or schedule_changed))
    if freed_slot_changed:
        # Promote waitlist on the OLD slot (table just freed there)
        promoted += await _promote_waitlist(existing["date"], existing["time"], existing["zone"])
        # And on the new slot too in case scheduling created room
        if schedule_changed:
            promoted += await _promote_waitlist(new_date, new_time, new_zone)

    fresh = await db.reservations.find_one({"id": rid}, {"_id": 0})
    return {"reservation": _serialise_res(fresh) if fresh else None,
            "promoted": [_serialise_res(p) for p in promoted]}


@api.post("/admin/reservations")
async def admin_create_reservation(b: ResIn, authorization: Optional[str] = Header(None)):
    """Manual booking by staff (e.g. phone reservation). Same auto-confirm or waitlist rules."""
    await _require_admin(authorization)
    return await _create_reservation_record(None, b.name, None, b)


@api.get("/reservations/me")
async def my_res(authorization: Optional[str] = Header(None)):
    u = await cu(authorization)
    return await db.reservations.find({"user_id": u["user_id"]}, {"_id": 0}).sort("created_at", -1).to_list(100)


# ============================================================================
# PUSH NOTIFICATION endpoints
# ============================================================================

@api.get("/push/web/public-key")
async def push_public_key():
    """Public — frontend fetches this VAPID public key to call PushManager.subscribe()."""
    return {"public_key": VAPID_PUBLIC_KEY}


@api.post("/push/web/subscribe")
async def push_web_subscribe(b: WebPushSubscriptionIn, authorization: Optional[str] = Header(None)):
    """Authenticated — store a browser's push subscription for the logged-in user."""
    u = await cu(authorization)
    await _save_web_subscription(u["user_id"], {"endpoint": b.endpoint, "keys": b.keys})
    return {"ok": True}


@api.post("/push/web/unsubscribe")
async def push_web_unsubscribe(b: WebPushSubscriptionIn, authorization: Optional[str] = Header(None)):
    u = await cu(authorization)
    r = await db.push_subscriptions.delete_one({"user_id": u["user_id"], "endpoint": b.endpoint})
    return {"deleted": r.deleted_count}


@api.get("/push/web/status")
async def push_web_status(authorization: Optional[str] = Header(None)):
    """Returns the count of web subscriptions for the current user."""
    u = await cu(authorization)
    n = await db.push_subscriptions.count_documents({"user_id": u["user_id"], "kind": "web"})
    return {"subscribed": n > 0, "count": n}


@api.post("/push/web/test")
async def push_web_test(authorization: Optional[str] = Header(None)):
    """Send a test push to all of the current user's web subscriptions."""
    u = await cu(authorization)
    n = await push_to_user_ids([u["user_id"]], {
        "title": "Test · Pizza Denfert",
        "body": "Les notifications fonctionnent !",
        "url": "/account",
        "tag": "test",
    })
    return {"sent": n}


@api.post("/register-push", status_code=201)
async def register_native_push(b: RegisterDevicePushIn):
    """Native (iOS/Android) device token registration via Emergent push relay.
    No-ops gracefully when EMERGENT_PUSH_KEY is placeholder (e.g. self-hosted deployment)."""
    if EMERGENT_PUSH_KEY == "placeholder":
        return {"status": "skipped", "reason": "EMERGENT_PUSH_KEY not configured"}
    try:
        async with httpx.AsyncClient(timeout=8.0, headers={"X-Push-Key": EMERGENT_PUSH_KEY}) as cx:
            r = await cx.post(f"{EMERGENT_PUSH_BASE}/api/v1/push/users/register",
                              json=b.model_dump())
            if r.status_code >= 500:
                raise HTTPException(502, "Push provider unavailable")
            r.raise_for_status()
        return {"status": "registered"}
    except HTTPException:
        raise
    except Exception as e:
        log.warning(f"Native push register failed: {e}")
        return {"status": "error", "detail": str(e)[:200]}


# Loyalty
REWARD_THRESHOLDS = {"coffee": 3, "dessert": 5, "margherita": 10}

def _compute_available(pizza_count: int, redeemed: list) -> list:
    """List of reward keys currently claimable (threshold reached and not yet redeemed for that tier)."""
    out = []
    for key, thresh in REWARD_THRESHOLDS.items():
        # how many times threshold has been met
        earned = pizza_count // thresh
        used = sum(1 for r in redeemed if r == key)
        if earned > used:
            out.append({"reward": key, "available": earned - used})
    return out

@api.get("/loyalty/me")
async def loyalty_me(authorization: Optional[str] = Header(None)):
    u = await cu(authorization)
    pc = u.get("pizza_count", 0)
    redeemed = u.get("rewards_redeemed", [])
    return {
        "pizza_count": pc, "qr_token": u.get("qr_token"),
        "qr_data": f"PIZZA-DENFERT:{u['user_id']}:{u.get('qr_token')}",
        "name": u["name"], "email": u["email"],
        "thresholds": REWARD_THRESHOLDS,
        "available_rewards": _compute_available(pc, redeemed),
        "history": u.get("rewards_history", []),
        "next_coffee": max(0, REWARD_THRESHOLDS["coffee"] - (pc % REWARD_THRESHOLDS["coffee"])) if pc % REWARD_THRESHOLDS["coffee"] != 0 else 0,
        "next_dessert": max(0, REWARD_THRESHOLDS["dessert"] - (pc % REWARD_THRESHOLDS["dessert"])) if pc % REWARD_THRESHOLDS["dessert"] != 0 else 0,
        "next_margherita": max(0, REWARD_THRESHOLDS["margherita"] - (pc % REWARD_THRESHOLDS["margherita"])) if pc % REWARD_THRESHOLDS["margherita"] != 0 else 0,
    }

@api.post("/loyalty/add-purchase")
async def add_purchase(b: PurchaseIn, authorization: Optional[str] = Header(None)):
    """ADMIN ONLY: increment pizza count for self (deprecated for customer use)."""
    u = await cu(authorization)
    if not u.get("is_admin"):
        raise HTTPException(403, "Admin only")
    if b.pizza_count < 1 or b.pizza_count > 10:
        raise HTTPException(400, "invalid count")
    await db.users.update_one({"user_id": u["user_id"]}, {"$inc": {"pizza_count": b.pizza_count}})
    nu = await db.users.find_one({"user_id": u["user_id"]}, {"_id": 0, "password": 0})
    return {"pizza_count": nu.get("pizza_count", 0)}


async def _require_admin(authorization: Optional[str] = Header(None)) -> dict:
    u = await cu(authorization)
    if not u.get("is_admin"):
        raise HTTPException(403, "Admin only")
    return u


def _parse_qr(qr_data: str) -> tuple:
    """Parse PIZZA-DENFERT:{user_id}:{qr_token} -> (user_id, qr_token) or raise."""
    parts = qr_data.strip().split(":")
    if len(parts) != 3 or parts[0] != "PIZZA-DENFERT":
        raise HTTPException(400, "Invalid QR code")
    return parts[1], parts[2]


def _customer_payload(u: dict) -> dict:
    pc = u.get("pizza_count", 0)
    redeemed = u.get("rewards_redeemed", [])
    return {
        "user_id": u["user_id"],
        "qr_token": u.get("qr_token"),
        "name": u.get("name"),
        "email": u.get("email"),
        "pizza_count": pc,
        "available_rewards": _compute_available(pc, redeemed),
        "history": u.get("rewards_history", []),
        "thresholds": REWARD_THRESHOLDS,
        "next_coffee": (REWARD_THRESHOLDS["coffee"] - pc % REWARD_THRESHOLDS["coffee"]) % REWARD_THRESHOLDS["coffee"] or 0,
        "next_dessert": (REWARD_THRESHOLDS["dessert"] - pc % REWARD_THRESHOLDS["dessert"]) % REWARD_THRESHOLDS["dessert"] or 0,
        "next_margherita": (REWARD_THRESHOLDS["margherita"] - pc % REWARD_THRESHOLDS["margherita"]) % REWARD_THRESHOLDS["margherita"] or 0,
    }


@api.post("/admin/scan")
async def admin_scan(b: ScanIn, authorization: Optional[str] = Header(None)):
    """Admin scans customer QR code → returns customer + loyalty progress."""
    await _require_admin(authorization)
    user_id, qr_token = _parse_qr(b.qr_data)
    user = await db.users.find_one({"user_id": user_id, "qr_token": qr_token}, {"_id": 0, "password": 0})
    if not user:
        raise HTTPException(404, "Customer not found or QR invalid")
    return _customer_payload(user)


@api.post("/admin/customer/add-pizza")
async def admin_add_pizza(b: AdminPizzaInExt, authorization: Optional[str] = Header(None)):
    """Admin adjusts a customer's loyalty pizza count.

    Positive `pizza_count` adds; negative values remove (clamped at 0).
    Logs every adjustment (including negatives) for analytics.
    """
    admin = await _require_admin(authorization)
    if b.pizza_count == 0 or b.pizza_count < -20 or b.pizza_count > 20:
        raise HTTPException(400, "Invalid count")
    user = await db.users.find_one({"user_id": b.user_id, "qr_token": b.qr_token})
    if not user:
        raise HTTPException(404, "Customer not found")
    current = int(user.get("pizza_count", 0) or 0)
    # Clamp at zero — never go below.
    effective_delta = b.pizza_count if b.pizza_count >= 0 else max(b.pizza_count, -current)
    new_count = current + effective_delta
    if effective_delta == 0:
        # Already at 0 and the admin tried to subtract → no-op, still return current payload.
        nu = await db.users.find_one({"user_id": b.user_id}, {"_id": 0, "password": 0})
        return _customer_payload(nu)
    update: dict = {"$set": {"pizza_count": new_count}}
    # If we removed pizzas, also clear over-counted rewards in `rewards_redeemed` to keep
    # the loyalty math consistent (so the customer can earn back the same tier later).
    if effective_delta < 0:
        redeemed = list(user.get("rewards_redeemed", []))
        for key, thresh in REWARD_THRESHOLDS.items():
            allowed = new_count // thresh
            used = sum(1 for r in redeemed if r == key)
            while used > allowed:
                # Remove one redemption of this key
                for i in range(len(redeemed) - 1, -1, -1):
                    if redeemed[i] == key:
                        redeemed.pop(i)
                        used -= 1
                        break
        update["$set"]["rewards_redeemed"] = redeemed
    await db.users.update_one({"user_id": b.user_id}, update)
    # Log the adjustment (positive or negative) for analytics.
    await db.pizza_events.insert_one({
        "user_id": b.user_id,
        "count": effective_delta,
        "pizza_id": b.pizza_id,
        "admin_id": admin.get("user_id"),
        "at": now(),
    })
    nu = await db.users.find_one({"user_id": b.user_id}, {"_id": 0, "password": 0})
    return _customer_payload(nu)


@api.post("/admin/customer/redeem")
async def admin_redeem(b: AdminRedeemIn, authorization: Optional[str] = Header(None)):
    """Admin validates a reward redemption for a customer."""
    await _require_admin(authorization)
    if b.reward not in REWARD_THRESHOLDS:
        raise HTTPException(400, "Invalid reward")
    user = await db.users.find_one({"user_id": b.user_id, "qr_token": b.qr_token})
    if not user:
        raise HTTPException(404, "Customer not found")
    avail = _compute_available(user.get("pizza_count", 0), user.get("rewards_redeemed", []))
    if not any(a["reward"] == b.reward for a in avail):
        raise HTTPException(400, "Reward not available")
    entry = {"reward": b.reward, "redeemed_at": now().isoformat()}
    await db.users.update_one(
        {"user_id": b.user_id},
        {"$push": {"rewards_redeemed": b.reward, "rewards_history": entry}},
    )
    nu = await db.users.find_one({"user_id": b.user_id}, {"_id": 0, "password": 0})
    return _customer_payload(nu)

@api.post("/loyalty/redeem")
async def redeem(b: RedeemIn, authorization: Optional[str] = Header(None)):
    u = await cu(authorization)
    if b.reward not in REWARD_THRESHOLDS:
        raise HTTPException(400, "invalid reward")
    avail = _compute_available(u.get("pizza_count", 0), u.get("rewards_redeemed", []))
    if not any(a["reward"] == b.reward for a in avail):
        raise HTTPException(400, "reward not available")
    entry = {"reward": b.reward, "redeemed_at": now().isoformat()}
    await db.users.update_one(
        {"user_id": u["user_id"]},
        {"$push": {"rewards_redeemed": b.reward, "rewards_history": entry}},
    )
    return {"ok": True, "redeemed": b.reward}

@api.post("/admin/search")
async def admin_search(b: AdminSearchIn, authorization: Optional[str] = Header(None)):
    """Search customer by phone, email or name."""
    await _require_admin(authorization)
    q = b.query.strip()
    if not q:
        return []
    # Try exact phone first
    phone_clean = q.replace(" ", "")
    # Escape user input before injecting into MongoDB $regex to avoid invalid-regex errors.
    safe_name = re.escape(q)
    safe_phone = re.escape(phone_clean)
    users = await db.users.find(
        {"$or": [
            {"phone": phone_clean},
            {"email": q.lower()},
            {"name": {"$regex": safe_name, "$options": "i"}},
            {"phone": {"$regex": safe_phone, "$options": "i"}},
        ], "is_admin": {"$ne": True}},
        {"_id": 0, "password": 0},
    ).limit(20).to_list(20)
    return [_customer_payload(u) for u in users]


@api.post("/admin/staff/create")
async def admin_create_staff(b: CreateStaffIn, authorization: Optional[str] = Header(None)):
    """Create a new admin/staff account (owner only)."""
    admin = await _require_admin(authorization)
    if admin.get("role", "owner") not in ("owner", "manager"):
        raise HTTPException(403, "Owner/manager only")
    phone = b.phone.strip().replace(" ", "")
    if await db.users.find_one({"phone": phone}):
        raise HTTPException(400, "Phone already registered")
    uid = ("admin_" if b.role in ("owner", "manager", "cashier") else "staff_") + secrets.token_hex(6)
    user = {
        "user_id": uid, "phone": phone, "name": b.name, "email": None,
        "is_admin": True, "role": b.role,
        "pizza_count": 0, "qr_token": secrets.token_hex(12),
        "rewards_redeemed": [], "rewards_history": [], "created_at": now(),
    }
    await db.users.insert_one(user)
    user.pop("_id", None)
    return {"created": user, "note": "Use phone + OTP to login as this staff member"}


@api.get("/admin/staff")
async def admin_list_staff(authorization: Optional[str] = Header(None)):
    """List all admin/staff accounts."""
    me_admin = await _require_admin(authorization)
    rows = await db.users.find(
        {"is_admin": True},
        {"_id": 0, "password": 0, "qr_token": 0, "rewards_history": 0, "rewards_redeemed": 0, "pizza_count": 0},
    ).sort("created_at", 1).to_list(200)
    out = []
    for r in rows:
        out.append({
            "user_id": r["user_id"],
            "name": r.get("name") or r.get("email") or r.get("phone"),
            "email": r.get("email"),
            "phone": r.get("phone"),
            "role": r.get("role", "owner"),
            "disabled": bool(r.get("disabled", False)),
            "is_self": r["user_id"] == me_admin["user_id"],
            "created_at": (r.get("created_at").isoformat() if r.get("created_at") else None),
        })
    return out


def _check_can_manage(actor: dict):
    if actor.get("role", "owner") not in ("owner", "manager"):
        raise HTTPException(403, "Owner/manager only")


@api.patch("/admin/staff/{user_id}/role")
async def admin_update_role(user_id: str, b: UpdateRoleIn, authorization: Optional[str] = Header(None)):
    """Update an admin user's role."""
    me_admin = await _require_admin(authorization)
    _check_can_manage(me_admin)
    if b.role not in ("owner", "manager", "cashier", "staff"):
        raise HTTPException(400, "Invalid role")
    target = await db.users.find_one({"user_id": user_id, "is_admin": True})
    if not target:
        raise HTTPException(404, "Staff not found")
    # Demoting the last owner is forbidden.
    if target.get("role", "owner") == "owner" and b.role != "owner":
        owners = await db.users.count_documents({"is_admin": True, "role": "owner"})
        if owners <= 1:
            raise HTTPException(400, "Cannot demote the last owner")
    await db.users.update_one({"user_id": user_id}, {"$set": {"role": b.role}})
    return {"ok": True, "user_id": user_id, "role": b.role}


@api.patch("/admin/staff/{user_id}/disable")
async def admin_disable_staff(user_id: str, b: DisableIn, authorization: Optional[str] = Header(None)):
    """Enable / disable a staff member. Disabled accounts cannot authenticate."""
    me_admin = await _require_admin(authorization)
    _check_can_manage(me_admin)
    if user_id == me_admin["user_id"]:
        raise HTTPException(400, "Cannot disable yourself")
    target = await db.users.find_one({"user_id": user_id, "is_admin": True})
    if not target:
        raise HTTPException(404, "Staff not found")
    # Disabling the last active owner is forbidden.
    if b.disabled and target.get("role", "owner") == "owner":
        active_owners = await db.users.count_documents({"is_admin": True, "role": "owner", "disabled": {"$ne": True}})
        if active_owners <= 1:
            raise HTTPException(400, "Cannot disable the last active owner")
    await db.users.update_one({"user_id": user_id}, {"$set": {"disabled": bool(b.disabled)}})
    if b.disabled:
        await db.user_sessions.delete_many({"user_id": user_id})
    return {"ok": True, "user_id": user_id, "disabled": bool(b.disabled)}


@api.delete("/admin/staff/{user_id}")
async def admin_delete_staff(user_id: str, authorization: Optional[str] = Header(None)):
    """Delete an admin/staff account."""
    me_admin = await _require_admin(authorization)
    _check_can_manage(me_admin)
    if user_id == me_admin["user_id"]:
        raise HTTPException(400, "Cannot delete yourself")
    target = await db.users.find_one({"user_id": user_id, "is_admin": True})
    if not target:
        raise HTTPException(404, "Staff not found")
    if target.get("role", "owner") == "owner":
        owners = await db.users.count_documents({"is_admin": True, "role": "owner"})
        if owners <= 1:
            raise HTTPException(400, "Cannot delete the last owner")
    await db.users.delete_one({"user_id": user_id})
    await db.user_sessions.delete_many({"user_id": user_id})
    return {"ok": True, "deleted": user_id}


@api.get("/admin/dashboard")
async def admin_dashboard(period: str = "all", authorization: Optional[str] = Header(None)):
    """Aggregated stats for the analytics dashboard.

    Query param `period` ∈ {today, week, month, all}.
    Falls back to `all` when value is unknown.
    """
    await _require_admin(authorization)
    today = now().replace(hour=0, minute=0, second=0, microsecond=0)
    week_ago = today - timedelta(days=7)
    month_ago = today - timedelta(days=30)

    period = (period or "all").lower()
    start = {
        "today": today,
        "week": week_ago,
        "month": month_ago,
        "all": None,
    }.get(period)
    if period not in ("today", "week", "month", "all"):
        period = "all"
        start = None

    # Pizzas sold in period (from pizza_events log). Lifetime falls back to summing users.pizza_count.
    if start is None:
        agg = await db.users.aggregate([
            {"$match": {"is_admin": {"$ne": True}}},
            {"$group": {"_id": None, "total": {"$sum": "$pizza_count"}}},
        ]).to_list(1)
        total_pizzas = int(agg[0]["total"]) if agg else 0
    else:
        agg = await db.pizza_events.aggregate([
            {"$match": {"at": {"$gte": start}}},
            {"$group": {"_id": None, "total": {"$sum": "$count"}}},
        ]).to_list(1)
        total_pizzas = int(agg[0]["total"]) if agg else 0

    # Reservations (lifetime + per period quick-lookups for context).
    reservations_total = await db.reservations.count_documents({})
    reservations_today = await db.reservations.count_documents({"created_at": {"$gte": today}})
    reservations_week = await db.reservations.count_documents({"created_at": {"$gte": week_ago}})
    reservations_month = await db.reservations.count_documents({"created_at": {"$gte": month_ago}})
    reservations_period = {
        "today": reservations_today, "week": reservations_week,
        "month": reservations_month, "all": reservations_total,
    }[period]

    loyalty_members = await db.users.count_documents({"is_admin": {"$ne": True}, "phone": {"$ne": None}})
    vip_count = await db.users.count_documents({"is_admin": {"$ne": True}, "pizza_count": {"$gte": 10}})

    # Redeemed rewards. Period filter uses rewards_history.redeemed_at if available.
    if start is None:
        rewards_agg = await db.users.aggregate([
            {"$match": {"is_admin": {"$ne": True}}},
            {"$unwind": "$rewards_history"},
            {"$group": {"_id": "$rewards_history.reward", "count": {"$sum": 1}}},
        ]).to_list(10)
    else:
        rewards_agg = await db.users.aggregate([
            {"$match": {"is_admin": {"$ne": True}}},
            {"$unwind": "$rewards_history"},
            {"$match": {"rewards_history.redeemed_at": {"$gte": start.isoformat()}}},
            {"$group": {"_id": "$rewards_history.reward", "count": {"$sum": 1}}},
        ]).to_list(10)
    redeemed = {r["_id"]: r["count"] for r in rewards_agg}

    # Top customers (lifetime — most loyal).
    top_customers = await db.users.find(
        {"is_admin": {"$ne": True}}, {"_id": 0, "password": 0}
    ).sort("pizza_count", -1).limit(5).to_list(5)

    # Top pizzas (from pizza_events with a pizza_id, joined with menu names). Period-aware.
    match_stage = {"pizza_id": {"$ne": None}}
    if start is not None:
        match_stage["at"] = {"$gte": start}
    pizza_agg = await db.pizza_events.aggregate([
        {"$match": match_stage},
        {"$group": {"_id": "$pizza_id", "total": {"$sum": "$count"}}},
        {"$sort": {"total": -1}},
        {"$limit": 5},
    ]).to_list(5)
    top_pizzas = []
    if pizza_agg:
        ids = [p["_id"] for p in pizza_agg]
        menu_rows = await db.menu.find({"id": {"$in": ids}}, {"_id": 0, "id": 1, "name": 1, "image": 1}).to_list(20)
        name_map = {m["id"]: m for m in menu_rows}
        for p in pizza_agg:
            m = name_map.get(p["_id"], {})
            top_pizzas.append({
                "pizza_id": p["_id"],
                "name": m.get("name") or p["_id"],
                "image": m.get("image"),
                "count": int(p["total"]),
            })

    return {
        "period": period,
        "total_pizzas_sold": total_pizzas,
        "loyalty_members": loyalty_members,
        "vip_customers": vip_count,
        "reservations_in_period": reservations_period,
        "reservations": {
            "today": reservations_today,
            "week": reservations_week,
            "month": reservations_month,
            "total": reservations_total,
        },
        "rewards_redeemed": {
            "coffee": redeemed.get("coffee", 0),
            "dessert": redeemed.get("dessert", 0),
            "margherita": redeemed.get("margherita", 0),
            "total": sum(redeemed.values()),
        },
        "top_customers": [
            {"name": c["name"], "phone": c.get("phone"), "pizzas": c.get("pizza_count", 0)}
            for c in top_customers
        ],
        "top_pizzas": top_pizzas,
    }


# ============================================================================
# KIOSK / Advertising Management — public-read for the kiosk display, admin-write.
# Slides are grouped by section and ordered within each section.
# ============================================================================
DEFAULT_KIOSK_SETTINGS = {
    "idle_seconds": 30,
    "loop": True,
    "default_duration_ms": 5000,
    "show_section_titles": True,
}

# Default content — seeded on first call, then admin-editable.
DEFAULT_SLIDES = [
    # Section 1 — Loyalty Club (4 slides)
    {"section": "loyalty", "order": 1, "title": "Rejoignez le Club Pizza Denfert",
     "subtitle": "Plus vous mangez, plus vous gagnez 🍕"},
    {"section": "loyalty", "order": 2, "title": "3 pizzas = 1 café offert",
     "subtitle": "Votre fidélité commence dès la première bouchée ☕"},
    {"section": "loyalty", "order": 3, "title": "5 pizzas = 1 dessert offert",
     "subtitle": "De quoi terminer le repas en beauté 🍰"},
    {"section": "loyalty", "order": 4, "title": "10 pizzas = 1 Margherita offerte",
     "subtitle": "Le grand classique, gratuit, rien que pour vous 🍕"},
    # Section 2 — Restaurant Experience (4 slides)
    {"section": "experience", "order": 1, "title": "Votre pizzeria de quartier",
     "subtitle": "Au pied du Mur des Canuts"},
    {"section": "experience", "order": 2, "title": "Notre terrasse vous attend",
     "subtitle": "À deux pas de la Croix-Rousse"},
    {"section": "experience", "order": 3, "title": "Une belle carte des vins",
     "subtitle": "Sélection de producteurs régionaux"},
    {"section": "experience", "order": 4, "title": "Une atmosphère chaleureuse",
     "subtitle": "Comme à la maison"},
    # Section 3 — Ingredients & Craftsmanship (6 slides)
    {"section": "ingredients", "order": 1, "title": "Tomates italiennes San Marzano",
     "subtitle": "La base d'une vraie pizza"},
    {"section": "ingredients", "order": 2, "title": "Produits locaux du Rhône-Alpes",
     "subtitle": "Notre terroir au cœur de chaque assiette"},
    {"section": "ingredients", "order": 3, "title": "Farine T65 française tradition",
     "subtitle": "Une pâte légère et digeste"},
    {"section": "ingredients", "order": 4, "title": "Fromages AOP",
     "subtitle": "Mozzarella di Bufala · Gorgonzola · Parmigiano Reggiano"},
    {"section": "ingredients", "order": 5, "title": "Pizza moderne franco-italienne",
     "subtitle": "Un savoir-faire qui réunit deux cultures"},
    {"section": "ingredients", "order": 6, "title": "Cuit au feu de bois",
     "subtitle": "Pour ce goût inimitable qui change tout"},
]


def _serialise_slide(s: dict) -> dict:
    s = dict(s); s.pop("_id", None)
    for k in ("created_at", "updated_at"):
        v = s.get(k)
        if isinstance(v, datetime):
            s[k] = v.isoformat()
    return s


async def _seed_default_slides_if_empty():
    """One-shot: if no ad_slides exist, insert the default catalog. Admin-editable afterwards."""
    n = await db.ad_slides.count_documents({})
    if n > 0:
        return
    docs = []
    for s in DEFAULT_SLIDES:
        docs.append({
            "id": str(uuid.uuid4()),
            "section": s["section"], "order": s["order"],
            "title": s["title"], "subtitle": s.get("subtitle", ""),
            "image_url": "", "duration_ms": 5000, "active": True,
            "created_at": now(), "updated_at": now(),
        })
    if docs:
        await db.ad_slides.insert_many(docs)
        log.info(f"Seeded {len(docs)} default kiosk slides")


async def _get_kiosk_settings() -> dict:
    doc = await db.app_settings.find_one({"key": "kiosk"}, {"_id": 0})
    if not doc:
        await db.app_settings.update_one(
            {"key": "kiosk"},
            {"$set": {"key": "kiosk", **DEFAULT_KIOSK_SETTINGS, "updated_at": now()}},
            upsert=True,
        )
        return dict(DEFAULT_KIOSK_SETTINGS)
    return {
        "idle_seconds": int(doc.get("idle_seconds", DEFAULT_KIOSK_SETTINGS["idle_seconds"])),
        "loop": bool(doc.get("loop", DEFAULT_KIOSK_SETTINGS["loop"])),
        "default_duration_ms": int(doc.get("default_duration_ms", DEFAULT_KIOSK_SETTINGS["default_duration_ms"])),
        "show_section_titles": bool(doc.get("show_section_titles", DEFAULT_KIOSK_SETTINGS["show_section_titles"])),
    }


@api.get("/ads/slides")
async def public_slides():
    """Public — kiosk displays consume this. Returns only ACTIVE slides ordered by section + order."""
    await _seed_default_slides_if_empty()
    cur = db.ad_slides.find({"active": True}, {"_id": 0}).sort([("section", 1), ("order", 1)])
    items = await cur.to_list(500)
    # Stable section ordering: loyalty → experience → ingredients
    section_rank = {s: i for i, s in enumerate(AD_SECTIONS)}
    items.sort(key=lambda x: (section_rank.get(x.get("section"), 99), int(x.get("order", 0))))
    return {"slides": [_serialise_slide(s) for s in items],
            "settings": await _get_kiosk_settings()}


@api.get("/admin/ads/slides")
async def admin_list_slides(authorization: Optional[str] = Header(None)):
    await _require_admin(authorization)
    await _seed_default_slides_if_empty()
    cur = db.ad_slides.find({}, {"_id": 0}).sort([("section", 1), ("order", 1)])
    items = await cur.to_list(500)
    section_rank = {s: i for i, s in enumerate(AD_SECTIONS)}
    items.sort(key=lambda x: (section_rank.get(x.get("section"), 99), int(x.get("order", 0))))
    return {"slides": [_serialise_slide(s) for s in items]}


@api.post("/admin/ads/slides", status_code=201)
async def admin_create_slide(b: AdSlideIn, authorization: Optional[str] = Header(None)):
    me = await _require_admin(authorization)
    if b.section not in AD_SECTIONS:
        raise HTTPException(400, f"Invalid section. Allowed: {', '.join(AD_SECTIONS)}")
    if b.duration_ms < 500 or b.duration_ms > 60000:
        raise HTTPException(400, "duration_ms must be between 500 and 60000")
    order = b.order
    if order is None:
        # Append: max order in section + 1
        agg = await db.ad_slides.find({"section": b.section}, {"_id": 0, "order": 1}).sort("order", -1).to_list(1)
        order = (agg[0]["order"] + 1) if agg else 1
    doc = {
        "id": str(uuid.uuid4()),
        "section": b.section, "order": int(order),
        "title": b.title, "subtitle": b.subtitle or "",
        "image_url": b.image_url or "", "duration_ms": int(b.duration_ms),
        "active": bool(b.active),
        "created_at": now(), "updated_at": now(),
        "created_by": me.get("user_id"),
    }
    await db.ad_slides.insert_one(dict(doc))
    return _serialise_slide(doc)


@api.patch("/admin/ads/slides/{sid}")
async def admin_update_slide(sid: str, b: AdSlideUpdateIn, authorization: Optional[str] = Header(None)):
    await _require_admin(authorization)
    update: dict = {"updated_at": now()}
    if b.section is not None:
        if b.section not in AD_SECTIONS:
            raise HTTPException(400, "Invalid section")
        update["section"] = b.section
    if b.order is not None: update["order"] = int(b.order)
    if b.title is not None: update["title"] = b.title
    if b.subtitle is not None: update["subtitle"] = b.subtitle
    if b.image_url is not None: update["image_url"] = b.image_url
    if b.duration_ms is not None:
        if b.duration_ms < 500 or b.duration_ms > 60000:
            raise HTTPException(400, "duration_ms must be between 500 and 60000")
        update["duration_ms"] = int(b.duration_ms)
    if b.active is not None: update["active"] = bool(b.active)
    r = await db.ad_slides.update_one({"id": sid}, {"$set": update})
    if r.matched_count == 0:
        raise HTTPException(404, "Slide not found")
    fresh = await db.ad_slides.find_one({"id": sid}, {"_id": 0})
    return _serialise_slide(fresh) if fresh else {}


@api.delete("/admin/ads/slides/{sid}")
async def admin_delete_slide(sid: str, authorization: Optional[str] = Header(None)):
    await _require_admin(authorization)
    r = await db.ad_slides.delete_one({"id": sid})
    if r.deleted_count == 0:
        raise HTTPException(404, "Slide not found")
    return {"deleted": True}


@api.put("/admin/ads/reorder")
async def admin_reorder_slides(b: AdReorderIn, authorization: Optional[str] = Header(None)):
    """Bulk reorder: pass an ordered list of IDs. Each slide's `order` field is rewritten
    to its index within its own section so the kiosk shows them in the requested sequence."""
    await _require_admin(authorization)
    # Map id -> section to recompute per-section order
    docs = [d async for d in db.ad_slides.find({"id": {"$in": b.ids}}, {"_id": 0, "id": 1, "section": 1})]
    sec_by_id = {d["id"]: d["section"] for d in docs}
    counters: dict = {}
    for sid in b.ids:
        sec = sec_by_id.get(sid)
        if not sec:
            continue
        counters[sec] = counters.get(sec, 0) + 1
        await db.ad_slides.update_one({"id": sid}, {"$set": {"order": counters[sec], "updated_at": now()}})
    return {"reordered": len(b.ids)}


@api.put("/admin/ads/settings")
async def admin_update_kiosk_settings(b: KioskSettingsIn, authorization: Optional[str] = Header(None)):
    await _require_admin(authorization)
    update: dict = {"key": "kiosk", "updated_at": now()}
    if b.idle_seconds is not None:
        if b.idle_seconds < 5 or b.idle_seconds > 600:
            raise HTTPException(400, "idle_seconds must be between 5 and 600")
        update["idle_seconds"] = int(b.idle_seconds)
    if b.loop is not None: update["loop"] = bool(b.loop)
    if b.default_duration_ms is not None:
        if b.default_duration_ms < 500 or b.default_duration_ms > 60000:
            raise HTTPException(400, "default_duration_ms must be between 500 and 60000")
        update["default_duration_ms"] = int(b.default_duration_ms)
    if b.show_section_titles is not None:
        update["show_section_titles"] = bool(b.show_section_titles)
    await db.app_settings.update_one({"key": "kiosk"}, {"$set": update}, upsert=True)
    return await _get_kiosk_settings()


@api.get("/admin/ads/settings")
async def admin_get_kiosk_settings(authorization: Optional[str] = Header(None)):
    await _require_admin(authorization)
    return await _get_kiosk_settings()


@api.get("/")
async def api_root(): return {"service": "Pizza Denfert API", "status": "ok"}


# ============================================================================
# Supabase CMS — one-time bulk seed of the legacy MongoDB menu into Supabase.
# Protected by FastAPI admin JWT. Uses the server-only SERVICE_ROLE_KEY so it
# bypasses RLS for this single trusted call. Idempotent on category slug + item
# name — re-running will NOT create duplicates.
# ============================================================================

# Maps the legacy SEED.category strings → (name_fr, slug, sort_order).
_CATEGORY_MAP = {
    "pizzas":    ("Pizzas",    "pizzas",    1),
    "focaccias": ("Focaccias", "focaccias", 2),
    "gratins":   ("Gratins",   "gratins",   3),
    "salades":   ("Salades",   "salades",   4),
    "desserts":  ("Desserts",  "desserts",  5),
    "boissons":  ("Boissons",  "boissons",  6),
    "vins":      ("Vins",      "vins",      7),
}


def _sb_headers():
    if not SUPABASE_URL or not SUPABASE_SERVICE_ROLE_KEY:
        raise HTTPException(503, "Supabase not configured on server (SUPABASE_URL or SUPABASE_SERVICE_ROLE_KEY missing). See /app/SUPABASE_SETUP.md")
    return {
        "apikey": SUPABASE_SERVICE_ROLE_KEY,
        "Authorization": f"Bearer {SUPABASE_SERVICE_ROLE_KEY}",
        "Content-Type": "application/json",
        "Prefer": "resolution=merge-duplicates,return=representation",
    }


@api.post("/admin/cms/seed-from-mongo")
async def cms_seed_from_mongo(authorization: Optional[str] = Header(None)):
    """One-shot import of SEED → Supabase categories + menu_items.
    Requires FastAPI admin auth. Safe to call multiple times — uses upsert on
    category slug and item (category_id, name). Returns counts.
    """
    await _require_admin(authorization)
    headers = _sb_headers()
    base = f"{SUPABASE_URL}/rest/v1"

    inserted_categories = 0
    inserted_items = 0

    async with httpx.AsyncClient(timeout=30.0) as cli:
        # 1. Upsert categories. Conflict target = slug (which is unique).
        cat_payload = [
            {"name": name, "slug": slug, "sort_order": order, "is_active": True}
            for (name, slug, order) in _CATEGORY_MAP.values()
        ]
        r = await cli.post(
            f"{base}/categories?on_conflict=slug",
            headers=headers, json=cat_payload,
        )
        if r.status_code >= 400:
            raise HTTPException(502, f"Supabase categories upsert failed: {r.status_code} {r.text[:300]}")
        inserted_categories = len(r.json() or [])

        # Fetch the resulting slug → id map.
        r = await cli.get(f"{base}/categories?select=id,slug", headers=headers)
        if r.status_code >= 400:
            raise HTTPException(502, f"Supabase categories fetch failed: {r.text[:300]}")
        slug_to_id = {row["slug"]: row["id"] for row in r.json()}

        # 2. Upsert menu_items. We DO NOT have a unique constraint on (name) yet,
        # so we manually check existing names per category to stay idempotent.
        r = await cli.get(f"{base}/menu_items?select=name,category_id", headers=headers)
        existing_pairs = set()
        if r.status_code < 400:
            for row in r.json():
                existing_pairs.add((row.get("category_id"), (row.get("name") or "").strip().lower()))

        items_payload = []
        for idx, s in enumerate(SEED):
            cat_id = slug_to_id.get(s["category"])
            if not cat_id:
                continue
            key = (cat_id, s["name"].strip().lower())
            if key in existing_pairs:
                continue
            # Prices: pizzas use `{26, 31}` map, others use single `price`.
            if "prices" in s:
                prices = {str(k): float(v) for k, v in s["prices"].items()}
            else:
                prices = {"default": float(s.get("price") or 0)}
            ingredients_text = s.get("ingredients_fr") or ""
            ingredients = [t.strip() for t in re.split(r",|·", ingredients_text) if t.strip()]
            items_payload.append({
                "name": s["name"],
                "description": s.get("desc_fr") or None,
                "ingredients": ingredients,
                "prices": prices,
                "image_url": s.get("image"),
                "category_id": cat_id,
                "sort_order": idx,
                "is_active": True,
            })

        if items_payload:
            r = await cli.post(f"{base}/menu_items", headers=headers, json=items_payload)
            if r.status_code >= 400:
                raise HTTPException(502, f"Supabase menu_items insert failed: {r.status_code} {r.text[:400]}")
            inserted_items = len(r.json() or [])

    return {
        "ok": True,
        "inserted_categories": inserted_categories,
        "inserted_items": inserted_items,
        "skipped_existing": len(SEED) - inserted_items,
    }


app.include_router(api)
app.add_middleware(CORSMiddleware, allow_credentials=True, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"])

@app.on_event("shutdown")
async def shut(): client.close()
