import os
import secrets
import string
from datetime import datetime, timedelta, timezone
from typing import Optional

import uuid
import uvicorn
from dotenv import load_dotenv
from fastapi import Depends, FastAPI, HTTPException, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from jose import JWTError, jwt
from pydantic import BaseModel, EmailStr
from supabase import Client, create_client

load_dotenv()

SUPABASE_URL = os.environ["SUPABASE_URL"]
SUPABASE_SERVICE_KEY = os.environ["SUPABASE_SERVICE_KEY"]
JWT_SECRET = os.environ["JWT_SECRET"]
JWT_ALGORITHM = os.getenv("JWT_ALGORITHM", "HS256")
ACCESS_TOKEN_EXPIRE_MINUTES = int(os.getenv("ACCESS_TOKEN_EXPIRE_MINUTES", "60"))
REFRESH_TOKEN_EXPIRE_DAYS = int(os.getenv("REFRESH_TOKEN_EXPIRE_DAYS", "30"))

supabase: Client = create_client(SUPABASE_URL, SUPABASE_SERVICE_KEY)
bearer_scheme = HTTPBearer()

app = FastAPI(title="Con Gusto Accounts API", version="0.1.0")
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_credentials=True, allow_methods=["*"], allow_headers=["*"])

# ---------------------------------------------------------------------------
# Schemas
# ---------------------------------------------------------------------------

class RegisterRequest(BaseModel):
    email: EmailStr
    password: str
    full_name: str
    phone: Optional[str] = None
    organization_name: Optional[str] = None
    role: str = "EMPLOYEE"

class RegisterResponse(BaseModel):
    access_token: str
    refresh_token: Optional[str]
    token_type: str = "bearer"
    user: dict

class JoinOrganizationRequest(BaseModel):
    join_code: str

class JoinOrganizationResponse(BaseModel):
    organization_name: str
    organization_slug: str
    role: str
    message: str

class OrganizationDetail(BaseModel):
    id: str
    name: str
    slug: str
    join_code: str
    join_code_enabled: bool
    chat_mode: str
    plan_tier: Optional[str]
    member_count: int
    created_at: str

class UpdateOrganizationRequest(BaseModel):
    name: Optional[str] = None
    chat_mode: Optional[str] = None
    join_code_enabled: Optional[bool] = None

class RegenerateJoinCodeResponse(BaseModel):
    join_code: str

class MemberItem(BaseModel):
    id: str
    email: str
    full_name: Optional[str]
    role: str
    phone: Optional[str]
    is_active: bool
    joined_at: str

class MemberListResponse(BaseModel):
    members: list[MemberItem]
    total: int

class UpdateMemberRequest(BaseModel):
    role: Optional[str] = None
    is_active: Optional[bool] = None

# ---------------------------------------------------------------------------
# Auth helpers — we trust Supabase's own JWT for authenticated calls
# ---------------------------------------------------------------------------

def _get_supabase_user(token: str) -> dict:
    """Validate token via Supabase and return the public.users row."""
    try:
        user_resp = supabase.auth.get_user(token)
        if not user_resp or not user_resp.user:
            raise HTTPException(status_code=401, detail="Invalid or expired token.")
        auth_user_id = user_resp.user.id
    except Exception:
        raise HTTPException(status_code=401, detail="Invalid or expired token.")

    result = supabase.table("users").select("*").eq("id", auth_user_id).single().execute()
    if not result.data:
        raise HTTPException(status_code=401, detail="User profile not found.")
    return result.data

def get_current_user(credentials: HTTPAuthorizationCredentials = Depends(bearer_scheme)) -> dict:
    return _get_supabase_user(credentials.credentials)

def require_admin(current_user: dict = Depends(get_current_user)) -> dict:
    if current_user.get("role", "").upper() not in ("PROPERTY_MANAGER", "ADMIN"):
        raise HTTPException(status_code=403, detail="Admin access required.")
    return current_user

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _generate_join_code(length: int = 6) -> str:
    alphabet = string.ascii_uppercase + string.digits
    return "".join(secrets.choice(alphabet) for _ in range(length))

def _slugify(name: str) -> str:
    return name.lower().replace(" ", "-").replace("_", "-").strip("-")[:48]

def _user_to_dict(user_row: dict) -> dict:
    return {
        "id": user_row["id"],
        "email": user_row["email"],
        "full_name": user_row.get("full_name"),
        "phone": user_row.get("phone"),
        "role": user_row.get("role", "employee"),
        "avatar_url": user_row.get("avatar_url"),
        "contractor_profile_id": user_row.get("contractor_profile_id"),
    }

# ---------------------------------------------------------------------------
# POST /auth/register
# ---------------------------------------------------------------------------

@app.post("/auth/register", response_model=RegisterResponse, status_code=201)
async def register(body: RegisterRequest):
    if len(body.password) < 8:
        raise HTTPException(status_code=422, detail="Password must be at least 8 characters.")

    role = "PROPERTY_MANAGER" if body.organization_name else body.role.upper()

    # 1. Create auth user via Supabase Auth
    try:
        auth_resp = supabase.auth.admin.create_user({
            "email": body.email,
            "password": body.password,
            "email_confirm": True,
            "user_metadata": {"full_name": body.full_name, "role": role}
        })
    except Exception as e:
        msg = str(e)
        if "already registered" in msg.lower() or "already exists" in msg.lower():
            raise HTTPException(status_code=409, detail="An account with that email already exists.")
        raise HTTPException(status_code=500, detail=f"Failed to create auth user: {msg}")

    auth_user = auth_resp.user
    user_id = auth_user.id

    # 2. Upsert into public.users
    now = datetime.now(timezone.utc).isoformat()
    user_row = {
        "id": user_id,
        "email": body.email,
        "full_name": body.full_name.strip(),
        "phone": body.phone,
        "role": role.upper(),
        "created_at": now,
        "updated_at": now,
    }
    supabase.table("users").upsert(user_row).execute()

    # 3. Create organization if requested
    if body.organization_name:
        base_slug = _slugify(body.organization_name)
        slug = base_slug
        suffix = 1
        while True:
            slug_check = supabase.table("organizations").select("id").eq("slug", slug).execute()
            if not slug_check.data:
                break
            slug = f"{base_slug}-{suffix}"
            suffix += 1

        org_result = supabase.table("organizations").insert({
            "id": str(uuid.uuid4()),
            "name": body.organization_name.strip(),
            "slug": slug,
            "join_code": _generate_join_code(),
            "join_code_enabled": True,
            "chat_mode": "standard",
            "is_active": True,
            "created_at": now,
            "updated_at": now,
        }).execute()

        if not org_result.data:
            raise HTTPException(status_code=500, detail="Failed to create organization.")

        org_id = org_result.data[0]["id"]

        try:
            member_result = supabase.table("organization_members").insert({
                "id": str(uuid.uuid4()),
                "organization_id": org_id,
                "user_id": user_id,
                "role": role.lower(),
                "is_active": True,
                "joined_at": now,
            }).execute()
            print(f"[register] org_member insert: {member_result.data}")
        except Exception as e:
            print(f"[register] org_member insert FAILED: {e}")
            raise HTTPException(status_code=500, detail=f"Failed to create org member: {str(e)}")

        update_result = supabase.table("users").update({"organization_id": org_id}).eq("id", user_id).execute()
        print(f"[register] users update: {update_result.data}")
        user_row["organization_id"] = org_id

    # 4. Sign in to get real Supabase tokens
    try:
        sign_in = supabase.auth.sign_in_with_password({
            "email": body.email,
            "password": body.password
        })
        access_token = sign_in.session.access_token
        refresh_token = sign_in.session.refresh_token
    except Exception:
        raise HTTPException(status_code=500, detail="Account created but could not issue session.")

    return RegisterResponse(
        access_token=access_token,
        refresh_token=refresh_token,
        user=_user_to_dict(user_row)
    )

# ---------------------------------------------------------------------------
# POST /organizations/join
# ---------------------------------------------------------------------------

@app.post("/organizations/join", response_model=JoinOrganizationResponse)
async def join_organization(body: JoinOrganizationRequest, current_user: dict = Depends(get_current_user)):
    code = body.join_code.strip().upper()
    org_result = supabase.table("organizations").select("*").eq("join_code", code).eq("join_code_enabled", True).execute()
    if not org_result.data:
        raise HTTPException(status_code=404, detail="That code doesn't match any active organization.")

    org = org_result.data[0]
    org_id = org["id"]
    user_id = current_user["id"]

    existing = supabase.table("organization_members").select("id").eq("organization_id", org_id).eq("user_id", user_id).execute()
    if existing.data:
        raise HTTPException(status_code=409, detail="You're already a member of this organization.")

    now = datetime.now(timezone.utc).isoformat()
    supabase.table("organization_members").insert({
        "organization_id": org_id,
        "user_id": user_id,
        "role": current_user.get("role", "employee"),
        "is_active": True,
        "joined_at": now,
    }).execute()

    supabase.table("users").update({"organization_id": org_id, "updated_at": now}).eq("id", user_id).execute()

    return JoinOrganizationResponse(
        organization_name=org["name"],
        organization_slug=org["slug"],
        role=current_user.get("role", "EMPLOYEE"),
        message=f"You've successfully joined {org['name']}.",
    )

# ---------------------------------------------------------------------------
# GET /admin/organization
# ---------------------------------------------------------------------------

@app.get("/admin/organization", response_model=OrganizationDetail)
async def get_organization(admin: dict = Depends(require_admin)):
    org_id = admin.get("organization_id")
    if not org_id:
        raise HTTPException(status_code=404, detail="No organization found for this account.")

    org = supabase.table("organizations").select("*").eq("id", org_id).single().execute()
    if not org.data:
        raise HTTPException(status_code=404, detail="Organization not found.")

    count_result = supabase.table("organization_members").select("id", count="exact").eq("organization_id", org_id).eq("is_active", True).execute()
    member_count = count_result.count or 0
    d = org.data

    return OrganizationDetail(
        id=d["id"], name=d["name"], slug=d["slug"],
        join_code=d["join_code"], join_code_enabled=d.get("join_code_enabled", True),
        chat_mode=d.get("chat_mode", "standard"), plan_tier=d.get("plan_tier"),
        member_count=member_count, created_at=str(d["created_at"])
    )

# ---------------------------------------------------------------------------
# PATCH /admin/organization
# ---------------------------------------------------------------------------

@app.patch("/admin/organization", response_model=OrganizationDetail)
async def update_organization(body: UpdateOrganizationRequest, admin: dict = Depends(require_admin)):
    org_id = admin.get("organization_id")
    if not org_id:
        raise HTTPException(status_code=404, detail="No organization found.")
    updates: dict = {}
    if body.name is not None: updates["name"] = body.name.strip()
    if body.chat_mode is not None:
        if body.chat_mode not in ("standard", "advanced", "off"):
            raise HTTPException(status_code=422, detail="Invalid chat_mode.")
        updates["chat_mode"] = body.chat_mode
    if body.join_code_enabled is not None: updates["join_code_enabled"] = body.join_code_enabled
    if updates:
        updates["updated_at"] = datetime.now(timezone.utc).isoformat()
        supabase.table("organizations").update(updates).eq("id", org_id).execute()
    return await get_organization(admin)

# ---------------------------------------------------------------------------
# POST /admin/organization/regenerate-join-code
# ---------------------------------------------------------------------------

@app.post("/admin/organization/regenerate-join-code", response_model=RegenerateJoinCodeResponse)
async def regenerate_join_code(admin: dict = Depends(require_admin)):
    org_id = admin.get("organization_id")
    if not org_id:
        raise HTTPException(status_code=404, detail="No organization found.")
    new_code = _generate_join_code()
    supabase.table("organizations").update({"join_code": new_code, "updated_at": datetime.now(timezone.utc).isoformat()}).eq("id", org_id).execute()
    return RegenerateJoinCodeResponse(join_code=new_code)

# ---------------------------------------------------------------------------
# GET /admin/members
# ---------------------------------------------------------------------------

@app.get("/admin/members", response_model=MemberListResponse)
async def list_members(admin: dict = Depends(require_admin)):
    org_id = admin.get("organization_id")
    if not org_id:
        raise HTTPException(status_code=404, detail="No organization found.")
    memberships = supabase.table("organization_members").select("*, users(id, email, full_name, phone, role)").eq("organization_id", org_id).order("joined_at", desc=False).execute()
    members = []
    for m in memberships.data or []:
        u = m.get("users") or {}
        members.append(MemberItem(
            id=u.get("id", m["user_id"]), email=u.get("email", ""),
            full_name=u.get("full_name"), role=m.get("role", u.get("role", "employee")),
            phone=u.get("phone"), is_active=m.get("is_active", True), joined_at=m.get("joined_at", "")
        ))
    return MemberListResponse(members=members, total=len(members))

# ---------------------------------------------------------------------------
# PATCH /admin/members/{member_id}
# ---------------------------------------------------------------------------

@app.patch("/admin/members/{member_id}", response_model=MemberItem)
async def update_member(member_id: str, body: UpdateMemberRequest, admin: dict = Depends(require_admin)):
    org_id = admin.get("organization_id")
    membership = supabase.table("organization_members").select("*, users(id, email, full_name, phone, role)").eq("organization_id", org_id).eq("user_id", member_id).single().execute()
    if not membership.data:
        raise HTTPException(status_code=404, detail="Member not found.")
    updates: dict = {}
    if body.role is not None:
        if body.role not in ("property_manager", "contractor", "employee"):
            raise HTTPException(status_code=422, detail="Invalid role.")
        updates["role"] = body.role
    if body.is_active is not None:
        updates["is_active"] = body.is_active
    if updates:
        supabase.table("organization_members").update(updates).eq("organization_id", org_id).eq("user_id", member_id).execute()
        if body.role:
            supabase.table("users").update({"role": body.role, "updated_at": datetime.now(timezone.utc).isoformat()}).eq("id", member_id).execute()
    updated = supabase.table("organization_members").select("*, users(id, email, full_name, phone, role)").eq("organization_id", org_id).eq("user_id", member_id).single().execute()
    m = updated.data
    u = m.get("users") or {}
    return MemberItem(id=u.get("id", member_id), email=u.get("email", ""), full_name=u.get("full_name"),
                      role=m.get("role", u.get("role", "employee")), phone=u.get("phone"),
                      is_active=m.get("is_active", True), joined_at=m.get("joined_at", ""))

# ---------------------------------------------------------------------------
# Health
# ---------------------------------------------------------------------------

@app.get("/health")
async def health():
    return {"status": "ok", "service": "con-gusto-accounts"}

if __name__ == "__main__":
    uvicorn.run("con_gusto_accounts_api:app", host="0.0.0.0", port=8001, reload=True)
