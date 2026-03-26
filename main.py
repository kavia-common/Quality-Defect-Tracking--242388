import os
from datetime import datetime, timedelta, timezone
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple
from uuid import UUID, uuid4

import jwt
from fastapi import (
    Depends,
    FastAPI,
    File,
    Form,
    HTTPException,
    Query,
    Request,
    Response,
    UploadFile,
)
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import OAuth2PasswordBearer
from passlib.context import CryptContext
from pydantic import BaseModel, Field
from sqlalchemy import (
    Boolean,
    CheckConstraint,
    Column,
    Date,
    DateTime,
    ForeignKey,
    Index,
    Integer,
    Table,
    Text,
    UniqueConstraint,
    and_,
    create_engine,
    desc,
    func,
    or_,
    select,
)
from sqlalchemy.dialects.postgresql import ARRAY, INET, JSONB, UUID as PGUUID
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import DeclarativeBase, Mapped, Session, mapped_column, relationship, sessionmaker

# --------------------------------------------------------------------------------------
# App metadata / OpenAPI tags
# --------------------------------------------------------------------------------------

openapi_tags = [
    {"name": "Health", "description": "Service health check."},
    {"name": "Auth", "description": "Authentication and authorization (JWT) endpoints."},
    {"name": "Users", "description": "User and role management endpoints."},
    {"name": "Config", "description": "Configuration endpoints (defect types, rules, lines, shifts)."},
    {"name": "Defects", "description": "Defect CRUD, optional photo upload, and severity classification."},
    {"name": "RCA", "description": "Root cause analysis capture workflows (5-Why and Fishbone)."},
    {"name": "Actions", "description": "Corrective actions assignment, status updates, and overdue logic."},
    {"name": "Dashboard", "description": "Aggregated metrics for dashboards (overdue, Pareto, trends)."},
    {"name": "Audit", "description": "Audit trail for changes across entities."},
    {"name": "Export", "description": "Export endpoints (CSV/PDF) for reporting and compliance."},
]


app = FastAPI(
    title="Manufacturing Defect Management API",
    description=(
        "Backend APIs for defect logging, severity classification, RCA capture, corrective actions, "
        "dashboard aggregations, audit logging, and export.\n\n"
        "Notes:\n"
        "- Database is PostgreSQL (expected preview port 5001).\n"
        "- Auth is JWT bearer; include `Authorization: Bearer <token>`.\n"
    ),
    version="0.2.0",
    openapi_tags=openapi_tags,
)

# --------------------------------------------------------------------------------------
# CORS
# --------------------------------------------------------------------------------------

cors_allow_origins = os.getenv("CORS_ALLOW_ORIGINS", "*")
allow_origins = ["*"] if cors_allow_origins.strip() == "*" else [o.strip() for o in cors_allow_origins.split(",") if o.strip()]

app.add_middleware(
    CORSMiddleware,
    allow_origins=allow_origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# --------------------------------------------------------------------------------------
# Configuration / DB
# --------------------------------------------------------------------------------------

DATABASE_URL = os.getenv("DATABASE_URL", "postgresql+psycopg://appuser:dbuser123@localhost:5001/myapp")
UPLOAD_DIR = Path(os.getenv("UPLOAD_DIR", "./uploads"))
MAX_UPLOAD_MB = int(os.getenv("MAX_UPLOAD_MB", "10"))

JWT_SECRET = os.getenv("JWT_SECRET", "change_me")  # NOTE: should be set via environment in real deployments.
JWT_ALGORITHM = os.getenv("JWT_ALGORITHM", "HS256")
ACCESS_TOKEN_EXPIRE_MINUTES = int(os.getenv("ACCESS_TOKEN_EXPIRE_MINUTES", "480"))

UPLOAD_DIR.mkdir(parents=True, exist_ok=True)

engine = create_engine(DATABASE_URL, pool_pre_ping=True)
SessionLocal = sessionmaker(bind=engine, autoflush=False, autocommit=False)


# PUBLIC_INTERFACE
def get_db() -> Session:
    """FastAPI dependency that provides a SQLAlchemy session and ensures it is closed."""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


# --------------------------------------------------------------------------------------
# SQLAlchemy models
# --------------------------------------------------------------------------------------


class Base(DeclarativeBase):
    pass


class Severity(str, Enum):
    critical = "Critical"
    major = "Major"
    minor = "Minor"


class DefectStatus(str, Enum):
    open = "Open"
    in_review = "In Review"
    closed = "Closed"


class RcaMethod(str, Enum):
    five_why = "5-Why"
    fishbone = "Fishbone"


class ActionStatus(str, Enum):
    open = "Open"
    in_progress = "In Progress"
    done = "Done"
    cancelled = "Cancelled"
    overdue = "Overdue"


user_roles_table = Table(
    "user_roles",
    Base.metadata,
    Column("user_id", PGUUID(as_uuid=True), ForeignKey("users.id", ondelete="CASCADE"), primary_key=True),
    Column("role_id", PGUUID(as_uuid=True), ForeignKey("roles.id", ondelete="CASCADE"), primary_key=True),
)


class User(Base):
    __tablename__ = "users"

    id: Mapped[UUID] = mapped_column(PGUUID(as_uuid=True), primary_key=True, default=uuid4)
    email: Mapped[str] = mapped_column(Text, unique=True, index=True, nullable=False)
    full_name: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    password_hash: Mapped[str] = mapped_column(Text, nullable=False)
    is_active: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)

    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=lambda: datetime.now(timezone.utc))
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=lambda: datetime.now(timezone.utc))

    roles: Mapped[List["Role"]] = relationship("Role", secondary=user_roles_table, back_populates="users")


class Role(Base):
    __tablename__ = "roles"

    id: Mapped[UUID] = mapped_column(PGUUID(as_uuid=True), primary_key=True, default=uuid4)
    name: Mapped[str] = mapped_column(Text, unique=True, nullable=False, index=True)
    description: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=lambda: datetime.now(timezone.utc))

    users: Mapped[List[User]] = relationship("User", secondary=user_roles_table, back_populates="roles")


class ProductionLine(Base):
    __tablename__ = "production_lines"
    id: Mapped[UUID] = mapped_column(PGUUID(as_uuid=True), primary_key=True, default=uuid4)
    code: Mapped[str] = mapped_column(Text, unique=True, nullable=False)
    name: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    is_active: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=lambda: datetime.now(timezone.utc))


class Shift(Base):
    __tablename__ = "shifts"
    id: Mapped[UUID] = mapped_column(PGUUID(as_uuid=True), primary_key=True, default=uuid4)
    code: Mapped[str] = mapped_column(Text, unique=True, nullable=False)
    name: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    start_time: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    end_time: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=lambda: datetime.now(timezone.utc))


class DefectType(Base):
    __tablename__ = "defect_types"
    id: Mapped[UUID] = mapped_column(PGUUID(as_uuid=True), primary_key=True, default=uuid4)
    code: Mapped[str] = mapped_column(Text, unique=True, nullable=False)
    name: Mapped[str] = mapped_column(Text, nullable=False)
    default_severity: Mapped[str] = mapped_column(Text, nullable=False, default=Severity.minor.value)
    is_active: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=lambda: datetime.now(timezone.utc))


class SeverityRule(Base):
    __tablename__ = "severity_rules"
    id: Mapped[UUID] = mapped_column(PGUUID(as_uuid=True), primary_key=True, default=uuid4)
    defect_type_id: Mapped[UUID] = mapped_column(PGUUID(as_uuid=True), ForeignKey("defect_types.id", ondelete="CASCADE"), nullable=False)
    rule_json: Mapped[Dict[str, Any]] = mapped_column(JSONB, nullable=False, default=dict)
    severity: Mapped[str] = mapped_column(Text, nullable=False)
    is_active: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=lambda: datetime.now(timezone.utc))

    defect_type: Mapped[DefectType] = relationship("DefectType")


class Defect(Base):
    __tablename__ = "defects"
    __table_args__ = (
        UniqueConstraint("defect_number", name="uq_defects_defect_number"),
        Index("idx_defects_occurred_at", "occurred_at"),
        Index("idx_defects_type", "defect_type_id"),
        CheckConstraint("quantity_affected >= 0", name="ck_defects_quantity_nonneg"),
    )

    id: Mapped[UUID] = mapped_column(PGUUID(as_uuid=True), primary_key=True, default=uuid4)
    defect_number: Mapped[str] = mapped_column(Text, nullable=False, unique=True, index=True)

    occurred_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=lambda: datetime.now(timezone.utc))
    part_number: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    description: Mapped[Optional[str]] = mapped_column(Text, nullable=True)

    defect_type_id: Mapped[Optional[UUID]] = mapped_column(PGUUID(as_uuid=True), ForeignKey("defect_types.id"), nullable=True)
    production_line_id: Mapped[Optional[UUID]] = mapped_column(PGUUID(as_uuid=True), ForeignKey("production_lines.id"), nullable=True)
    shift_id: Mapped[Optional[UUID]] = mapped_column(PGUUID(as_uuid=True), ForeignKey("shifts.id"), nullable=True)

    quantity_affected: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    severity: Mapped[str] = mapped_column(Text, nullable=False, default=Severity.minor.value)
    status: Mapped[str] = mapped_column(Text, nullable=False, default=DefectStatus.open.value)

    reported_by_user_id: Mapped[Optional[UUID]] = mapped_column(PGUUID(as_uuid=True), ForeignKey("users.id"), nullable=True)

    tags: Mapped[Optional[List[str]]] = mapped_column(ARRAY(Text), nullable=True)
    extra: Mapped[Dict[str, Any]] = mapped_column(JSONB, nullable=False, default=dict)

    photo_path: Mapped[Optional[str]] = mapped_column(Text, nullable=True)

    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=lambda: datetime.now(timezone.utc))
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=lambda: datetime.now(timezone.utc))

    defect_type: Mapped[Optional[DefectType]] = relationship("DefectType")
    production_line: Mapped[Optional[ProductionLine]] = relationship("ProductionLine")
    shift: Mapped[Optional[Shift]] = relationship("Shift")
    reported_by: Mapped[Optional[User]] = relationship("User")

    rca: Mapped[Optional["DefectRca"]] = relationship("DefectRca", back_populates="defect", uselist=False)
    actions: Mapped[List["CorrectiveAction"]] = relationship("CorrectiveAction", back_populates="defect")


class DefectRca(Base):
    __tablename__ = "defect_rca"
    __table_args__ = (UniqueConstraint("defect_id", name="uq_defect_rca_defect_id"),)

    id: Mapped[UUID] = mapped_column(PGUUID(as_uuid=True), primary_key=True, default=uuid4)
    defect_id: Mapped[UUID] = mapped_column(PGUUID(as_uuid=True), ForeignKey("defects.id", ondelete="CASCADE"), nullable=False)

    method: Mapped[str] = mapped_column(Text, nullable=False)
    five_whys: Mapped[Optional[Dict[str, Any]]] = mapped_column(JSONB, nullable=True)
    fishbone: Mapped[Optional[Dict[str, Any]]] = mapped_column(JSONB, nullable=True)
    conclusion: Mapped[Optional[str]] = mapped_column(Text, nullable=True)

    created_by_user_id: Mapped[Optional[UUID]] = mapped_column(PGUUID(as_uuid=True), ForeignKey("users.id"), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=lambda: datetime.now(timezone.utc))
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=lambda: datetime.now(timezone.utc))

    defect: Mapped[Defect] = relationship("Defect", back_populates="rca")
    created_by: Mapped[Optional[User]] = relationship("User")


class CorrectiveAction(Base):
    __tablename__ = "corrective_actions"
    __table_args__ = (Index("idx_corrective_actions_due_status", "due_date", "status"),)

    id: Mapped[UUID] = mapped_column(PGUUID(as_uuid=True), primary_key=True, default=uuid4)
    defect_id: Mapped[UUID] = mapped_column(PGUUID(as_uuid=True), ForeignKey("defects.id", ondelete="CASCADE"), nullable=False)

    title: Mapped[str] = mapped_column(Text, nullable=False)
    description: Mapped[Optional[str]] = mapped_column(Text, nullable=True)

    assignee_user_id: Mapped[Optional[UUID]] = mapped_column(PGUUID(as_uuid=True), ForeignKey("users.id"), nullable=True)
    due_date: Mapped[Optional[datetime]] = mapped_column(Date, nullable=True)

    status: Mapped[str] = mapped_column(Text, nullable=False, default=ActionStatus.open.value)
    completed_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)

    created_by_user_id: Mapped[Optional[UUID]] = mapped_column(PGUUID(as_uuid=True), ForeignKey("users.id"), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=lambda: datetime.now(timezone.utc))
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=lambda: datetime.now(timezone.utc))

    defect: Mapped[Defect] = relationship("Defect", back_populates="actions")
    assignee: Mapped[Optional[User]] = relationship("User", foreign_keys=[assignee_user_id])
    created_by: Mapped[Optional[User]] = relationship("User", foreign_keys=[created_by_user_id])


class Attachment(Base):
    __tablename__ = "attachments"
    __table_args__ = (
        CheckConstraint(
            "(defect_id IS NOT NULL AND corrective_action_id IS NULL) OR (defect_id IS NULL AND corrective_action_id IS NOT NULL)",
            name="ck_attachment_one_parent",
        ),
    )

    id: Mapped[UUID] = mapped_column(PGUUID(as_uuid=True), primary_key=True, default=uuid4)
    defect_id: Mapped[Optional[UUID]] = mapped_column(PGUUID(as_uuid=True), ForeignKey("defects.id", ondelete="CASCADE"), nullable=True)
    corrective_action_id: Mapped[Optional[UUID]] = mapped_column(
        PGUUID(as_uuid=True), ForeignKey("corrective_actions.id", ondelete="CASCADE"), nullable=True
    )

    file_name: Mapped[str] = mapped_column(Text, nullable=False)
    mime_type: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    file_size_bytes: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    storage_path: Mapped[str] = mapped_column(Text, nullable=False)

    uploaded_by_user_id: Mapped[Optional[UUID]] = mapped_column(PGUUID(as_uuid=True), ForeignKey("users.id"), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=lambda: datetime.now(timezone.utc))


class AuditLog(Base):
    __tablename__ = "audit_log"
    id: Mapped[UUID] = mapped_column(PGUUID(as_uuid=True), primary_key=True, default=uuid4)
    entity_type: Mapped[str] = mapped_column(Text, nullable=False)
    entity_id: Mapped[UUID] = mapped_column(PGUUID(as_uuid=True), nullable=False)
    action: Mapped[str] = mapped_column(Text, nullable=False)
    actor_user_id: Mapped[Optional[UUID]] = mapped_column(PGUUID(as_uuid=True), ForeignKey("users.id"), nullable=True)

    before_state: Mapped[Optional[Dict[str, Any]]] = mapped_column(JSONB, nullable=True)
    after_state: Mapped[Optional[Dict[str, Any]]] = mapped_column(JSONB, nullable=True)

    ip_address: Mapped[Optional[str]] = mapped_column(INET, nullable=True)
    user_agent: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=lambda: datetime.now(timezone.utc))


# --------------------------------------------------------------------------------------
# Auth helpers
# --------------------------------------------------------------------------------------

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/auth/login")


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _hash_password(password: str) -> str:
    return pwd_context.hash(password)


def _verify_password(password: str, password_hash: str) -> bool:
    return pwd_context.verify(password, password_hash)


def _create_access_token(subject_user_id: str, roles: List[str]) -> str:
    expire = _utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    payload = {"sub": subject_user_id, "roles": roles, "exp": expire}
    return jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGORITHM)


# PUBLIC_INTERFACE
def require_roles(required_roles: List[str]):
    """Dependency factory enforcing that the current user has at least one of the required roles."""

    def _dep(current_user: "UserContext" = Depends(get_current_user)) -> "UserContext":
        if not current_user.is_active:
            raise HTTPException(status_code=403, detail="Inactive user")
        if required_roles and not set(current_user.roles).intersection(set(required_roles)):
            raise HTTPException(status_code=403, detail="Insufficient role")
        return current_user

    return _dep


class UserContext(BaseModel):
    id: UUID
    email: str
    full_name: Optional[str] = None
    is_active: bool
    roles: List[str] = Field(default_factory=list)


# PUBLIC_INTERFACE
def get_current_user(token: str = Depends(oauth2_scheme), db: Session = Depends(get_db)) -> UserContext:
    """Parse JWT token and load user information for request context."""
    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
        user_id = payload.get("sub")
        if not user_id:
            raise HTTPException(status_code=401, detail="Invalid token")
    except jwt.ExpiredSignatureError as exc:
        raise HTTPException(status_code=401, detail="Token expired") from exc
    except jwt.PyJWTError as exc:
        raise HTTPException(status_code=401, detail="Invalid token") from exc

    user = db.get(User, UUID(user_id))
    if not user:
        raise HTTPException(status_code=401, detail="User not found")

    # Use roles from DB as source of truth (token roles are informational)
    db_roles = [r.name for r in user.roles]
    return UserContext(id=user.id, email=user.email, full_name=user.full_name, is_active=user.is_active, roles=db_roles)


def _ensure_schema(db: Session) -> None:
    """Create tables if missing (simple bootstrap; migrations recommended for production)."""
    Base.metadata.create_all(bind=engine)

    # Seed roles
    existing_roles = set(db.scalars(select(Role.name)).all())
    for role_name in ["operator", "engineer", "manager", "admin"]:
        if role_name not in existing_roles:
            db.add(Role(name=role_name, description=f"Seeded role: {role_name}"))

    # Seed shifts if empty
    shifts_count = db.scalar(select(func.count()).select_from(Shift)) or 0
    if shifts_count == 0:
        db.add_all(
            [
                Shift(code="A", name="Shift A", start_time="06:00", end_time="14:00"),
                Shift(code="B", name="Shift B", start_time="14:00", end_time="22:00"),
                Shift(code="C", name="Shift C", start_time="22:00", end_time="06:00"),
            ]
        )
    db.commit()


@app.on_event("startup")
def _startup() -> None:
    # Ensure schema exists at service start
    with SessionLocal() as db:
        _ensure_schema(db)


# --------------------------------------------------------------------------------------
# Audit logging
# --------------------------------------------------------------------------------------


def _client_ip(request: Request) -> Optional[str]:
    # Try common reverse-proxy headers first; fallback to socket client host.
    xff = request.headers.get("x-forwarded-for")
    if xff:
        return xff.split(",")[0].strip()
    if request.client:
        return request.client.host
    return None


def _audit(
    db: Session,
    *,
    request: Request,
    entity_type: str,
    entity_id: UUID,
    action: str,
    actor_user_id: Optional[UUID],
    before_state: Optional[Dict[str, Any]],
    after_state: Optional[Dict[str, Any]],
) -> None:
    db.add(
        AuditLog(
            entity_type=entity_type,
            entity_id=entity_id,
            action=action,
            actor_user_id=actor_user_id,
            before_state=before_state,
            after_state=after_state,
            ip_address=_client_ip(request),
            user_agent=request.headers.get("user-agent"),
        )
    )


def _model_to_dict(obj: Any, fields: Optional[List[str]] = None) -> Dict[str, Any]:
    """Convert ORM object to JSON-serializable dict for audit logging (best-effort)."""
    if obj is None:
        return {}
    data: Dict[str, Any] = {}
    for col in obj.__table__.columns:  # type: ignore[attr-defined]
        if fields and col.name not in fields:
            continue
        val = getattr(obj, col.name)
        if isinstance(val, UUID):
            data[col.name] = str(val)
        elif isinstance(val, datetime):
            data[col.name] = val.isoformat()
        else:
            data[col.name] = val
    return data


# --------------------------------------------------------------------------------------
# Severity evaluation rules
# --------------------------------------------------------------------------------------


def _evaluate_rule(rule_json: Dict[str, Any], defect: Dict[str, Any]) -> bool:
    """
    Very small rule evaluator.
    Supported:
      - {"all": [cond, ...]} / {"any": [cond, ...]}
      - cond: {"field":"quantity_affected","op":">=","value":10}
      - op in: ==, !=, >, >=, <, <=, in
    """
    if not rule_json:
        return False

    if "all" in rule_json:
        return all(_evaluate_rule(item, defect) for item in rule_json["all"])
    if "any" in rule_json:
        return any(_evaluate_rule(item, defect) for item in rule_json["any"])

    field = rule_json.get("field")
    op = rule_json.get("op")
    value = rule_json.get("value")
    if field is None or op is None:
        return False

    left = defect.get(field)
    if op == "==":
        return left == value
    if op == "!=":
        return left != value
    if op == ">":
        return left is not None and left > value
    if op == ">=":
        return left is not None and left >= value
    if op == "<":
        return left is not None and left < value
    if op == "<=":
        return left is not None and left <= value
    if op == "in":
        return left in (value or [])
    return False


def _compute_severity(db: Session, *, defect_type_id: Optional[UUID], quantity_affected: int, manual: Optional[str]) -> Tuple[str, str]:
    """
    Compute severity: manual overrides rules; otherwise first matching active rule; otherwise defect type default.
    Returns (severity, source) where source in {"manual","rule","default"}.
    """
    if manual:
        return manual, "manual"

    if defect_type_id:
        rules = db.scalars(
            select(SeverityRule).where(and_(SeverityRule.defect_type_id == defect_type_id, SeverityRule.is_active.is_(True))).order_by(
                SeverityRule.created_at.asc()
            )
        ).all()
        defect_ctx = {"quantity_affected": quantity_affected}
        for r in rules:
            if _evaluate_rule(r.rule_json, defect_ctx):
                return r.severity, "rule"

        dt = db.get(DefectType, defect_type_id)
        if dt:
            return dt.default_severity, "default"

    return Severity.minor.value, "default"


def _update_overdue_actions(db: Session) -> None:
    """Set status=Overdue for actions past due that are not done/cancelled."""
    today = datetime.now(timezone.utc).date()
    actions = db.scalars(
        select(CorrectiveAction).where(
            and_(
                CorrectiveAction.due_date.is_not(None),
                CorrectiveAction.due_date < today,
                CorrectiveAction.status.notin_([ActionStatus.done.value, ActionStatus.cancelled.value]),
            )
        )
    ).all()
    for a in actions:
        a.status = ActionStatus.overdue.value
        a.updated_at = _utcnow()


# --------------------------------------------------------------------------------------
# Pydantic schemas
# --------------------------------------------------------------------------------------


class TokenResponse(BaseModel):
    access_token: str = Field(..., description="JWT access token")
    token_type: str = Field("bearer", description="Token type (always 'bearer')")


class RegisterRequest(BaseModel):
    email: str = Field(..., description="User email (unique)")
    full_name: Optional[str] = Field(None, description="Full name")
    password: str = Field(..., min_length=8, description="Plaintext password (min length 8)")
    roles: List[str] = Field(default_factory=list, description="Role names (admin only). If empty, defaults to operator.")


class LoginRequest(BaseModel):
    email: str = Field(..., description="Email")
    password: str = Field(..., description="Password")


class UserResponse(BaseModel):
    id: UUID
    email: str
    full_name: Optional[str] = None
    is_active: bool
    roles: List[str] = Field(default_factory=list)


class DefectCreate(BaseModel):
    occurred_at: Optional[datetime] = Field(None, description="When the defect occurred (defaults to now)")
    part_number: Optional[str] = Field(None, description="Part number")
    description: Optional[str] = Field(None, description="Description")
    defect_type_id: Optional[UUID] = Field(None, description="Defect type id")
    production_line_id: Optional[UUID] = Field(None, description="Production line id")
    shift_id: Optional[UUID] = Field(None, description="Shift id")
    quantity_affected: int = Field(0, ge=0, description="Quantity affected (>=0)")
    severity_manual: Optional[str] = Field(None, description="Manual severity override (Critical/Major/Minor)")
    tags: Optional[List[str]] = Field(None, description="Tags")
    extra: Dict[str, Any] = Field(default_factory=dict, description="Additional data (JSON)")


class DefectUpdate(BaseModel):
    occurred_at: Optional[datetime] = None
    part_number: Optional[str] = None
    description: Optional[str] = None
    defect_type_id: Optional[UUID] = None
    production_line_id: Optional[UUID] = None
    shift_id: Optional[UUID] = None
    quantity_affected: Optional[int] = Field(None, ge=0)
    severity_manual: Optional[str] = None
    status: Optional[str] = None
    tags: Optional[List[str]] = None
    extra: Optional[Dict[str, Any]] = None


class DefectResponse(BaseModel):
    id: UUID
    defect_number: str
    occurred_at: datetime
    part_number: Optional[str] = None
    description: Optional[str] = None
    defect_type_id: Optional[UUID] = None
    production_line_id: Optional[UUID] = None
    shift_id: Optional[UUID] = None
    quantity_affected: int
    severity: str
    status: str
    reported_by_user_id: Optional[UUID] = None
    tags: Optional[List[str]] = None
    extra: Dict[str, Any]
    photo_path: Optional[str] = None
    created_at: datetime
    updated_at: datetime


class RcaUpsert(BaseModel):
    method: str = Field(..., description="RCA method: '5-Why' or 'Fishbone'")
    five_whys: Optional[Dict[str, Any]] = Field(None, description="JSON structure containing 5-Why answers")
    fishbone: Optional[Dict[str, Any]] = Field(None, description="JSON structure containing fishbone categories/causes")
    conclusion: Optional[str] = Field(None, description="RCA conclusion")


class RcaResponse(BaseModel):
    id: UUID
    defect_id: UUID
    method: str
    five_whys: Optional[Dict[str, Any]] = None
    fishbone: Optional[Dict[str, Any]] = None
    conclusion: Optional[str] = None
    created_by_user_id: Optional[UUID] = None
    created_at: datetime
    updated_at: datetime


class CorrectiveActionCreate(BaseModel):
    defect_id: UUID
    title: str = Field(..., description="Action title")
    description: Optional[str] = Field(None, description="Action description")
    assignee_user_id: Optional[UUID] = Field(None, description="Assignee user id")
    due_date: Optional[datetime] = Field(None, description="Due date (date only is used)")
    status: Optional[str] = Field(None, description="Initial status (Open/In Progress/Done/Cancelled)")


class CorrectiveActionUpdate(BaseModel):
    title: Optional[str] = None
    description: Optional[str] = None
    assignee_user_id: Optional[UUID] = None
    due_date: Optional[datetime] = None
    status: Optional[str] = None


class CorrectiveActionResponse(BaseModel):
    id: UUID
    defect_id: UUID
    title: str
    description: Optional[str] = None
    assignee_user_id: Optional[UUID] = None
    due_date: Optional[datetime] = None
    status: str
    completed_at: Optional[datetime] = None
    created_by_user_id: Optional[UUID] = None
    created_at: datetime
    updated_at: datetime


class DashboardOverdueResponse(BaseModel):
    overdue_actions: int
    overdue_by_assignee: List[Dict[str, Any]]


class ParetoItem(BaseModel):
    defect_type_code: str
    defect_type_name: str
    count: int


class TrendPoint(BaseModel):
    period: str
    count: int
    critical: int
    major: int
    minor: int


# --------------------------------------------------------------------------------------
# Health + docs help
# --------------------------------------------------------------------------------------


@app.get("/", tags=["Health"], summary="Health check")
def health_check() -> Dict[str, str]:
    """Return a basic health response."""
    return {"message": "Healthy"}


@app.get("/docs/help", tags=["Health"], summary="API usage help")
def docs_help() -> Dict[str, Any]:
    """Provide quick usage notes for authentication and key workflows."""
    return {
        "auth": {
            "login": "POST /auth/login with {email,password} to obtain a JWT token",
            "header": "Use Authorization: Bearer <token> for protected endpoints",
        },
        "workflows": {
            "defect_with_photo": "POST /defects with multipart/form-data including optional photo",
            "rca_capture": "PUT /defects/{id}/rca to set 5-Why or Fishbone",
            "actions": "POST /actions to assign, PATCH /actions/{id} to update status/due date",
        },
        "database": {"expected_postgres_port": 5001, "database_url_env": "DATABASE_URL"},
    }


# --------------------------------------------------------------------------------------
# Auth endpoints
# --------------------------------------------------------------------------------------


@app.post("/auth/register", tags=["Auth"], summary="Register user", response_model=UserResponse)
def register_user(
    payload: RegisterRequest,
    request: Request,
    db: Session = Depends(get_db),
    current_user: Optional[UserContext] = Depends(lambda: None),
) -> UserResponse:
    """
    Register a new user.

    - If no users exist yet, the first user is created as admin automatically.
    - After bootstrap, only admins should assign roles; non-admin registration defaults to operator.
    """
    _ensure_schema(db)

    users_count = db.scalar(select(func.count()).select_from(User)) or 0
    is_bootstrap = users_count == 0

    roles_to_set = payload.roles or (["admin"] if is_bootstrap else ["operator"])

    # If not bootstrap, require admin to assign roles other than operator
    if not is_bootstrap and payload.roles:
        # Soft enforcement: if JWT is provided, validate roles; otherwise reject.
        auth_header = request.headers.get("authorization")
        if not auth_header:
            raise HTTPException(status_code=403, detail="Only admin can assign roles")
        try:
            token = auth_header.split(" ", 1)[1]
            ctx = get_current_user(token=token, db=db)
            if "admin" not in ctx.roles:
                raise HTTPException(status_code=403, detail="Only admin can assign roles")
        except IndexError as exc:
            raise HTTPException(status_code=401, detail="Invalid Authorization header") from exc

    role_objs = db.scalars(select(Role).where(Role.name.in_(roles_to_set))).all()
    if len(role_objs) != len(set(roles_to_set)):
        raise HTTPException(status_code=400, detail="One or more roles not found")

    user = User(email=payload.email.lower().strip(), full_name=payload.full_name, password_hash=_hash_password(payload.password))
    user.roles = role_objs
    db.add(user)
    try:
        db.commit()
    except IntegrityError as exc:
        db.rollback()
        raise HTTPException(status_code=409, detail="Email already registered") from exc

    _audit(
        db,
        request=request,
        entity_type="users",
        entity_id=user.id,
        action="create",
        actor_user_id=None,
        before_state=None,
        after_state=_model_to_dict(user),
    )
    db.commit()

    return UserResponse(id=user.id, email=user.email, full_name=user.full_name, is_active=user.is_active, roles=[r.name for r in user.roles])


@app.post("/auth/login", tags=["Auth"], summary="Login", response_model=TokenResponse)
def login(payload: LoginRequest, db: Session = Depends(get_db)) -> TokenResponse:
    """Authenticate a user and return a JWT bearer token."""
    _ensure_schema(db)

    user = db.scalar(select(User).where(User.email == payload.email.lower().strip()))
    if not user or not _verify_password(payload.password, user.password_hash):
        raise HTTPException(status_code=401, detail="Invalid credentials")
    if not user.is_active:
        raise HTTPException(status_code=403, detail="Inactive user")

    token = _create_access_token(str(user.id), [r.name for r in user.roles])
    return TokenResponse(access_token=token)


# --------------------------------------------------------------------------------------
# Users / roles (admin)
# --------------------------------------------------------------------------------------


@app.get("/users/me", tags=["Users"], summary="Get current user", response_model=UserResponse)
def get_me(current_user: UserContext = Depends(get_current_user)) -> UserResponse:
    """Return the authenticated user's profile."""
    return UserResponse(
        id=current_user.id,
        email=current_user.email,
        full_name=current_user.full_name,
        is_active=current_user.is_active,
        roles=current_user.roles,
    )


@app.get("/users", tags=["Users"], summary="List users", response_model=List[UserResponse], dependencies=[Depends(require_roles(["admin"]))])
def list_users(db: Session = Depends(get_db)) -> List[UserResponse]:
    """List users (admin only)."""
    users = db.scalars(select(User).order_by(User.created_at.desc())).all()
    return [UserResponse(id=u.id, email=u.email, full_name=u.full_name, is_active=u.is_active, roles=[r.name for r in u.roles]) for u in users]


@app.post("/users/{user_id}/roles", tags=["Users"], summary="Set roles for a user", dependencies=[Depends(require_roles(["admin"]))])
def set_user_roles(
    user_id: UUID,
    roles: List[str],
    request: Request,
    db: Session = Depends(get_db),
    current_user: UserContext = Depends(get_current_user),
) -> Dict[str, Any]:
    """Set role list for a user (admin only)."""
    user = db.get(User, user_id)
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    role_objs = db.scalars(select(Role).where(Role.name.in_(roles))).all()
    if len(role_objs) != len(set(roles)):
        raise HTTPException(status_code=400, detail="One or more roles not found")

    before = _model_to_dict(user)
    user.roles = role_objs
    user.updated_at = _utcnow()
    db.commit()

    _audit(
        db,
        request=request,
        entity_type="users",
        entity_id=user.id,
        action="set_roles",
        actor_user_id=current_user.id,
        before_state=before,
        after_state=_model_to_dict(user),
    )
    db.commit()

    return {"user_id": str(user.id), "roles": [r.name for r in user.roles]}


# --------------------------------------------------------------------------------------
# Config endpoints (basic)
# --------------------------------------------------------------------------------------


@app.get("/config/defect-types", tags=["Config"], summary="List defect types")
def list_defect_types(db: Session = Depends(get_db), _: UserContext = Depends(get_current_user)) -> List[Dict[str, Any]]:
    """List defect types."""
    items = db.scalars(select(DefectType).where(DefectType.is_active.is_(True)).order_by(DefectType.code.asc())).all()
    return [{"id": str(i.id), "code": i.code, "name": i.name, "default_severity": i.default_severity} for i in items]


@app.post("/config/defect-types", tags=["Config"], summary="Create defect type", dependencies=[Depends(require_roles(["engineer", "manager", "admin"]))])
def create_defect_type(
    code: str = Form(...),
    name: str = Form(...),
    default_severity: str = Form(Severity.minor.value),
    request: Request = None,  # type: ignore[assignment]
    db: Session = Depends(get_db),
    current_user: UserContext = Depends(get_current_user),
) -> Dict[str, Any]:
    """Create a defect type."""
    dt = DefectType(code=code.strip(), name=name.strip(), default_severity=default_severity)
    db.add(dt)
    try:
        db.commit()
    except IntegrityError as exc:
        db.rollback()
        raise HTTPException(status_code=409, detail="Defect type code already exists") from exc

    _audit(db, request=request, entity_type="defect_types", entity_id=dt.id, action="create", actor_user_id=current_user.id, before_state=None, after_state=_model_to_dict(dt))
    db.commit()
    return {"id": str(dt.id), "code": dt.code, "name": dt.name, "default_severity": dt.default_severity}


@app.get("/config/production-lines", tags=["Config"], summary="List production lines")
def list_production_lines(db: Session = Depends(get_db), _: UserContext = Depends(get_current_user)) -> List[Dict[str, Any]]:
    """List production lines."""
    lines = db.scalars(select(ProductionLine).where(ProductionLine.is_active.is_(True)).order_by(ProductionLine.code.asc())).all()
    return [{"id": str(l.id), "code": l.code, "name": l.name} for l in lines]


@app.post("/config/production-lines", tags=["Config"], summary="Create production line", dependencies=[Depends(require_roles(["engineer", "manager", "admin"]))])
def create_production_line(
    code: str = Form(...),
    name: Optional[str] = Form(None),
    request: Request = None,  # type: ignore[assignment]
    db: Session = Depends(get_db),
    current_user: UserContext = Depends(get_current_user),
) -> Dict[str, Any]:
    """Create a production line."""
    pl = ProductionLine(code=code.strip(), name=name.strip() if name else None)
    db.add(pl)
    try:
        db.commit()
    except IntegrityError as exc:
        db.rollback()
        raise HTTPException(status_code=409, detail="Production line code already exists") from exc

    _audit(db, request=request, entity_type="production_lines", entity_id=pl.id, action="create", actor_user_id=current_user.id, before_state=None, after_state=_model_to_dict(pl))
    db.commit()
    return {"id": str(pl.id), "code": pl.code, "name": pl.name}


@app.get("/config/shifts", tags=["Config"], summary="List shifts")
def list_shifts(db: Session = Depends(get_db), _: UserContext = Depends(get_current_user)) -> List[Dict[str, Any]]:
    """List shifts."""
    shifts = db.scalars(select(Shift).order_by(Shift.code.asc())).all()
    return [{"id": str(s.id), "code": s.code, "name": s.name, "start_time": s.start_time, "end_time": s.end_time} for s in shifts]


@app.get("/config/severity-rules", tags=["Config"], summary="List severity rules")
def list_severity_rules(
    defect_type_id: Optional[UUID] = Query(None, description="Filter by defect_type_id"),
    db: Session = Depends(get_db),
    _: UserContext = Depends(get_current_user),
) -> List[Dict[str, Any]]:
    """List severity rules."""
    q = select(SeverityRule).where(SeverityRule.is_active.is_(True))
    if defect_type_id:
        q = q.where(SeverityRule.defect_type_id == defect_type_id)
    rules = db.scalars(q.order_by(SeverityRule.created_at.asc())).all()
    return [{"id": str(r.id), "defect_type_id": str(r.defect_type_id), "rule_json": r.rule_json, "severity": r.severity} for r in rules]


@app.post("/config/severity-rules", tags=["Config"], summary="Create severity rule", dependencies=[Depends(require_roles(["engineer", "manager", "admin"]))])
def create_severity_rule(
    defect_type_id: UUID = Form(...),
    severity: str = Form(...),
    rule_json: str = Form(..., description="JSON string of rule logic"),
    request: Request = None,  # type: ignore[assignment]
    db: Session = Depends(get_db),
    current_user: UserContext = Depends(get_current_user),
) -> Dict[str, Any]:
    """Create a severity rule for a defect type."""
    import json as _json

    try:
        parsed = _json.loads(rule_json)
    except Exception as exc:
        raise HTTPException(status_code=400, detail="rule_json must be valid JSON") from exc

    sr = SeverityRule(defect_type_id=defect_type_id, severity=severity, rule_json=parsed, is_active=True)
    db.add(sr)
    db.commit()
    _audit(db, request=request, entity_type="severity_rules", entity_id=sr.id, action="create", actor_user_id=current_user.id, before_state=None, after_state=_model_to_dict(sr))
    db.commit()
    return {"id": str(sr.id)}


# --------------------------------------------------------------------------------------
# Defects endpoints (CRUD + optional photo upload)
# --------------------------------------------------------------------------------------


def _generate_defect_number(db: Session) -> str:
    """Generate a human-readable defect number with date prefix and daily sequence."""
    prefix = datetime.now(timezone.utc).strftime("DEF-%Y%m%d")
    like = f"{prefix}-%"
    last = db.scalar(select(Defect.defect_number).where(Defect.defect_number.like(like)).order_by(desc(Defect.defect_number)).limit(1))
    if not last:
        return f"{prefix}-001"
    try:
        seq = int(last.split("-")[-1]) + 1
    except Exception:
        seq = 1
    return f"{prefix}-{seq:03d}"


def _save_upload(file: UploadFile, defect_id: UUID) -> str:
    """Store uploaded file on disk and return storage path."""
    if not file.filename:
        raise HTTPException(status_code=400, detail="Missing filename")
    contents = file.file.read()
    max_bytes = MAX_UPLOAD_MB * 1024 * 1024
    if len(contents) > max_bytes:
        raise HTTPException(status_code=413, detail=f"File too large (max {MAX_UPLOAD_MB} MB)")

    safe_name = Path(file.filename).name
    storage_dir = UPLOAD_DIR / "defects" / str(defect_id)
    storage_dir.mkdir(parents=True, exist_ok=True)
    storage_path = storage_dir / f"{uuid4()}_{safe_name}"
    storage_path.write_bytes(contents)
    return str(storage_path)


@app.get("/defects", tags=["Defects"], summary="List defects", response_model=List[DefectResponse])
def list_defects(
    db: Session = Depends(get_db),
    _: UserContext = Depends(get_current_user),
    start: Optional[datetime] = Query(None, description="Occurred_at >= start"),
    end: Optional[datetime] = Query(None, description="Occurred_at <= end"),
    severity: Optional[str] = Query(None, description="Filter by severity"),
    status: Optional[str] = Query(None, description="Filter by status"),
    defect_type_id: Optional[UUID] = Query(None),
    production_line_id: Optional[UUID] = Query(None),
    shift_id: Optional[UUID] = Query(None),
    q: Optional[str] = Query(None, description="Search in part_number/description/defect_number"),
    limit: int = Query(100, ge=1, le=500),
    offset: int = Query(0, ge=0),
) -> List[DefectResponse]:
    """List defects with filters and pagination."""
    _update_overdue_actions(db)
    db.commit()

    stmt = select(Defect)
    filters = []
    if start:
        filters.append(Defect.occurred_at >= start)
    if end:
        filters.append(Defect.occurred_at <= end)
    if severity:
        filters.append(Defect.severity == severity)
    if status:
        filters.append(Defect.status == status)
    if defect_type_id:
        filters.append(Defect.defect_type_id == defect_type_id)
    if production_line_id:
        filters.append(Defect.production_line_id == production_line_id)
    if shift_id:
        filters.append(Defect.shift_id == shift_id)
    if q:
        qq = f"%{q.strip()}%"
        filters.append(or_(Defect.part_number.ilike(qq), Defect.description.ilike(qq), Defect.defect_number.ilike(qq)))

    if filters:
        stmt = stmt.where(and_(*filters))
    stmt = stmt.order_by(Defect.occurred_at.desc()).offset(offset).limit(limit)

    defects = db.scalars(stmt).all()
    return [
        DefectResponse(
            id=d.id,
            defect_number=d.defect_number,
            occurred_at=d.occurred_at,
            part_number=d.part_number,
            description=d.description,
            defect_type_id=d.defect_type_id,
            production_line_id=d.production_line_id,
            shift_id=d.shift_id,
            quantity_affected=d.quantity_affected,
            severity=d.severity,
            status=d.status,
            reported_by_user_id=d.reported_by_user_id,
            tags=d.tags,
            extra=d.extra or {},
            photo_path=d.photo_path,
            created_at=d.created_at,
            updated_at=d.updated_at,
        )
        for d in defects
    ]


@app.get("/defects/{defect_id}", tags=["Defects"], summary="Get defect", response_model=DefectResponse)
def get_defect(defect_id: UUID, db: Session = Depends(get_db), _: UserContext = Depends(get_current_user)) -> DefectResponse:
    """Get a defect by id."""
    d = db.get(Defect, defect_id)
    if not d:
        raise HTTPException(status_code=404, detail="Defect not found")
    return DefectResponse(
        id=d.id,
        defect_number=d.defect_number,
        occurred_at=d.occurred_at,
        part_number=d.part_number,
        description=d.description,
        defect_type_id=d.defect_type_id,
        production_line_id=d.production_line_id,
        shift_id=d.shift_id,
        quantity_affected=d.quantity_affected,
        severity=d.severity,
        status=d.status,
        reported_by_user_id=d.reported_by_user_id,
        tags=d.tags,
        extra=d.extra or {},
        photo_path=d.photo_path,
        created_at=d.created_at,
        updated_at=d.updated_at,
    )


@app.post(
    "/defects",
    tags=["Defects"],
    summary="Create defect (supports optional photo upload)",
    response_model=DefectResponse,
)
def create_defect(
    request: Request,
    db: Session = Depends(get_db),
    current_user: UserContext = Depends(get_current_user),
    occurred_at: Optional[str] = Form(None),
    part_number: Optional[str] = Form(None),
    description: Optional[str] = Form(None),
    defect_type_id: Optional[str] = Form(None),
    production_line_id: Optional[str] = Form(None),
    shift_id: Optional[str] = Form(None),
    quantity_affected: int = Form(0),
    severity_manual: Optional[str] = Form(None),
    tags: Optional[str] = Form(None, description="Comma-separated tags"),
    extra: Optional[str] = Form(None, description="JSON string extra"),
    photo: Optional[UploadFile] = File(None),
) -> DefectResponse:
    """
    Create a defect. Accepts multipart/form-data to allow photo upload.

    Fields:
    - severity_manual (optional) overrides rule/default severity.
    - photo (optional) is stored on server disk under UPLOAD_DIR and persisted as `photo_path`.
    """
    import json as _json

    dt_id = UUID(defect_type_id) if defect_type_id else None
    pl_id = UUID(production_line_id) if production_line_id else None
    sh_id = UUID(shift_id) if shift_id else None

    occurred_dt = datetime.fromisoformat(occurred_at) if occurred_at else _utcnow()
    extra_obj: Dict[str, Any] = {}
    if extra:
        try:
            extra_obj = _json.loads(extra)
        except Exception as exc:
            raise HTTPException(status_code=400, detail="extra must be valid JSON") from exc

    severity, severity_source = _compute_severity(db, defect_type_id=dt_id, quantity_affected=quantity_affected, manual=severity_manual)

    d = Defect(
        defect_number=_generate_defect_number(db),
        occurred_at=occurred_dt,
        part_number=part_number,
        description=description,
        defect_type_id=dt_id,
        production_line_id=pl_id,
        shift_id=sh_id,
        quantity_affected=quantity_affected,
        severity=severity,
        status=DefectStatus.open.value,
        reported_by_user_id=current_user.id,
        tags=[t.strip() for t in tags.split(",") if t.strip()] if tags else None,
        extra={**extra_obj, "severity_source": severity_source},
    )

    db.add(d)
    db.commit()
    db.refresh(d)

    if photo:
        storage_path = _save_upload(photo, d.id)
        d.photo_path = storage_path
        db.add(Attachment(defect_id=d.id, file_name=Path(photo.filename or "photo").name, mime_type=photo.content_type, file_size_bytes=None, storage_path=storage_path, uploaded_by_user_id=current_user.id))
        db.commit()

    _audit(
        db,
        request=request,
        entity_type="defects",
        entity_id=d.id,
        action="create",
        actor_user_id=current_user.id,
        before_state=None,
        after_state=_model_to_dict(d),
    )
    db.commit()

    return get_defect(d.id, db=db, _=current_user)


@app.patch("/defects/{defect_id}", tags=["Defects"], summary="Update defect", response_model=DefectResponse)
def update_defect(
    defect_id: UUID,
    payload: DefectUpdate,
    request: Request,
    db: Session = Depends(get_db),
    current_user: UserContext = Depends(get_current_user),
) -> DefectResponse:
    """Update defect fields; recomputes severity if relevant inputs changed."""
    d = db.get(Defect, defect_id)
    if not d:
        raise HTTPException(status_code=404, detail="Defect not found")

    before = _model_to_dict(d)

    if payload.occurred_at is not None:
        d.occurred_at = payload.occurred_at
    if payload.part_number is not None:
        d.part_number = payload.part_number
    if payload.description is not None:
        d.description = payload.description
    if payload.defect_type_id is not None:
        d.defect_type_id = payload.defect_type_id
    if payload.production_line_id is not None:
        d.production_line_id = payload.production_line_id
    if payload.shift_id is not None:
        d.shift_id = payload.shift_id
    if payload.quantity_affected is not None:
        d.quantity_affected = payload.quantity_affected
    if payload.status is not None:
        d.status = payload.status
    if payload.tags is not None:
        d.tags = payload.tags
    if payload.extra is not None:
        d.extra = payload.extra

    # Severity recompute (manual can be set/cleared)
    severity, severity_source = _compute_severity(
        db,
        defect_type_id=d.defect_type_id,
        quantity_affected=d.quantity_affected,
        manual=payload.severity_manual,
    )
    d.severity = severity
    d.extra = {**(d.extra or {}), "severity_source": severity_source}

    d.updated_at = _utcnow()
    db.commit()

    _audit(
        db,
        request=request,
        entity_type="defects",
        entity_id=d.id,
        action="update",
        actor_user_id=current_user.id,
        before_state=before,
        after_state=_model_to_dict(d),
    )
    db.commit()

    return get_defect(d.id, db=db, _=current_user)


@app.post("/defects/{defect_id}/photo", tags=["Defects"], summary="Upload/replace defect photo")
def upload_defect_photo(
    defect_id: UUID,
    request: Request,
    photo: UploadFile = File(...),
    db: Session = Depends(get_db),
    current_user: UserContext = Depends(get_current_user),
) -> Dict[str, Any]:
    """Upload or replace a defect photo (stored on disk + attachment metadata)."""
    d = db.get(Defect, defect_id)
    if not d:
        raise HTTPException(status_code=404, detail="Defect not found")

    before = _model_to_dict(d)
    storage_path = _save_upload(photo, d.id)
    d.photo_path = storage_path
    d.updated_at = _utcnow()

    db.add(Attachment(defect_id=d.id, file_name=Path(photo.filename or "photo").name, mime_type=photo.content_type, file_size_bytes=None, storage_path=storage_path, uploaded_by_user_id=current_user.id))
    db.commit()

    _audit(db, request=request, entity_type="defects", entity_id=d.id, action="upload_photo", actor_user_id=current_user.id, before_state=before, after_state=_model_to_dict(d))
    db.commit()
    return {"defect_id": str(d.id), "photo_path": d.photo_path}


# --------------------------------------------------------------------------------------
# RCA endpoints (5-Why / Fishbone)
# --------------------------------------------------------------------------------------


@app.get("/defects/{defect_id}/rca", tags=["RCA"], summary="Get defect RCA", response_model=Optional[RcaResponse])
def get_defect_rca(defect_id: UUID, db: Session = Depends(get_db), _: UserContext = Depends(get_current_user)) -> Optional[RcaResponse]:
    """Fetch RCA for a defect (returns null if not created yet)."""
    r = db.scalar(select(DefectRca).where(DefectRca.defect_id == defect_id))
    if not r:
        return None
    return RcaResponse(
        id=r.id,
        defect_id=r.defect_id,
        method=r.method,
        five_whys=r.five_whys,
        fishbone=r.fishbone,
        conclusion=r.conclusion,
        created_by_user_id=r.created_by_user_id,
        created_at=r.created_at,
        updated_at=r.updated_at,
    )


@app.put("/defects/{defect_id}/rca", tags=["RCA"], summary="Upsert defect RCA", response_model=RcaResponse)
def upsert_defect_rca(
    defect_id: UUID,
    payload: RcaUpsert,
    request: Request,
    db: Session = Depends(get_db),
    current_user: UserContext = Depends(get_current_user),
) -> RcaResponse:
    """
    Create or update RCA for a defect.

    Enforces workflow: method must be one of '5-Why' or 'Fishbone'.
    """
    d = db.get(Defect, defect_id)
    if not d:
        raise HTTPException(status_code=404, detail="Defect not found")

    existing = db.scalar(select(DefectRca).where(DefectRca.defect_id == defect_id))
    if payload.method not in [RcaMethod.five_why.value, RcaMethod.fishbone.value]:
        raise HTTPException(status_code=400, detail="Invalid method")

    if existing:
        before = _model_to_dict(existing)
        existing.method = payload.method
        existing.five_whys = payload.five_whys
        existing.fishbone = payload.fishbone
        existing.conclusion = payload.conclusion
        existing.updated_at = _utcnow()
        db.commit()

        _audit(
            db,
            request=request,
            entity_type="defect_rca",
            entity_id=existing.id,
            action="update",
            actor_user_id=current_user.id,
            before_state=before,
            after_state=_model_to_dict(existing),
        )
        db.commit()
        r = existing
    else:
        r = DefectRca(
            defect_id=defect_id,
            method=payload.method,
            five_whys=payload.five_whys,
            fishbone=payload.fishbone,
            conclusion=payload.conclusion,
            created_by_user_id=current_user.id,
        )
        db.add(r)
        db.commit()
        db.refresh(r)

        _audit(db, request=request, entity_type="defect_rca", entity_id=r.id, action="create", actor_user_id=current_user.id, before_state=None, after_state=_model_to_dict(r))
        db.commit()

    return RcaResponse(
        id=r.id,
        defect_id=r.defect_id,
        method=r.method,
        five_whys=r.five_whys,
        fishbone=r.fishbone,
        conclusion=r.conclusion,
        created_by_user_id=r.created_by_user_id,
        created_at=r.created_at,
        updated_at=r.updated_at,
    )


# --------------------------------------------------------------------------------------
# Corrective actions endpoints
# --------------------------------------------------------------------------------------


@app.get("/actions", tags=["Actions"], summary="List corrective actions", response_model=List[CorrectiveActionResponse])
def list_actions(
    db: Session = Depends(get_db),
    _: UserContext = Depends(get_current_user),
    status: Optional[str] = Query(None),
    assignee_user_id: Optional[UUID] = Query(None),
    defect_id: Optional[UUID] = Query(None),
    overdue_only: bool = Query(False),
    limit: int = Query(100, ge=1, le=500),
    offset: int = Query(0, ge=0),
) -> List[CorrectiveActionResponse]:
    """List corrective actions with filters and automatic overdue updates."""
    _update_overdue_actions(db)
    db.commit()

    stmt = select(CorrectiveAction)
    filters = []
    if status:
        filters.append(CorrectiveAction.status == status)
    if assignee_user_id:
        filters.append(CorrectiveAction.assignee_user_id == assignee_user_id)
    if defect_id:
        filters.append(CorrectiveAction.defect_id == defect_id)
    if overdue_only:
        filters.append(CorrectiveAction.status == ActionStatus.overdue.value)
    if filters:
        stmt = stmt.where(and_(*filters))

    actions = db.scalars(stmt.order_by(CorrectiveAction.created_at.desc()).offset(offset).limit(limit)).all()
    return [
        CorrectiveActionResponse(
            id=a.id,
            defect_id=a.defect_id,
            title=a.title,
            description=a.description,
            assignee_user_id=a.assignee_user_id,
            due_date=datetime.combine(a.due_date, datetime.min.time(), tzinfo=timezone.utc) if a.due_date else None,
            status=a.status,
            completed_at=a.completed_at,
            created_by_user_id=a.created_by_user_id,
            created_at=a.created_at,
            updated_at=a.updated_at,
        )
        for a in actions
    ]


@app.post("/actions", tags=["Actions"], summary="Create corrective action", response_model=CorrectiveActionResponse)
def create_action(
    payload: CorrectiveActionCreate,
    request: Request,
    db: Session = Depends(get_db),
    current_user: UserContext = Depends(get_current_user),
) -> CorrectiveActionResponse:
    """Create a corrective action assigned to a user and due date; overdue logic updates automatically."""
    d = db.get(Defect, payload.defect_id)
    if not d:
        raise HTTPException(status_code=404, detail="Defect not found")

    due_date = payload.due_date.date() if payload.due_date else None
    status = payload.status or ActionStatus.open.value

    a = CorrectiveAction(
        defect_id=payload.defect_id,
        title=payload.title.strip(),
        description=payload.description,
        assignee_user_id=payload.assignee_user_id,
        due_date=due_date,
        status=status,
        created_by_user_id=current_user.id,
    )
    db.add(a)
    db.commit()
    db.refresh(a)

    _update_overdue_actions(db)
    db.commit()

    _audit(db, request=request, entity_type="corrective_actions", entity_id=a.id, action="create", actor_user_id=current_user.id, before_state=None, after_state=_model_to_dict(a))
    db.commit()

    return list_actions(db=db, _=current_user, defect_id=payload.defect_id, limit=1, offset=0)[0]


@app.patch("/actions/{action_id}", tags=["Actions"], summary="Update corrective action", response_model=CorrectiveActionResponse)
def update_action(
    action_id: UUID,
    payload: CorrectiveActionUpdate,
    request: Request,
    db: Session = Depends(get_db),
    current_user: UserContext = Depends(get_current_user),
) -> CorrectiveActionResponse:
    """Update corrective action fields; handles status transitions and overdue logic."""
    a = db.get(CorrectiveAction, action_id)
    if not a:
        raise HTTPException(status_code=404, detail="Action not found")

    before = _model_to_dict(a)

    if payload.title is not None:
        a.title = payload.title.strip()
    if payload.description is not None:
        a.description = payload.description
    if payload.assignee_user_id is not None:
        a.assignee_user_id = payload.assignee_user_id
    if payload.due_date is not None:
        a.due_date = payload.due_date.date()
    if payload.status is not None:
        a.status = payload.status
        if payload.status == ActionStatus.done.value:
            a.completed_at = _utcnow()
        elif payload.status in [ActionStatus.open.value, ActionStatus.in_progress.value, ActionStatus.cancelled.value]:
            a.completed_at = None

    a.updated_at = _utcnow()
    db.commit()

    _update_overdue_actions(db)
    db.commit()

    _audit(db, request=request, entity_type="corrective_actions", entity_id=a.id, action="update", actor_user_id=current_user.id, before_state=before, after_state=_model_to_dict(a))
    db.commit()

    # Re-load for response
    a = db.get(CorrectiveAction, action_id)
    return CorrectiveActionResponse(
        id=a.id,
        defect_id=a.defect_id,
        title=a.title,
        description=a.description,
        assignee_user_id=a.assignee_user_id,
        due_date=datetime.combine(a.due_date, datetime.min.time(), tzinfo=timezone.utc) if a.due_date else None,
        status=a.status,
        completed_at=a.completed_at,
        created_by_user_id=a.created_by_user_id,
        created_at=a.created_at,
        updated_at=a.updated_at,
    )


# --------------------------------------------------------------------------------------
# Dashboard aggregations
# --------------------------------------------------------------------------------------


@app.get("/dashboard/overdue", tags=["Dashboard"], summary="Overdue actions metrics", response_model=DashboardOverdueResponse)
def dashboard_overdue(
    db: Session = Depends(get_db),
    _: UserContext = Depends(get_current_user),
) -> DashboardOverdueResponse:
    """Return overdue actions count and breakdown by assignee."""
    _update_overdue_actions(db)
    db.commit()

    overdue_count = db.scalar(select(func.count()).select_from(CorrectiveAction).where(CorrectiveAction.status == ActionStatus.overdue.value)) or 0

    rows = db.execute(
        select(CorrectiveAction.assignee_user_id, func.count().label("count"))
        .where(CorrectiveAction.status == ActionStatus.overdue.value)
        .group_by(CorrectiveAction.assignee_user_id)
        .order_by(desc(func.count()))
    ).all()

    return DashboardOverdueResponse(
        overdue_actions=int(overdue_count),
        overdue_by_assignee=[{"assignee_user_id": str(r[0]) if r[0] else None, "count": int(r[1])} for r in rows],
    )


@app.get("/dashboard/pareto", tags=["Dashboard"], summary="Pareto of defect types", response_model=List[ParetoItem])
def dashboard_pareto(
    db: Session = Depends(get_db),
    _: UserContext = Depends(get_current_user),
    start: Optional[datetime] = Query(None),
    end: Optional[datetime] = Query(None),
    production_line_id: Optional[UUID] = Query(None),
    shift_id: Optional[UUID] = Query(None),
    limit: int = Query(10, ge=1, le=50),
) -> List[ParetoItem]:
    """Return top defect types by count with optional filters."""
    stmt = (
        select(DefectType.code, DefectType.name, func.count(Defect.id))
        .select_from(Defect)
        .join(DefectType, Defect.defect_type_id == DefectType.id, isouter=True)
    )
    filters = []
    if start:
        filters.append(Defect.occurred_at >= start)
    if end:
        filters.append(Defect.occurred_at <= end)
    if production_line_id:
        filters.append(Defect.production_line_id == production_line_id)
    if shift_id:
        filters.append(Defect.shift_id == shift_id)
    if filters:
        stmt = stmt.where(and_(*filters))

    stmt = stmt.group_by(DefectType.code, DefectType.name).order_by(desc(func.count(Defect.id))).limit(limit)
    rows = db.execute(stmt).all()

    result: List[ParetoItem] = []
    for code, name, count in rows:
        if code is None:
            continue
        result.append(ParetoItem(defect_type_code=code, defect_type_name=name or code, count=int(count)))
    return result


@app.get("/dashboard/trends", tags=["Dashboard"], summary="Trends over time", response_model=List[TrendPoint])
def dashboard_trends(
    db: Session = Depends(get_db),
    _: UserContext = Depends(get_current_user),
    start: datetime = Query(..., description="Start datetime (inclusive)"),
    end: datetime = Query(..., description="End datetime (inclusive)"),
    period: str = Query("day", description="Aggregation period: day|week|month"),
    defect_type_id: Optional[UUID] = Query(None),
    production_line_id: Optional[UUID] = Query(None),
    shift_id: Optional[UUID] = Query(None),
) -> List[TrendPoint]:
    """Return trend series (counts and severity breakdowns) for given filters."""
    if period not in ["day", "week", "month"]:
        raise HTTPException(status_code=400, detail="period must be day|week|month")

    # Use date_trunc for bucketing
    bucket = func.date_trunc(period, Defect.occurred_at).label("bucket")
    stmt = select(
        bucket,
        func.count().label("count"),
        func.sum(func.case((Defect.severity == Severity.critical.value, 1), else_=0)).label("critical"),
        func.sum(func.case((Defect.severity == Severity.major.value, 1), else_=0)).label("major"),
        func.sum(func.case((Defect.severity == Severity.minor.value, 1), else_=0)).label("minor"),
    ).where(and_(Defect.occurred_at >= start, Defect.occurred_at <= end))

    if defect_type_id:
        stmt = stmt.where(Defect.defect_type_id == defect_type_id)
    if production_line_id:
        stmt = stmt.where(Defect.production_line_id == production_line_id)
    if shift_id:
        stmt = stmt.where(Defect.shift_id == shift_id)

    stmt = stmt.group_by(bucket).order_by(bucket.asc())
    rows = db.execute(stmt).all()

    return [
        TrendPoint(
            period=r[0].isoformat(),
            count=int(r[1] or 0),
            critical=int(r[2] or 0),
            major=int(r[3] or 0),
            minor=int(r[4] or 0),
        )
        for r in rows
    ]


# --------------------------------------------------------------------------------------
# Audit endpoints
# --------------------------------------------------------------------------------------


@app.get("/audit", tags=["Audit"], summary="List audit log entries", dependencies=[Depends(require_roles(["manager", "admin"]))])
def list_audit(
    db: Session = Depends(get_db),
    entity_type: Optional[str] = Query(None),
    entity_id: Optional[UUID] = Query(None),
    actor_user_id: Optional[UUID] = Query(None),
    limit: int = Query(200, ge=1, le=1000),
    offset: int = Query(0, ge=0),
) -> List[Dict[str, Any]]:
    """List audit log entries (manager/admin)."""
    stmt = select(AuditLog)
    filters = []
    if entity_type:
        filters.append(AuditLog.entity_type == entity_type)
    if entity_id:
        filters.append(AuditLog.entity_id == entity_id)
    if actor_user_id:
        filters.append(AuditLog.actor_user_id == actor_user_id)
    if filters:
        stmt = stmt.where(and_(*filters))
    stmt = stmt.order_by(AuditLog.created_at.desc()).offset(offset).limit(limit)
    rows = db.scalars(stmt).all()
    return [
        {
            "id": str(r.id),
            "entity_type": r.entity_type,
            "entity_id": str(r.entity_id),
            "action": r.action,
            "actor_user_id": str(r.actor_user_id) if r.actor_user_id else None,
            "before_state": r.before_state,
            "after_state": r.after_state,
            "ip_address": r.ip_address,
            "user_agent": r.user_agent,
            "created_at": r.created_at.isoformat(),
        }
        for r in rows
    ]


# --------------------------------------------------------------------------------------
# Export endpoints (CSV + PDF)
# --------------------------------------------------------------------------------------


@app.get("/export/defects.csv", tags=["Export"], summary="Export defects as CSV")
def export_defects_csv(
    db: Session = Depends(get_db),
    _: UserContext = Depends(get_current_user),
    start: Optional[datetime] = Query(None),
    end: Optional[datetime] = Query(None),
) -> Response:
    """Export defects as CSV with basic columns."""
    import csv
    import io

    stmt = select(Defect).order_by(Defect.occurred_at.desc())
    if start:
        stmt = stmt.where(Defect.occurred_at >= start)
    if end:
        stmt = stmt.where(Defect.occurred_at <= end)

    defects = db.scalars(stmt).all()

    buf = io.StringIO()
    writer = csv.writer(buf)
    writer.writerow(["defect_number", "occurred_at", "part_number", "description", "quantity_affected", "severity", "status"])
    for d in defects:
        writer.writerow([d.defect_number, d.occurred_at.isoformat(), d.part_number or "", d.description or "", d.quantity_affected, d.severity, d.status])

    return Response(content=buf.getvalue(), media_type="text/csv", headers={"Content-Disposition": "attachment; filename=defects.csv"})


@app.get("/export/defects.pdf", tags=["Export"], summary="Export defects as PDF (simple report)")
def export_defects_pdf(
    db: Session = Depends(get_db),
    _: UserContext = Depends(get_current_user),
    start: Optional[datetime] = Query(None),
    end: Optional[datetime] = Query(None),
) -> Response:
    """Export defects as a simple PDF report."""
    import io

    from reportlab.lib.pagesizes import letter
    from reportlab.pdfgen import canvas

    stmt = select(Defect).order_by(Defect.occurred_at.desc()).limit(500)
    if start:
        stmt = stmt.where(Defect.occurred_at >= start)
    if end:
        stmt = stmt.where(Defect.occurred_at <= end)

    defects = db.scalars(stmt).all()

    out = io.BytesIO()
    c = canvas.Canvas(out, pagesize=letter)
    width, height = letter

    y = height - 50
    c.setFont("Helvetica-Bold", 14)
    c.drawString(40, y, "Defect Report")
    y -= 20
    c.setFont("Helvetica", 10)
    c.drawString(40, y, f"Generated at: {_utcnow().isoformat()}")
    y -= 20

    c.setFont("Helvetica-Bold", 9)
    c.drawString(40, y, "Defect#")
    c.drawString(130, y, "Occurred")
    c.drawString(230, y, "Part")
    c.drawString(320, y, "Qty")
    c.drawString(360, y, "Severity")
    c.drawString(430, y, "Status")
    y -= 12
    c.setFont("Helvetica", 9)

    for d in defects:
        if y < 60:
            c.showPage()
            y = height - 50
            c.setFont("Helvetica", 9)
        c.drawString(40, y, d.defect_number[:12])
        c.drawString(130, y, d.occurred_at.date().isoformat())
        c.drawString(230, y, (d.part_number or "")[:14])
        c.drawString(320, y, str(d.quantity_affected))
        c.drawString(360, y, d.severity)
        c.drawString(430, y, d.status)
        y -= 12

    c.showPage()
    c.save()
    pdf_bytes = out.getvalue()
    return Response(content=pdf_bytes, media_type="application/pdf", headers={"Content-Disposition": "attachment; filename=defects.pdf"})
