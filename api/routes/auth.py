
"""Authentication endpoints for registration, login, and user profile verification."""

from datetime import datetime, timedelta, timezone
import logging
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Request, status
from pydantic import BaseModel, EmailStr, field_validator
from sqlalchemy import func, or_, select
from sqlalchemy.exc import DBAPIError, OperationalError
from sqlalchemy.orm import Session

from api.auth import (
    create_access_token,
    get_current_user,
    hash_password,
    normalize_role,
    verify_password,
)
from database.connection import get_db
from database.models import User
from services.audit_service import log_audit_event

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/auth", tags=["auth"])

SUPPORTED_DEPARTMENTS = {
    "it": "IT Support",
    "it support": "IT Support",
    "hr": "Human Resources",
    "human resources": "Human Resources",
    "finance": "Finance & Claims",
    "finance & claims": "Finance & Claims",
    "project": "Project Department",
    "project department": "Project Department",
    "management": "Management",
    "admin": "Admin",
    "adm": "Admin",
    "administration": "Admin",
}


def normalize_department(dept_raw: str) -> Optional[str]:
    if not dept_raw:
        return None
    return SUPPORTED_DEPARTMENTS.get(dept_raw.strip().lower())


class UserRegisterSchema(BaseModel):
    email: EmailStr
    password: str
    full_name: str
    employee_id: str
    department: str
    job_title: Optional[str] = None

    @field_validator("password")
    @classmethod
    def validate_password_length(cls, v: str) -> str:
        if len(v.strip()) < 4:
            raise ValueError("Password must be at least 4 characters long.")
        return v

    @field_validator("full_name")
    @classmethod
    def validate_name(cls, v: str) -> str:
        name = v.strip()
        if not name:
            raise ValueError("Full name is required.")
        return name

    @field_validator("employee_id")
    @classmethod
    def validate_employee_id(cls, v: str) -> str:
        emp_id = v.strip()
        if not emp_id:
            raise ValueError("Employee ID is required.")
        return emp_id

    @field_validator("department")
    @classmethod
    def validate_dept(cls, v: str) -> str:
        norm = normalize_department(v)
        if not norm:
            raise ValueError(
                "Invalid department. Supported departments are: "
                "IT Support, Human Resources, Finance & Claims, "
                "Project Department, Management, Admin."
            )
        return norm


class UserLoginSchema(BaseModel):
    email: str
    password: str


class UserProfileSchema(BaseModel):
    id: int
    email: str
    username: str
    full_name: Optional[str] = None
    role: str
    employee_id: Optional[str] = None
    department: Optional[str] = None
    job_title: Optional[str] = None
    is_active: bool = True
    last_login_at: Optional[datetime] = None


class TokenResponseSchema(BaseModel):
    access_token: str
    token_type: str
    user: Optional[UserProfileSchema] = None


@router.post("/register", response_model=UserProfileSchema)
def register(
    data: UserRegisterSchema,
    request: Request,
    db: Session = Depends(get_db),
):
    """Register a new employee."""

    clean_email = data.email.strip().lower()
    clean_emp_id = data.employee_id.strip()

    try:
        existing_email = db.execute(
            select(User).where(func.lower(User.email) == clean_email)
        ).scalar_one_or_none()

        if existing_email:
            raise HTTPException(
                status_code=400,
                detail="An account with this email already exists.",
            )

        existing_emp = db.execute(
            select(User).where(User.employee_id == clean_emp_id)
        ).scalar_one_or_none()

        if existing_emp:
            raise HTTPException(
                status_code=400,
                detail="An account with this Employee ID already exists.",
            )

        username_base = clean_email.split("@")[0]
        username = username_base
        counter = 1

        while db.execute(
            select(User).where(func.lower(User.username) == username.lower())
        ).scalar_one_or_none():
            username = f"{username_base}{counter}"
            counter += 1

        hashed = hash_password(data.password)

        user = User(
            email=clean_email,
            username=username,
            full_name=data.full_name.strip(),
            hashed_password=hashed,
            employee_id=clean_emp_id,
            department=data.department,
            job_title=data.job_title.strip() if data.job_title else None,
            role="Employee",
            is_active=True,
            failed_login_attempts=0,
            token_version=1,
        )

        db.add(user)
        db.commit()
        db.refresh(user)

        client_ip = request.client.host if request.client else "Unknown"

        log_audit_event(
            db=db,
            action="USER_REGISTERED",
            target_user=user,
            resource_type="USER",
            resource_id=str(user.id),
            summary=f"New employee registered: {user.full_name} ({user.email}) in {user.department}",
            ip_address=client_ip,
        )

        logger.info(f"Successfully registered new user: {clean_email}")
        return user

    except HTTPException:
        raise
    except (OperationalError, DBAPIError) as db_exc:
        db.rollback()
        logger.error("Database error during registration", exc_info=True)
        raise HTTPException(
            status_code=503,
            detail="Database service is currently unavailable. Please try again shortly.",
        )


@router.post("/login", response_model=TokenResponseSchema)
async def login(
    data: UserLoginSchema,
    request: Request,
    db: Session = Depends(get_db),
):
    """Authenticate employee and return JWT access token."""

    identifier = data.email.strip()
    password = data.password

    if not identifier or not password:
        raise HTTPException(
            status_code=400,
            detail="Email/Employee ID and password are required.",
        )

    clean_identifier = identifier
    clean_lower = clean_identifier.lower()
    client_ip = request.client.host if request.client else "Unknown"

    try:
        user = db.execute(
            select(User).where(
                or_(
                    func.lower(User.email) == clean_lower,
                    User.employee_id == clean_identifier,
                    func.lower(User.username) == clean_lower,
                )
            )
        ).scalar_one_or_none()

    except (OperationalError, DBAPIError):
        logger.error("Database error during login", exc_info=True)
        raise HTTPException(
            status_code=503,
            detail="Database service is currently unavailable. Please try again shortly.",
        )

    if not user:
        log_audit_event(
            db=db,
            action="USER_LOGIN_FAILED",
            resource_type="AUTH",
            summary=f"Login failed: Account '{clean_identifier}' not found",
            status="FAILED",
            ip_address=client_ip,
        )
        raise HTTPException(
            status_code=401,
            detail="Invalid email, Employee ID, or password.",
            headers={"WWW-Authenticate": "Bearer"},
        )

    if getattr(user, "is_active", True) is False:
        log_audit_event(
            db=db,
            action="USER_LOGIN_FAILED",
            target_user=user,
            resource_type="AUTH",
            summary=f"Login blocked for deactivated account: {user.email}",
            status="FAILED",
            ip_address=client_ip,
        )
        raise HTTPException(
            status_code=403,
            detail="This employee account has been deactivated. Please contact your company administrator.",
        )

    now = datetime.now(timezone.utc)

    if user.locked_until and user.locked_until > now:
        remaining_secs = int((user.locked_until - now).total_seconds())
        remaining_mins = max(1, remaining_secs // 60)

        raise HTTPException(
            status_code=403,
            detail=f"Account is temporarily locked. Retry in {remaining_mins} minute(s).",
        )

    if not verify_password(password, user.hashed_password):
        user.failed_login_attempts = (
            getattr(user, "failed_login_attempts", 0) or 0
        ) + 1

        if user.failed_login_attempts >= 5:
            user.locked_until = now + timedelta(minutes=15)
            db.commit()

            log_audit_event(
                db=db,
                action="USER_ACCOUNT_LOCKED",
                target_user=user,
                resource_type="SECURITY",
                summary=f"Account locked for 15 minutes: {user.email}",
                status="ALERT",
                ip_address=client_ip,
            )

            raise HTTPException(
                status_code=403,
                detail="Account has been temporarily locked for 15 minutes.",
            )

        db.commit()

        log_audit_event(
            db=db,
            action="USER_LOGIN_FAILED",
            target_user=user,
            resource_type="AUTH",
            summary=f"Invalid password attempt for {user.email}",
            status="FAILED",
            ip_address=client_ip,
        )

        raise HTTPException(
            status_code=401,
            detail="Invalid email, Employee ID, or password.",
            headers={"WWW-Authenticate": "Bearer"},
        )

    user.failed_login_attempts = 0
    user.locked_until = None
    user.last_login_at = now
    db.commit()

    log_audit_event(
        db=db,
        action="USER_LOGIN_SUCCESS",
        actor=user,
        target_user=user,
        resource_type="AUTH",
        summary=f"Employee logged in successfully: {user.email}",
        status="SUCCESS",
        ip_address=client_ip,
    )

    access_token = create_access_token(
        data={"sub": user.email},
        token_version=getattr(user, "token_version", 1),
    )

    return {
        "access_token": access_token,
        "token_type": "bearer",
        "user": user,
    }


@router.get("/me", response_model=UserProfileSchema)
def get_me(current_user: User = Depends(get_current_user)):
    """Fetch current employee session user profile."""
    return current_user


@router.post("/admin-login", response_model=TokenResponseSchema)
async def admin_login(
    request: Request,
    db: Session = Depends(get_db),
):
    """Authenticate corporate Super Admin."""

    identifier = None
    password = None

    content_type = request.headers.get("content-type", "")

    if "application/json" in content_type:
        try:
            body = await request.json()
            identifier = (
                body.get("email")
                or body.get("username")
                or body.get("employee_id")
                or body.get("identifier")
            )
            password = body.get("password")
        except Exception:
            pass
    else:
        try:
            form_data = await request.form()
            identifier = (
                form_data.get("username")
                or form_data.get("email")
                or form_data.get("employee_id")
            )
            password = form_data.get("password")
        except Exception:
            pass

    if not identifier or not password:
        raise HTTPException(
            status_code=400,
            detail="Administrator email/username and password are required.",
        )

    clean_identifier = str(identifier).strip()
    clean_lower = clean_identifier.lower()
    client_ip = request.client.host if request.client else "Unknown"

    try:
        user = db.execute(
            select(User).where(
                or_(
                    func.lower(User.email) == clean_lower,
                    User.employee_id == clean_identifier,
                    func.lower(User.username) == clean_lower,
                )
            )
        ).scalar_one_or_none()

    except (OperationalError, DBAPIError):
        logger.error("Database error during admin login", exc_info=True)
        raise HTTPException(
            status_code=503,
            detail="Database service is currently unavailable. Please try again shortly.",
        )

    if not user:
        raise HTTPException(
            status_code=401,
            detail="Invalid administrator email, username, or password.",
            headers={"WWW-Authenticate": "Bearer"},
        )

    if getattr(user, "is_active", True) is False:
        raise HTTPException(
            status_code=403,
            detail="This administrator account has been deactivated.",
        )

    now = datetime.now(timezone.utc)

    if user.locked_until and user.locked_until > now:
        remaining_secs = int((user.locked_until - now).total_seconds())
        remaining_mins = max(1, remaining_secs // 60)

        raise HTTPException(
            status_code=403,
            detail=f"Account is temporarily locked. Retry in {remaining_mins} minute(s).",
        )

    if not verify_password(password, user.hashed_password):
        user.failed_login_attempts = (
            getattr(user, "failed_login_attempts", 0) or 0
        ) + 1

        if user.failed_login_attempts >= 5:
            user.locked_until = now + timedelta(minutes=15)
            db.commit()
            raise HTTPException(
                status_code=403,
                detail="Account has been temporarily locked for 15 minutes.",
            )

        db.commit()

        raise HTTPException(
            status_code=401,
            detail="Invalid administrator email, username, or password.",
            headers={"WWW-Authenticate": "Bearer"},
        )

    norm_role = normalize_role(user.role)

    if norm_role != "super_admin":
        log_audit_event(
            db=db,
            action="ADMIN_LOGIN_DENIED_UNAUTHORIZED_ROLE",
            actor=user,
            target_user=user,
            resource_type="SECURITY",
            summary=f"Unauthorized admin login attempt: {user.email}",
            status="ALERT",
            ip_address=client_ip,
        )

        raise HTTPException(
            status_code=403,
            detail="Access Denied: Only authorized Super Admins can use this portal.",
        )

    user.failed_login_attempts = 0
    user.locked_until = None
    user.last_login_at = now
    db.commit()

    log_audit_event(
        db=db,
        action="SUPER_ADMIN_LOGIN_SUCCESS",
        actor=user,
        target_user=user,
        resource_type="AUTH",
        summary=f"Super Admin authenticated successfully: {user.email}",
        status="SUCCESS",
        ip_address=client_ip,
    )

    access_token = create_access_token(
        data={"sub": user.email},
        token_version=getattr(user, "token_version", 1),
    )

    return {
        "access_token": access_token,
        "token_type": "bearer",
        "user": user,
    }


# Dynamic registration to prevent circular import at module load time
from api.routes.biometrics import (
    BiometricAdminVerifySchema,
    verify_admin_face_login,
)
from services.biometric_service import get_biometric_service


@router.post("/admin-face-login", response_model=TokenResponseSchema)
def admin_face_login(
    request: Request,
    data: BiometricAdminVerifySchema,
    db: Session = Depends(get_db),
    service=Depends(get_biometric_service),
):
    """Authenticate Super Admin via Face ID verification."""
    return verify_admin_face_login(
        request=request,
        data=data,
        db=db,
        service=service,
    )
