from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.security import OAuth2PasswordRequestForm
from sqlalchemy.orm import Session
from sqlalchemy import func
from datetime import timedelta
from app.database import get_db
from app.config import settings
from app import models, schemas
from app.auth import verify_password, get_password_hash, create_access_token, get_current_user
from app.services.ldap_service import LdapService

router = APIRouter(prefix="/auth", tags=["Autenticação"])

def authenticate_user_credentials(db: Session, username_clean: str, password: str) -> models.User:
    user = db.query(models.User).filter(
        (func.lower(models.User.username) == username_clean.lower()) |
        (func.lower(models.User.sam_account_name) == username_clean.lower())
    ).first()

    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Usuário ou senha incorretos.",
            headers={"WWW-Authenticate": "Bearer"},
        )

    if not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Usuário inativo no sistema. Contate o administrador."
        )

    if getattr(user, "auth_type", "local") == "ldap":
        ldap_config = db.query(models.LdapConfig).filter(models.LdapConfig.id == 1).first()
        if not ldap_config or not ldap_config.is_enabled:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="A integração LDAP/Active Directory está desabilitada no sistema. Contate o administrador."
            )
        success, err_msg, ldap_info = LdapService.authenticate_user(
            ldap_config,
            user.sam_account_name or user.username,
            password
        )
        if not success:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail=err_msg or "Usuário ou senha incorretos.",
                headers={"WWW-Authenticate": "Bearer"},
            )
        if ldap_info:
            if ldap_info.get("full_name") and ldap_info["full_name"] != user.full_name:
                user.full_name = ldap_info["full_name"]
            if ldap_info.get("email") and ldap_info["email"] != user.email:
                conflict = db.query(models.User).filter(models.User.email == ldap_info["email"], models.User.id != user.id).first()
                if not conflict:
                    user.email = ldap_info["email"]
            db.commit()
    else:
        password_clean = password.strip() if password else ""
        is_valid = verify_password(password, user.hashed_password)
        if not is_valid and password_clean != password:
            is_valid = verify_password(password_clean, user.hashed_password)

        # Suporte resiliente para credenciais iniciais do Administrador (Admin/Admin ou admin/admin)
        if not is_valid and user.username.lower() == "admin":
            if password_clean.lower() == "admin":
                if verify_password("Admin", user.hashed_password) or verify_password("admin", user.hashed_password):
                    is_valid = True

        if not is_valid:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Usuário ou senha incorretos.",
                headers={"WWW-Authenticate": "Bearer"},
            )

    return user

def build_user_dict(user: models.User, db: Session) -> dict:
    perms = db.query(models.UserAssetGroup).filter(models.UserAssetGroup.user_id == user.id).all()
    allowed_groups = []
    allowed_group_ids = []
    for p in perms:
        allowed_groups.append({
            "id": p.id,
            "asset_group_id": p.asset_group_id,
            "asset_group_name": p.asset_group.name if p.asset_group else "",
            "can_treat": p.can_treat,
            "can_import": p.can_import,
            "can_author": p.can_author
        })
        allowed_group_ids.append(p.asset_group_id)

    return {
        "id": user.id,
        "username": user.username,
        "email": user.email,
        "full_name": user.full_name,
        "role": user.role,
        "auth_type": getattr(user, "auth_type", "local"),
        "sam_account_name": user.sam_account_name,
        "allowed_groups": allowed_groups,
        "allowed_group_ids": allowed_group_ids
    }

@router.post("/login", response_model=schemas.Token)
def login_for_access_token(
    login_data: schemas.LoginRequest,
    db: Session = Depends(get_db)
):
    """
    Login endpoint supporting JSON payload (Manual local users and Active Directory LDAP users).
    """
    username_clean = login_data.username.strip()
    user = authenticate_user_credentials(db, username_clean, login_data.password)

    access_token_expires = timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data={"sub": user.username, "role": user.role},
        expires_delta=access_token_expires
    )

    return {
        "access_token": access_token,
        "token_type": "bearer",
        "user": build_user_dict(user, db)
    }

@router.post("/login-form", response_model=schemas.Token, include_in_schema=False)
def login_form(
    form_data: OAuth2PasswordRequestForm = Depends(),
    db: Session = Depends(get_db)
):
    """OAuth2 compatible form endpoint for Swagger UI."""
    username_clean = form_data.username.strip()
    user = authenticate_user_credentials(db, username_clean, form_data.password)

    access_token = create_access_token(data={"sub": user.username, "role": user.role})
    return {
        "access_token": access_token,
        "token_type": "bearer",
        "user": build_user_dict(user, db)
    }

@router.get("/me", response_model=schemas.UserOut)
def read_current_user(
    current_user: models.User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Retorna os dados do usuário autenticado na sessão."""
    from app.api.routes_users import format_user_out
    return format_user_out(current_user, db)

@router.post("/change-password")
def change_password(
    data: schemas.PasswordChangeRequest,
    current_user: models.User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Permite ao usuário autenticado alterar sua própria senha."""
    if getattr(current_user, "auth_type", "local") == "ldap":
        raise HTTPException(
            status_code=400,
            detail="Usuários autenticados via Active Directory/LDAP devem alterar sua senha diretamente na rede corporativa."
        )

    if not verify_password(data.old_password, current_user.hashed_password):
        raise HTTPException(status_code=400, detail="Senha atual incorreta.")
    
    current_user.hashed_password = get_password_hash(data.new_password)
    db.commit()
    return {"message": "Senha alterada com sucesso."}
