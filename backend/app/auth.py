from datetime import datetime, timedelta, timezone
from typing import Optional, List
from jose import JWTError, jwt
from passlib.context import CryptContext
from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer
from sqlalchemy.orm import Session
from app.config import settings
from app.database import get_db
from app import models, schemas

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl=f"{settings.API_V1_STR}/auth/login-form")

def verify_password(plain_password: str, hashed_password: str) -> bool:
    return pwd_context.verify(plain_password, hashed_password)

def get_password_hash(password: str) -> str:
    return pwd_context.hash(password)

def create_access_token(data: dict, expires_delta: Optional[timedelta] = None) -> str:
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.now(timezone.utc) + expires_delta
    else:
        expire = datetime.now(timezone.utc) + timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, settings.SECRET_KEY, algorithm=settings.ALGORITHM)
    return encoded_jwt

async def get_current_user(
    token: str = Depends(oauth2_scheme), 
    db: Session = Depends(get_db)
) -> models.User:
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Credenciais inválidas ou sessão expirada",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, settings.SECRET_KEY, algorithms=[settings.ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            raise credentials_exception
    except JWTError:
        raise credentials_exception
        
    user = db.query(models.User).filter(models.User.username == username).first()
    if user is None:
        raise credentials_exception
    if not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN, 
            detail="Usuário inativo. Contate o administrador."
        )
    return user

def require_admin(current_user: models.User = Depends(get_current_user)) -> models.User:
    if current_user.role != "admin":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Acesso restrito apenas a Administradores."
        )
    return current_user

def require_roles(*allowed_roles: str):
    def role_checker(current_user: models.User = Depends(get_current_user)) -> models.User:
        if current_user.role not in allowed_roles:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Acesso negado para o perfil '{current_user.role}'. Esta operação requer permissão de: {', '.join(allowed_roles)}."
            )
        return current_user
    return role_checker

require_analyst_or_admin = require_roles("admin", "analyst")

def get_user_allowed_group_ids(db: Session, user: models.User, action: Optional[str] = None) -> Optional[List[int]]:
    """
    Retorna a lista de IDs de Grupos de Ativos aos quais o usuário tem acesso.
    - Se o usuário for Administrador ('admin'), retorna None (acesso irrestrito total a todos os grupos).
    - Se o usuário não tiver restrições cadastradas em user_asset_groups (lista vazia), retorna None (acesso global padrão).
    - Se o usuário tiver restrições cadastradas, retorna a lista de IDs permitidos para a respectiva ação (expandindo subgrupos).
    """
    if user.role == "admin":
        return None

    perms = db.query(models.UserAssetGroup).filter(models.UserAssetGroup.user_id == user.id).all()
    if not perms:
        return None

    allowed_base_ids = []
    for p in perms:
        if action == "treat" and not p.can_treat:
            continue
        if action == "import" and not p.can_import:
            continue
        if action == "author" and not p.can_author:
            continue
        allowed_base_ids.append(p.asset_group_id)

    if not allowed_base_ids:
        return []

    # Expand child subgroups recursively across all levels of hierarchy (RBAC multi-level inheritance)
    from app.services.asset_group_service import expand_descendant_group_ids
    return expand_descendant_group_ids(db, allowed_base_ids)

def check_user_group_access(db: Session, user: models.User, asset_group_id: int, action: str = "view"):
    """
    Valida se o usuário possui permissão de acesso ao Grupo de Ativos para a ação informada.
    Lança HTTPException 403 caso o acesso seja negado.
    """
    if user.role == "admin":
        return True

    allowed_ids = get_user_allowed_group_ids(db, user, action=action)
    if allowed_ids is None:
        return True

    if asset_group_id not in allowed_ids:
        action_names = {
            "treat": "tratamento de vulnerabilidades",
            "import": "importação de varreduras (scans)",
            "author": "emissão e autoria de relatórios",
            "view": "visualização de dados"
        }
        act_desc = action_names.get(action, action)
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"Acesso negado: Você não possui permissão para {act_desc} no grupo de ativos selecionado."
        )
    return True

