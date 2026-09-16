import secrets
from typing import List
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session
from sqlalchemy import func
from sqlalchemy.exc import IntegrityError
from app.database import get_db
from app import models, schemas
from app.auth import get_current_user, require_admin, get_password_hash
from app.services.ldap_service import LdapService

router = APIRouter(prefix="/users", tags=["Gestão de Usuários"])

def format_user_out(user: models.User, db: Session) -> schemas.UserOut:
    out = schemas.UserOut.model_validate(user)
    perms = db.query(models.UserAssetGroup).filter(models.UserAssetGroup.user_id == user.id).all()
    out.allowed_groups = []
    out.allowed_group_ids = []
    for p in perms:
        p_out = schemas.UserGroupPermissionOut.model_validate(p)
        p_out.asset_group_name = p.asset_group.name if p.asset_group else ""
        out.allowed_groups.append(p_out)
        out.allowed_group_ids.append(p.asset_group_id)
    return out

@router.get("", response_model=List[schemas.UserOut])
def list_users(
    db: Session = Depends(get_db),
    current_user: models.User = Depends(require_admin)
):
    """Lista todos os usuários cadastrados (Requer perfil Administrador)."""
    users = db.query(models.User).order_by(models.User.id.asc()).all()
    return [format_user_out(u, db) for u in users]

@router.post("", response_model=schemas.UserOut, status_code=status.HTTP_201_CREATED)
def create_user(
    user_in: schemas.UserCreate,
    db: Session = Depends(get_db),
    current_user: models.User = Depends(require_admin)
):
    """
    Cria um novo usuário no sistema (Requer perfil Administrador).
    Suporta cadastro manual local ou vínculo com conta de rede Active Directory (LDAP).
    """
    auth_type = getattr(user_in, "auth_type", "local") or "local"

    if auth_type == "ldap":
        sam_account_name = (user_in.sam_account_name or user_in.username or "").strip()
        if not sam_account_name:
            raise HTTPException(status_code=400, detail="Para cadastrar usuário de rede / LDAP, informe o sAMAccountName.")

        # Verificar se integração LDAP está habilitada
        ldap_cfg = db.query(models.LdapConfig).filter(models.LdapConfig.id == 1).first()
        if not ldap_cfg or not ldap_cfg.is_enabled:
            raise HTTPException(
                status_code=400,
                detail="A integração LDAP está desabilitada no sistema. Ative a integração na tela de Configuração LDAP antes de cadastrar usuários de rede."
            )

        # Validar e buscar dados no Active Directory
        try:
            ldap_info = LdapService.search_user(ldap_cfg, sam_account_name)
        except Exception as e:
            raise HTTPException(
                status_code=400,
                detail=f"Erro ao validar sAMAccountName no Active Directory: {str(e)}"
            )

        if not ldap_info:
            raise HTTPException(
                status_code=404,
                detail=f"Usuário com sAMAccountName '{sam_account_name}' não foi localizado no Active Directory."
            )

        username = ldap_info["sam_account_name"]
        full_name = user_in.full_name.strip() if user_in.full_name and user_in.full_name.strip() else ldap_info["full_name"]
        email = user_in.email.strip() if user_in.email and user_in.email.strip() else ldap_info["email"]

        existing_username = db.query(models.User).filter(func.lower(models.User.username) == username.lower()).first()
        if existing_username:
            raise HTTPException(status_code=400, detail="Este nome de usuário / sAMAccountName já está cadastrado no sistema.")

        existing_email = db.query(models.User).filter(func.lower(models.User.email) == email.lower()).first()
        if existing_email:
            raise HTTPException(status_code=400, detail="O e-mail deste usuário já está cadastrado no sistema.")

        unusable_hash = get_password_hash("NO_LOCAL_LOGIN_LDAP_MANAGED_" + secrets.token_hex(16))

        user = models.User(
            username=username,
            email=email,
            full_name=full_name,
            hashed_password=unusable_hash,
            role=user_in.role if user_in.role in ["admin", "analyst", "auditor"] else "analyst",
            is_active=user_in.is_active,
            auth_type="ldap",
            sam_account_name=sam_account_name
        )
    else:
        # Usuário manual local
        if not user_in.password:
            raise HTTPException(status_code=400, detail="A senha é obrigatória para cadastro manual de usuário.")

        username = user_in.username.strip()
        existing_username = db.query(models.User).filter(func.lower(models.User.username) == username.lower()).first()
        if existing_username:
            raise HTTPException(status_code=400, detail="Este nome de usuário já está em uso.")

        email = user_in.email.strip()
        existing_email = db.query(models.User).filter(func.lower(models.User.email) == email.lower()).first()
        if existing_email:
            raise HTTPException(status_code=400, detail="Este e-mail já está cadastrado.")

        user = models.User(
            username=username,
            email=email,
            full_name=user_in.full_name,
            hashed_password=get_password_hash(user_in.password),
            role=user_in.role if user_in.role in ["admin", "analyst", "auditor"] else "analyst",
            is_active=user_in.is_active,
            auth_type="local",
            sam_account_name=None
        )

    db.add(user)
    try:
        db.commit()
        db.refresh(user)
    except IntegrityError:
        db.rollback()
        raise HTTPException(status_code=400, detail="Nome de usuário ou e-mail já em uso.")

    if user_in.allowed_groups and user.role != "admin":
        for g_perm in user_in.allowed_groups:
            grp = db.query(models.AssetGroup).filter(models.AssetGroup.id == g_perm.asset_group_id).first()
            if grp:
                db.add(models.UserAssetGroup(
                    user_id=user.id,
                    asset_group_id=g_perm.asset_group_id,
                    can_treat=g_perm.can_treat,
                    can_import=g_perm.can_import,
                    can_author=g_perm.can_author
                ))
        db.commit()

    return format_user_out(user, db)

@router.get("/{user_id}", response_model=schemas.UserOut)
def get_user(
    user_id: int,
    db: Session = Depends(get_db),
    current_user: models.User = Depends(require_admin)
):
    """Obtém detalhes de um usuário específico (Requer perfil Administrador)."""
    user = db.query(models.User).filter(models.User.id == user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="Usuário não encontrado.")
    return format_user_out(user, db)

@router.put("/{user_id}", response_model=schemas.UserOut)
def update_user(
    user_id: int,
    user_update: schemas.UserUpdate,
    db: Session = Depends(get_db),
    current_user: models.User = Depends(require_admin)
):
    """Atualiza dados e permissões de um usuário (Requer Administrador)."""
    user = db.query(models.User).filter(models.User.id == user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="Usuário não encontrado.")

    if user_update.email is not None:
        email_clean = user_update.email.strip()
        email_check = db.query(models.User).filter(models.User.email == email_clean, models.User.id != user_id).first()
        if email_check:
            raise HTTPException(status_code=400, detail="Este e-mail já está em uso por outro usuário.")
        user.email = email_clean

    if user_update.full_name is not None:
        user.full_name = user_update.full_name.strip()

    if user_update.role is not None:
        if user_update.role in ["admin", "analyst", "auditor"]:
            user.role = user_update.role

    if user_update.is_active is not None:
        # Prevent disabling the last active admin
        if not user_update.is_active and user.role == "admin":
            admin_count = db.query(models.User).filter(models.User.role == "admin", models.User.is_active == True).count()
            if admin_count <= 1:
                raise HTTPException(status_code=400, detail="Não é permitido desativar o único administrador ativo.")
        user.is_active = user_update.is_active

    if user_update.password:
        if getattr(user, "auth_type", "local") == "ldap":
            raise HTTPException(
                status_code=400,
                detail="Usuários autenticados via Active Directory/LDAP possuem credenciais gerenciadas pelo domínio de rede. A senha não pode ser alterada localmente."
            )
        user.hashed_password = get_password_hash(user_update.password)

    if user_update.allowed_groups is not None:
        db.query(models.UserAssetGroup).filter(models.UserAssetGroup.user_id == user_id).delete()
        if user.role != "admin":
            for g_perm in user_update.allowed_groups:
                grp = db.query(models.AssetGroup).filter(models.AssetGroup.id == g_perm.asset_group_id).first()
                if grp:
                    db.add(models.UserAssetGroup(
                        user_id=user.id,
                        asset_group_id=g_perm.asset_group_id,
                        can_treat=g_perm.can_treat,
                        can_import=g_perm.can_import,
                        can_author=g_perm.can_author
                    ))

    try:
        db.commit()
        db.refresh(user)
    except IntegrityError:
        db.rollback()
        raise HTTPException(status_code=400, detail="Nome de usuário ou e-mail já em uso.")
    return format_user_out(user, db)

@router.delete("/{user_id}")
def delete_user(
    user_id: int,
    db: Session = Depends(get_db),
    current_user: models.User = Depends(require_admin)
):
    """Exclui um usuário do sistema (Requer Administrador)."""
    user = db.query(models.User).filter(models.User.id == user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="Usuário não encontrado.")

    if user.id == current_user.id:
        raise HTTPException(status_code=400, detail="Você não pode excluir sua própria conta enquanto conectado.")

    if user.role == "admin":
        admin_count = db.query(models.User).filter(models.User.role == "admin").count()
        if admin_count <= 1:
            raise HTTPException(status_code=400, detail="Não é permitido excluir o único administrador do sistema.")

    db.delete(user)
    db.commit()
    return {"message": "Usuário excluído com sucesso."}
