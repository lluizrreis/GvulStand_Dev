from fastapi import APIRouter, Depends, HTTPException, status, Query
from sqlalchemy.orm import Session
from app.database import get_db
from app import models, schemas
from app.auth import require_admin
from app.services.ldap_service import LdapService
from app.crypto_utils import encrypt_secret, decrypt_secret, is_encrypted

router = APIRouter(prefix="/ldap", tags=["Integração LDAP / Active Directory"])

def get_or_create_ldap_config(db: Session) -> models.LdapConfig:
    config = db.query(models.LdapConfig).filter(models.LdapConfig.id == 1).first()
    if not config:
        config = models.LdapConfig(
            id=1,
            is_enabled=False,
            server_host="",
            server_port=389,
            use_ssl=False,
            use_starttls=False,
            bind_user="",
            bind_password="",
            base_dn="",
            user_search_filter="(&(objectClass=user)(sAMAccountName={username}))",
            sam_attribute="sAMAccountName",
            name_attribute="displayName",
            email_attribute="mail",
            connection_timeout=5
        )
        db.add(config)
        db.commit()
        db.refresh(config)
    return config

@router.get("/config", response_model=schemas.LdapConfigOut)
def get_ldap_config(
    db: Session = Depends(get_db),
    current_user: models.User = Depends(require_admin)
):
    """
    Retorna as configurações atuais da integração LDAP/AD.
    Acesso restrito a Administradores. A senha é ocultada/mascarada.
    """
    config = get_or_create_ldap_config(db)
    has_pwd = bool(config.bind_password)
    
    return schemas.LdapConfigOut(
        id=config.id,
        is_enabled=config.is_enabled,
        server_host=config.server_host or "",
        server_port=config.server_port or 389,
        use_ssl=config.use_ssl or False,
        use_starttls=config.use_starttls or False,
        bind_user=config.bind_user or "",
        base_dn=config.base_dn or "",
        user_search_filter=config.user_search_filter or "(&(objectClass=user)(sAMAccountName={username}))",
        sam_attribute=config.sam_attribute or "sAMAccountName",
        name_attribute=config.name_attribute or "displayName",
        email_attribute=config.email_attribute or "mail",
        connection_timeout=config.connection_timeout or 5,
        is_password_configured=has_pwd,
        updated_at=config.updated_at
    )

@router.put("/config", response_model=schemas.LdapConfigOut)
def update_ldap_config(
    payload: schemas.LdapConfigUpdate,
    db: Session = Depends(get_db),
    current_user: models.User = Depends(require_admin)
):
    """
    Atualiza as configurações de integração LDAP/AD.
    Quando habilitado, os campos de servidor, porta, bind_user e base_dn são obrigatórios.
    """
    config = get_or_create_ldap_config(db)

    # Validar campos se a integração estiver sendo habilitada
    if payload.is_enabled:
        if not payload.server_host or not payload.server_host.strip():
            raise HTTPException(status_code=400, detail="Ao habilitar a integração LDAP, o servidor (Host/IP) é obrigatório.")
        if not payload.server_port or payload.server_port <= 0:
            raise HTTPException(status_code=400, detail="Ao habilitar a integração LDAP, uma porta válida (ex: 389 ou 636) é obrigatória.")
        if not payload.bind_user or not payload.bind_user.strip():
            raise HTTPException(status_code=400, detail="Ao habilitar a integração LDAP, o usuário de leitura/bind é obrigatório.")
        if not payload.base_dn or not payload.base_dn.strip():
            raise HTTPException(status_code=400, detail="Ao habilitar a integração LDAP, o Base DN de busca (ex: DC=empresa,DC=local) é obrigatório.")
        # Se for habilitado e não havia senha antes nem foi passada agora
        effective_pwd = payload.bind_password.strip() if payload.bind_password else ""
        if (not effective_pwd or effective_pwd == "********") and not config.bind_password:
            raise HTTPException(status_code=400, detail="Ao habilitar a integração LDAP, a senha do usuário de leitura é obrigatória.")

    config.is_enabled = payload.is_enabled
    config.server_host = payload.server_host.strip() if payload.server_host else ""
    config.server_port = payload.server_port or 389
    config.use_ssl = payload.use_ssl
    config.use_starttls = payload.use_starttls
    config.bind_user = payload.bind_user.strip() if payload.bind_user else ""
    config.base_dn = payload.base_dn.strip() if payload.base_dn else ""
    config.user_search_filter = payload.user_search_filter.strip() if payload.user_search_filter else "(&(objectClass=user)(sAMAccountName={username}))"
    config.sam_attribute = payload.sam_attribute.strip() if payload.sam_attribute else "sAMAccountName"
    config.name_attribute = payload.name_attribute.strip() if payload.name_attribute else "displayName"
    config.email_attribute = payload.email_attribute.strip() if payload.email_attribute else "mail"
    config.connection_timeout = payload.connection_timeout if (payload.connection_timeout and payload.connection_timeout > 0) else 5

    # Atualiza a senha se fornecida e não for a máscara
    if payload.bind_password and payload.bind_password.strip() and payload.bind_password.strip() != "********":
        config.bind_password = encrypt_secret(payload.bind_password.strip())

    db.commit()
    db.refresh(config)

    return schemas.LdapConfigOut(
        id=config.id,
        is_enabled=config.is_enabled,
        server_host=config.server_host,
        server_port=config.server_port,
        use_ssl=config.use_ssl,
        use_starttls=config.use_starttls,
        bind_user=config.bind_user,
        base_dn=config.base_dn,
        user_search_filter=config.user_search_filter,
        sam_attribute=config.sam_attribute,
        name_attribute=config.name_attribute,
        email_attribute=config.email_attribute,
        connection_timeout=config.connection_timeout,
        is_password_configured=bool(config.bind_password),
        updated_at=config.updated_at
    )

@router.post("/test", response_model=schemas.LdapTestResponse)
def test_ldap_connection(
    payload: schemas.LdapTestRequest,
    db: Session = Depends(get_db),
    current_user: models.User = Depends(require_admin)
):
    """
    Testa a conectividade com o servidor LDAP e a autenticação do usuário leitor/bind.
    Pode usar a senha enviada ou a senha salva no banco.
    """
    effective_password = payload.bind_password
    if not effective_password or effective_password == "********":
        saved_config = db.query(models.LdapConfig).filter(models.LdapConfig.id == 1).first()
        if saved_config and saved_config.bind_password:
            try:
                effective_password = decrypt_secret(saved_config.bind_password)
            except (ValueError, RuntimeError):
                return schemas.LdapTestResponse(
                    success=False,
                    message="Não foi possível descriptografar a senha salva. Reconfigure a senha do usuário de leitura LDAP."
                )

    if not effective_password:
        return schemas.LdapTestResponse(
            success=False,
            message="Senha do usuário de leitura não informada para o teste."
        )

    result = LdapService.test_connection(
        server_host=payload.server_host.strip() if payload.server_host else "",
        server_port=payload.server_port or 389,
        use_ssl=payload.use_ssl,
        use_starttls=payload.use_starttls,
        bind_user=payload.bind_user.strip() if payload.bind_user else "",
        bind_password=effective_password,
        base_dn=payload.base_dn.strip() if payload.base_dn else None,
        timeout=payload.connection_timeout or 5
    )

    return schemas.LdapTestResponse(
        success=result["success"],
        message=result["message"],
        details=result.get("details")
    )

@router.get("/validate-user", response_model=schemas.LdapValidateUserResponse)
def validate_ldap_user(
    sam_account_name: str = Query(..., description="sAMAccountName do usuário no Active Directory"),
    db: Session = Depends(get_db),
    current_user: models.User = Depends(require_admin)
):
    """
    Valida e consulta os dados de um usuário no Active Directory pelo sAMAccountName.
    Utilizado na tela de Gestão de Usuários para preencher nome e e-mail corporativo.
    """
    config = db.query(models.LdapConfig).filter(models.LdapConfig.id == 1).first()
    if not config or not config.is_enabled:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="A integração LDAP/Active Directory está desabilitada no sistema. Ative a integração na tela de Configuração LDAP antes de validar contas de rede."
        )

    clean_sam = sam_account_name.strip()
    if not clean_sam:
        raise HTTPException(status_code=400, detail="O sAMAccountName deve ser informado.")

    try:
        user_info = LdapService.search_user(config, clean_sam)
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail=f"Falha de comunicação com o servidor LDAP/Active Directory: {str(e)}"
        )

    if not user_info:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Usuário com sAMAccountName '{clean_sam}' não foi encontrado no Active Directory."
        )

    return schemas.LdapValidateUserResponse(
        valid=True,
        sam_account_name=user_info["sam_account_name"],
        full_name=user_info["full_name"],
        email=user_info["email"],
        distinguished_name=user_info.get("distinguished_name"),
        message="Usuário localizado com sucesso no Active Directory."
    )
