import pytest
from unittest.mock import patch, MagicMock
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool
from app.database import Base, get_db
from app.main import app
from app import models
from app.auth import get_password_hash

test_engine = create_engine(
    "sqlite:///:memory:",
    connect_args={"check_same_thread": False},
    poolclass=StaticPool
)
TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=test_engine)

def override_get_db():
    db = TestingSessionLocal()
    try:
        yield db
    finally:
        db.close()

@pytest.fixture(scope="module", autouse=True)
def setup_database():
    Base.metadata.create_all(bind=test_engine)
    db = TestingSessionLocal()

    # Seed Admin and Analyst
    admin = models.User(
        username="AdminLdapTest",
        email="admin_ldap@gvulstand.local",
        full_name="Admin LDAP Tester",
        hashed_password=get_password_hash("Admin123"),
        role="admin",
        is_active=True
    )
    analyst = models.User(
        username="AnalystLdapTest",
        email="analyst_ldap@gvulstand.local",
        full_name="Analyst LDAP Tester",
        hashed_password=get_password_hash("Analyst123"),
        role="analyst",
        is_active=True
    )
    db.add(admin)
    db.add(analyst)

    # Initialize default LDAP config
    ldap_cfg = models.LdapConfig(
        id=1,
        is_enabled=False,
        server_host="",
        server_port=389,
        bind_user="",
        bind_password="",
        base_dn=""
    )
    db.add(ldap_cfg)
    db.commit()
    db.close()

    prev_override = app.dependency_overrides.get(get_db)
    app.dependency_overrides[get_db] = override_get_db
    yield
    if prev_override is not None:
        app.dependency_overrides[get_db] = prev_override
    else:
        app.dependency_overrides.pop(get_db, None)

def get_admin_token(client: TestClient) -> str:
    res = client.post("/api/auth/login", json={"username": "AdminLdapTest", "password": "Admin123"})
    assert res.status_code == 200, res.text
    return res.json()["access_token"]

def get_analyst_token(client: TestClient) -> str:
    res = client.post("/api/auth/login", json={"username": "AnalystLdapTest", "password": "Analyst123"})
    assert res.status_code == 200, res.text
    return res.json()["access_token"]

def test_ldap_config_rbac():
    client = TestClient(app)
    analyst_token = get_analyst_token(client)
    headers = {"Authorization": f"Bearer {analyst_token}"}

    # Analyst cannot read LDAP config
    res = client.get("/api/ldap/config", headers=headers)
    assert res.status_code == 403

    # Analyst cannot update LDAP config
    res = client.put("/api/ldap/config", headers=headers, json={"is_enabled": False})
    assert res.status_code == 403

def test_ldap_config_get_and_update():
    client = TestClient(app)
    admin_token = get_admin_token(client)
    headers = {"Authorization": f"Bearer {admin_token}"}

    # Read initial config
    res = client.get("/api/ldap/config", headers=headers)
    assert res.status_code == 200
    data = res.json()
    assert data["is_enabled"] is False
    assert data["server_port"] == 389
    assert data["is_password_configured"] is False

    # Attempt enabling LDAP without required fields should fail (400)
    res_fail = client.put("/api/ldap/config", headers=headers, json={
        "is_enabled": True,
        "server_host": "",
        "server_port": 389,
        "bind_user": "",
        "base_dn": ""
    })
    assert res_fail.status_code == 400

    # Successfully configure and enable LDAP
    res_save = client.put("/api/ldap/config", headers=headers, json={
        "is_enabled": True,
        "server_host": "dc01.empresa.local",
        "server_port": 389,
        "use_ssl": False,
        "use_starttls": False,
        "bind_user": "CN=svc_ldap,OU=ServiceAccounts,DC=empresa,DC=local",
        "bind_password": "SuperSecretBindPassword123",
        "base_dn": "DC=empresa,DC=local",
        "user_search_filter": "(&(objectClass=user)(sAMAccountName={username}))",
        "sam_attribute": "sAMAccountName",
        "name_attribute": "displayName",
        "email_attribute": "mail",
        "connection_timeout": 5
    })
    assert res_save.status_code == 200
    cfg = res_save.json()
    assert cfg["is_enabled"] is True
    assert cfg["server_host"] == "dc01.empresa.local"
    assert cfg["is_password_configured"] is True

    # Read config again and ensure password is not returned in plain text
    res_read = client.get("/api/ldap/config", headers=headers)
    assert res_read.status_code == 200
    cfg2 = res_read.json()
    assert "SuperSecretBindPassword123" not in str(cfg2)
    assert cfg2["is_password_configured"] is True

def test_ldap_test_connection_mocked():
    client = TestClient(app)
    admin_token = get_admin_token(client)
    headers = {"Authorization": f"Bearer {admin_token}"}

    with patch("app.api.routes_ldap.LdapService.test_connection") as mock_test:
        mock_test.return_value = {
            "success": True,
            "message": "Conexão e autenticação com o servidor LDAP/Active Directory realizadas com sucesso!",
            "details": {"host": "dc01.empresa.local", "port": 389}
        }

        res = client.post("/api/ldap/test", headers=headers, json={
            "server_host": "dc01.empresa.local",
            "server_port": 389,
            "bind_user": "CN=svc_ldap,DC=empresa,DC=local",
            "bind_password": "********"  # Uses saved password
        })
        assert res.status_code == 200
        assert res.json()["success"] is True

def test_ldap_validate_user_endpoint():
    client = TestClient(app)
    admin_token = get_admin_token(client)
    headers = {"Authorization": f"Bearer {admin_token}"}

    with patch("app.api.routes_ldap.LdapService.search_user") as mock_search:
        mock_search.return_value = {
            "valid": True,
            "sam_account_name": "mariasilva",
            "full_name": "Maria Silva",
            "email": "maria.silva@empresa.local",
            "distinguished_name": "CN=Maria Silva,OU=Users,DC=empresa,DC=local"
        }

        res = client.get("/api/ldap/validate-user?sam_account_name=mariasilva", headers=headers)
        assert res.status_code == 200
        data = res.json()
        assert data["valid"] is True
        assert data["sam_account_name"] == "mariasilva"
        assert data["full_name"] == "Maria Silva"
        assert data["email"] == "maria.silva@empresa.local"

def test_create_ldap_user_and_authenticate():
    client = TestClient(app)
    admin_token = get_admin_token(client)
    headers = {"Authorization": f"Bearer {admin_token}"}

    # Mock search user when creating LDAP user
    with patch("app.api.routes_users.LdapService.search_user") as mock_search:
        mock_search.return_value = {
            "valid": True,
            "sam_account_name": "joaosantos",
            "full_name": "João Santos",
            "email": "joao.santos@empresa.local",
            "distinguished_name": "CN=João Santos,OU=Users,DC=empresa,DC=local"
        }

        res_create = client.post("/api/users", headers=headers, json={
            "username": "joaosantos",
            "email": "joao.santos@empresa.local",
            "full_name": "João Santos",
            "role": "auditor",  # Manual role selection
            "auth_type": "ldap",
            "sam_account_name": "joaosantos",
            "is_active": True
        })
        assert res_create.status_code == 201, res_create.text
        created_user = res_create.json()
        assert created_user["username"] == "joaosantos"
        assert created_user["role"] == "auditor"
        assert created_user["auth_type"] == "ldap"
        assert created_user["sam_account_name"] == "joaosantos"

    # Authenticate joaosantos via LDAP
    with patch("app.api.routes_auth.LdapService.authenticate_user") as mock_auth:
        mock_auth.return_value = (
            True,
            None,
            {
                "sam_account_name": "joaosantos",
                "full_name": "João Santos",
                "email": "joao.santos@empresa.local"
            }
        )

        res_login = client.post("/api/auth/login", json={
            "username": "joaosantos",
            "password": "DomainPassword2026!"
        })
        assert res_login.status_code == 200, res_login.text
        login_data = res_login.json()
        assert "access_token" in login_data
        assert login_data["user"]["username"] == "joaosantos"
        assert login_data["user"]["role"] == "auditor"
        assert login_data["user"]["auth_type"] == "ldap"

        # Check me
        ldap_token = login_data["access_token"]
        res_me = client.get("/api/auth/me", headers={"Authorization": f"Bearer {ldap_token}"})
        assert res_me.status_code == 200
        assert res_me.json()["role"] == "auditor"

        # Check that LDAP user cannot change password locally
        res_change = client.post("/api/auth/change-password", headers={"Authorization": f"Bearer {ldap_token}"}, json={
            "old_password": "DomainPassword2026!",
            "new_password": "NewLocalPassword!"
        })
        assert res_change.status_code == 400
        assert "Active Directory" in res_change.text

def test_ldap_disabled_prevents_login_and_creation():
    client = TestClient(app)
    admin_token = get_admin_token(client)
    headers = {"Authorization": f"Bearer {admin_token}"}

    # Disable LDAP
    res_disable = client.put("/api/ldap/config", headers=headers, json={
        "is_enabled": False,
        "server_host": "dc01.empresa.local",
        "server_port": 389,
        "bind_user": "svc_ldap",
        "base_dn": "DC=empresa,DC=local"
    })
    assert res_disable.status_code == 200
    assert res_disable.json()["is_enabled"] is False

    # Attempt to login with LDAP user should fail because LDAP is disabled
    res_login = client.post("/api/auth/login", json={
        "username": "joaosantos",
        "password": "DomainPassword2026!"
    })
    assert res_login.status_code == 403
    assert "desabilitada" in res_login.text

    # Attempt to create new LDAP user should fail
    res_create = client.post("/api/users", headers=headers, json={
        "username": "novousuario",
        "email": "novo@empresa.local",
        "role": "analyst",
        "auth_type": "ldap",
        "sam_account_name": "novousuario"
    })
    assert res_create.status_code == 400
    assert "desabilitada" in res_create.text

    # Manual user login still works fine!
    res_admin_login = client.post("/api/auth/login", json={
        "username": "AdminLdapTest",
        "password": "Admin123"
    })
    assert res_admin_login.status_code == 200

def test_ldap_bind_password_is_encrypted_at_rest():
    """
    Garante que a bind_password do LDAP é armazenada criptografada no banco
    e que a descriptografia recupera o valor original corretamente.
    """
    from app.crypto_utils import encrypt_secret, decrypt_secret, is_encrypted

    plaintext = "MinhaS3nhaS3creta!"

    # Criptografa e verifica que o resultado não é o texto original
    encrypted = encrypt_secret(plaintext)
    assert encrypted != plaintext
    assert len(encrypted) > 0
    assert "MinhaS3nhaS3creta!" not in encrypted

    # Tokens Fernet são detectados corretamente
    assert is_encrypted(encrypted) is True
    assert is_encrypted(plaintext) is False
    assert is_encrypted("") is False

    # Descriptografa e recupera o valor original
    decrypted = decrypt_secret(encrypted)
    assert decrypted == plaintext

    # Via API: salvar configuração e verificar que o banco armazena criptografado
    client = TestClient(app)
    admin_token = get_admin_token(client)
    headers = {"Authorization": f"Bearer {admin_token}"}

    # Re-habilita LDAP para este teste
    client.put("/api/ldap/config", headers=headers, json={
        "is_enabled": True,
        "server_host": "dc01.empresa.local",
        "server_port": 389,
        "bind_user": "CN=svc_ldap,DC=empresa,DC=local",
        "bind_password": plaintext,
        "base_dn": "DC=empresa,DC=local"
    })

    # Lê diretamente do banco e confirma que está criptografado
    db = TestingSessionLocal()
    cfg = db.query(models.LdapConfig).filter(models.LdapConfig.id == 1).first()
    assert cfg is not None
    assert cfg.bind_password != plaintext, "A senha NÃO deve ser salva em texto puro no banco!"
    assert is_encrypted(cfg.bind_password), "A senha deve estar no formato Fernet criptografado."

    # Confirma que a descriptografia recupera a senha original
    assert decrypt_secret(cfg.bind_password) == plaintext
    db.close()
