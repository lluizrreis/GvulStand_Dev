"""
Utilitários de criptografia simétrica para dados sensíveis em repouso.

Usa Fernet (AES-128-CBC + HMAC-SHA256) derivado da SECRET_KEY da aplicação
para criptografar/descriptografar senhas de serviço (ex: bind_password do LDAP)
que precisam ser recuperadas em texto claro para autenticação em sistemas externos.

A chave Fernet é derivada dos primeiros 32 bytes do SHA-256 da SECRET_KEY,
garantindo que a mesma chave de ambiente sempre produza o mesmo resultado.
"""

import base64
import hashlib
import logging

from cryptography.fernet import Fernet, InvalidToken

from app.config import settings

logger = logging.getLogger(__name__)


def _get_fernet() -> Fernet:
    """
    Deriva uma chave Fernet de 32 bytes a partir da SECRET_KEY da aplicação.
    Fernet exige uma chave URL-safe base64 de exatamente 32 bytes.
    """
    raw = settings.SECRET_KEY.encode("utf-8")
    key_bytes = hashlib.sha256(raw).digest()          # 32 bytes
    fernet_key = base64.urlsafe_b64encode(key_bytes)  # base64url(32 bytes) = 44 chars
    return Fernet(fernet_key)


def encrypt_secret(plaintext: str) -> str:
    """
    Criptografa uma string sensível e retorna o token Fernet como string UTF-8.
    Retorna string vazia se o plaintext for vazio ou None.
    """
    if not plaintext:
        return ""
    try:
        f = _get_fernet()
        token = f.encrypt(plaintext.encode("utf-8"))
        return token.decode("utf-8")
    except Exception as exc:
        logger.error("Erro ao criptografar segredo: %s", exc)
        raise RuntimeError("Falha na criptografia do segredo.") from exc


def decrypt_secret(ciphertext: str) -> str:
    """
    Descriptografa um token Fernet e retorna o texto original.
    Retorna string vazia se o ciphertext for vazio ou None.
    Lança ValueError se o token for inválido ou corrompido.
    """
    if not ciphertext:
        return ""
    try:
        f = _get_fernet()
        plaintext = f.decrypt(ciphertext.encode("utf-8"))
        return plaintext.decode("utf-8")
    except InvalidToken as exc:
        logger.error("Token de descriptografia inválido (possível mudança de SECRET_KEY ou dado corrompido).")
        raise ValueError(
            "Não foi possível descriptografar a senha do LDAP. "
            "Se a SECRET_KEY foi alterada, reconfigure a senha de leitura LDAP."
        ) from exc
    except Exception as exc:
        logger.error("Erro inesperado ao descriptografar segredo: %s", exc)
        raise RuntimeError("Falha na descriptografia do segredo.") from exc


def is_encrypted(value: str) -> bool:
    """
    Heurística leve: tokens Fernet começam com 'gAAAAA' (base64url de \x80).
    Útil para detectar senhas legadas em texto puro que ainda não foram migradas.
    """
    if not value:
        return False
    return value.startswith("gAAAAA")
