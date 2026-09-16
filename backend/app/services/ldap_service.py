import logging
import socket
from typing import Optional, Tuple, Dict, Any
import ldap3
from ldap3.core.exceptions import LDAPException, LDAPBindError, LDAPSocketOpenError
from app.crypto_utils import decrypt_secret, is_encrypted

logger = logging.getLogger(__name__)

class LdapService:
    @staticmethod
    def get_server(host: str, port: int, use_ssl: bool, timeout: int = 5) -> ldap3.Server:
        return ldap3.Server(
            host=host,
            port=port,
            use_ssl=use_ssl,
            get_info=ldap3.NONE,
            connect_timeout=timeout
        )

    @classmethod
    def test_connection(
        cls,
        server_host: str,
        server_port: int,
        use_ssl: bool,
        use_starttls: bool,
        bind_user: str,
        bind_password: str,
        base_dn: Optional[str] = None,
        timeout: int = 5
    ) -> Dict[str, Any]:
        """
        Tests LDAP / Active Directory connection and authentication with the reader user.
        """
        if not server_host:
            return {"success": False, "message": "O endereço do servidor LDAP/AD deve ser informado."}
        if not server_port:
            return {"success": False, "message": "A porta do servidor LDAP/AD deve ser informada."}
        if not bind_user:
            return {"success": False, "message": "O usuário de leitura/consulta (Bind User) deve ser informado."}
        if not bind_password:
            return {"success": False, "message": "A senha do usuário de leitura/consulta deve ser informada."}

        try:
            server = cls.get_server(
                host=server_host,
                port=server_port,
                use_ssl=use_ssl,
                timeout=timeout
            )
            conn = ldap3.Connection(
                server,
                user=bind_user,
                password=bind_password,
                authentication=ldap3.SIMPLE,
                auto_bind=False,
                raise_exceptions=True
            )

            conn.open()
            if use_starttls and not use_ssl:
                conn.start_tls()
            
            bound = conn.bind()
            if not bound:
                return {
                    "success": False,
                    "message": f"Falha na autenticação do usuário de consulta: {conn.result.get('description', 'Credenciais inválidas.')}"
                }

            # If base_dn is provided, verify query permission
            search_ok = True
            if base_dn:
                try:
                    conn.search(
                        search_base=base_dn,
                        search_filter="(objectClass=*)",
                        search_scope=ldap3.BASE,
                        attributes=["cn", "namingContexts", "defaultNamingContext"],
                        size_limit=1
                    )
                except Exception as search_err:
                    logger.warning(f"LDAP base_dn search test warning: {search_err}")
                    search_ok = False

            conn.unbind()
            
            msg = "Conexão e autenticação com o servidor LDAP/Active Directory realizadas com sucesso!"
            if base_dn and not search_ok:
                msg += f" (Aviso: Não foi possível ler o Base DN '{base_dn}'. Verifique se o caminho existe e as permissões do usuário)."

            return {
                "success": True,
                "message": msg,
                "details": {
                    "host": server_host,
                    "port": server_port,
                    "ssl": use_ssl,
                    "starttls": use_starttls,
                    "base_dn_verified": search_ok if base_dn else None
                }
            }
        except LDAPSocketOpenError as e:
            logger.error(f"LDAP Socket Open Error: {e}")
            return {
                "success": False,
                "message": f"Não foi possível conectar ao servidor {server_host}:{server_port}. Verifique se o host está acessível na rede e a porta correta."
            }
        except LDAPBindError as e:
            logger.error(f"LDAP Bind Error: {e}")
            return {
                "success": False,
                "message": f"Falha na autenticação do usuário de leitura (Bind User). Verifique o usuário e senha informados."
            }
        except socket.timeout:
            return {
                "success": False,
                "message": f"Tempo limite ({timeout}s) esgotado ao tentar conectar a {server_host}:{server_port}."
            }
        except Exception as e:
            logger.error(f"LDAP unexpected connection error: {e}")
            return {
                "success": False,
                "message": f"Erro na conexão LDAP: {str(e)}"
            }

    @classmethod
    def search_user(cls, config, sam_account_name: str) -> Optional[Dict[str, Any]]:
        """
        Searches for a user by sAMAccountName in the Active Directory using configured reader credentials.
        """
        if not config or not config.is_enabled:
            return None

        if not config.server_host or not config.bind_user or not config.bind_password or not config.base_dn:
            logger.error("LDAP search called with incomplete configuration.")
            return None

        # Descriptografa a senha armazenada (suporta legado em texto puro)
        try:
            bind_pwd = decrypt_secret(config.bind_password) if is_encrypted(config.bind_password) else config.bind_password
        except (ValueError, RuntimeError) as exc:
            logger.error("Falha ao descriptografar bind_password para search_user: %s", exc)
            raise RuntimeError("Não foi possível descriptografar a senha do usuário de leitura LDAP.") from exc

        clean_sam = sam_account_name.strip()
        escaped_sam = ldap3.utils.conv.escape_filter_chars(clean_sam)

        # Build search filter
        filter_pattern = config.user_search_filter or "(&(objectClass=user)(sAMAccountName={username}))"
        if "{username}" in filter_pattern:
            user_filter = filter_pattern.replace("{username}", escaped_sam)
        else:
            user_filter = f"(&(objectClass=user)(sAMAccountName={escaped_sam}))"

        sam_attr = config.sam_attribute or "sAMAccountName"
        name_attr = config.name_attribute or "displayName"
        email_attr = config.email_attribute or "mail"

        attributes = list(set([
            sam_attr,
            name_attr,
            email_attr,
            "displayName",
            "cn",
            "mail",
            "userPrincipalName",
            "sAMAccountName"
        ]))

        try:
            server = cls.get_server(
                host=config.server_host,
                port=config.server_port,
                use_ssl=config.use_ssl,
                timeout=config.connection_timeout or 5
            )
            conn = ldap3.Connection(
                server,
                user=config.bind_user,
                password=bind_pwd,
                authentication=ldap3.SIMPLE,
                auto_bind=False,
                raise_exceptions=True
            )

            conn.open()
            if config.use_starttls and not config.use_ssl:
                conn.start_tls()
            
            conn.bind()

            conn.search(
                search_base=config.base_dn,
                search_filter=user_filter,
                search_scope=ldap3.SUBTREE,
                attributes=attributes
            )

            if not conn.entries:
                conn.unbind()
                return None

            entry = conn.entries[0]
            dn = entry.entry_dn

            # Extract fields with sensible fallbacks
            found_sam = clean_sam
            if hasattr(entry, sam_attr) and getattr(entry, sam_attr).value:
                found_sam = str(getattr(entry, sam_attr).value)
            elif hasattr(entry, "sAMAccountName") and entry.sAMAccountName.value:
                found_sam = str(entry.sAMAccountName.value)

            full_name = ""
            if hasattr(entry, name_attr) and getattr(entry, name_attr).value:
                full_name = str(getattr(entry, name_attr).value)
            elif hasattr(entry, "displayName") and entry.displayName.value:
                full_name = str(entry.displayName.value)
            elif hasattr(entry, "cn") and entry.cn.value:
                full_name = str(entry.cn.value)

            email = ""
            if hasattr(entry, email_attr) and getattr(entry, email_attr).value:
                email = str(getattr(entry, email_attr).value)
            elif hasattr(entry, "mail") and entry.mail.value:
                email = str(entry.mail.value)
            elif hasattr(entry, "userPrincipalName") and entry.userPrincipalName.value:
                upn = str(entry.userPrincipalName.value)
                if "@" in upn:
                    email = upn

            conn.unbind()

            return {
                "valid": True,
                "sam_account_name": found_sam,
                "full_name": full_name or found_sam,
                "email": email or f"{found_sam}@ad.local",
                "distinguished_name": dn
            }
        except Exception as e:
            logger.error(f"Error searching user in LDAP ({clean_sam}): {e}")
            raise e

    @classmethod
    def authenticate_user(
        cls,
        config,
        username_or_sam: str,
        password: str
    ) -> Tuple[bool, Optional[str], Optional[Dict[str, Any]]]:
        """
        Authenticates a user against Active Directory.
        1. Queries user by sAMAccountName with the reader account to get DN and profile info.
        2. Tries to bind with user's DN and the provided password.
        """
        if not config or not config.is_enabled:
            return False, "A integração LDAP está desabilitada no sistema.", None

        if not password:
            return False, "Senha não informada.", None

        # Step 1: Query user to get exact DN
        try:
            user_info = cls.search_user(config, username_or_sam)
        except Exception as e:
            return False, f"Falha na consulta ao Active Directory: {str(e)}", None

        if not user_info or not user_info.get("distinguished_name"):
            return False, "Usuário não localizado no Active Directory.", None

        user_dn = user_info["distinguished_name"]

        # Step 2: Bind as the user with their password
        try:
            server = cls.get_server(
                host=config.server_host,
                port=config.server_port,
                use_ssl=config.use_ssl,
                timeout=config.connection_timeout or 5
            )
            user_conn = ldap3.Connection(
                server,
                user=user_dn,
                password=password,
                authentication=ldap3.SIMPLE,
                auto_bind=False
            )

            user_conn.open()
            if config.use_starttls and not config.use_ssl:
                user_conn.start_tls()

            bound = user_conn.bind()
            user_conn.unbind()

            if bound:
                return True, None, user_info
            else:
                return False, "Senha incorreta no Active Directory.", None
        except LDAPSocketOpenError:
            return False, "Não foi possível conectar ao servidor Active Directory.", None
        except LDAPBindError:
            return False, "Senha incorreta ou conta bloqueada no Active Directory.", None
        except Exception as e:
            logger.error(f"LDAP authenticate_user error: {e}")
            return False, f"Erro durante autenticação LDAP: {str(e)}", None
