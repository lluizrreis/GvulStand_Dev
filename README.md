# 🛡️ GvulStand - Sistema de Gestão de Vulnerabilidades

**GvulStand** é um sistema web completo e moderno para Gestão e Governança de Vulnerabilidades de Segurança da Informação baseado na importação e análise de relatórios em CSV do **Tenable / Nessus**, desenvolvido em conformidade com as melhores práticas de mercado e os padrões normativos **ISO/IEC 27001 / ISO 27002** (Controles de Segurança e Tratamento de Riscos Técnicos) e **ISO 9001** (Melhoria Contínua da Qualidade - Ciclo PDCA).

---

## 🎯 Principais Funcionalidades

### 1. Autenticação & Controle de Acesso (RBAC)
- Credenciais iniciais padrão: Usuário `Admin` / Senha `Admin`
- Três perfis de acesso: **Administrador**, **Analista de Segurança** e **Auditor ISO**
- Autenticação local com JWT (HS256, 24h) e senhas criptografadas com **bcrypt**
- **Integração com Active Directory / LDAP** (LDAP, LDAPS e StartTLS)
  - Criação de usuários vinculados ao AD via `sAMAccountName`
  - Autenticação corporativa transparente com sincronização de nome e e-mail
  - Configuração centralizada com máscara de senha na resposta da API
- Alteração de senha própria pelo usuário autenticado

### 2. Governança Alinhada à ISO/IEC 27000 e ISO 9000
- **Índice de Postura de Risco ISO 27001 (Controle 8.8)**: cálculo ponderado de exposição ao risco
- **Taxa de Eficácia de Remediação ISO 9001 (PDCA)**: acompanhamento de resolução e conformidade com SLAs
- **Ciclo de Vida do Tratamento**: status *Open*, *In Remediation*, *Accepted Risk*, *Remediated* com registro de auditoria (quem tratou e quando)
- **Audit Trail completo**: `treated_by_username` e `treated_at` gravados em cada apontamento

### 3. Dashboard Executivo & KPIs
- Cards de severidade quantitativa (Critical, High, Medium, Low, Info)
- Cards de governança com contadores de tratativa por criticidade
- **Vulnerability Priority Rating (VPR)** Tenable nas faixas 9-10, 7-8.9, 4-6.9 e 0-3.9
- **Aging de vulnerabilidades** em 4 faixas: 0-30, 31-60, 61-90 e >90 dias
- **Matriz de Aging granular** em 6 buckets: 0-7, 8-14, 15-30, 31-60, 61-90 e 90+ dias por severidade
- **SLA Progress** por severidade: itens dentro e fora do prazo
- **Scan Health & Cobertura de Credenciais**: qualidade da coleta por host
- **Vetores de Exploração**: malware, frameworks públicos (Metasploit), exploit remoto, etc.
- **Research & Patch Advisory**: patches pendentes vs. aplicados
- Contagem de CVEs únicos por criticidade

### 4. Top 100 Vulnerabilidades Críticas
- Tabela priorizada por exploit disponível, CVSS v3 e volume de hosts afetados
- Drill-down interativo com solução completa do fabricante e lista de todos os hosts/portas afetados

### 5. Top 20 Hosts Críticos com Exploits Públicos
- Identificação dos hosts de altíssimo risco com exploits em frameworks conhecidos (Metasploit, Exploit-DB, CANVAS, Core Impact, D2 Elliot)
- Exibe IP, hostname, OS, grupo de ativos, score de risco e frameworks aplicáveis

### 6. Central de Relatórios & Exportação PDF
- **Relatório Sumário Executivo** para Diretoria/C-Level: inventário, detecção de SO em EOL, termômetro de risco, top 5 vulnerabilidades e indicadores de SLA/MTTR
- **Relatório Técnico Detalhado** ativo por ativo: CVEs, portas TCP/UDP, plugin outputs, vetores de exploração
- Exportação PDF via navegador (`window.print()`) e via **ReportLab** no backend
- Parametrização: título, escopo, grupo de ativos, período, equipe emissora e classificação da informação

### 7. Comparativo Antes vs. Depois (PDCA ISO 9001)
- Seleção livre de qualquer par de scans do grupo para cruzamento analítico
- Identificação de: 🟢 Vulnerabilidades Remediadas | 🟡 Persistentes | 🔴 Novas/Regressões
- Cálculo automático de Taxa de Resolução (%) e Redução Líquida de Risco (%)

### 8. Grupos de Ativos
- **Hierarquia de grupos pai/filho** com subgrupos e SLAs independentes por severidade
- Permissões granulares por usuário + grupo: `can_treat`, `can_import`, `can_author`
- Filtros de dashboard e relatórios por grupo específico ou consolidado geral

### 9. Gestão de Scans
- Upload de CSV Nessus/Tenable com suporte a arquivos massivos (100+ MB)
- Tipos de scan: **Baseline** (antes) e **Retest** (pós-tratativa)
- Data da varredura desacoplada da data de upload (`scan_date` editável)
- **Diagnóstico de Scan Health**: mapeamento de falhas por ICMP, autenticação Windows/SSH e escalação `sudo`
- Exportação de modelo CSV para testes diretamente na interface

### 10. Explorador de Vulnerabilidades
- Listagem paginada (até 200 por página) com filtros avançados: severidade, status de tratativa, exploit, busca textual, host, grupo, scan
- Tratamento em massa (bulk update) com registro de auditoria
- Detalhamento individual com modal completo de solução e hosts afetados

### 11. Parâmetros Globais do Sistema (Administração Pontual)
- **Definição de Fuso Horário Operacional**: lista de fusos horários (com foco no Brasil e padrões internacionais) para conversão e registro fidedigno de carimbos de auditoria, relatórios e emissões com relógio dinâmico ao vivo (*Live Clock*).
- **Prazos Padrão de SLA por Criticidade**: configuração centralizada de prazos de remediação em dias (Críticas, Altas, Médias e Baixas) com botão de replicação em massa para todos os grupos de ativos.
- **Expurgo Automático de Vulnerabilidades / Falso-Positivo**: exclusão automática de Plugins ou IDs informados de todos os cálculos de indicadores, dashboards, relatórios técnicos/executivos, conformidade com SLA e comparativos antes vs. depois, com simulação em tempo real (*preview*) antes de aplicar.

---

## 🚀 Como Executar

### Opção 1: Docker & Docker Compose (Recomendado — MariaDB)

```bash
# Iniciar containers em segundo plano
docker compose up --build -d

# Acessar no navegador:
# http://localhost:8000

# Parar os containers:
docker compose down
```

### Opção 2: Execução Local (Python 3.12 + SQLite)

```bash
# Instalar dependências
pip install -r backend/requirements.txt

# Iniciar
python run_local.py
```

No Windows, utilize o inicializador interativo:
```cmd
start.bat
```

---

## 🔑 Credenciais Padrão

| Usuário | Senha | Perfil |
|---------|-------|--------|
| `Admin` | `Admin` | Administrador Geral |
| `analista` | `analista` | Analista de Segurança |
| `auditor` | `auditor` | Auditor ISO (somente leitura) |

> Altere as senhas após o primeiro acesso. O sistema bloqueia exclusão do último administrador ativo.

---

## 📂 Arquivos de Exemplo

O diretório `samples/` contém CSVs no padrão Tenable/Nessus para testes:

- `nessus_baseline_scan.csv` — Scan com vulnerabilidades críticas (Log4Shell, EternalBlue, PHP CGI RCE)
- `nessus_retest_post_remediation.csv` — Scan pós-tratativa para validar o comparativo Antes vs. Depois

Na tela de **Importar Scans**, clique em **"Baixar Modelo de CSV Nessus para Teste"** para obter o modelo diretamente.

---

## 🧪 Testes Automatizados

```bash
# Executar a suíte completa (35 testes)
python -m pytest backend/tests/ -v
```

Cobertura: parser Nessus, autenticação JWT/LDAP, RBAC, dashboard, grupos, tratativas, comparativo, relatórios e diagnóstico de scan health.

**Resultado: 35/35 aprovados (100%)**

---

## 🏗️ Estrutura do Projeto

```text
GvulStand/
├── backend/
│   ├── app/
│   │   ├── api/
│   │   │   ├── routes_auth.py           # Login, refresh, change-password
│   │   │   ├── routes_users.py          # CRUD usuários + vinculação LDAP
│   │   │   ├── routes_ldap.py           # Config LDAP/AD, test-connection, validate-user
│   │   │   ├── routes_asset_groups.py   # Grupos/subgrupos, SLAs, permissões
│   │   │   ├── routes_scans.py          # Upload CSV, listagem, exclusão
│   │   │   ├── routes_dashboard.py      # Stats, Top-100, Top-20, scan-health, diagnostics
│   │   │   ├── routes_comparative.py    # Diff Antes vs. Depois
│   │   │   ├── routes_vulnerabilities.py# Listagem paginada, filtros, bulk treatment
│   │   │   └── routes_reports.py        # Templates, sumário executivo, técnico detalhado
│   │   ├── services/
│   │   │   ├── parser_nessus.py         # Parser CSV resiliente (multi-CVE, multi-encoding)
│   │   │   ├── comparative_service.py   # Motor de diff de scans
│   │   │   ├── scan_service.py          # Helpers de scan_ids mais recentes
│   │   │   └── ldap_service.py          # Cliente LDAP/AD (ldap3)
│   │   ├── pdf_assets/                  # Imagens para relatórios PDF (gráficos, fórmulas, diagramas)
│   │   ├── generate_pdf.py              # Geração de PDF via ReportLab
│   │   ├── auth.py                      # JWT, bcrypt, dependências RBAC
│   │   ├── config.py                    # Configurações de ambiente (pydantic-settings)
│   │   ├── database.py                  # SQLAlchemy engine, sessões e seed inicial
│   │   ├── models.py                    # Modelos ORM (User, AssetGroup, Scan, Host, Vulnerability, LdapConfig)
│   │   ├── schemas.py                   # Schemas Pydantic v2 (DTOs de entrada e saída)
│   │   └── main.py                      # FastAPI App, middlewares, routers e SPA server
│   ├── requirements.txt
│   └── tests/
│       ├── test_all.py                  # 24 testes: parser, auth, RBAC, dashboard, scans
│       ├── test_ldap.py                 # 6 testes: config LDAP, autenticação AD, RBAC
│       └── test_reports.py              # 5 testes: templates, sumário executivo, técnico
├── frontend/
│   └── public/
│       ├── index.html                   # SPA Principal
│       ├── report-summary.html          # Relatório Sumário Executivo (janela dedicada)
│       ├── css/styles.css               # Estilos, temas claro/escuro, @media print A4
│       └── js/                          # Controladores, API client, gráficos Chart.js
├── samples/
│   ├── nessus_baseline_scan.csv
│   └── nessus_retest_post_remediation.csv
├── data/
│   └── uploads/                         # CSVs importados (mapeado via volume Docker)
├── docker-compose.yml                   # Orquestração Docker (MariaDB 11.4 + Web App)
├── Dockerfile                           # Build de produção
├── .env.example                         # Exemplo de variáveis de ambiente
├── run_local.py                         # Inicializador local (SQLite)
└── start.bat                            # Inicializador rápido Windows
```

---

## ⚙️ Variáveis de Ambiente

Copie `.env.example` para `.env` e ajuste conforme o ambiente:

```env
APP_NAME="GvulStand - Vulnerability Management System"
SECRET_KEY="troque-por-uma-chave-segura-em-producao"
ACCESS_TOKEN_EXPIRE_MINUTES=1440

DEFAULT_ADMIN_USERNAME="Admin"
DEFAULT_ADMIN_PASSWORD="Admin"
DEFAULT_ADMIN_EMAIL="admin@gvulstand.local"

# SQLite (desenvolvimento local):
DATABASE_URL="sqlite:///./data/gvulstand.db"

# MariaDB (Docker/produção):
# DATABASE_URL="mysql+pymysql://gvuluser:gvulpassword@localhost:3306/gvulstand?charset=utf8mb4"
```

---

## 🔌 API REST

Prefixo base: `/api/v1`

| Módulo | Rota | Descrição |
|--------|------|-----------|
| Auth | `POST /auth/login` | Login e obtenção de token JWT |
| Auth | `POST /auth/refresh` | Renovação de token |
| Auth | `POST /auth/change-password` | Alteração de senha |
| Usuários | `GET/POST /users` | Listar e criar usuários (admin) |
| Usuários | `GET/PUT/DELETE /users/{id}` | Gerenciar usuário específico (admin) |
| LDAP | `GET/PUT /ldap/config` | Configurar integração LDAP/AD (admin) |
| LDAP | `POST /ldap/test-connection` | Testar conexão com servidor AD |
| LDAP | `POST /ldap/validate-user` | Validar usuário no AD |
| Grupos | `GET/POST /asset-groups` | Listar e criar grupos de ativos |
| Grupos | `GET/PUT/DELETE /asset-groups/{id}` | Gerenciar grupo específico |
| Scans | `GET /scans` | Listar scans importados |
| Scans | `POST /scans/upload` | Importar CSV Nessus (analista/admin) |
| Scans | `DELETE /scans/{id}` | Excluir scan (admin) |
| Dashboard | `GET /dashboard/stats` | Métricas consolidadas e KPIs |
| Dashboard | `GET /dashboard/top-100-criticals` | Top 100 vulnerabilidades críticas |
| Dashboard | `GET /dashboard/top-20-hosts` | Top 20 hosts com exploits |
| Dashboard | `GET /dashboard/scan-health` | Diagnóstico de cobertura de credenciais |
| Dashboard | `GET /dashboard/diagnostics` | Troubleshooting detalhado de scan |
| Comparativo | `GET /comparative` | Diff entre dois scans |
| Vulns | `GET /vulnerabilities` | Listagem paginada com filtros |
| Vulns | `POST /vulnerabilities/treatment` | Atualizar tratativa (individual ou bulk) |
| Vulns | `GET /vulnerabilities/{id}/solution` | Solução e hosts afetados |
| Relatórios | `GET /reports/templates` | Catálogo de templates disponíveis |
| Relatórios | `GET /reports/executive_summary` | Dados do sumário executivo |
| Relatórios | `GET /reports/technical_inventory` | Dados do relatório técnico detalhado |
| Health | `GET /health` | Status da aplicação |

---

## 🛠️ Tecnologias Utilizadas

| Camada | Tecnologia | Versão |
|--------|-----------|--------|
| Backend Framework | FastAPI | 0.115.0 |
| Servidor ASGI | Uvicorn | 0.30.6 |
| ORM | SQLAlchemy | 2.0.35 |
| Validação | Pydantic | 2.9.2 |
| Autenticação | Passlib + Bcrypt + Python-Jose | 1.7.4 / 4.0.1 / 3.3.0 |
| Integração AD | ldap3 | 2.9.1 |
| Geração PDF | ReportLab | ≥ 4.2.0 |
| Gráficos PDF | Matplotlib | ≥ 3.9.0 |
| Manipulação PDF | PyMuPDF | ≥ 1.24.0 |
| Banco (Produção) | MariaDB | 11.4 LTS |
| Banco (Dev) | SQLite | 3 (embutido) |
| Frontend | Vanilla JS (ES6+) + Tailwind CSS | — |
| Gráficos UI | Chart.js | 4.x |
| Conteinerização | Docker & Docker Compose | — |
| Testes | pytest + httpx | 8.3.3 / 0.27.2 |
