# 🛡️ GvulStand - Documentação de Funcionalidades e Requisitos Técnicos
**Sistema de Gestão e Governança de Vulnerabilidades de Segurança da Informação**  
*Conforme as normas ISO/IEC 27001:2022 (Controles 8.8), ISO 9001:2015 (Ciclo PDCA) e Tenable/Nessus CSV Integration*

---

## 1. Visão Geral e Contexto Executivo

### 1.1 O que é o GvulStand?
O **GvulStand** é uma plataforma corporativa web de alta performance voltada para a **Gestão de Vulnerabilidades Técnicas**, **Governança de Riscos Cibernéticos** e **Melhoria Contínua da Qualidade**. O sistema foi concebido para transformar arquivos brutos de varreduras de vulnerabilidades gerados por ferramentas líderes de mercado (especialmente a suíte **Tenable Nessus / Tenable.sc / Tenable.io**) em painéis analíticos, indicadores normativos auditáveis e fluxos de remediação rastreáveis.

### 1.2 Problema que o Sistema Resolve
1. **Sobrecarga de Dados (Data Overload):** Relatórios de varredura Nessus frequentemente contêm milhares de linhas e múltiplos megabytes em CSV, dificultando a triagem manual por planilhas estáticas.
2. **Ausência de Linha de Base (Baseline vs. Reteste):** Dificuldade em comprovar se as equipes de infraestrutura e desenvolvimento realmente corrigiram as vulnerabilidades apontadas no último scan.
3. **Falta de Rastreabilidade e Auditoria (Quem e Quando):** Dificuldade de demonstrar aos auditores normativos de **ISO/IEC 27001** e **ISO 9001** o histórico de tratativas, justificativas de aceite formal de risco e conformidade com os SLAs de segurança.
4. **Falhas Ocultas em Scans:** Varreduras que falham silenciosamente devido a bloqueios de firewall (ICMP), falhas de credenciais (SMB/SSH) ou falta de privilégios (`sudo`), resultando em falsos sentimentos de segurança.

### 1.3 Alinhamento Normativo Internacional
- **ISO/IEC 27001:2022 & ISO/IEC 27002:2022 (Controle 8.8 - Gestão de Vulnerabilidades Técnicas):**
  - Obtenção tempestiva de informações sobre vulnerabilidades técnicas.
  - Avaliação da exposição da organização e determinação de medidas apropriadas.
  - Acompanhamento do ciclo de vida de cada apontamento com registro formal de tratativas.
- **ISO 9001:2015 (Ciclo PDCA - Melhoria Contínua):**
  - **Plan (Planejar):** Estabelecer linha de base (Baseline) e definir metas/SLAs por grupo de ativos.
  - **Do (Executar):** Implementação de patches e planos de remediação pelas equipes técnicas.
  - **Check (Verificar):** Realização de retestes (Scan Pós-Tratativa) e cruzamento analítico antes vs. depois.
  - **Act (Agir):** Avaliação de vulnerabilidades persistentes e regressões, ajustando políticas e recursos.

---

## 2. Arquitetura do Sistema e Tecnologias

### 2.1 Diagrama Arquitetural

```mermaid
graph TD
    subgraph Cliente [Frontend SPA - Web Browser]
        UI["Interface Responsiva Tailwind CSS + Vanilla JS (ES6+)"]
        Charts["Gráficos Dinâmicos Chart.js"]
        Icons["Lucide Icons"]
        Theme["Controle de Tema Claro / Escuro"]
        PrintReports["Módulos de Impressão A4 e PDF (Sumário & Técnico)"]
    end

    subgraph Backend [Backend API - FastAPI & Python 3.12]
        Router["API Routers: Auth, Scans, Dashboard, Comparative, Vulns, Users, Groups, LDAP, Reports"]
        AuthMod["Segurança JWT + Hashing Bcrypt + RBAC Granular por Grupo"]
        LdapMod["Serviço LDAP / Active Directory (ldap3)"]
        Parser["Motor Parser Nessus CSV Resiliente (Multi-CVE, Multi-Encoding)"]
        CompEngine["Motor Comparativo Diff Antes vs Depois (scan_date)"]
        DiagEngine["Motor de Diagnóstico e Troubleshoot de Scans"]
        ReportEngine["Motor de Relatórios: EOL, SLA, MTTR, PDF (ReportLab + Matplotlib)"]
        ORM["SQLAlchemy 2.0 ORM Engine (Modelos Relacionais com Cascade)"]
    end

    subgraph Persistencia [Camada de Armazenamento]
        DB[("MariaDB 11.4 LTS / SQLite 3")]
        FS["Armazenamento Local de Uploads CSV (data/uploads/)"]
    end

    subgraph Externo [Serviços Corporativos Externos]
        AD["Active Directory / OpenLDAP (TCP 389 / 636 LDAPS / StartTLS)"]
    end

    UI -->|Requisições REST JSON / Multipart| Router
    PrintReports -->|Consumo de Dados /reports/*| Router
    Router --> AuthMod
    Router --> LdapMod
    Router --> Parser
    Router --> CompEngine
    Router --> DiagEngine
    Router --> ReportEngine
    LdapMod -->|Autenticação & Busca de Usuários| AD
    Parser --> ORM
    CompEngine --> ORM
    DiagEngine --> ORM
    ReportEngine --> ORM
    Router --> ORM
    ORM --> DB
    Router --> FS
```

### 2.2 Tecnologias Utilizadas

| Camada | Tecnologia | Versão | Finalidade |
| :--- | :--- | :--- | :--- |
| **Backend Framework** | FastAPI | 0.115.0 | Framework assíncrono com documentação OpenAPI nativa e validação via Pydantic v2 |
| **Servidor ASGI** | Uvicorn | 0.30.6 | Servidor ASGI robusto para produção conteinerizada |
| **ORM & DB Abstraction** | SQLAlchemy | 2.0.35 | Mapeamento tipado, relacionamentos em cascata e consultas agregadas |
| **Validação & Serialização** | Pydantic | 2.9.2 | Schemas de entrada/saída (DTOs) com validação em C/Rust |
| **Autenticação JWT** | Python-Jose | 3.3.0 | Tokens JWT HMAC-SHA256 com expiração configurável |
| **Hashing de Senhas** | Passlib + Bcrypt | 1.7.4 / 4.0.1 | Bcrypt com salt dinâmico para senhas locais |
| **Integração AD** | ldap3 | 2.9.1 | Cliente LDAP puro Python para AD/OpenLDAP (LDAP, LDAPS, StartTLS) |
| **Geração PDF** | ReportLab | ≥ 4.2.0 | Relatórios PDF programáticos com gráficos e layouts complexos |
| **Gráficos PDF** | Matplotlib | ≥ 3.9.0 | Geração de charts PNG embutidos nos relatórios PDF |
| **Manipulação PDF** | PyMuPDF | ≥ 1.24.0 | Processamento e inspeção de documentos PDF |
| **Driver MariaDB** | PyMySQL | 1.1.1 | Conector Python para MariaDB/MySQL |
| **Banco Produção** | MariaDB | 11.4 LTS | SGDB relacional corporativo com transações ACID e UTF8MB4 |
| **Banco Dev** | SQLite | 3 (embutido) | Banco local para desenvolvimento e testes sem Docker |
| **Frontend** | Vanilla JS (ES6+) | — | SPA sem dependência de build tools (Node/Webpack/Vite) |
| **Design** | Tailwind CSS (CDN) | — | Interface com glassmorphism, temas claro/escuro e responsividade |
| **Gráficos UI** | Chart.js | 4.x | Visualizações interativas de risco, aging, SLA e comparativos |
| **Iconografia** | Lucide Icons | — | Ícones vetoriais uniformes via script |
| **Conteinerização** | Docker & Docker Compose | — | Orquestração backend + MariaDB com healthchecks |
| **Testes** | pytest + httpx | 8.3.3 / 0.27.2 | Suíte completa de testes unitários e de integração |

---

## 3. Verificação de Funcionalidades e Auditoria de Testes

Todas as funcionalidades foram integralmente testadas via suíte formal de testes automatizados (**pytest**), atingindo **100% de aprovação (35 de 35 testes aprovados)**.

### 3.1 Resumo dos Testes Automatizados (35/35 Aprovados)

```text
============================= test session results ==============================
platform linux -- Python 3.12.14, pytest-8.3.3, pluggy-1.6.0
collected 35 items

backend/tests/test_all.py::test_nessus_parser_unit PASSED
backend/tests/test_all.py::test_tenable_official_semicolon_csv PASSED
backend/tests/test_all.py::test_unquoted_newlines_and_mixed_endings PASSED
backend/tests/test_all.py::test_login_default_admin PASSED
backend/tests/test_all.py::test_login_invalid_credentials PASSED
backend/tests/test_all.py::test_create_user_and_auth PASSED
backend/tests/test_all.py::test_scan_upload_and_dashboard PASSED
backend/tests/test_all.py::test_exploit_verdadeiro_falso_and_info_exclusion PASSED
backend/tests/test_all.py::test_scan_diagnostics_troubleshooting PASSED
backend/tests/test_all.py::test_multiple_mac_addresses_and_cvss_formats PASSED
backend/tests/test_all.py::test_aging_breakdown_and_treatment_audit_trail PASSED
backend/tests/test_all.py::test_first_found_date_formats_and_aging_calculation PASSED
backend/tests/test_all.py::test_tenable_dashboard_widgets_metrics PASSED
backend/tests/test_all.py::test_bulk_vulnerability_treatment PASSED
backend/tests/test_all.py::test_comparative_diff_excludes_info_and_none PASSED
backend/tests/test_all.py::test_multi_cve_aggregation_in_parser_and_upload PASSED
backend/tests/test_all.py::test_parent_and_subgroup_management_and_filtering PASSED
backend/tests/test_all.py::test_plugin_solution_and_affected_hosts PASSED
backend/tests/test_all.py::test_rbac_user_management PASSED
backend/tests/test_all.py::test_rbac_asset_group_permissions PASSED
backend/tests/test_all.py::test_rbac_scan_import_and_deletion PASSED
backend/tests/test_all.py::test_rbac_vulnerability_treatment_and_auditing PASSED
backend/tests/test_all.py::test_scan_date_and_free_comparative_selection PASSED
backend/tests/test_ldap.py::test_ldap_config_rbac PASSED
backend/tests/test_ldap.py::test_ldap_config_get_and_update PASSED
backend/tests/test_ldap.py::test_ldap_test_connection_mocked PASSED
backend/tests/test_ldap.py::test_ldap_validate_user_endpoint PASSED
backend/tests/test_ldap.py::test_create_ldap_user_and_authenticate PASSED
backend/tests/test_ldap.py::test_ldap_disabled_prevents_login_and_creation PASSED
backend/tests/test_reports.py::test_get_report_templates PASSED
backend/tests/test_reports.py::test_get_executive_summary_empty PASSED
backend/tests/test_reports.py::test_get_executive_summary_with_scan_and_custom_params PASSED
backend/tests/test_reports.py::test_get_executive_summary_empty_query_strings PASSED
backend/tests/test_reports.py::test_get_technical_report_empty PASSED
backend/tests/test_reports.py::test_get_technical_report_with_data PASSED

====================== 35 passed in 15.33s =======================
```

### 3.2 Matriz de Cobertura e Status de Funcionalidades

| Módulo / Funcionalidade | Descrição do Teste | Status |
| :--- | :--- | :---: |
| **Parser Nessus Oficial** | Delimitadores `;`, `,`, `\t` e `|` | ✅ Aprovado |
| **Resiliência a Quebras de Linha** | Costura de campos multilinhas sem aspas em Plugin Output | ✅ Aprovado |
| **Agregação Multi-CVE** | Unificação automática de múltiplos CVEs sem duplicatas | ✅ Aprovado |
| **Tolerância a Formatos CVSS** | Escala decimal, inteira, vírgula flutuante e fallbacks | ✅ Aprovado |
| **Detecção de Exploits Multilíngue** | `True`/`False`, `Verdadeiro`/`Falso`, `Sim`/`Não` e frameworks | ✅ Aprovado |
| **Autenticação JWT Local** | Login com credenciais locais e bloqueio de inválidas | ✅ Aprovado |
| **Autenticação LDAP / AD** | Login com contas corporativas do Active Directory | ✅ Aprovado |
| **RBAC: Gestão de Usuários** | Acesso restrito a Admin; bloqueio HTTP 403 para outros perfis | ✅ Aprovado |
| **RBAC: Grupos de Ativos** | Criação/edição por Admin/Analista; restrições de exclusão | ✅ Aprovado |
| **RBAC: Importação & Exclusão de Scans** | Upload por Admin/Analista; exclusão restrita a Admin | ✅ Aprovado |
| **RBAC: Tratativa ISO 27001** | Analista/Admin tratam; Auditor somente leitura (HTTP 403) | ✅ Aprovado |
| **Hierarquia de Grupos (Subgrupos)** | Criação de parent/child com métricas consolidadas | ✅ Aprovado |
| **Dashboard Executivo & KPIs** | Severidades, hosts únicos, ISO 27001, ISO 9001, VPR, Aging | ✅ Aprovado |
| **Solução do Fornecedor & Hosts Afetados** | Modal com solução oficial e hosts por grupo | ✅ Aprovado |
| **Aging & Matriz de SLAs** | Janelas 0-7, 8-14, 15-30, 31-60, 61-90 e 90+ dias | ✅ Aprovado |
| **Data Real do Scan (`scan_date`)** | Ordenação cronológica desacoplada da data de upload | ✅ Aprovado |
| **Comparativo Antes vs. Depois (Livre)** | Seleção livre com taxa de resolução e redução de risco | ✅ Aprovado |
| **Configuração LDAP (RBAC)** | Admin configura; Analista/Auditor sem acesso (HTTP 403) | ✅ Aprovado |
| **Validação de Usuário no LDAP** | Busca por `sAMAccountName` preenchendo nome e e-mail | ✅ Aprovado |
| **Relatório Sumário Executivo** | Inventário, EOL, termômetro, top 5, SLA/MTTR | ✅ Aprovado |
| **Relatório Técnico Detalhado** | Dossiê ativo por ativo com portas, evidências e formatação A4 | ✅ Aprovado |
| **Troubleshoot & Scan Health** | Mapeamento de erros ICMP, autenticação Windows/SSH e sudo | ✅ Aprovado |

---

## 4. Mapeamento Detalhado de Módulos e Funcionalidades

### 4.1 Módulo de Autenticação e RBAC

**Credenciais de Fábrica (Seed Idempotente):**
- **Administrador:** `Admin` / `Admin`
- **Analista de Segurança:** `analista` / `analista`
- **Auditor ISO:** `auditor` / `auditor`

**Perfis de Acesso:**

1. **Administrador Geral (`admin`):** Permissão total e irrestrita. Única função com acesso à Gestão de Usuários, exclusão de scans e de grupos, e configuração do LDAP.

2. **Analista de Segurança (`analyst`):** Acesso operacional completo: dashboard, top 100 críticas, top 20 hosts, comparativo, explorador de vulnerabilidades, importação de scans, criação/edição de grupos, tratamento individual e em lote (bulk), emissão de relatórios. Sem permissão de exclusão ou gerenciamento de usuários.

3. **Auditor ISO (`auditor`):** Acesso estritamente somente leitura a todos os dashboards e relatórios. Não pode tratar vulnerabilidades (bloqueio visual + HTTP 403 na API), importar scans, criar/editar grupos ou gerenciar usuários.

**Matriz de Permissões RBAC:**

| Funcionalidade | Administrador (`admin`) | Analista (`analyst`) | Auditor (`auditor`) |
| :--- | :---: | :---: | :---: |
| Dashboard Executivo & KPIs | ✅ Leitura | ✅ Leitura | ✅ Leitura |
| Top 100 Críticas & Top 20 Hosts | ✅ Leitura | ✅ Leitura | ✅ Leitura |
| Relatórios Executivos & PDF | ✅ Emitir & Salvar | ✅ Emitir & Salvar | ✅ Emitir & Salvar |
| Comparativo Antes/Depois | ✅ Leitura | ✅ Leitura | ✅ Leitura |
| Explorador de Vulnerabilidades | ✅ Leitura & Filtros | ✅ Leitura & Filtros | ✅ Leitura & Filtros |
| Tratamento de Vulnerabilidades | ✅ Individual & Bulk | ✅ Individual & Bulk | 🚫 Bloqueado (HTTP 403) |
| Importação de Scans CSV | ✅ Permitido | ✅ Permitido | 🚫 Sem acesso |
| Exclusão de Scans | ✅ Permitido | 🚫 Sem permissão | 🚫 Sem acesso |
| Criação e Edição de Grupos | ✅ Permitido | ✅ Permitido | 🚫 Sem acesso |
| Exclusão de Grupos | ✅ Permitido | 🚫 Sem permissão | 🚫 Sem acesso |
| Gestão de Usuários (CRUD) | ✅ Permitido | 🚫 Sem acesso | 🚫 Sem acesso |
| Configuração LDAP/AD | ✅ Permitido | 🚫 Sem acesso | 🚫 Sem acesso |
| Parâmetros do Sistema (Fuso, SLAs, Falsos-Positivos) | ✅ Permitido | 🚫 Sem acesso | 🚫 Sem acesso |

**RBAC Granular por Grupo de Ativos (`UserAssetGroup`):**

Além do RBAC por perfil global, o sistema suporta permissões granulares por usuário + grupo:
- `can_treat`: permissão de tratamento de vulnerabilidades no grupo
- `can_import`: permissão de importação de scans no grupo
- `can_author`: permissão de emissão de relatórios do grupo

**Mecanismos de Defesa em Profundidade:**
- **API (Backend):** Dependências FastAPI `require_admin`, `require_analyst_or_admin` e `check_user_group_access` retornam HTTP 403 em caso de não autorização.
- **Interface (Frontend):** Menus dinâmicos, rotas protegidas, botões ocultados condicionalmente e formulários de tratativa em modo somente leitura com badge "Modo Auditoria".
- **Tokens JWT:** HMAC-SHA256 (`HS256`) com expiração de 24 horas (1440 minutos configurável).
- **Senhas:** Bcrypt com salt dinâmico; proteção contra exclusão do último administrador ativo.

---

### 4.2 Motor de Ingestão e Parser Resiliente do Tenable Nessus CSV

O parser foi desenvolvido para superar as inconsistências comuns em exportações CSV de scanners corporativos:

- **Suporte a Arquivos Massivos:** Remoção do limite padrão do Python (`csv.field_size_limit(sys.maxsize)`), permitindo processar relatórios de 100 MB+.
- **Detecção Inteligente de Delimitadores:** Identifica automaticamente separadores `;`, `,`, `\t` ou `|`.
- **Suporte a Múltiplos Encodings:** Tentativa sequencial de UTF-8, UTF-8-sig, Latin-1 e CP1252 para garantir compatibilidade com exports de ferramentas legadas.
- **Reconstrução de Quebras de Linha (Stitching Engine):** Reconstrói linhas corrompidas por quebras não escapadas dentro de campos como `Plugin Output`, `Description` ou `Synopsis`, reconhecendo a assinatura de início de registro Tenable (Plugin ID numérico).
- **Mapeamento Flexível e Bilíngue de Cabeçalhos:** Dicionário com mais de 30 aliases em português e inglês:
  - `Plugin ID`: `plugin id`, `pluginid`, `id`
  - `Risk/Severity`: `risk`, `severity`, `risk factor`, `criticidade`
  - `Host/IP`: `ip address`, `ip`, `host ip`, `host`, `target`
  - `Exploit Available`: `exploit available`, `exploit?`, `exploravel?`
  - `Datas`: `first found`, `first seen`, `data primeira detecção`, etc.
- **Motor de Agregação Multi-CVE:** Consolida e deduplica múltiplos CVEs da mesma vulnerabilidade (`Host IP + Plugin ID + Porta + Protocolo`) em um único registro limpo. Extração heurística via regex sobre `See Also` e `Synopsis` quando a coluna CVE está vazia.
- **Múltiplos Endereços MAC:** Suporte a ativos com múltiplos adaptadores (VMware, Hyper-V, interfaces multihomed).
- **Data Efetiva da Varredura (`scan_date`):** Permite ao operador informar a data real da varredura, desacoplando-a da data de upload do arquivo (`created_at`). Suporta múltiplos formatos: `YYYY-MM-DD`, `DD/MM/YYYY`, ISO 8601 com e sem hora.
- **Auto-Detecção de SO:** Extrai o sistema operacional dos plugins Nessus 11936, 10287 e 45590 quando a coluna de OS não está preenchida.
- **Bulk Insert Otimizado:** Vulnerabilidades inseridas em chunks de 500 registros via `bulk_save_objects` para performance com arquivos grandes.

---

### 4.3 Painel Executivo (Dashboard) e Indicadores de Governança

O dashboard consolida métricas baseadas estritamente no **scan mais recente de cada Grupo de Ativos** para evitar contagem duplicada de dados históricos.

**Componentes principais (`GET /api/v1/dashboard/stats`):**

1. **Cards de Severidade Quantitativa:** Critical, High, Medium, Low, Info com contagem de CVEs únicos dedupados
2. **Cards de Governança do Ciclo de Vida:** Totalizadores por status de tratativa (Open, In Remediation, Accepted Risk, Remediated) com subdivisão por criticidade
3. **VPR (Vulnerability Priority Rating) Tenable:** Faixas 9-10, 7-8.9, 4-6.9 e 0-3.9
4. **Aging de Vulnerabilidades:**
   - Macro: 0-30 (No SLA), 31-60 (Atenção), 61-90 (Atrasado), >90 (Débito Crítico)
   - Granular por severidade: 0-7, 8-14, 15-30, 31-60, 61-90 e 90+ dias
5. **SLA Progress por Severidade:** Contadores de itens dentro/fora do prazo por nível
6. **Scan Health & Cobertura de Credenciais:** Gráfico de qualidade da coleta por host (autenticado, acesso insuficiente, falha de credencial, intermitente, sem credenciais)
7. **Vetores de Exploração:** Proporção de vulnerabilidades por tipo (malware ativo, exploit remoto baixa complexidade, exploit local, Metasploit, remoto alta complexidade)
8. **Research & Patch Advisory:** Missing patches vs. applied patches
9. **Índice de Postura de Risco ISO 27001** e **Eficácia de Remediação ISO 9001**

**Top 100 Críticas (`GET /api/v1/dashboard/top-100-criticals`):**
- Ordenação: exploit disponível > CVSS v3 > volume de hosts afetados
- Campos: Plugin ID, nome, CVEs, CVSS v3, hosts afetados, IPs, sinopse e solução
- Drill-down interativo com solução completa e lista exaustiva de hosts afetados

**Top 20 Hosts (`GET /api/v1/dashboard/top-20-hosts`):**
- Hosts com vulnerabilidades críticas exploráveis em frameworks conhecidos (Metasploit, Exploit-DB, CANVAS, Core Impact, D2 Elliot)
- Exibe IP, hostname, OS, grupo, score de risco e frameworks aplicáveis

**Scan Health & Diagnóstico (`GET /api/v1/dashboard/scan-health`, `GET /api/v1/dashboard/diagnostics`):**
- Mapeamento de plugins de erro: SMB/WMI (24786, 104410), SSH (12650, 21745), sudo (102094, 102095), ICMP (1102, 10180), interrupções (26917)
- Tabela prescritiva com ação recomendada por host antes do próximo scan

---

### 4.4 Módulo de Relatórios Executivos & PDF

**Rotas disponíveis:**
- `GET /api/v1/reports/templates` — catálogo de templates
- `GET /api/v1/reports/executive_summary` — dados do sumário executivo
- `GET /api/v1/reports/technical_inventory` — dados do relatório técnico detalhado

**Parâmetros de personalização (query strings):**
- `asset_group_id`, `scan_id`, `title`, `period`, `team`, `classification`, `scope`

**Template 1 — Relatório Sumário Executivo (`executive_summary`):**
- Cabeçalho com metadados de governança
- **Inventário com Diagnóstico de EOL (End-of-Life):** Detecção algorítmica de SOs descontinuados:
  - EOL decretado: Windows Server 2003/2008/2012, Windows XP/Vista/7/8, CentOS 5/6/7/8, Ubuntu 12.04/14.04/16.04/18.04, Debian ≤ 10 (Buster), RHEL 5/6
  - Próximos do EOL: Windows 10 (Out/2025), Ubuntu 20.04 (Abr/2025)
- Sumário de risco global ponderado com tendência vs. ciclo anterior
- Matriz de severidade e proporção de exploits disponíveis
- Top 5 hosts de maior risco e Top 5 vulnerabilidades de maior impacto
- **Indicadores de SLA e MTTR (Mean Time to Remediate)** por nível de criticidade

**Template 2 — Relatório Técnico Detalhado (`technical_inventory`):**
- Dossiê completo por ativo: IP, FQDN, NetBIOS, OS, contadores de severidade, score de risco
- Tabela exaustiva de apontamentos: Plugin ID, CVEs, portas TCP/UDP, CVSS, vetores de exploit
- Solução do fornecedor e bloco expansível de Plugin Output (evidência técnica bruta)
- Filtros rápidos por criticidade e busca em tempo real
- Layout otimizado para impressão/exportação A4 via `@media print`

**Geração PDF via ReportLab (`generate_pdf.py`):**
- Arquivo de 57 KB com geração programática de PDFs
- Assets em `pdf_assets/`: gráficos gerados por Matplotlib (severity_chart, aging_chart, exploits_health_chart, comparative_chart), fórmulas (6 imagens de fórmulas matemáticas) e diagrama de arquitetura

---

### 4.5 Motor Comparativo Antes vs. Depois (PDCA ISO 9001)

**Rota:** `GET /api/v1/comparative`

**Lógica:**
- Seleção livre de qualquer par de scans do grupo (ordenação cronológica por `scan_date`)
- Chave quádrupla de cruzamento: `IP + Plugin ID + Porta + Protocolo`
- Exclui achados Info/None; foca em Critical, High, Medium, Low
- Três categorias de resultado:
  - 🟢 **Remediadas:** presentes no Baseline, ausentes no Reteste
  - 🟡 **Persistentes:** presentes em ambos (cobrança de SLA)
  - 🔴 **Novas/Regressões:** ausentes no Baseline, presentes no Reteste
- Cálculo de Taxa de Resolução (%) e Redução Líquida de Risco (%)

---

### 4.6 Explorador de Vulnerabilidades

**Rota:** `GET /api/v1/vulnerabilities` com paginação no servidor

**Filtros disponíveis:**
- `asset_group_id`, `scan_id`, `host_id`, `host` (IP ou hostname parcial)
- `severity` (Critical/High/Medium/Low/Info)
- `exclude_info` (boolean), `exploit_only` (boolean), `has_exploit`
- `treatment_status` (Open/In_Remediation/Accepted_Risk/Remediated)
- `search` (busca textual em nome do plugin, CVE, IP)
- Paginação: `page`, `page_size` (máx. 200) ou `limit`/`offset`

**Tratamento Individual:** `PUT /api/v1/vulnerabilities/{id}/treatment`

**Tratamento em Lote (Bulk):** `POST /api/v1/vulnerabilities/treatment`
- Seleciona múltiplas vulnerabilidades simultaneamente
- Aplica status e nota em uma única transação
- Grava `treated_by_username` (usuário autenticado) e `treated_at` (UTC)

**Solução e Hosts Afetados:** `GET /api/v1/vulnerabilities/{id}/solution`

---

### 4.7 Grupos de Ativos e Hierarquia

**Rota:** `/api/v1/asset-groups`

**Hierarquia Parent/Subgroups:**
- Campo `parent_id` com suporte nativo a estruturas em árvore
- Criação de grupos principais e subgrupos associados
- Consolidação recursiva de métricas no grupo pai
- Seletor global no cabeçalho com visualização indentada em árvore

**SLAs configuráveis por grupo (em dias):**
- `sla_critical_days` (padrão: 7)
- `sla_high_days` (padrão: 15)
- `sla_medium_days` (padrão: 30)
- `sla_low_days` (padrão: 60)

**Permissões granulares (`UserAssetGroup`):**
- `can_treat`, `can_import`, `can_author` — por usuário + grupo
- Verificação em todos os endpoints via `check_user_group_access()`

---

### 4.8 Integração LDAP / Active Directory

**Rotas:** `/api/v1/ldap/*` (acesso restrito a Administrador)

**Configurações disponíveis:**
- `server_host`, `server_port` (389/636)
- `use_ssl` (LDAPS), `use_starttls`
- `bind_user`, `bind_password` (armazenado com máscara de retorno)
- `base_dn`, `user_search_filter`
- `sam_attribute` (padrão: `sAMAccountName`), `name_attribute`, `email_attribute`
- `connection_timeout` (padrão: 5 segundos)
- `is_enabled` (on/off sem perda de configuração)

**Endpoints:**
- `GET /ldap/config` — retorna configuração atual (senha mascarada)
- `PUT /ldap/config` — atualiza configuração
- `POST /ldap/test-connection` — testa conectividade com o servidor AD
- `POST /ldap/validate-user` — busca usuário por `sAMAccountName` no AD

**Criação de Usuário LDAP:**
- Na rota `POST /users`, `auth_type: "ldap"` ativa o fluxo de cadastro AD
- Verifica que a integração está habilitada antes de prosseguir
- Busca nome completo e e-mail corporativo automaticamente via `LdapService`
- Senha gerenciada pelo AD; autenticação local como fallback se AD indisponível

---

### 4.9 Gestão de Usuários

**Rota:** `/api/v1/users` (Administrador apenas)

**Operações:**
- `GET /users` — lista todos os usuários com suas permissões por grupo
- `POST /users` — cria usuário local ou LDAP
- `GET /users/{id}` — detalhes de usuário específico
- `PUT /users/{id}` — atualizar dados, perfil, senha
- `DELETE /users/{id}` — excluir usuário (com proteção para último admin ativo)

**Campos retornados:**
- `allowed_groups` (lista de `UserGroupPermissionOut` com nome do grupo e permissões granulares)
- `allowed_group_ids`, `auth_type`, `sam_account_name`

---

### 4.10 Parâmetros do Sistema (Administração Pontual)

**Rota:** `/api/v1/parameters/*` (Administrador apenas)

O módulo de **Parâmetros do Sistema** permite ao Administrador Geral configurar os ajustes pontuais e operacionais globais que influenciam a consolidação de dados, a apuração de SLAs e a emissão de relatórios:

1. **Definição de Fuso Horário Operacional (`timezone`):**
   - Base de referência para conversão e exibição de todos os carimbos de data/hora salvos (`treated_at`, geração de relatórios técnicos e executivos, emissão de PDFs e auditorias).
   - Validação estrita via biblioteca padrão Python `zoneinfo.ZoneInfo`.
   - Suporte a listagem de fusos com prioridade para o Brasil (`America/Sao_Paulo`, `America/Manaus`, `America/Belem`, `America/Fortaleza`, `America/Recife`, `America/Cuiaba`, `America/Porto_Velho`, `America/Boa_Vista`, `America/Rio_Branco`, `America/Noronha`) além dos principais fusos internacionais (UTC, América do Norte, Europa e Ásia).
   - Componente de relógio digital ao vivo (*Live Clock*) com indicação de offset em relação ao UTC.

2. **Definição de Prazos Padrão de SLA de Remediação:**
   - Configuração centralizada de prazos em dias para cada nível de severidade:
     - **Crítica (`sla_critical_days`):** Padrão recomendado: 7 dias.
     - **Alta (`sla_high_days`):** Padrão recomendado: 15 dias.
     - **Média (`sla_medium_days`):** Padrão recomendado: 30 dias.
     - **Baixa (`sla_low_days`):** Padrão recomendado: 60 dias.
   - Utilizados automaticamente como fallback para grupos de ativos que não definam SLAs específicos.
   - Recurso de **Replicar em Todos os Grupos** (`POST /api/parameters/apply-slas-to-all-groups`) para atualizar em lote todos os grupos cadastrados.

3. **Expurgo Automático de Vulnerabilidades / Falsos-Positivos nos Indicadores (`ignored_vulnerability_ids`):**
   - Campo de texto aceitando IDs de Plugins Nessus e IDs internos separados por vírgula, espaço, quebra de linha ou ponto e vírgula.
   - Identificação de regras ativas com renderização de tags/chips interativos (permitindo adição com 1 clique do plugin informativo padrão `19506 - Nessus Scan Information` e remoção individual).
   - **Impacto Abrangente nos Indicadores:** Qualquer vulnerabilidade que corresponda a um dos IDs configurados é automaticamente expurgada de:
     - Cards de contagem e gráficos de severidade do Dashboard (`/api/dashboard/stats`).
     - Tabela das Top 100 Vulnerabilidades Críticas (`/api/dashboard/top-100-critical`).
     - Tabela dos Top 20 Hosts com Exploits Públicos (`/api/dashboard/top-20-hosts`).
     - Apuração de cumprimento de SLAs (`sla_compliance_rate` e `sla_progress`).
     - Relatório Sumário Executivo, Relatório Técnico e Auditoria de SLA (`/api/reports/*`).
     - Motor comparativo de linha de base vs. reteste (`ComparativeService`).
     - Totais e métricas consolidadas por grupo de ativos (`/api/asset-groups`).
     - Filtro opcional no Explorador de Vulnerabilidades (`exclude_ignored=true`).
   - **Simulação em Tempo Real:** Recurso de **Pré-visualizar Impacto** (`POST /api/parameters/preview-ignored`) com modal detalhado exibindo a quantidade de ocorrências excluídas, hosts impactados e listagem analítica antes de confirmar a gravação.

---

### 4.11 Modelos de Dados (ORM)

#### User
```
id, username, email, full_name, hashed_password
role: admin | analyst | auditor
auth_type: local | ldap
sam_account_name, is_active
created_at, updated_at
→ asset_group_permissions (UserAssetGroup)
```

#### AssetGroup
```
id, name, description, network_range, owner
sla_critical_days, sla_high_days, sla_medium_days, sla_low_days
parent_id (FK → AssetGroup, hierarquia)
created_at, updated_at
→ parent, subgroups, scans, hosts, vulnerabilities, user_permissions
```

#### UserAssetGroup
```
user_id (FK), asset_group_id (FK)
can_treat, can_import, can_author
created_at
[UNIQUE: user_id + asset_group_id]
```

#### Scan
```
id, asset_group_id (FK), scan_name
scan_type: baseline | retest
filename, file_size_bytes
total_hosts, total_findings
critical_count, high_count, medium_count, low_count, info_count, exploitable_critical_count
scan_date (data real da varredura), created_at (data do upload), notes
→ hosts, vulnerabilities
```

#### Host
```
id, scan_id (FK), asset_group_id (FK)
ip_address, hostname, netbios_name, mac_address, os
critical_count, high_count, medium_count, low_count, info_count, exploitable_critical_count
risk_score
[INDEX: scan_id + ip_address]
```

#### Vulnerability
```
id, scan_id (FK), host_id (FK), asset_group_id (FK)
plugin_id, plugin_name, cve (Text), cvss_v3, cvss_v2, vpr
severity: Critical | High | Medium | Low | Info
port, protocol, synopsis, description, solution, see_also, plugin_output
exploit_available, exploit_frameworks, exploited_by_malware
stig_severity, risk_factor, patch_available, plugin_type
first_found, last_found
treatment_status: Open | In_Remediation | Accepted_Risk | Remediated
treatment_notes, treated_by_username, treated_at
created_at
[INDEX: scan_id+severity, severity+exploit_available]
```

#### LdapConfig (singleton id=1)
```
is_enabled, server_host, server_port, use_ssl, use_starttls
bind_user, bind_password, base_dn
user_search_filter, sam_attribute, name_attribute, email_attribute
connection_timeout, updated_at
```

#### SystemParameters (singleton id=1)
```
id, timezone (ex: "America/Sao_Paulo")
sla_critical_days, sla_high_days, sla_medium_days, sla_low_days
ignored_vulnerability_ids (texto com IDs de plugins ou vulnerabilidades a expurgar)
updated_at, updated_by_username
```

---

## 5. Fórmulas Matemáticas e Métricas de Governança

### 5.1 Índice de Postura de Risco ISO/IEC 27001 (Controle 8.8)

$$\text{Risco Bruto} = (N_{\text{Críticas}} \times 10.0) + (N_{\text{Altas}} \times 5.0) + (N_{\text{Médias}} \times 2.0) + (N_{\text{Baixas}} \times 0.5)$$

$$\text{Índice de Postura de Risco} = \frac{\text{Risco Bruto}}{\max(1, \text{Total de Hosts Únicos})}$$

### 5.2 Score de Risco por Host Individual

$$\text{Host Risk Score} = (N_{\text{Crit}} \times 10) + (N_{\text{High}} \times 5) + (N_{\text{Med}} \times 2) + (N_{\text{Low}} \times 0.5) + (N_{\text{Crit c/ Exploit}} \times 5)$$

### 5.3 Taxa de Eficácia de Remediação ISO 9001 (PDCA Global)

$$\text{Eficácia de Remediação (\%)} = \left( \frac{\text{Total Remediated}}{\max(1, \text{Total Acionáveis})} \right) \times 100$$

### 5.4 Taxa de Resolução do Comparativo

$$\text{Taxa de Resolução (\%)} = \left( \frac{\text{Vulnerabilidades Remediadas no Reteste}}{\text{Total de Vulnerabilidades no Baseline}} \right) \times 100$$

### 5.5 Redução Líquida de Risco do Comparativo

$$\text{Risco Antes} = (C_{\text{Antes}} \times 10) + (A_{\text{Antes}} \times 5) + (M_{\text{Antes}} \times 2) + (B_{\text{Antes}} \times 0.5)$$

$$\text{Redução Líquida de Risco (\%)} = \left( \frac{\text{Risco Antes} - \text{Risco Depois}}{\text{Risco Antes}} \right) \times 100$$

---

## 6. Mapeamento Completo da API REST

**Prefixo base:** `/api/v1`

### Autenticação (`/auth`)
| Método | Rota | Perfil | Descrição |
| :--- | :--- | :--- | :--- |
| POST | `/auth/login` | Público | Login e geração de token JWT |
| POST | `/auth/refresh` | Autenticado | Renovação de token |
| POST | `/auth/change-password` | Autenticado | Alteração de senha própria |

### Usuários (`/users`)
| Método | Rota | Perfil | Descrição |
| :--- | :--- | :--- | :--- |
| GET | `/users` | Admin | Listar todos os usuários |
| POST | `/users` | Admin | Criar usuário (local ou LDAP) |
| GET | `/users/{id}` | Admin | Detalhes de usuário |
| PUT | `/users/{id}` | Admin | Atualizar usuário |
| DELETE | `/users/{id}` | Admin | Excluir usuário |

### LDAP (`/ldap`)
| Método | Rota | Perfil | Descrição |
| :--- | :--- | :--- | :--- |
| GET | `/ldap/config` | Admin | Obter configuração LDAP (senha mascarada) |
| PUT | `/ldap/config` | Admin | Atualizar configuração LDAP |
| POST | `/ldap/test-connection` | Admin | Testar conexão com servidor AD |
| POST | `/ldap/validate-user` | Admin | Validar usuário no AD por sAMAccountName |

### Parâmetros do Sistema (`/parameters`)
| Método | Rota | Perfil | Descrição |
| :--- | :--- | :--- | :--- |
| GET | `/parameters` | Admin | Obter parâmetros atuais (fuso, SLAs, IDs ignorados, metadados) |
| PUT | `/parameters` | Admin | Atualizar fuso horário, SLAs e lista de vulnerabilidades ignoradas |
| GET | `/parameters/timezones` | Admin | Listar fusos horários disponíveis com offsets formatados |
| POST | `/parameters/preview-ignored` | Admin | Simular o impacto dos IDs informados na base de scans ativa |
| POST | `/parameters/apply-slas-to-all-groups` | Admin | Replicar os prazos de SLA padrão em todos os grupos de ativos |

### Grupos de Ativos (`/asset-groups`)
| Método | Rota | Perfil | Descrição |
| :--- | :--- | :--- | :--- |
| GET | `/asset-groups` | Autenticado | Listar grupos (filtrados por permissão) |
| POST | `/asset-groups` | Admin/Analista | Criar grupo de ativos |
| GET | `/asset-groups/{id}` | Autenticado | Detalhes de grupo |
| PUT | `/asset-groups/{id}` | Admin/Analista | Atualizar grupo |
| DELETE | `/asset-groups/{id}` | Admin | Excluir grupo (cascade) |

### Scans (`/scans`)
| Método | Rota | Perfil | Descrição |
| :--- | :--- | :--- | :--- |
| GET | `/scans` | Autenticado | Listar scans (filtros: group, type) |
| POST | `/scans/upload` | Admin/Analista | Importar CSV Nessus |
| GET | `/scans/{id}` | Autenticado | Detalhes de scan |
| DELETE | `/scans/{id}` | Admin | Excluir scan e dados em cascata |

### Dashboard (`/dashboard`)
| Método | Rota | Perfil | Descrição |
| :--- | :--- | :--- | :--- |
| GET | `/dashboard/stats` | Autenticado | Métricas consolidadas e KPIs |
| GET | `/dashboard/top-100-criticals` | Autenticado | Top 100 vulnerabilidades críticas |
| GET | `/dashboard/top-20-hosts` | Autenticado | Top 20 hosts com exploits |
| GET | `/dashboard/scan-health` | Autenticado | Diagnóstico de cobertura |
| GET | `/dashboard/diagnostics` | Autenticado | Troubleshoot detalhado |

### Comparativo (`/comparative`)
| Método | Rota | Perfil | Descrição |
| :--- | :--- | :--- | :--- |
| GET | `/comparative` | Autenticado | Diff entre dois scans selecionados |

### Vulnerabilidades (`/vulnerabilities`)
| Método | Rota | Perfil | Descrição |
| :--- | :--- | :--- | :--- |
| GET | `/vulnerabilities` | Autenticado | Listagem paginada com filtros |
| PUT | `/vulnerabilities/{id}/treatment` | Admin/Analista | Tratar vulnerabilidade individual |
| POST | `/vulnerabilities/treatment` | Admin/Analista | Tratamento em lote (bulk) |
| GET | `/vulnerabilities/{id}/solution` | Autenticado | Solução e hosts afetados |

### Relatórios (`/reports`)
| Método | Rota | Perfil | Descrição |
| :--- | :--- | :--- | :--- |
| GET | `/reports/templates` | Autenticado | Catálogo de templates disponíveis |
| GET | `/reports/executive_summary` | Autenticado | Dados do sumário executivo |
| GET | `/reports/technical_inventory` | Autenticado | Dados do relatório técnico |

### Health Check
| Método | Rota | Descrição |
| :--- | :--- | :--- |
| GET | `/health` | Status e versão da aplicação |

---

## 7. Requisitos Técnicos do Sistema

### 7.1 Requisitos de Hardware

| Componente | Mínimo (Testes/Homologação) | Recomendado (Produção) |
| :--- | :--- | :--- |
| CPU | 2 Cores (x86_64 ou ARM64) | 4 Cores ou superior |
| RAM | 4 GB | 8–16 GB (para CSVs de 100 MB+) |
| Disco | 20 GB livres | 100 GB SSD/NVMe |
| Rede | 100 Mbps | 1 Gbps |

### 7.2 Requisitos de Software

| Componente | Versão Homologada |
| :--- | :--- |
| OS do servidor | Linux (Ubuntu 22.04+, Debian 12+, RHEL 9+) ou Windows 10/11 |
| Docker Engine | 24+ com Docker Compose v2+ |
| Python | 3.12+ (sem Docker) |
| Navegadores | Chrome 110+, Firefox 110+, Edge 110+, Safari 16+ |

### 7.3 Portas

| Porta | Descrição |
| :---: | :--- |
| 8000/TCP | Interface web (SPA) e API REST FastAPI |
| 3306/TCP | MariaDB (rede interna Docker, não exposta externamente em produção) |
| 389/TCP | LDAP para Active Directory (opcional) |
| 636/TCP | LDAPS (opcional, com SSL) |

### 7.4 Variáveis de Ambiente (`.env`)

```ini
# Identidade
APP_NAME="GvulStand - Vulnerability Management System"

# Segurança
SECRET_KEY="troque-por-chave-segura-em-producao"
ACCESS_TOKEN_EXPIRE_MINUTES=1440

# Admin padrão (seed idempotente)
DEFAULT_ADMIN_USERNAME=Admin
DEFAULT_ADMIN_PASSWORD=Admin
DEFAULT_ADMIN_EMAIL=admin@gvulstand.local

# Banco de dados
# SQLite (desenvolvimento):
DATABASE_URL="sqlite:///./data/gvulstand.db"
# MariaDB (produção Docker):
# DATABASE_URL="mysql+pymysql://gvuluser:gvulpassword@mariadb:3306/gvulstand?charset=utf8mb4"
```

---

## 8. Guia de Implantação e Operação

### 8.1 Docker & Docker Compose (Produção)

```bash
# Iniciar com build
docker compose up --build -d

# Verificar status
docker compose ps

# Ver logs da aplicação
docker compose logs -f web

# Executar testes dentro do container
docker exec gvulstand_app pytest backend/tests/ -v

# Parar containers
docker compose down
```

### 8.2 Execução Local (Dev / SQLite)

```bash
pip install -r backend/requirements.txt
python run_local.py
# Acesse: http://localhost:8000
```

### 8.3 Fluxo de Importação de Scan

1. Preparar o CSV exportado do Tenable Nessus/SC/IO
2. Acessar **Importar Scans** na interface web
3. Selecionar o **Grupo de Ativos** de destino
4. Informar o nome do scan e o **Tipo** (Baseline ou Retest)
5. Informar a **Data Real da Varredura** (campo `scan_date`)
6. Fazer upload do arquivo CSV
7. Aguardar processamento (bulk insert otimizado de 500 em 500 registros)
8. Verificar no Dashboard as métricas atualizadas

---

## 9. Conclusão

O **GvulStand** estabelece uma ponte sólida entre a engenharia de segurança técnica e a governança executiva de TI. Ao unificar:
- Ingestão resiliente de relatórios **Tenable Nessus** (multi-CVE, multi-encoding, 100 MB+)
- Cumprimento formal do **Controle 8.8 da ISO/IEC 27001** com ciclo de vida auditável
- Medição de eficácia exigida pela **ISO 9001** (PDCA com comparativo antes/depois)
- Integração nativa com **Active Directory / LDAP** para identidade corporativa
- Relatórios executivos e técnicos com geração PDF via **ReportLab + Matplotlib**
- RBAC granular com permissões por usuário + grupo de ativos

O sistema garante conformidade auditável, redução expressiva do risco cibernético e clareza na prestação de contas para comitês de auditoria, CISOs e diretorias de tecnologia.
