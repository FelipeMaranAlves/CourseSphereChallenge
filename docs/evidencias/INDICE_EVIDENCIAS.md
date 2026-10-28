# Índice de Evidências de Segurança (Pré-Correção / Baseline)

Esta pasta reúne todas as evidências coletadas durante a fase de **Análise de Vulnerabilidades (Estática, Dependências e Inspeção Dinâmica via Burp Suite Community)** sobre a versão original da aplicação **CourseSphere**.

---

## 1. Arquivos de Evidência Automatizada (SAST & SCA)

| Arquivo | Ferramenta / Tipo | Escopo | Resumo dos Achados |
| :--- | :--- | :--- | :--- |
| [`bandit.txt`](./bandit.txt) | **Bandit (SAST Python — Baseline)** | `backend/` | **20 problemas identificados** (1 High, 15 Medium, 4 Low): SQL Injection (`B608`), Flask `debug=True` (`B201`), PRNG inseguro (`B311`) e uso de `assert` (`B101`). |
| [`bandit-pos-correcao.txt`](./bandit-pos-correcao.txt) | **Bandit (SAST Python — Pós-Correção)** | `backend/` | **0 problemas identificados (`No issues identified`)** em 1.137 linhas de código após as correções da Fase 2. |
| [`eslint-security.txt`](./eslint-security.txt) | **ESLint Security (SAST TS/React)** | `frontend/src/` | **26 problemas identificados**: `security/detect-object-injection` em `CardDeck.tsx:31`, tipagem insegura (`Function` / `any`) e variáveis não utilizadas. |
| [`npm-audit`](./npm-audit) | **npm audit (SCA Frontend)** | `frontend/package-lock.json` | **39 vulnerabilidades** em dependências (2 Critical, 19 High, 17 Moderate, 1 Low), incluindo `protobufjs`, `websocket-driver`, `@remix-run/router`, `vite`/`esbuild` e `rollup`. |
| [`pip-audit`](./pip-audit) | **pip-audit (SCA Backend)** | Ambiente Python | **12 vulnerabilidades conhecidas** identificadas na versão do gerenciador `pip`. |
| [`http-requests-responses.txt`](./http-requests-responses.txt) | **Logs HTTP Brutos** | Rotas da API Flask (`endpoints.py`) | Registro textual completo das requisições e respostas HTTP capturadas. |

---

## 2. Evidências Visuais — Capturas do Burp Suite Community (`docs/evidencias/prints/`)

| Arquivo de Imagem | Rota Inspecionada | Vulnerabilidade Comprovada |
| :--- | :--- | :--- |
| [`prints/01-burp-unauth-query.png`](./prints/01-burp-unauth-query.png) | `POST /users/query` | **Quebra de Autenticação (OWASP A01/A07):** Requisição sem token retorna `200 OK`. |
| [`prints/02-burp-jwt-url-error-leak.png`](./prints/02-burp-jwt-url-error-leak.png) | `GET /users/info?id_token=...` | **Exposição de JWT na URL & Information Disclosure (OWASP A02/A05):** Token trafegando na query string e vazamento de exceção interna do `firebase_admin`. |
| [`prints/03-burp-cors-missing-headers.png`](./prints/03-burp-cors-missing-headers.png) | `OPTIONS /users/create` | **Configuração Incorreta de CORS & Ausência de Security Headers (OWASP A05):** Reflexão de origem arbitrária em `Access-Control-Allow-Origin` e falta de `CSP`, `HSTS`, `X-Frame-Options` e `X-Content-Type-Options`. |
| [`prints/04-burp-assert-validation.png`](./prints/04-burp-assert-validation.png) | `POST /users/query` | **Uso Inseguro de `assert` para Validação (OWASP A04 / CWE-703):** Envio de `{"query": null}` dispara `AssertionError`. |
| [`prints/05-burp-werkzeug-debug-trace.png`](./prints/05-burp-werkzeug-debug-trace.png) | `POST /users/create` ou `POST /hash` | **Flask `debug=True` & Vazamento de Stack Trace / Exceção (OWASP A05 / CWE-94):** Exposição do debugger interativo do Werkzeug e erros internos do Python (`AttributeError`). |
| [`prints/06-docker-nginx-load-balancer.png`](./prints/06-docker-nginx-load-balancer.png) | `GET /health` via Nginx LB (`:5000`) | **Infraestrutura & Escalabilidade (Requisito 5):** Demonstração de balanceamento *round-robin* entre `backend-1` e `backend-2` e logs do `coursesphere-nginx-lb`. |
| [`prints/07-prometheus-grafana-dashboard.png`](./prints/07-prometheus-grafana-dashboard.png) | `GET /metrics` via Prometheus (`:9090`) / Grafana (`:3001`) | **Observabilidade & SRE (Requisito 4 / Diferencial):** Dashboard funcional com métricas de tráfego por instância, latência p95, falhas de autenticação e uptime. |

---

## 3. Mapeamento Completo: Vulnerabilidade $\rightarrow$ Evidências

### VULN-01: SQL Injection (OWASP A03:2021 – Injection | CWE-89)
- **Evidência SAST:** [`bandit.txt`](./bandit.txt) (Linhas 4–62 em `backend/blueprints/courses.py` e Linhas 64–158 em `data-migrations.py`).

### VULN-02: Quebra de Autenticação na Rota `/users/query` (OWASP A01:2021 / A07:2021)
- **Print Burp Suite:** [`prints/01-burp-unauth-query.png`](./prints/01-burp-unauth-query.png)
- **Log HTTP:** [`http-requests-responses.txt`](./http-requests-responses.txt) (*EVIDÊNCIA HTTP 01*).

![01 - Quebra de Autenticação em /users/query](./prints/01-burp-unauth-query.png)

### VULN-03: Exposição de Token JWT na URL e Vazamento de Exceções Internas (OWASP A02:2021 / A05:2021)
- **Print Burp Suite:** [`prints/02-burp-jwt-url-error-leak.png`](./prints/02-burp-jwt-url-error-leak.png)
- **Log HTTP:** [`http-requests-responses.txt`](./http-requests-responses.txt) (*EVIDÊNCIA HTTP 02*).

![02 - Exposição de JWT na URL e Vazamento de Exceção](./prints/02-burp-jwt-url-error-leak.png)

### VULN-04: Configuração Incorreta de Segurança — CORS Irrestrito, Falta de Headers e `debug=True` (OWASP A05:2021)
- **Print Burp Suite (CORS e Headers):** [`prints/03-burp-cors-missing-headers.png`](./prints/03-burp-cors-missing-headers.png)
- **Print Burp Suite (Werkzeug Debug / Erro 500):** [`prints/05-burp-werkzeug-debug-trace.png`](./prints/05-burp-werkzeug-debug-trace.png)
- **Evidência SAST (`debug=True`):** [`bandit.txt`](./bandit.txt) (Linhas 160–167 — `B201:flask_debug_true`).

![03 - CORS Irrestrito e Falta de Security Headers](./prints/03-burp-cors-missing-headers.png)
![05 - Werkzeug Debugger e Erro 500](./prints/05-burp-werkzeug-debug-trace.png)

### VULN-05: Uso de Gerador Pseudo-Aleatório Inseguro (`random`) e `assert` em Produção (CWE-330 / CWE-703)
- **Evidência SAST:** [`bandit.txt`](./bandit.txt) (Linhas 169–197 — `B311` em `main.py:15-16`; Linhas 199–207 — `B101` em `query_manager.py:44`).
- **Print Burp Suite (`assert`):** [`prints/04-burp-assert-validation.png`](./prints/04-burp-assert-validation.png)

![04 - Falha de Validação via assert](./prints/04-burp-assert-validation.png)

### VULN-06: Uso de Componentes e Dependências Vulneráveis (OWASP A06:2021)
- **Evidência SCA:** [`npm-audit`](./npm-audit) (39 vulnerabilidades no frontend) e [`pip-audit`](./pip-audit) (12 vulnerabilidades no ambiente Python), além da imagem `node:16-alpine` EOL em `frontend/Dockerfile`.

### VULN-07: Object Injection Sink e Exposição Visual de Senha no Frontend (OWASP A03:2021 / A04:2021)
- **Evidência SAST:** [`eslint-security.txt`](./eslint-security.txt) (Linha 36 — `security/detect-object-injection` em `CardDeck.tsx:31`) e inspeção de código em `frontend/src/pages/signup/SignUp.tsx:44` (ausência de `type="password"`).

---

## 4. Evidência de Escalabilidade e Balanceamento de Carga (SRE / Infraestrutura)

### Requisito 5: Orquestração `docker-compose` + Balanceador Nginx (`backend-1` e `backend-2`)
- **Print de Execução e Logs do Nginx:** [`prints/06-docker-nginx-load-balancer.png`](./prints/06-docker-nginx-load-balancer.png)
- **Descrição:** Comprova a distribuição *round-robin* de 6 requisições consecutivas no endpoint `/health` alternando entre `instance_id: "backend-1"` e `instance_id: "backend-2"`, acompanhada dos logs de acesso do container `coursesphere-nginx-lb`.

![06 - Balanceamento de Carga Nginx entre backend-1 e backend-2](./prints/06-docker-nginx-load-balancer.png)

### Requisito 4 (Diferencial): Dashboard Funcional de Observabilidade (Prometheus + Grafana)
- **Print do Dashboard:** [`prints/07-prometheus-grafana-dashboard.png`](./prints/07-prometheus-grafana-dashboard.png)

![07 - Dashboard de Observabilidade Prometheus e Grafana](./prints/07-prometheus-grafana-dashboard.png)

