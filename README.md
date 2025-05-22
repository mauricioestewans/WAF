# Web Application Firewall (WAF)

Um WAF simples mas eficaz para proteção contra ataques web comuns, acompanhado de um painel de monitoramento.

## Funcionalidades

### Módulo WAF
- Detecção de SQL Injection
- Detecção de XSS (Cross-Site Scripting)
- Detecção de LFI/RFI (Local/Remote File Inclusion)
- Bloqueio por User-Agent malicioso
- Rate Limiting (limitação de requisições)
- Bloqueio automático de IPs maliciosos
- Logging de ataques em banco de dados SQLite

### Dashboard
- Visualização do total de ataques
- Gráfico de ataques nas últimas 24h
- Listagem de IPs mais maliciosos
- Estatísticas por tipo de ataque

## Requisitos

- Python 3.6+
- Bibliotecas:
  - flask
  - matplotlib
  - sqlite3

## Instalação

1. Clone o repositório:
   ```bash
   git clone https://github.com/seu-usuario/waf.git
   cd waf
