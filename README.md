# Web Application Firewall (WAF)

Um WAF robusto para proteção contra ataques web comuns, com dashboard de monitoramento em tempo real.

## 🚀 Novas Funcionalidades

- **Autenticação segura** no dashboard
- **Persistência de rate limits** entre reinicializações
- **HTTPS suportado** para ambas as aplicações
- **Interface responsiva** com Bootstrap 5
- **Monitoramento detalhado** com logging abrangente
- **Proteção contra grandes requisições** (anti-DoS)

## 📋 Requisitos

- Python 3.8+
- Bibliotecas:
flask
matplotlib
flask-httpauth
pyopenssl (para HTTPS)


## 🛠️ Instalação

```bash
git clone https://github.com/seu-usuario/waf.git
cd waf
pip install -r requirements.txt
⚙️ Configuração
Copie o arquivo de configuração exemplo:

bash
cp waf_config.example.json waf_config.json
Edite as configurações conforme necessário

Para HTTPS, adicione caminhos para certificado e chave no config

🏃 Uso
Iniciar o WAF
bash
python waf.py
Iniciar o Dashboard
bash
python dashboard.py
🔐 Credenciais padrão:

Admin: admin/admin123

Monitor: monitor/monitor123

🐛 Solução de Problemas
Erro de Sintaxe
Se encontrar o erro:

SyntaxError: invalid syntax. Perhaps you forgot a comma?
Verifique a linha 167 no waf.py

Corrija para:

python
cursor.execute(
    "INSERT INTO attack_logs (ip, attack_type, request_data, timestamp) VALUES (?, ?, ?, ?)",
    (ip, attack_type, json.dumps(request_data), datetime.now())
)
Certifique-se de que todos os parênteses e vírgulas estão corretos

📈 Dashboard Features
Gráficos de ataques em tempo real

Top IPs maliciosos

Estatísticas por tipo de ataque

Visualização mobile-friendly

🔒 Segurança
Todos os dados sensíveis são sanitizados

Conexões HTTPS recomendadas

Rate limiting persistente

Proteção contra injection no banco de dados
