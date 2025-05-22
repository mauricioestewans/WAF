from flask import Flask, render_template, abort
from flask_httpauth import HTTPBasicAuth
from werkzeug.security import generate_password_hash, check_password_hash
import sqlite3
from datetime import datetime, timedelta
import matplotlib.pyplot as plt
from io import BytesIO
import base64
import logging
from typing import Dict, Any, List, Tuple
from contextlib import closing
from typing import Optional  # Adicione esta linha

# Configuração de logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('dashboard.log'),
        logging.StreamHandler()
    ]
)

app = Flask(__name__)
auth = HTTPBasicAuth()

# Configuração simples (em produção, use um sistema de configuração mais seguro)
users = {
    "admin": generate_password_hash("admin123"),
    "monitor": generate_password_hash("monitor123")
}

@auth.verify_password
def verify_password(username: str, password: str) -> Optional[str]:
    if username in users and check_password_hash(users.get(username), password):
        return username
    return None

def get_db_connection() -> sqlite3.Connection:
    """Cria e retorna uma conexão com o banco de dados"""
    try:
        conn = sqlite3.connect('waf.db', timeout=10)
        conn.row_factory = sqlite3.Row
        return conn
    except sqlite3.Error as e:
        logging.error(f"Erro ao conectar ao banco de dados: {e}")
        raise

def get_attack_stats() -> Dict[str, Any]:
    """Obtém estatísticas de ataques do banco de dados"""
    stats = {
        'total_attacks': 0,
        'attacks_by_type': {},
        'recent_attacks': 0,
        'top_ips': []
    }
    
    try:
        with closing(get_db_connection()) as conn:
            cursor = conn.cursor()
            
            # Estatísticas gerais
            cursor.execute("SELECT COUNT(*) FROM attack_logs")
            stats['total_attacks'] = cursor.fetchone()[0] or 0
            
            # Ataques por tipo
            cursor.execute("SELECT attack_type, COUNT(*) FROM attack_logs GROUP BY attack_type")
            stats['attacks_by_type'] = dict(cursor.fetchall())
            
            # Ataques recentes (últimas 24h)
            time_threshold = datetime.now() - timedelta(hours=24)
            cursor.execute("SELECT COUNT(*) FROM attack_logs WHERE timestamp > ?", (time_threshold,))
            stats['recent_attacks'] = cursor.fetchone()[0] or 0
            
            # IPs mais maliciosos
            cursor.execute("""
                SELECT ip, COUNT(*) as count 
                FROM attack_logs 
                GROUP BY ip 
                ORDER BY count DESC 
                LIMIT 5
            """)
            stats['top_ips'] = cursor.fetchall()
            
    except sqlite3.Error as e:
        logging.error(f"Erro ao obter estatísticas de ataques: {e}")
    
    return stats

def generate_attack_chart() -> Optional[str]:
    """Gera um gráfico de ataques nas últimas 24 horas"""
    try:
        with closing(get_db_connection()) as conn:
            cursor = conn.cursor()
            
            # Agrupar ataques por hora nas últimas 24h
            time_threshold = datetime.now() - timedelta(hours=24)
            cursor.execute('''
                SELECT strftime('%Y-%m-%d %H:00', timestamp) as hour, 
                       COUNT(*) as count 
                FROM attack_logs 
                WHERE timestamp > ? 
                GROUP BY hour
                ORDER BY hour
            ''', (time_threshold,))
            
            data = cursor.fetchall()
            if not data:
                return None
                
            hours = [row['hour'][-8:-3] for row in data]  # Extrai apenas HH:MM
            counts = [row['count'] for row in data]
            
            # Gerar gráfico responsivo
            plt.figure(figsize=(10, 5))
            plt.bar(hours, counts)
            plt.xlabel('Hora')
            plt.ylabel('Número de ataques')
            plt.title('Ataques nas últimas 24 horas')
            plt.xticks(rotation=45)
            plt.tight_layout()  # Ajusta o layout para evitar cortes
            
            # Converter para imagem base64
            buffer = BytesIO()
            plt.savefig(buffer, format='png', dpi=100, bbox_inches='tight')
            buffer.seek(0)
            image_base64 = base64.b64encode(buffer.read()).decode('utf-8')
            plt.close()
            
            return image_base64
            
    except sqlite3.Error as e:
        logging.error(f"Erro ao gerar gráfico de ataques: {e}")
        return None
    except Exception as e:
        logging.error(f"Erro inesperado ao gerar gráfico: {e}")
        return None

@app.route('/')
@auth.login_required
def dashboard():
    """Rota principal do dashboard"""
    try:
        stats = get_attack_stats()
        chart = generate_attack_chart()
        return render_template('dashboard.html', 
                           stats=stats, 
                           chart=chart,
                           username=auth.current_user())
    except Exception as e:
        logging.error(f"Erro na rota principal: {e}")
        abort(500)

@app.errorhandler(404)
def page_not_found(e):
    return render_template('404.html'), 404

@app.errorhandler(500)
def internal_server_error(e):
    return render_template('500.html'), 500

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, ssl_context='adhoc')  # SSL adhoc para desenvolvimento