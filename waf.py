#!/usr/bin/env python3
from http.server import BaseHTTPRequestHandler, HTTPServer
import re
import time
import json
from urllib.parse import unquote, parse_qs
import sqlite3
import threading
from datetime import datetime
import ssl
from http import HTTPStatus
import logging
from typing import Optional, Dict, List, Set, Any

# Configuração de logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('waf.log'),
        logging.StreamHandler()
    ]
)

class AdvancedWAF:
    def __init__(self):
        self.config = self.load_config()
        self.db_conn = self.init_db_connection()
        self.init_db()
        self.blocked_ips: Set[str] = set()
        self.load_blocked_ips()
        self.request_counters: Dict[str, Dict[str, Any]] = {}
        self.lock = threading.Lock()
        self.max_request_size = self.config.get('max_request_size', 1024 * 1024)  # 1MB default

    def init_db_connection(self) -> sqlite3.Connection:
        """Inicializa e retorna uma conexão com o banco de dados com tratamento de erros"""
        try:
            conn = sqlite3.connect('waf.db', timeout=10)
            conn.execute("PRAGMA journal_mode=WAL")  # Melhor desempenho para concorrência
            return conn
        except sqlite3.Error as e:
            logging.error(f"Erro ao conectar ao banco de dados: {e}")
            raise

    def load_config(self) -> Dict[str, Any]:
        """Carrega a configuração do WAF com tratamento de erros melhorado"""
        default_config = {
            "rate_limit": 100,
            "blocked_ips": [],
            "sql_patterns": [
                r"(\%27)|(\')|(\-\-)",
                r"((\%3D)|(=))[^\n]*((\%27)|(\')|(\-\-)|(\%3B)|(;))",
                r"\w*((\%27)|(\'))((\%6F)|o|(\%4F))((\%72)|r|(\%52))",
                r"exec(\s|\+)+(s|x)p\w+"
            ],
            "xss_patterns": [
                r"<script.*?>.*?</script>",
                r"javascript:",
                r"onerror\s*=",
                r"<iframe.*?>",
                r"alert\(.*?\)"
            ],
            "malicious_user_agents": [
                "sqlmap", "nmap", "nikto", "metasploit", "wpscan", "havij"
            ],
            "lfi_patterns": [
                r"\.\./",
                r"\.\.\\",
                r"etc/passwd",
                r"boot\.ini"
            ],
            "max_request_size": 1048576,  # 1MB
            "ssl_certfile": None,
            "ssl_keyfile": None
        }

        try:
            with open('waf_config.json') as f:
                user_config = json.load(f)
                # Mescla as configurações padrão com as do usuário
                return {**default_config, **user_config}
        except FileNotFoundError:
            logging.warning("Arquivo de configuração não encontrado, usando configurações padrão")
            return default_config
        except json.JSONDecodeError as e:
            logging.error(f"Erro ao decodificar waf_config.json: {e}. Usando configurações padrão")
            return default_config
        except Exception as e:
            logging.error(f"Erro inesperado ao carregar configuração: {e}. Usando configurações padrão")
            return default_config

    def init_db(self) -> None:
        """Inicializa as tabelas do banco de dados com tratamento de erros"""
        try:
            cursor = self.db_conn.cursor()
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS blocked_ips (
                    ip TEXT PRIMARY KEY,
                    reason TEXT,
                    timestamp DATETIME
                )
            ''')
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS attack_logs (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    ip TEXT,
                    attack_type TEXT,
                    request_data TEXT,
                    timestamp DATETIME
                )
            ''')
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS rate_limits (
                    ip TEXT PRIMARY KEY,
                    count INTEGER,
                    timestamp REAL
                )
            ''')
            self.db_conn.commit()
        except sqlite3.Error as e:
            logging.error(f"Erro ao inicializar banco de dados: {e}")
            raise

    def load_blocked_ips(self) -> None:
        """Carrega IPs bloqueados do banco de dados"""
        try:
            cursor = self.db_conn.cursor()
            cursor.execute("SELECT ip FROM blocked_ips")
            self.blocked_ips = {row[0] for row in cursor.fetchall()}
        except sqlite3.Error as e:
            logging.error(f"Erro ao carregar IPs bloqueados: {e}")

    def load_rate_limits(self) -> None:
        """Carrega o estado de rate limits do banco de dados"""
        try:
            cursor = self.db_conn.cursor()
            cursor.execute("SELECT ip, count, timestamp FROM rate_limits")
            with self.lock:
                for ip, count, timestamp in cursor.fetchall():
                    self.request_counters[ip] = {'count': count, 'timestamp': timestamp}
        except sqlite3.Error as e:
            logging.error(f"Erro ao carregar rate limits: {e}")

    def block_ip(self, ip: str, reason: str) -> None:
        """Bloqueia um IP e registra no banco de dados"""
        try:
            with self.lock:
                if ip not in self.blocked_ips:
                    self.blocked_ips.add(ip)
                    cursor = self.db_conn.cursor()
                    cursor.execute(
                        "INSERT OR REPLACE INTO blocked_ips VALUES (?, ?, ?)",
                        (ip, reason, datetime.now())
                    )
                    self.db_conn.commit()
                    logging.info(f"IP bloqueado: {ip} - Razão: {reason}")
        except sqlite3.Error as e:
            logging.error(f"Erro ao bloquear IP {ip}: {e}")

    def log_attack(self, ip: str, attack_type: str, request_data: Dict[str, Any]) -> None:
        """Registra um ataque no banco de dados"""
        try:
            cursor = self.db_conn.cursor()
            cursor.execute(
                "INSERT INTO attack_logs (ip, attack_type, request_data, timestamp) VALUES (?, ?, ?, ?)",
        
    (ip, attack_type, json.dumps(request_data), datetime.now())
)
        except sqlite3.Error as e:
            logging.error(f"Erro ao registrar ataque: {e}")

    def save_rate_limits(self) -> None:
        """Salva o estado atual de rate limits no banco de dados"""
        try:
            cursor = self.db_conn.cursor()
            cursor.execute("DELETE FROM rate_limits")
            with self.lock:
                for ip, data in self.request_counters.items():
                    cursor.execute(
    "INSERT INTO rate_limits VALUES (?, ?, ?)",
    (ip, data['count'], data['timestamp'])
)
            self.db_conn.commit()
        except sqlite3.Error as e:
            logging.error(f"Erro ao salvar rate limits: {e}")

    def is_ip_blocked(self, ip: str) -> bool:
        """Verifica se um IP está bloqueado"""
        return ip in self.blocked_ips

    def is_rate_limited(self, ip: str) -> bool:
        """Verifica se um IP excedeu o limite de requisições"""
        now = time.time()
        with self.lock:
            if ip not in self.request_counters:
                self.request_counters[ip] = {'count': 1, 'timestamp': now}
                return False

            time_diff = now - self.request_counters[ip]['timestamp']
            if time_diff > 60:  # Reset after 1 minute
                self.request_counters[ip] = {'count': 1, 'timestamp': now}
                return False

            self.request_counters[ip]['count'] += 1
            if self.request_counters[ip]['count'] > self.config['rate_limit']:
                self.block_ip(ip, "Rate limit exceeded")
                return True
            return False

    def detect_attack(self, path: str, headers: Dict[str, str], body: Optional[str] = None) -> Optional[str]:
        """Detecta vários tipos de ataques web"""
        try:
            decoded_path = unquote(path).lower()
            user_agent = headers.get('User-Agent', '').lower()
            
            # Verifica tamanho da requisição
            request_size = len(decoded_path) + sum(len(k) + len(v) for k, v in headers.items())
            if body:
                request_size += len(body)
            if request_size > self.max_request_size:
                return "Oversized request"

            # SQL Injection detection
            for pattern in self.config['sql_patterns']:
                if re.search(pattern, decoded_path, re.IGNORECASE):
                    return 'SQL Injection'
            
            # XSS detection
            for pattern in self.config['xss_patterns']:
                if re.search(pattern, decoded_path, re.IGNORECASE):
                    return 'XSS Attack'
            
            # LFI/RFI detection
            for pattern in self.config['lfi_patterns']:
                if re.search(pattern, decoded_path, re.IGNORECASE):
                    return 'LFI/RFI Attack'
            
            # Malicious User-Agent detection
            for agent in self.config['malicious_user_agents']:
                if agent.lower() in user_agent:
                    return 'Malicious User-Agent'
            
            return None
        except Exception as e:
            logging.error(f"Erro durante detecção de ataque: {e}")
            return "Detection error"

class WAFRequestHandler(BaseHTTPRequestHandler):
    waf = AdvancedWAF()
    
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
    
    def log_message(self, format: str, *args) -> None:
        """Customiza o log para incluir mais informações"""
        logging.info(f"{self.client_address[0]} - {format % args}")

    def do_GET(self) -> None:
        """Handle GET requests"""
        self.handle_request()

    def do_POST(self) -> None:
        """Handle POST requests"""
        content_length = self.headers.get('Content-Length')
        if not content_length:
            self.send_error(HTTPStatus.LENGTH_REQUIRED, "Content-Length header required")
            return
            
        try:
            content_length = int(content_length)
            if content_length > self.waf.max_request_size:
                self.send_error(HTTPStatus.REQUEST_ENTITY_TOO_LARGE, "Request too large")
                return
                
            post_data = self.rfile.read(content_length).decode('utf-8')
            self.handle_request(post_data)
        except ValueError:
            self.send_error(HTTPStatus.BAD_REQUEST, "Invalid Content-Length")
        except UnicodeDecodeError:
            self.send_error(HTTPStatus.BAD_REQUEST, "Invalid encoding")

    def handle_request(self, body: Optional[str] = None) -> None:
        """Processa todas as requisições"""
        client_ip = self.client_address[0]
        
        if self.waf.is_ip_blocked(client_ip):
            self.send_error(HTTPStatus.FORBIDDEN, "IP Bloqueado pelo WAF")
            return

        if self.waf.is_rate_limited(client_ip):
            self.send_error(HTTPStatus.TOO_MANY_REQUESTS, "Muitas requisições. Tente novamente mais tarde.")
            return

        attack_type = self.waf.detect_attack(
            path=self.path,
            headers={k: v for k, v in self.headers.items()},
            body=body
        )

        if attack_type:
            self.waf.log_attack(client_ip, attack_type, {
                'path': self.path,
                'headers': dict(self.headers),
                'body': body
            })
            self.waf.block_ip(client_ip, attack_type)
            self.send_error(HTTPStatus.FORBIDDEN, f"Ataque bloqueado: {attack_type}")
            return

        self.send_response(HTTPStatus.OK)
        self.send_header('Content-type', 'text/html')
        self.end_headers()
        self.wfile.write(b"<h1>Requisicao segura!</h1>")

def run_server():
    server_address = ('', 8000)
    httpd = HTTPServer(server_address, WAFRequestHandler)
    
    # Configuração SSL se disponível
    if WAFRequestHandler.waf.config.get('ssl_certfile') and WAFRequestHandler.waf.config.get('ssl_keyfile'):
        try:
            context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
            context.load_cert_chain(
                certfile=WAFRequestHandler.waf.config['ssl_certfile'],
                keyfile=WAFRequestHandler.waf.config['ssl_keyfile']
            )
            httpd.socket = context.wrap_socket(httpd.socket, server_side=True)
            logging.info("SSL habilitado")
        except Exception as e:
            logging.error(f"Erro ao configurar SSL: {e}")
            return
    
    # Carrega rate limits persistentes
    WAFRequestHandler.waf.load_rate_limits()
    
    try:
        logging.info(f"WAF rodando na porta {server_address[1]}...")
        httpd.serve_forever()
    except KeyboardInterrupt:
        logging.info("Desligando o WAF...")
        WAFRequestHandler.waf.save_rate_limits()
        httpd.server_close()
    except Exception as e:
        logging.error(f"Erro no servidor: {e}")
    finally:
        WAFRequestHandler.waf.db_conn.close()

if __name__ == "__main__":
    run_server()