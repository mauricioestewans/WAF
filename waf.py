#!/usr/bin/env python3
from http.server import BaseHTTPRequestHandler, HTTPServer
import re
import time
import json
from urllib.parse import unquote, parse_qs
import sqlite3
import threading
from datetime import datetime

class AdvancedWAF:
    def __init__(self):
        self.config = self.load_config()
        self.db_conn = sqlite3.connect('waf.db')
        self.init_db()
        self.blocked_ips = set()
        self.load_blocked_ips()
        self.request_counters = {}
        self.lock = threading.Lock()

    def load_config(self):
        try:
            with open('waf_config.json') as f:
                return json.load(f)
        except:
            return {
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
                ]
            }

    def init_db(self):
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
        self.db_conn.commit()

    def load_blocked_ips(self):
        cursor = self.db_conn.cursor()
        cursor.execute("SELECT ip FROM blocked_ips")
        for row in cursor.fetchall():
            self.blocked_ips.add(row[0])

    def block_ip(self, ip, reason):
        with self.lock:
            if ip not in self.blocked_ips:
                self.blocked_ips.add(ip)
                cursor = self.db_conn.cursor()
                cursor.execute(
                    "INSERT INTO blocked_ips VALUES (?, ?, ?)",
                    (ip, reason, datetime.now())
                )
                self.db_conn.commit()

    def log_attack(self, ip, attack_type, request_data):
        cursor = self.db_conn.cursor()
        cursor.execute(
            "INSERT INTO attack_logs (ip, attack_type, request_data, timestamp) VALUES (?, ?, ?, ?)",
            (ip, attack_type, str(request_data), datetime.now())
        )
        self.db_conn.commit()

    def is_ip_blocked(self, ip):
        return ip in self.blocked_ips

    def is_rate_limited(self, ip):
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
            return self.request_counters[ip]['count'] > self.config['rate_limit']

    def detect_attack(self, path, headers, body=None):
        decoded_path = unquote(path).lower()
        user_agent = headers.get('User-Agent', '').lower()
        query_params = parse_qs(decoded_path.split('?')[-1] if '?' in decoded_path else '')
        
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
            if agent in user_agent:
                return 'Malicious User-Agent'
        
        return None

class WAFRequestHandler(BaseHTTPRequestHandler):
    waf = AdvancedWAF()

    def do_GET(self):
        self.handle_request()

    def do_POST(self):
        content_length = int(self.headers.get('Content-Length', 0))
        post_data = self.rfile.read(content_length).decode('utf-8')
        self.handle_request(post_data)

    def handle_request(self, body=None):
        client_ip = self.client_address[0]
        
        if self.waf.is_ip_blocked(client_ip):
            self.send_error(403, "IP Bloqueado pelo WAF")
            return

        if self.waf.is_rate_limited(client_ip):
            self.send_error(429, "Muitas requisições. Tente novamente mais tarde.")
            return

        attack_type = self.waf.detect_attack(
            path=self.path,
            headers=self.headers,
            body=body
        )

        if attack_type:
            self.waf.log_attack(client_ip, attack_type, {
                'path': self.path,
                'headers': dict(self.headers),
                'body': body
            })
            self.waf.block_ip(client_ip, attack_type)
            self.send_error(403, f"Ataque bloqueado: {attack_type}")
            return

        self.send_response(200)
        self.send_header('Content-type', 'text/html')
        self.end_headers()
        self.wfile.write(b"<h1>Requisicao segura!</h1>")

if __name__ == "__main__":
    server = HTTPServer(('', 8000), WAFRequestHandler)
    print("WAF rodando na porta 8000...")
    server.serve_forever()