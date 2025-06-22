import logging
import re
import urllib.parse
import os
import json
import time
import threading
from collections import defaultdict, deque
from functools import lru_cache
from datetime import datetime, timedelta
from dataclasses import dataclass
from typing import Dict, List, Optional, Tuple
import hashlib

try:
    import requests
    THREAT_INTEL_AVAILABLE = True
except ImportError:
    THREAT_INTEL_AVAILABLE = False
    print('Uyarı: requests kütüphanesi bulunamadı. Tehdit istihbaratı kontrolü yapılamayacak.')

@dataclass
class ThreatEvent:
    """Tehdit olaylarını temsil eden veri sınıfı"""
    timestamp: float
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    threat_type: str
    threat_score: int
    details: str
    payload_hash: str

class ConfigManager:
    """Konfigürasyon yönetimi için sınıf"""
    
    def __init__(self, config_file='../data/ids_config.json'):
        self.config_file = config_file
        self.config = self.load_config()
    
    def load_config(self) -> Dict:
        """Config dosyasını yükler"""
        default_config = {
            'logging': {
                'log_file': '../data/ids.log',
                'level': 'INFO',
                'max_file_size': 10485760,  # 10MB
                'backup_count': 5
            },
            'detection': {
                'request_threshold': 50,
                'time_window': 60,
                'threat_score_threshold': 2,
                'payload_size_threshold': 10240,
                'enable_behavioral_analysis': True,
                'login_failure_threshold': 5,
                'auto_block_on_brute_force': True,
                'ip_block_duration': 3600
            },
            'whitelist': [
                "127.0.0.1",
                "192.168.1.1"
            ],
            'threat_intel': {
                'enabled': False,
                'api_key': '',
                'cache_duration': 3600  # 1 hour
            },
            'alerting': {
                'enable_email': False,
                'email_config': {
                    'smtp_server': '',
                    'smtp_port': 587,
                    'username': '',
                    'password': '',
                    'to_addresses': []
                }
            }
        }
        
        try:
            if os.path.exists(self.config_file):
                with open(self.config_file, 'r', encoding='utf-8') as f:
                    config = json.load(f)
                    # Default config ile birleştir
                    return {**default_config, **config}
            else:
                # Config dosyası yoksa default'u oluştur
                os.makedirs(os.path.dirname(self.config_file), exist_ok=True)
                with open(self.config_file, 'w', encoding='utf-8') as f:
                    json.dump(default_config, f, indent=2)
                return default_config
        except Exception as e:
            print(f'Config yükleme hatası: {e}. Default config kullanılıyor.')
            return default_config

class EnhancedLogger:
    """Gelişmiş loglama sistemi"""
    
    def __init__(self, config: Dict):
        self.config = config['logging']
        self.setup_logging()
        self.lock = threading.Lock()
    
    def setup_logging(self):
        """Logging sistemini kurar"""
        from logging.handlers import RotatingFileHandler
        
        log_dir = os.path.dirname(self.config['log_file'])
        if not os.path.exists(log_dir):
            os.makedirs(log_dir)
        
        # Rotating file handler
        handler = RotatingFileHandler(
            self.config['log_file'],
            maxBytes=self.config['max_file_size'],
            backupCount=self.config['backup_count']
        )
        
        formatter = logging.Formatter(
            '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
        )
        handler.setFormatter(formatter)
        
        self.logger = logging.getLogger('IDS')
        self.logger.setLevel(getattr(logging, self.config['level']))
        self.logger.addHandler(handler)
    
    def log_threat(self, threat_event: ThreatEvent):
        """Tehdit olayını loglar"""
        with self.lock:
            msg = (f"THREAT_DETECTED | Type: {threat_event.threat_type} | "
                   f"Score: {threat_event.threat_score} | "
                   f"Source: {threat_event.src_ip}:{threat_event.src_port} | "
                   f"Target: {threat_event.dst_ip}:{threat_event.dst_port} | "
                   f"Details: {threat_event.details}")
            
            # Özel threat tiplerini farklı log seviyelerinde logla
            if threat_event.threat_type == "credential_bruteforce":
                self.logger.error(f"BRUTE_FORCE_ATTACK | {msg}")
            elif threat_event.threat_type == "csrf":
                self.logger.warning(f"CSRF_ATTACK | {msg}")
            elif threat_event.threat_score >= 3:
                self.logger.critical(msg)
            else:
                self.logger.warning(msg)

class RuleEngine:
    """Gelişmiş kural motoru"""
    
    def __init__(self, rules_file='../data/rules.json'):
        self.rules_file = rules_file
        self.rules = self.load_rules()
        self.compiled_patterns = self.compile_patterns()
        self.last_modified = os.path.getmtime(rules_file) if os.path.exists(rules_file) else 0
    
    def load_rules(self) -> Dict:
        """Kuralları yükler"""
        default_rules = {
            'sql_injection': {
                'patterns': [
                    r'(?i)UNION\s*SELECT',
                    r'(?i)UNION\s*/\*.*\*/\s*SELECT',
                    r'(?i)OR\s*1\s*=\s*1',
                    r'(?i)AND\s*1\s*=\s*1',
                    r'--',
                    r';\s*DROP\s*TABLE',
                    r'(?i)EXEC\s+xp_',
                    r'(?i)EXEC\s+sp_',
                    r'%27', r'%22', r'%3B', r'%2D%2D',
                    r'(?i)INSERT\s+INTO',
                    r'(?i)UPDATE\s+.*SET',
                    r'(?i)DELETE\s+FROM'
                ],
                'threat_score': 2,
                'enabled': True
            },
            'command_injection': {
                'patterns': [
                    r';\s*(ls|dir|cat|whoami|id|pwd|uname|netstat|ps|top)',
                    r'&&\s*(ls|dir|cat|whoami|id|pwd|uname)',
                    r'\|\s*(ls|dir|cat|whoami|id|pwd)',
                    r'(?i)exec\s*\(',
                    r'(?i)system\s*\(',
                    r'(?i)eval\s*\(',
                    r'%3B', r'%26%26', r'%7C',
                    r';\s*rm\s*-rf',
                    r';\s*chmod', r';\s*chown'
                ],
                'threat_score': 2,
                'enabled': True
            },
            'directory_traversal': {
                'patterns': [
                    r'\.\.\/',
                    r'\.\\.\\',
                    r'%2e%2e%2f',
                    r'%2e%2e%5c',
                    r'etc/passwd',
                    r'boot\.ini',
                    r'win\.ini',
                    r'system32',
                    r'/proc/self/environ',
                    r'/etc/shadow'
                ],
                'threat_score': 2,
                'enabled': True
            },
            'xss': {
                'patterns': [
                    r'(?i)<script\s*.*?>',
                    r'(?i)javascript:',
                    r'(?i)on(error|load|click|mouseover|mouseout|submit|focus|blur|change|input|keydown|keypress|keyup)\s*=',
                    r'(?i)alert\s*\(',
                    r'(?i)eval\s*\(',
                    r'%3Cscript%3E',
                    r'%6A%61%76%61%73%63%72%69%70%74',
                    r'(?i)document\.cookie',
                    r'(?i)window\.location',
                    r'(?i)<img\s+src\s*=\s*[\'"]javascript:'
                ],
                'threat_score': 1,
                'enabled': True
            },
            'csrf': {
                'patterns': [
                    r'(?i)^(POST|PUT|PATCH|DELETE)\s',
                    r'(?i)Content-Type:\s*application/x-www-form-urlencoded',
                    r'(?i)Content-Type:\s*multipart/form-data'
                ],
                'threat_score': 2,
                'enabled': True,
                'suspicious_domains': ['evil.com', 'malicious.com', 'phishing.org', 'attacker.net'],
                'required_headers': ['Referer', 'Origin'],
                'csrf_token_patterns': [
                    r'(?i)csrf[_-]?token',
                    r'(?i)xsrf[_-]?token',
                    r'(?i)authenticity[_-]?token',
                    r'(?i)__RequestVerificationToken'
                ]
            }
        }
        
        try:
            if os.path.exists(self.rules_file):
                with open(self.rules_file, 'r', encoding='utf-8') as f:
                    rules = json.load(f)
                    return {**default_rules, **rules}
            else:
                os.makedirs(os.path.dirname(self.rules_file), exist_ok=True)
                with open(self.rules_file, 'w', encoding='utf-8') as f:
                    json.dump(default_rules, f, indent=2)
                return default_rules
        except Exception as e:
            print(f'Kural yükleme hatası: {e}')
            return default_rules
    
    def compile_patterns(self) -> Dict:
        """Regex kalıplarını önceden derler"""
        compiled = {}
        for category, rule_data in self.rules.items():
            if rule_data.get('enabled', True):
                patterns = []
                for pattern in rule_data.get('patterns', []):
                    try:
                        patterns.append(re.compile(pattern))
                    except re.error as e:
                        print(f'Regex derleme hatası ({pattern}): {e}')
                compiled[category] = {
                    'patterns': patterns,
                    'threat_score': rule_data.get('threat_score', 1)
                }
        return compiled
    
    def check_for_rule_updates(self):
        """Kural dosyasının güncellenip güncellenmediğini kontrol eder"""
        if os.path.exists(self.rules_file):
            current_modified = os.path.getmtime(self.rules_file)
            if current_modified > self.last_modified:
                self.rules = self.load_rules()
                self.compiled_patterns = self.compile_patterns()
                self.last_modified = current_modified
                return True
        return False

class ThreatIntelligence:
    """Tehdit istihbaratı modülü"""
    
    def __init__(self, config: Dict):
        self.config = config.get('threat_intel', {})
        self.cache = {}
        self.cache_lock = threading.Lock()
    
    @lru_cache(maxsize=1000)
    def check_ip_reputation(self, ip: str) -> Tuple[bool, str]:
        """IP adresinin itibarını kontrol eder"""
        if not self.config.get('enabled', False) or not THREAT_INTEL_AVAILABLE:
            return False, "Threat intelligence disabled"
        
        # Cache kontrolü
        with self.cache_lock:
            if ip in self.cache:
                cache_time, result = self.cache[ip]
                if time.time() - cache_time < self.config.get('cache_duration', 3600):
                    return result
        
        try:
            api_key = self.config.get('api_key', '')
            if not api_key:
                return False, "API key not configured"
            
            # AbuseIPDB örneği
            url = f'https://api.abuseipdb.com/api/v2/check'
            headers = {
                'Key': api_key,
                'Accept': 'application/json'
            }
            params = {'ipAddress': ip, 'maxAgeInDays': 90}
            
            response = requests.get(url, headers=headers, params=params, timeout=5)
            if response.status_code == 200:
                data = response.json()
                abuse_score = data.get('data', {}).get('abuseConfidenceScore', 0)
                is_malicious = abuse_score > 50
                
                result = (is_malicious, f"Abuse score: {abuse_score}")
                
                # Cache'e kaydet
                with self.cache_lock:
                    self.cache[ip] = (time.time(), result)
                
                return result
        except Exception as e:
            print(f'Threat intelligence check failed: {e}')
        
        return False, "Check failed"

class BehavioralAnalyzer:
    """Davranışsal analiz modülü"""
    
    def __init__(self, config: Dict):
        self.config = config['detection']
        self.request_history = defaultdict(lambda: deque(maxlen=1000))
        self.login_failures = defaultdict(lambda: deque(maxlen=100))
        self.payload_patterns = defaultdict(set)
        self.lock = threading.Lock()
        
        # Login failure detection patterns
        self.failed_login_patterns = [
            re.compile(r'(?i)HTTP/1\.1\s+401'),  # HTTP 401 response
            re.compile(r'(?i)HTTP/1\.1\s+403'),  # HTTP 403 response
            re.compile(r'(?i)<[^>]*>Login Failed'),  # HTML içinde Login Failed
            re.compile(r'(?i)<[^>]*>Invalid credentials'),  # HTML içinde Invalid credentials
            re.compile(r'(?i)"error":\s*"[^"]*failed"'),  # JSON error response
            re.compile(r'(?i)"status":\s*"unauthorized"'),  # JSON status
            re.compile(r'(?i)Authentication failed'),
            re.compile(r'(?i)Invalid username or password'),
            re.compile(r'(?i)Login attempt failed'),
            re.compile(r'(?i)Account locked'),
            re.compile(r'(?i)Too many failed attempts')
        ]
        
        self.login_endpoints = [
            re.compile(r'(?i)^POST\s+/login'),
            re.compile(r'(?i)^POST\s+/signin'),
            re.compile(r'(?i)^POST\s+/auth'),
            re.compile(r'(?i)^POST\s+/authenticate'),
            re.compile(r'(?i)^POST\s+/admin/login'),
            re.compile(r'(?i)^POST\s+/api/login'),
            re.compile(r'(?i)^POST\s+/user/login'),
            re.compile(r'(?i)^POST\s+/account/login'),
            re.compile(r'(?i)^POST\s+/wp-login\.php'),
            re.compile(r'(?i)^POST\s+/administrator')
        ]
        
        # Blocked IPs tracking
        self.blocked_ips = {}
        self.block_duration = config.get('ip_block_duration', 3600)  # 1 hour default
    
    def analyze_request_pattern(self, src_ip: str, timestamp: float) -> Tuple[bool, str]:
        """İstek kalıplarını analiz eder"""
        # Önce IP'nin bloklu olup olmadığını kontrol et
        if self.is_ip_blocked(src_ip):
            return True, f"IP is blocked until {datetime.fromtimestamp(self.blocked_ips[src_ip]).strftime('%Y-%m-%d %H:%M:%S')}"
        
        with self.lock:
            now = timestamp
            window = self.config['time_window']
            threshold = self.config['request_threshold']
            
            # Eski kayıtları temizle
            self.request_history[src_ip] = deque(
                [t for t in self.request_history[src_ip] if now - t <= window],
                maxlen=1000
            )
            
            # Yeni isteği ekle
            self.request_history[src_ip].append(now)
            
            # Eşik kontrolü
            if len(self.request_history[src_ip]) > threshold:
                return True, f"High request rate: {len(self.request_history[src_ip])} requests in {window}s"
        
        return False, ""
    
    def is_ip_blocked(self, src_ip: str) -> bool:
        """IP'nin bloklu olup olmadığını kontrol eder"""
        with self.lock:
            if src_ip in self.blocked_ips:
                if time.time() < self.blocked_ips[src_ip]:
                    return True
                else:
                    # Blok süresi dolmuş, kaldır
                    del self.blocked_ips[src_ip]
        return False
    
    def block_ip(self, src_ip: str, duration: Optional[int] = None):
        """IP'yi belirli bir süre için bloklar"""
        with self.lock:
            block_until = time.time() + (duration or self.block_duration)
            self.blocked_ips[src_ip] = block_until
    
    def analyze_payload_similarity(self, src_ip: str, payload_hash: str) -> Tuple[bool, str]:
        """Payload benzerliğini analiz eder"""
        with self.lock:
            if payload_hash in self.payload_patterns[src_ip]:
                return True, "Repeated payload pattern detected"
            
            self.payload_patterns[src_ip].add(payload_hash)
            
            # Pattern sayısını sınırla
            if len(self.payload_patterns[src_ip]) > 50:
                # En eski pattern'ları kaldır (basit FIFO)
                old_patterns = list(self.payload_patterns[src_ip])[:10]
                for pattern in old_patterns:
                    self.payload_patterns[src_ip].discard(pattern)
        
        return False, ""
    
    def analyze_login_failures(self, src_ip: str, payload: str, timestamp: float) -> Tuple[bool, str]:
        """Başarısız giriş denemelerini analiz eder"""
        with self.lock:
            now = timestamp
            window = self.config['time_window']
            failure_threshold = self.config.get('login_failure_threshold', 5)
            
            # HTTP response'u parse et
            if any(pattern.search(payload) for pattern in self.failed_login_patterns):
                # Başarısız giriş tespit edildi
                # Eski kayıtları temizle
                self.login_failures[src_ip] = deque(
                    [t for t in self.login_failures[src_ip] if now - t <= window],
                    maxlen=100
                )
                
                # Yeni başarısız girişi ekle
                self.login_failures[src_ip].append(now)
                
                # Eşik kontrolü
                failure_count = len(self.login_failures[src_ip])
                if failure_count >= failure_threshold:
                    # Logla ve blokla
                    details = f"Multiple login failures detected: {failure_count} failed attempts in {window}s window"
                    
                    # Otomatik IP bloklama
                    if self.config.get('auto_block_on_brute_force', True):
                        block_duration = self.config.get('ip_block_duration', 3600)  # 1 saat default
                        self.block_ip(src_ip, block_duration)
                        details += f". IP blocked for {block_duration} seconds"
                    
                    return True, details
            
            # HTTP request kontrolü - sadece istatistik için
            elif any(pattern.search(payload) for pattern in self.login_endpoints):
                # Login denemesi yapılıyor, şimdilik bir şey yapma
                pass
        
        return False, ""

class EnhancedIDS:
    """Gelişmiş IDS ana sınıfı"""
    
    def __init__(self, config_file='../data/ids_config.json'):
        self.config_manager = ConfigManager(config_file)
        self.config = self.config_manager.config
        
        self.logger = EnhancedLogger(self.config)
        self.rule_engine = RuleEngine()
        self.threat_intel = ThreatIntelligence(self.config)
        self.behavioral_analyzer = BehavioralAnalyzer(self.config)
        
        self.whitelist = set(self.config.get('whitelist', []))
        self.threat_events = deque(maxlen=10000)  # Son 10000 olayı sakla
        
        # Statistics
        self.stats = {
            'total_packets': 0,
            'threats_detected': 0,
            'false_positives': 0,
            'start_time': time.time()
        }
    
    @lru_cache(maxsize=1000)
    def decode_payload(self, payload: bytes) -> Optional[str]:
        """Payload'u decode eder"""
        try:
            # UTF-8 dene
            try:
                payload_str = payload.decode('utf-8')
            except UnicodeDecodeError:
                # Latin-1 dene
                try:
                    payload_str = payload.decode('latin-1')
                except UnicodeDecodeError:
                    # Son çare olarak hataları yok say
                    payload_str = payload.decode('utf-8', errors='ignore')
            
            # URL decode
            return urllib.parse.unquote(payload_str)
        except Exception as e:
            self.logger.logger.warning(f'Payload decode error: {e}')
            return None
    
    def calculate_payload_hash(self, payload: str) -> str:
        """Payload'un hash'ini hesaplar"""
        return hashlib.md5(payload.encode()).hexdigest()
    
    def detect_pattern_based_threats(self, payload: str) -> List[Tuple[str, int, List[str]]]:
        """Pattern tabanlı tehdit tespiti"""
        threats = []
        
        for category, rule_data in self.rule_engine.compiled_patterns.items():
            matched_patterns = []
            for pattern in rule_data['patterns']:
                if pattern.search(payload):
                    matched_patterns.append(pattern.pattern)
            
            if matched_patterns:
                threats.append((category, rule_data['threat_score'], matched_patterns))
        
        return threats
    
    def detect_csrf_threat(self, payload_str: str, src_ip: str) -> Optional[ThreatEvent]:
        """CSRF saldırılarını tespit eder"""
        csrf_rules = self.rule_engine.rules.get('csrf', {})
        if not csrf_rules.get('enabled', False):
            return None
        
        # HTTP method kontrolü (POST, PUT, PATCH, DELETE)
        http_method_match = re.search(r'(?i)^(POST|PUT|PATCH|DELETE)\s', payload_str)
        if not http_method_match:
            return None
        
        threat_score = 0
        details = []
        http_method = http_method_match.group(1).upper()
        
        # Referer/Origin header kontrolü
        has_referer = re.search(r'(?i)Referer:\s*(\S+)', payload_str)
        has_origin = re.search(r'(?i)Origin:\s*(\S+)', payload_str)
        
        if not has_referer and not has_origin:
            threat_score += 2
            details.append(f"Missing Referer/Origin headers in {http_method} request")
        
        # CSRF token kontrolü
        csrf_token_patterns = csrf_rules.get('csrf_token_patterns', [])
        has_csrf_token = False
        for pattern in csrf_token_patterns:
            if re.search(pattern, payload_str):
                has_csrf_token = True
                break
        
        if not has_csrf_token and http_method in ['POST', 'PUT', 'PATCH', 'DELETE']:
            threat_score += 1
            details.append("Missing CSRF token in state-changing request")
        
        # Suspicious domain kontrolü
        if has_referer:
            referer_url = has_referer.group(1)
            referer_match = re.search(r'https?://([^/\s]+)', referer_url)
            if referer_match:
                referer_domain = referer_match.group(1).lower()
                suspicious_domains = csrf_rules.get('suspicious_domains', [])
                
                for suspicious_domain in suspicious_domains:
                    if suspicious_domain in referer_domain:
                        threat_score += 3
                        details.append(f"Suspicious referer domain: {referer_domain}")
                        break
        
        # Host header ile Referer/Origin karşılaştırması
        host_match = re.search(r'(?i)Host:\s*([^\s]+)', payload_str)
        if host_match and (has_referer or has_origin):
            host_domain = host_match.group(1).lower()
            
            if has_referer:
                referer_domain = referer_match.group(1).lower() if referer_match else ""
                if referer_domain and host_domain not in referer_domain and referer_domain not in host_domain:
                    threat_score += 2
                    details.append(f"Cross-origin request: host={host_domain}, referer={referer_domain}")
            
            if has_origin:
                origin_url = has_origin.group(1)
                origin_match = re.search(r'https?://([^/\s]+)', origin_url)
                if origin_match:
                    origin_domain = origin_match.group(1).lower()
                    if host_domain not in origin_domain and origin_domain not in host_domain:
                        threat_score += 2
                        details.append(f"Cross-origin request: host={host_domain}, origin={origin_domain}")
        
        if threat_score > 0:
            return ThreatEvent(
                timestamp=time.time(),
                src_ip=src_ip,
                dst_ip="",
                src_port=0,
                dst_port=0,
                threat_type="csrf",
                threat_score=min(threat_score, 3),  # Max score 3
                details="; ".join(details),
                payload_hash=self.calculate_payload_hash(payload_str)
            )
        
        return None
    
    def analyze_packet(self, packet, src_ip: str, dst_ip: str, src_port: int, dst_port: int) -> List[ThreatEvent]:
        """Ana paket analiz fonksiyonu"""
        self.stats['total_packets'] += 1
        
        # Kural güncellemelerini kontrol et
        if self.stats['total_packets'] % 1000 == 0:
            self.rule_engine.check_for_rule_updates()
        
        # Whitelist kontrolü
        if src_ip in self.whitelist:
            return []
        
        threats = []
        timestamp = time.time()
        
        # Raw payload kontrolü
        if hasattr(packet, 'haslayer') and packet.haslayer('Raw'):
            payload_bytes = packet['Raw'].load
            payload_str = self.decode_payload(payload_bytes)
            
            if payload_str:
                payload_hash = self.calculate_payload_hash(payload_str)
                
                # Pattern tabanlı tespit
                pattern_threats = self.detect_pattern_based_threats(payload_str)
                for threat_type, score, patterns in pattern_threats:
                    threat_event = ThreatEvent(
                        timestamp=timestamp,
                        src_ip=src_ip,
                        dst_ip=dst_ip,
                        src_port=src_port,
                        dst_port=dst_port,
                        threat_type=threat_type,
                        threat_score=score,
                        details=f"Matched patterns: {', '.join(patterns[:3])}",
                        payload_hash=payload_hash
                    )
                    threats.append(threat_event)
                
                # CSRF saldırı tespiti
                csrf_threat = self.detect_csrf_threat(payload_str, src_ip)
                if csrf_threat:
                    csrf_threat.dst_ip = dst_ip
                    csrf_threat.src_port = src_port
                    csrf_threat.dst_port = dst_port
                    threats.append(csrf_threat)
                
                # Davranışsal analiz
                if self.config['detection'].get('enable_behavioral_analysis', True):
                    # Yüksek istek oranı kontrolü
                    is_high_rate, rate_details = self.behavioral_analyzer.analyze_request_pattern(src_ip, timestamp)
                    if is_high_rate:
                        threat_event = ThreatEvent(
                            timestamp=timestamp,
                            src_ip=src_ip,
                            dst_ip=dst_ip,
                            src_port=src_port,
                            dst_port=dst_port,
                            threat_type="high_request_rate",
                            threat_score=2,
                            details=rate_details,
                            payload_hash=payload_hash
                        )
                        threats.append(threat_event)
                    
                    # Payload benzerlik kontrolü
                    is_similar, similarity_details = self.behavioral_analyzer.analyze_payload_similarity(src_ip, payload_hash)
                    if is_similar:
                        threat_event = ThreatEvent(
                            timestamp=timestamp,
                            src_ip=src_ip,
                            dst_ip=dst_ip,
                            src_port=src_port,
                            dst_port=dst_port,
                            threat_type="repeated_payload",
                            threat_score=1,
                            details=similarity_details,
                            payload_hash=payload_hash
                        )
                        threats.append(threat_event)
                    
                    # Login failure analizi
                    is_login_attack, login_details = self.behavioral_analyzer.analyze_login_failures(
                        src_ip, payload_str, timestamp
                    )
                    if is_login_attack:
                        threat_event = ThreatEvent(
                            timestamp=timestamp,
                            src_ip=src_ip,
                            dst_ip=dst_ip,
                            src_port=src_port,
                            dst_port=dst_port,
                            threat_type="credential_bruteforce",
                            threat_score=3,
                            details=login_details,
                            payload_hash=payload_hash
                        )
                        threats.append(threat_event)
        
        # Tehdit istihbaratı kontrolü
        is_malicious, intel_details = self.threat_intel.check_ip_reputation(src_ip)
        if is_malicious:
            threat_event = ThreatEvent(
                timestamp=timestamp,
                src_ip=src_ip,
                dst_ip=dst_ip,
                src_port=src_port,
                dst_port=dst_port,
                threat_type="malicious_ip",
                threat_score=3,
                details=intel_details,
                payload_hash=""
            )
            threats.append(threat_event)
        
        # Tehditleri logla ve sakla
        for threat in threats:
            self.logger.log_threat(threat)
            self.threat_events.append(threat)
            self.stats['threats_detected'] += 1
        
        return threats
    
    def get_statistics(self) -> Dict:
        """Sistem istatistiklerini döndürür"""
        runtime = time.time() - self.stats['start_time']
        return {
            **self.stats,
            'runtime_seconds': runtime,
            'packets_per_second': self.stats['total_packets'] / runtime if runtime > 0 else 0,
            'threats_per_hour': (self.stats['threats_detected'] / runtime * 3600) if runtime > 0 else 0
        }
    
    def export_threats(self, output_file: str, format: str = 'json'):
        """Tehditleri dışa aktarır"""
        threats_data = []
        for threat in self.threat_events:
            threats_data.append({
                'timestamp': datetime.fromtimestamp(threat.timestamp).isoformat(),
                'src_ip': threat.src_ip,
                'dst_ip': threat.dst_ip,
                'src_port': threat.src_port,
                'dst_port': threat.dst_port,
                'threat_type': threat.threat_type,
                'threat_score': threat.threat_score,
                'details': threat.details,
                'payload_hash': threat.payload_hash
            })
        
        if format.lower() == 'json':
            with open(output_file, 'w', encoding='utf-8') as f:
                json.dump(threats_data, f, indent=2, ensure_ascii=False)
        elif format.lower() == 'csv':
            import csv
            with open(output_file, 'w', newline='', encoding='utf-8') as f:
                if threats_data:
                    writer = csv.DictWriter(f, fieldnames=threats_data[0].keys())
                    writer.writeheader()
                    writer.writerows(threats_data)

# Kullanım örneği
if __name__ == "__main__":
    ids = EnhancedIDS()
    
    # Test için mock packet sınıfı
    class MockPacket:
        def __init__(self, payload):
            self.payload = payload
            
        def haslayer(self, layer):
            return layer == 'Raw'
        
        def __getitem__(self, layer):
            if layer == 'Raw':
                return type('Raw', (), {'load': self.payload})()
    
    print("=" * 60)
    print("Enhanced IDS Test Suite")
    print("=" * 60)
    
    # Test 1: SQL Injection
    print("\n1. SQL Injection Testi:")
    packet1 = MockPacket(b"GET /admin.php?id=1' OR 1=1-- HTTP/1.1")
    threats1 = ids.analyze_packet(packet1, "192.168.1.100", "192.168.1.1", 12345, 80)
    for threat in threats1:
        print(f"   - {threat.threat_type}: {threat.details}")
    
    # Test 2: CSRF Attack
    print("\n2. CSRF Attack Testi:")
    csrf_payload = b"""POST /transfer HTTP/1.1
Host: bank.com
Content-Type: application/x-www-form-urlencoded

amount=1000&to=attacker"""
    packet2 = MockPacket(csrf_payload)
    threats2 = ids.analyze_packet(packet2, "192.168.1.101", "192.168.1.1", 45678, 80)
    for threat in threats2:
        print(f"   - {threat.threat_type}: {threat.details}")
    
    # Test 3: CSRF with suspicious referer
    print("\n3. CSRF with Suspicious Referer Testi:")
    csrf_payload2 = b"""POST /transfer HTTP/1.1
Host: bank.com
Referer: http://evil.com/attack
Content-Type: application/x-www-form-urlencoded

amount=1000&to=attacker"""
    packet3 = MockPacket(csrf_payload2)
    threats3 = ids.analyze_packet(packet3, "192.168.1.102", "192.168.1.1", 34567, 80)
    for threat in threats3:
        print(f"   - {threat.threat_type}: {threat.details}")
    
    # Test 4: Login Failure (Brute Force)
    print("\n4. Login Brute Force Testi:")
    
    test_ip = "192.168.1.103"
    print(f"   Simüle ediliyor: 6 başarısız login denemesi ({test_ip})")
    
    # Farklı kullanıcı adı/şifre kombinasyonlarıyla denemeler
    failed_responses = [
        b"""HTTP/1.1 401 Unauthorized
Content-Type: application/json

{"error": "Login attempt failed", "message": "Invalid username or password"}""",

        b"""HTTP/1.1 401 Unauthorized
Content-Type: text/html

<div class="error">Invalid credentials</div>""",

        b"""HTTP/1.1 403 Forbidden
Content-Type: application/json

{"status": "unauthorized", "reason": "Account locked due to multiple failures"}""",

        b"""HTTP/1.1 401 Unauthorized
Content-Type: text/plain

Authentication failed: Too many failed attempts""",

        b"""HTTP/1.1 401 Unauthorized
Content-Type: application/json

{"error": "Access denied", "code": "INVALID_CREDENTIALS"}""",

        b"""HTTP/1.1 401 Unauthorized
Content-Type: text/html

<h1>Login Failed</h1><p>Multiple failed login attempts detected.</p>"""
    ]
    
    # Her başarısız denemeyi simüle et
    for i, response in enumerate(failed_responses):
        print(f"   - Deneme {i+1} simüle ediliyor...")
        
        # Failed response'u simüle et
        packet = MockPacket(response)
        threats = ids.analyze_packet(packet, test_ip, "192.168.1.1", 23456, 80)
        
        # Son denemede brute force tespit edilmeli
        if threats and i == len(failed_responses) - 1:
            print("\n   Tespit edilen tehditler:")
            for threat in threats:
                if threat.threat_type == "credential_bruteforce":
                    print(f"   ✓ {threat.threat_type}: {threat.details}")
                    
            # IP'nin bloklanıp bloklanmadığını kontrol et
            if ids.behavioral_analyzer.is_ip_blocked(test_ip):
                print(f"   ✓ IP başarıyla bloklandı: {test_ip}")
    
    # Test 5: XSS Attack
    print("\n5. XSS Attack Testi:")
    xss_payload = b"""GET /search?q=<script>alert('XSS')</script> HTTP/1.1
Host: vulnerable.com"""
    packet5 = MockPacket(xss_payload)
    threats5 = ids.analyze_packet(packet5, "192.168.1.104", "192.168.1.1", 56789, 80)
    for threat in threats5:
        print(f"   - {threat.threat_type}: {threat.details}")
    
    # Test 6: Blocked IP Check
    print("\n6. Blocked IP Kontrolü:")
    # IP'yi manuel olarak blokla
    ids.behavioral_analyzer.block_ip("192.168.1.200", 10)  # 10 saniye blokla
    packet6 = MockPacket(b"GET /index.html HTTP/1.1")
    threats6 = ids.analyze_packet(packet6, "192.168.1.200", "192.168.1.1", 12345, 80)
    for threat in threats6:
        print(f"   - {threat.threat_type}: {threat.details}")
    
    print("\n" + "=" * 60)
    print("Sistem İstatistikleri:")
    print("=" * 60)
    stats = ids.get_statistics()
    for key, value in stats.items():
        print(f"- {key}: {value}")
    
    # Blocked IPs listesi
    print(f"\nBlocked IPs: {list(ids.behavioral_analyzer.blocked_ips.keys())}")