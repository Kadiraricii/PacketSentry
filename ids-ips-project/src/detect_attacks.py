import logging
import re
import urllib.parse
import os
from collections import defaultdict
import time
import json
from functools import lru_cache
try:
    import requests
    THREAT_INTEL_AVAILABLE = True
except ImportError:
    THREAT_INTEL_AVAILABLE = False
    print('Uyarı: requests kütüphanesi bulunamadı. Tehdit istihbaratı kontrolü yapılamayacak.')

# Loglama ayarları
LOG_FILE = '../data/ids.log'
log_dir = os.path.dirname(LOG_FILE)
if not os.path.exists(log_dir):
    os.makedirs(log_dir)

logging.basicConfig(
    filename=LOG_FILE,
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)

logger = logging.getLogger(__name__)

# Beyaz liste (whitelist) - Yanlış pozitifleri azaltmak için
WHITELIST = [
    "127.0.0.1",  # Localhost
    "192.168.1.1",  # Örnek yerel ağ IP'si
    # Diğer güvenilir IP adreslerini buraya ekleyin
]

# Brute Force tespiti için IP bazlı istek sayacı ve zaman penceresi
REQUEST_THRESHOLD = 50  # Kısa sürede bu kadar istek brute force olarak işaretlenir
TIME_WINDOW = 60  # Zaman penceresi (saniye)
request_counts = defaultdict(list)
login_failure_counts = defaultdict(list)  # Başarısız giriş denemeleri için

# Genel tehdit puanlama sistemi
THREAT_SCORE_THRESHOLD = 2  # Tehdit puanı bu eşik değerini aşarsa kritik uyarı verilir

# Kural Yönetimi Sistemi: Kuralları JSON dosyasından yükleme
RULES_FILE = '../data/rules.json'
DEFAULT_RULES = {
    'sql_injection': {
        'regexes': [
            '(?i)UNION\\s*SELECT',  # Case-insensitive UNION SELECT
            '(?i)UNION\\s*/\\*.*\\*/\\s*SELECT',  # UNION/**/SELECT gibi yorumlu desenler
            '(?i)OR\\s*1\\s*=\\s*1',  # OR 1=1
            '(?i)AND\\s*1\\s*=\\s*1',  # AND 1=1
            '--',  # SQL yorum satırı
            ';\\s*DROP\\s*TABLE',  # DROP TABLE gibi tehlikeli komutlar
            '(?i)EXEC\\s+xp_',  # EXEC xp_ ile başlayan stored procedures
            '(?i)EXEC\\s+sp_',  # EXEC sp_ ile başlayan stored procedures
            '%27',  # Kodlanmış tek tırnak (')
            '%22',  # Kodlanmış çift tırnak (")
            '%3B',  # Kodlanmış noktalı virgül (;)
            '%2D%2D',  # Kodlanmış yorum satırı (--)
            '(?i)INSERT\\s+INTO',  # INSERT INTO komutları
            '(?i)UPDATE\\s+.*SET',  # UPDATE SET komutları
            '(?i)DELETE\\s+FROM'  # DELETE FROM komutları
        ],
        'byte_patterns': [
            'UNION SELECT', '1=1', 'OR 1=1', '--', '; DROP TABLE', 'EXEC xp_', 'EXEC sp_'
        ],
        'threat_score_per_match': 1
    },
    'command_injection': {
        'regexes': [
            ';\\s*(ls|dir|cat|whoami|id|pwd|uname|netstat|ps|top|ifconfig|ip|route|traceroute|ping|nc|netcat|curl|wget|telnet|ssh|ftp)',  # Komut ayırıcı sonrası yaygın komutlar
            '&&\\s*(ls|dir|cat|whoami|id|pwd|uname|netstat|ps|top|ifconfig|ip|route|traceroute|ping|nc|netcat|curl|wget|telnet|ssh|ftp)',  # Komut zincirleme
            '\\|\\s*(ls|dir|cat|whoami|id|pwd|uname|netstat|ps|top|ifconfig|ip|route|traceroute|ping|nc|netcat|curl|wget|telnet|ssh|ftp)',  # Pipe ile komut çalıştırma
            '(?i)exec\\s*\\(',  # exec fonksiyonu kullanımı
            '(?i)system\\s*\\(',  # system fonksiyonu kullanımı
            '(?i)eval\\s*\\(',  # eval fonksiyonu kullanımı
            '%3B',  # Kodlanmış noktalı virgül
            '%26%26',  # Kodlanmış &&
            '%7C',  # Kodlanmış pipe (|)
            ';\\s*rm\\s*-rf',  # Tehlikeli dosya silme komutları
            ';\\s*chmod',  # İzin değiştirme komutları
            ';\\s*chown'  # Sahiplik değiştirme komutları
        ],
        'byte_patterns': [
            '; ls', '; dir', '; cat', '; whoami', '; id',
            '&& ls', '&& dir', '&& cat', '&& whoami', '&& id',
            '| ls', '| dir', '| cat', '| whoami', '| id'
        ],
        'threat_score_per_match': 1
    },
    'directory_traversal': {
        'regexes': [
            '\\.\\./',  # ../ kalıbı
            '\\.\\.\\\\',  # ..\\ kalıbı (Windows)
            '%2e%2e%2f',  # Kodlanmış ../
            '%2e%2e%5c',  # Kodlanmış ..\\
            'etc/passwd',  # Hassas dosya erişimi (Linux)
            'boot.ini',  # Hassas dosya erişimi (Windows)
            'win.ini',  # Hassas dosya erişimi (Windows)
            'system32',  # Windows sistem dosyaları
            '/proc/self/environ',  # Linux proc dizini
            '/etc/shadow'  # Linux shadow dosyası
        ],
        'byte_patterns': [],
        'threat_score_per_match': 1
    },
    'xss': {
        'regexes': [
            '(?i)<script\\s*.*?>',  # <script> tag'i
            '(?i)javascript:',  # javascript: protokolü
            '(?i)on(error|load|click|mouseover|mouseout|submit|focus|blur|change|input|keydown|keypress|keyup)\\s*=',  # Event handler'lar
            '(?i)alert\\s*\\(',  # alert fonksiyonu
            '(?i)eval\\s*\\(',  # eval fonksiyonu
            '%3Cscript%3E',  # Kodlanmış <script>
            '%6A%61%76%61%73%63%72%69%70%74',  # Kodlanmış javascript
            '(?i)document\\.cookie',  # document.cookie erişimi
            '(?i)window\\.location',  # window.location manipülasyonu
            '(?i)<img\\s+src\\s*=\\s*[\'"]javascript:'  # img src ile javascript
        ],
        'byte_patterns': [],
        'threat_score_per_match': 1
    },
    'csrf': {
        'regexes': [
            '(?i)^POST\\s'  # POST isteklerini kontrol et
        ],
        'byte_patterns': [],
        'threat_score_per_match': 1
    },
    'malicious_upload': {
        'regexes': [
            '(?i)\\.php[\\s\';"]',  # PHP dosyaları
            '(?i)\\.exe[\\s\';"]',  # EXE dosyaları
            '(?i)\\.sh[\\s\';"]',  # Shell script'ler
            '(?i)\\.asp[\\s\';"]',  # ASP dosyaları
            '(?i)<\\?php',  # PHP kodu
            '(?i)eval\\s*\\(',  # eval fonksiyonu
            '(?i)system\\s*\\('  # system fonksiyonu
        ],
        'byte_patterns': [],
        'threat_score_per_match': 1
    }
}

def load_rules():
    """Kuralları JSON dosyasından yükler, dosya yoksa varsayılan kuralları kullanır."""
    try:
        if os.path.exists(RULES_FILE):
            with open(RULES_FILE, 'r') as f:
                rules = json.load(f)
                # Regex ifadelerini derle
                for category, rule_data in rules.items():
                    if 'regexes' in rule_data:
                        rule_data['regexes'] = [re.compile(regex) for regex in rule_data['regexes']]
                return rules
        else:
            logger.info(f'Kural dosyası bulunamadı: {RULES_FILE}. Varsayılan kurallar kullanılıyor.')
            # Varsayılan kuralları derle
            for category, rule_data in DEFAULT_RULES.items():
                if 'regexes' in rule_data:
                    rule_data['regexes'] = [re.compile(regex) for regex in rule_data['regexes']]
            return DEFAULT_RULES
    except Exception as e:
        logger.error(f'Kural dosyası yüklenirken hata oluştu: {str(e)}. Varsayılan kurallar kullanılıyor.')
        # Hata durumunda varsayılan kuralları derle
        for category, rule_data in DEFAULT_RULES.items():
            if 'regexes' in rule_data:
                rule_data['regexes'] = [re.compile(regex) for regex in rule_data['regexes']]
        return DEFAULT_RULES

rules = load_rules()

# Yardımcı fonksiyon: Payload'u decode etme
@lru_cache(maxsize=1000)
def decode_payload(payload):
    """Payload'u string'e çevirip URL kod çözme yapar."""
    try:
        payload_str = None
        try:
            payload_str = payload.decode('utf-8')
        except UnicodeDecodeError:
            try:
                payload_str = payload.decode('latin-1')
            except UnicodeDecodeError:
                payload_str = payload.decode('utf-8', errors='ignore')
        if payload_str:
            return urllib.parse.unquote(payload_str)
    except Exception as e:
        logger.warning(f'Payload çözümleme hatası: {str(e)}')
    return None

# Yardımcı fonksiyon: Uyarı mesajı oluşturma ve yazdırma
def log_and_alert(msg, level='warning', critical=False):
    """Uyarı mesajını loglar ve terminale yazdırır."""
    timestamp = time.strftime('%Y-%m-%d %H:%M:%S')
    if level == 'critical':
        logger.critical(msg)
    elif level == 'warning':
        logger.warning(msg)
    else:
        logger.info(msg)
    try:
        if os.isatty(1):  # Terminalde mi çalışıyoruz?
            if level == 'critical':
                color = '\033[91m'  # Kırmızı
            elif level == 'warning':
                color = '\033[93m'  # Turuncu
            elif level == 'success':
                color = '\033[92m'  # Yeşil
            else:
                color = '\033[94m'  # Mavi
            print(f'{color}{timestamp} [!!] {level.upper()}: {msg}\033[0m')
        else:
            print(f'{timestamp} [!!] {level.upper()}: {msg}')
    except:
        print(f'{timestamp} [!!] {level.upper()}: {msg}')

# Tehdit İstihbaratı Kontrolü
def check_threat_intel(ip):
    """IP adresini tehdit istihbaratı API'si ile kontrol eder (örneğin, AbuseIPDB)."""
    if not THREAT_INTEL_AVAILABLE:
        return False
    try:
        # Örnek olarak AbuseIPDB API'si kullanılıyor (API anahtarı gerekli)
        api_key = 'YOUR_ABUSEIPDB_API_KEY'  # API anahtarınızı buraya ekleyin
        if not api_key or api_key == 'YOUR_ABUSEIPDB_API_KEY':
            return False
        url = f'https://api.abuseipdb.com/api/v2/check?ipAddress={ip}'
        headers = {'Key': api_key, 'Accept': 'application/json'}
        response = requests.get(url, headers=headers, timeout=5)
        if response.status_code == 200:
            data = response.json()
            if data['data']['abuseConfidenceScore'] > 50:  # Eşik değer
                return True
    except Exception as e:
        logger.warning(f'Tehdit istihbaratı kontrol hatası: {str(e)}')
    return False

# SQL Injection Tespiti
def detect_sql_injection(packet, src_ip, dst_ip, sport, dport):
    """SQL Injection gibi şüpheli aktiviteleri tespit eder."""
    if packet.haslayer('Raw'):
        payload = packet['Raw'].load
        decoded_payload = decode_payload(payload)
        if decoded_payload:
            threat_score = 0
            matched_patterns = []
            for regex in rules['sql_injection']['regexes']:
                if re.search(regex, decoded_payload):
                    threat_score += rules['sql_injection']['threat_score_per_match']
                    matched_patterns.append(regex)
                    if threat_score >= THREAT_SCORE_THRESHOLD:  # Erken çıkış
                        break

            if threat_score > 0:
                alert_msg = f'!!! ŞÜPHELİ SQL INJECTION TESPİT EDİLDİ !!! Kaynak IP: {src_ip}, Hedef IP: {dst_ip}, Port: {sport}->{dport}, Tehdit Puanı: {threat_score}, Eşleşen Kalıplar: {", ".join(matched_patterns)}, Payload Özeti: {decoded_payload[:100]}...'
                level = 'critical' if threat_score >= THREAT_SCORE_THRESHOLD else 'warning'
                log_and_alert(alert_msg, level)
                return True
        else:
            for pattern in rules['sql_injection']['byte_patterns']:
                if pattern.encode() in payload:
                    alert_msg = f'!!! ŞÜPHELİ SQL INJECTION TESPİT EDİLDİ (Bayt Kontrolü) !!! Kaynak IP: {src_ip}, Hedef IP: {dst_ip}, Port: {sport}->{dport}, Kalıp: {pattern}'
                    log_and_alert(alert_msg)
                    return True
    return False

# Command Injection Tespiti
def detect_command_injection(packet, src_ip, dst_ip, sport, dport):
    """Command Injection gibi şüpheli aktiviteleri tespit eder."""
    if packet.haslayer('Raw'):
        payload = packet['Raw'].load
        decoded_payload = decode_payload(payload)
        if decoded_payload:
            threat_score = 0
            matched_patterns = []
            for regex in rules['command_injection']['regexes']:
                if re.search(regex, decoded_payload):
                    threat_score += rules['command_injection']['threat_score_per_match']
                    matched_patterns.append(regex)
                    if threat_score >= THREAT_SCORE_THRESHOLD:  # Erken çıkış
                        break

            if threat_score > 0:
                alert_msg = f'!!! ŞÜPHELİ COMMAND INJECTION TESPİT EDİLDİ !!! Kaynak IP: {src_ip}, Hedef IP: {dst_ip}, Port: {sport}->{dport}, Tehdit Puanı: {threat_score}, Eşleşen Kalıplar: {", ".join(matched_patterns)}, Payload Özeti: {decoded_payload[:100]}...'
                level = 'critical' if threat_score >= THREAT_SCORE_THRESHOLD else 'warning'
                log_and_alert(alert_msg, level)
                return True
        else:
            for pattern in rules['command_injection']['byte_patterns']:
                if pattern.encode() in payload:
                    alert_msg = f'!!! ŞÜPHELİ COMMAND INJECTION TESPİT EDİLDİ (Bayt Kontrolü) !!! Kaynak IP: {src_ip}, Hedef IP: {dst_ip}, Port: {sport}->{dport}, Kalıp: {pattern}'
                    log_and_alert(alert_msg)
                    return True
    return False

# Directory Traversal Tespiti
def detect_directory_traversal(packet, src_ip, dst_ip, sport, dport):
    """Directory Traversal gibi şüpheli aktiviteleri tespit eder."""
    if packet.haslayer('Raw'):
        payload = packet['Raw'].load
        decoded_payload = decode_payload(payload)
        if decoded_payload:
            threat_score = 0
            matched_patterns = []
            for regex in rules['directory_traversal']['regexes']:
                if re.search(regex, decoded_payload, re.IGNORECASE):
                    threat_score += rules['directory_traversal']['threat_score_per_match']
                    matched_patterns.append(regex)
                    if threat_score >= THREAT_SCORE_THRESHOLD:  # Erken çıkış
                        break

            if threat_score > 0:
                alert_msg = f'!!! ŞÜPHELİ DIRECTORY TRAVERSAL TESPİT EDİLDİ !!! Kaynak IP: {src_ip}, Hedef IP: {dst_ip}, Port: {sport}->{dport}, Tehdit Puanı: {threat_score}, Eşleşen Kalıplar: {", ".join(matched_patterns)}, Payload Özeti: {decoded_payload[:100]}...'
                level = 'critical' if threat_score >= THREAT_SCORE_THRESHOLD else 'warning'
                log_and_alert(alert_msg, level)
                return True
    return False

# XSS (Cross-Site Scripting) Tespiti
def detect_xss(packet, src_ip, dst_ip, sport, dport):
    """XSS (Cross-Site Scripting) gibi şüpheli aktiviteleri tespit eder."""
    if packet.haslayer('Raw'):
        payload = packet['Raw'].load
        decoded_payload = decode_payload(payload)
        if decoded_payload:
            threat_score = 0
            matched_patterns = []
            for regex in rules['xss']['regexes']:
                if re.search(regex, decoded_payload):
                    threat_score += rules['xss']['threat_score_per_match']
                    matched_patterns.append(regex)
                    if threat_score >= THREAT_SCORE_THRESHOLD:  # Erken çıkış
                        break

            if threat_score > 0:
                alert_msg = f'!!! ŞÜPHELİ XSS TESPİT EDİLDİ !!! Kaynak IP: {src_ip}, Hedef IP: {dst_ip}, Port: {sport}->{dport}, Tehdit Puanı: {threat_score}, Eşleşen Kalıplar: {", ".join(matched_patterns)}, Payload Özeti: {decoded_payload[:100]}...'
                level = 'critical' if threat_score >= THREAT_SCORE_THRESHOLD else 'warning'
                log_and_alert(alert_msg, level)
                return True
    return False

# CSRF (Cross-Site Request Forgery) Tespiti
def detect_csrf(packet, src_ip, dst_ip, sport, dport):
    """CSRF (Cross-Site Request Forgery) gibi şüpheli aktiviteleri tespit eder."""
    if packet.haslayer('Raw'):
        payload = packet['Raw'].load
        decoded_payload = decode_payload(payload)
        if decoded_payload:
            if re.search(rules['csrf']['regexes'][0], decoded_payload):
                if not re.search(r'(?i)Referer:', decoded_payload) and not re.search(r'(?i)Origin:', decoded_payload):
                    alert_msg = f'!!! ŞÜPHELİ CSRF TESPİT EDİLDİ !!! Kaynak IP: {src_ip}, Hedef IP: {dst_ip}, Port: {sport}->{dport}, Sebep: Referer veya Origin başlığı eksik, Payload Özeti: {decoded_payload[:100]}...'
                    log_and_alert(alert_msg)
                    return True
                referer_match = re.search(r'(?i)Referer:\\s*https?://([^/\\s]+)', decoded_payload)
                if referer_match:
                    referer_domain = referer_match.group(1)
                    suspicious_domains = ['evil.com', 'malicious.com']  # Güvenilmeyen domain listesi
                    if any(domain in referer_domain for domain in suspicious_domains):
                        alert_msg = f'!!! ŞÜPHELİ CSRF TESPİT EDİLDİ !!! Kaynak IP: {src_ip}, Hedef IP: {dst_ip}, Port: {sport}->{dport}, Sebep: Güvenilmeyen Referer domaini ({referer_domain}), Payload Özeti: {decoded_payload[:100]}...'
                        log_and_alert(alert_msg)
                        return True
    return False

# Malicious File Upload Tespiti
def detect_malicious_upload(packet, src_ip, dst_ip, sport, dport):
    """Zararlı dosya yükleme aktivitelerini tespit eder."""
    if packet.haslayer('Raw'):
        payload = packet['Raw'].load
        decoded_payload = decode_payload(payload)
        if decoded_payload:
            threat_score = 0
            matched_patterns = []
            for regex in rules['malicious_upload']['regexes']:
                if re.search(regex, decoded_payload):
                    threat_score += rules['malicious_upload']['threat_score_per_match']
                    matched_patterns.append(regex)
                    if threat_score >= THREAT_SCORE_THRESHOLD:  # Erken çıkış
                        break

            if threat_score > 0:
                alert_msg = f'!!! ŞÜPHELİ MALICIOUS FILE UPLOAD TESPİT EDİLDİ !!! Kaynak IP: {src_ip}, Hedef IP: {dst_ip}, Port: {sport}->{dport}, Tehdit Puanı: {threat_score}, Eşleşen Kalıplar: {", ".join(matched_patterns)}, Payload Özeti: {decoded_payload[:100]}...'
                level = 'critical' if threat_score >= THREAT_SCORE_THRESHOLD else 'warning'
                log_and_alert(alert_msg, level)
                return True
    return False

# Brute Force Tespiti
def detect_brute_force(packet, src_ip, dst_ip, sport, dport):
    """Brute Force saldırılarını tespit eder (aynı IP'den kısa sürede çok fazla istek)."""
    current_time = time.time()
    request_counts[src_ip].append(current_time)

    # Zaman penceresi dışındaki eski istekleri temizle
    request_counts[src_ip] = [req_time for req_time in request_counts[src_ip] if current_time - req_time <= TIME_WINDOW]

    # İstek sayısı eşik değerini aşıyorsa brute force olarak işaretle
    if len(request_counts[src_ip]) > REQUEST_THRESHOLD:
        alert_msg = f'!!! ŞÜPHELİ BRUTE FORCE TESPİT EDİLDİ !!! Kaynak IP: {src_ip}, Hedef IP: {dst_ip}, Port: {sport}->{dport}, İstek Sayısı: {len(request_counts[src_ip])}, Zaman Penceresi: {TIME_WINDOW}s'
        log_and_alert(alert_msg, level='critical')
        # Tekrar uyarı vermemek için sayacı sıfırla
        request_counts[src_ip] = []
        return True

    # Davranışsal analiz: Başarısız giriş denemeleri (örneğin, /login endpoint'ine yapılan istekler)
    if packet.haslayer('Raw'):
        payload = packet['Raw'].load
        decoded_payload = decode_payload(payload)
        if decoded_payload and '/login' in decoded_payload.lower():
            if '401 Unauthorized' in decoded_payload or '403 Forbidden' in decoded_payload or 'Login Failed' in decoded_payload:
                login_failure_counts[src_ip].append(current_time)
                login_failure_counts[src_ip] = [req_time for req_time in login_failure_counts[src_ip] if current_time - req_time <= TIME_WINDOW]
                if len(login_failure_counts[src_ip]) > 5:  # 5 başarısız giriş denemesi
                    alert_msg = f'!!! ŞÜPHELİ BRUTE FORCE (Başarısız Giriş Denemeleri) TESPİT EDİLDİ !!! Kaynak IP: {src_ip}, Hedef IP: {dst_ip}, Port: {sport}->{dport}, Başarısız Giriş Sayısı: {len(login_failure_counts[src_ip])}, Zaman Penceresi: {TIME_WINDOW}s'
                    log_and_alert(alert_msg, level='critical')
                    login_failure_counts[src_ip] = []
                    return True
    return False

# Zero-day Exploit Tespiti
def detect_zero_day(packet, src_ip, dst_ip, sport, dport):
    """Zero-day exploit'lerini tespit etmek için anormal davranışları kontrol eder."""
    if packet.haslayer('Raw'):
        payload = packet['Raw'].load
        # Anormal payload boyutu kontrolü (örneğin, 10KB üstü)
        PAYLOAD_SIZE_THRESHOLD = 10240  # 10KB
        if len(payload) > PAYLOAD_SIZE_THRESHOLD:
            alert_msg = f'!!! ŞÜPHELİ ZERO-DAY EXPLOIT TESPİT EDİLDİ !!! Kaynak IP: {src_ip}, Hedef IP: {dst_ip}, Port: {sport}->{dport}, Sebep: Anormal Payload Boyutu ({len(payload)} bayt)'
            log_and_alert(alert_msg, level='warning')
            return True
    return False

# Genel Saldırı Tespit Fonksiyonu
def detect_attacks(packet, src_ip, dst_ip, sport, dport):
    """Tüm saldırı türlerini kontrol eden ana fonksiyon."""
    # Beyaz listede ise saldırı kontrolü yapma
    if src_ip in WHITELIST:
        logger.info(f'Kaynak IP {src_ip} beyaz listede, saldırı kontrolü yapılmıyor.')
        return []

    threat_types = []
    # SQL Injection kontrolü
    if detect_sql_injection(packet, src_ip, dst_ip, sport, dport):
        threat_types.append("SQL Injection")
    # Command Injection kontrolü
    if detect_command_injection(packet, src_ip, dst_ip, sport, dport):
        threat_types.append("Command Injection")
    # Directory Traversal kontrolü
    if detect_directory_traversal(packet, src_ip, dst_ip, sport, dport):
        threat_types.append("Directory Traversal")
    # XSS kontrolü
    if detect_xss(packet, src_ip, dst_ip, sport, dport):
        threat_types.append("XSS")
    # CSRF kontrolü
    if detect_csrf(packet, src_ip, dst_ip, sport, dport):
        threat_types.append("CSRF")
    # Malicious File Upload kontrolü
    if detect_malicious_upload(packet, src_ip, dst_ip, sport, dport):
        threat_types.append("Malicious File Upload")
    # Brute Force kontrolü
    if detect_brute_force(packet, src_ip, dst_ip, sport, dport):
        threat_types.append("Brute Force")
    # Zero-day Exploit kontrolü
    if detect_zero_day(packet, src_ip, dst_ip, sport, dport):
        threat_types.append("Zero-day Exploit")
    # Tehdit İstihbaratı kontrolü
    if THREAT_INTEL_AVAILABLE and check_threat_intel(src_ip):
        alert_msg = f'!!! ŞÜPHELİ IP TESPİT EDİLDİ (Tehdit İstihbaratı) !!! Kaynak IP: {src_ip}, Hedef IP: {dst_ip}, Port: {sport}->{dport}, Sebep: Kötü Amaçlı IP Adresi'
        log_and_alert(alert_msg, level='critical')
        threat_types.append("Threat Intelligence Hit")
    return threat_types if threat_types else []
