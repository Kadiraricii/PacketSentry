import logging
import os
import subprocess
import time
import json
import platform
from collections import defaultdict
from threading import Timer
try:
    from tabulate import tabulate
    TABULATE_AVAILABLE = True
except ImportError:
    TABULATE_AVAILABLE = False
    print('Uyarı: tabulate kütüphanesi bulunamadı. Tablo formatında çıktı kullanılamayacak.')

# Loglama ayarları
LOG_FILE = '../data/ids.log'
TRAFFIC_LOG_FILE = '../data/traffic.log'
log_dir = os.path.dirname(LOG_FILE)
if not os.path.exists(log_dir):
    os.makedirs(log_dir)

# JSON formatında loglama için yapılandırılmış logger
logging.basicConfig(
    filename=LOG_FILE,
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)

logger = logging.getLogger(__name__)

# JSON loglama için handler
def log_json(data, log_file=LOG_FILE):
    """Veriyi JSON formatında log dosyasına yazar."""
    try:
        with open(log_file, 'a') as f:
            json.dump(data, f, indent=2)
            f.write('\n')
    except Exception as e:
        logger.error(f'JSON loglama hatası: {str(e)}')

# Engellenen IP'leri ve engelleme bilgilerini takip etme
BLOCKED_IPS_FILE = '../data/blocked_ips.json'
BLOCKED_IPS = defaultdict(dict)  # IP: {block_time, duration, reason, threat_type, rule}
BLOCKED_IPS_BUFFER = [] # Engellenen IP'leri tutan buffer
CLEANUP_INTERVAL = 300  # Temizleme aralığı (saniye cinsinden, 5 dakika)

# Tehdit türüne göre engelleme süreleri (saniye cinsinden) ve politikalar
BLOCK_POLICIES = {
    'SQL Injection': {
        'duration': 3600,
        'rule': 'INPUT -j DROP',
        'macOS_rule': 'block quick proto tcp from {ip} to any'
    },
    'Command Injection': {
        'duration': 3600,
        'rule': 'INPUT -j DROP',
        'macOS_rule': 'block quick proto tcp from {ip} to any'
    },
    'Directory Traversal': {
        'duration': 1800,
        'rule': 'INPUT -j DROP',
        'macOS_rule': 'block quick proto tcp from {ip} to any'
    },
    'XSS': {
        'duration': 1800,
        'rule': 'INPUT -j DROP',
        'macOS_rule': 'block quick proto tcp from {ip} to any'
    },
    'CSRF': {
        'duration': 900,
        'rule': 'INPUT -p tcp --dport 80 -j DROP',
        'macOS_rule': 'block quick proto tcp from {ip} to any port 80'
    },
    'Malicious File Upload': {
        'duration': 3600,
        'rule': 'INPUT -j DROP',
        'macOS_rule': 'block quick proto tcp from {ip} to any'
    },
    'Brute Force': {
        'duration': 600,
        'rule': 'INPUT -p tcp --dport 80 -j DROP',
        'macOS_rule': 'block quick proto tcp from {ip} to any port 80'
    },
    'Zero-day Exploit': {
        'duration': 7200,
        'rule': 'INPUT -j DROP',
        'macOS_rule': 'block quick proto tcp from {ip} to any'
    },
    'Threat Intelligence Hit': {
        'duration': 10800,
        'rule': 'INPUT -j DROP',
        'macOS_rule': 'block quick proto tcp from {ip} to any'
    }
}

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

# Engellenen IP'leri dosyadan yükleme
def load_blocked_ips():
    """Engellenen IP'leri JSON dosyasından yükler."""
    global BLOCKED_IPS
    try:
        if os.path.exists(BLOCKED_IPS_FILE):
            with open(BLOCKED_IPS_FILE, 'r') as f:
                loaded_data = json.load(f)
                BLOCKED_IPS = defaultdict(dict, {ip: data for ip, data in loaded_data.items()})
                logger.info(f'Engellenen IP\'ler yüklendi: {BLOCKED_IPS_FILE}')
    except Exception as e:
        logger.error(f'Engellenen IP\'ler yüklenirken hata oluştu: {str(e)}')

# Engellenen IP'leri dosyaya kaydetme
def save_blocked_ips():
    """Engellenen IP'leri JSON dosyasına kaydeder."""
    global BLOCKED_IPS, BLOCKED_IPS_BUFFER
    try:
        # BLOCKED_IPS_BUFFER içinde yeni IP'ler varsa, BLOCKED_IPS'i güncelle
        if BLOCKED_IPS_BUFFER:
            for ip in BLOCKED_IPS_BUFFER:
                # Eğer IP zaten BLOCKED_IPS içinde yoksa ekle
                if ip not in BLOCKED_IPS:
                    # BLOCKED_IPS_BUFFER'daki IP'lerin BLOCKED_IPS içinde de güncel olmasını sağla
                    # Eğer BLOCKED_IPS_BUFFER'daki IP için bir veri varsa onu kullan, yoksa varsayılan bir değer ata
                    BLOCKED_IPS[ip] = BLOCKED_IPS[ip] if ip in BLOCKED_IPS else {}

            # BLOCKED_IPS'i dosyaya yaz
            with open(BLOCKED_IPS_FILE, 'w') as f:
                json.dump(dict(BLOCKED_IPS), f, indent=2)

            logger.info(f'Engellenen IP\'ler kaydedildi: {BLOCKED_IPS_FILE}')
            BLOCKED_IPS_BUFFER = []  # Tamponu temizle
    except Exception as e:
        logger.error(f'Engellenen IP\'ler kaydedilirken hata oluştu: {str(e)}')

# macOS'ta pf servisinin aktif olup olmadığını kontrol etme
def check_pf_service():
    """macOS'ta pf servisinin aktif olup olmadığını kontrol eder."""
    if platform.system() != 'Darwin':
        return True  # macOS değilse kontrol yapmaya gerek yok
    try:
        result = subprocess.run('sudo pfctl -s info', shell=True, capture_output=True, text=True)
        if result.returncode == 0 and 'Status: Enabled' in result.stdout:
            return True
        else:
            logger.warning('macOS\'ta pf servisi aktif değil. Engelleme için lütfen pf servisini etkinleştirin.')
            log_and_alert('macOS\'ta pf servisi aktif değil. Engelleme çalışmayabilir.', level='warning')
            return False
    except Exception as e:
        logger.error(f'pf servisi kontrol hatası: {str(e)}')
        return False

# IP Engelleme Fonksiyonu
def block_ip(src_ip, dst_ip, sport, dport, reason, threat_type, duration, rule):
    """Belirtilen IP adresini işletim sistemine uygun şekilde engeller."""
    try:
        if src_ip in BLOCKED_IPS and time.time() - BLOCKED_IPS[src_ip].get('block_time', 0) < BLOCKED_IPS[src_ip].get('duration', 0):
            logger.info(f'IP zaten engelli: {src_ip}. Engelleme süresi uzatılmadı.')
            log_and_alert(f'IP zaten engelli: {src_ip}. Süre uzatılmadı.', level='info')
            return True

        system = platform.system()
        if system == 'Linux':
            cmd = f'sudo iptables -A {rule.format(ip=src_ip)}'
        elif system == 'Darwin':  # macOS
            if not check_pf_service():
                return False

            # Tehdit türüne göre macOS kuralını al
            rule = BLOCK_POLICIES.get(threat_type, {}).get('macOS_rule', 'block quick proto tcp from {ip} to any').format(ip=src_ip)

            cmd = f'sudo pfctl -a \"com.apple/anchor\" -t block -T add {rule}'
        elif system == 'Windows':
            specific_rule = BLOCK_POLICIES.get(threat_type, {}).get('macOS_rule', 'block quick proto tcp from {ip} to any')
            if 'port' in specific_rule:
                port = specific_rule.split('port')[-1].strip().split(' ')[0]
                cmd = f'netsh advfirewall firewall add rule name="Block {src_ip}" dir=in action=block remoteip={src_ip} remoteport={port}'
            else:
                cmd = f'netsh advfirewall firewall add rule name="Block {src_ip}" dir=in action=block remoteip={src_ip}'
        else:
            logger.error(f'Desteklenmeyen işletim sistemi: {system}')
            return False

        result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
        if result.returncode == 0:
            BLOCKED_IPS[src_ip] = {
                'block_time': time.time(),
                'duration': duration,
                'reason': reason,
                'threat_type': threat_type,
                'description': f'{threat_type} saldırısı tespit edildi. IP {src_ip} engellendi. Sebep: {reason}. Süre: {duration/60} dakika',
                'rule': rule
            }
            BLOCKED_IPS_BUFFER.append(src_ip)
            # save_blocked_ips() is called periodically by schedule_cleanup, not here to improve performance
            alert_msg = f'IP ENGELLENDİ: {src_ip}, Sebep: {reason}, Tehdit Türü: {threat_type}, Süre: {duration/60} dakika'
            log_and_alert(alert_msg, level='critical')
            # JSON loglama
            log_json({
                'event': 'IP_BLOCKED',
                'src_ip': src_ip,
                'dst_ip': dst_ip,
                'sport': sport,
                'dport': dport,
                'reason': reason,
                'threat_type': threat_type,
                'duration_minutes': duration/60,
                'timestamp': time.strftime('%Y-%m-%d %H:%M:%S')
            })
            return True
        else:
            logger.error(f'IP engelleme hatası: {src_ip}, Hata: {result.stderr}')
            log_and_alert(f'IP engelleme hatası: {src_ip}. Hata: {result.stderr}', level='warning')
            return False
    except Exception as e:
        logger.error(f'IP engelleme hatası: {src_ip}, Hata: {str(e)}')
        log_and_alert(f'IP engelleme hatası: {src_ip}. Hata: {str(e)}', level='warning')
        return False

# Engellemeyi Kaldırma Fonksiyonu (Manuel kullanım için)
def unblock_ip(ip):
    """Belirtilen IP adresinin engellemesini kaldırır."""
    try:
        system = platform.system()
        if system == 'Linux':
            rule = BLOCKED_IPS[ip].get('rule', 'INPUT -j DROP').replace('INPUT ', '').replace(' -j DROP', '')
            cmd = f'sudo iptables -D INPUT -s {ip} {rule} -j DROP'
        elif system == 'Darwin':  # macOS
            if not check_pf_service():
                return False
            cmd = f'sudo pfctl -a "com.apple/anchor" -t block -T delete {ip}'
        elif system == 'Windows':
            cmd = f'netsh advfirewall firewall delete rule name="Block {ip}"'
        else:
            logger.error(f'Desteklenmeyen işletim sistemi: {system}')
            return False

        result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
        if result.returncode == 0:
            if ip in BLOCKED_IPS:
                del BLOCKED_IPS[ip]
                save_blocked_ips()
            alert_msg = f'IP ENGELİ KALDIRILDI: {ip}'
            log_and_alert(alert_msg, level='success')
            # JSON loglama
            log_json({
                'event': 'IP_UNBLOCKED',
                'ip': ip,
                'timestamp': time.strftime('%Y-%m-%d %H:%M:%S')
            })
            return True
        else:
            logger.error(f'IP engel kaldırma hatası: {ip}, Hata: {result.stderr}')
            log_and_alert(f'IP engel kaldırma hatası: {ip}. Hata: {result.stderr}', level='warning')
            return False
    except Exception as e:
        logger.error(f'IP engel kaldırma hatası: {ip}, Hata: {str(e)}')
        log_and_alert(f'IP engel kaldırma hatası: {ip}. Hata: {str(e)}', level='warning')
        return False

# Engellenen IP'leri Temizleme Fonksiyonu
def cleanup_blocked_ips():
    """Süresi dolan engellemeleri temizler."""
    current_time = time.time()
    expired_ips = [ip for ip, data in BLOCKED_IPS.items() if current_time - data.get('block_time', 0) > data.get('duration', 0)]
    for ip in expired_ips:
        if unblock_ip(ip):
            logger.info(f'Engelleme süresi doldu, IP engeli kaldırıldı: {ip}')

# Otomatik Temizleme Zamanlayıcısı
def schedule_cleanup():
    """Belirli aralıklarla engellenen IP'leri temizlemek için zamanlayıcı ayarlar."""
    cleanup_blocked_ips()
    Timer(CLEANUP_INTERVAL, schedule_cleanup).start()
    #save blocked ips peridiocally
    Timer(CLEANUP_INTERVAL, save_blocked_ips).start()
    logger.info(f'Engellenen IP\'ler temizleme zamanlayıcısı ayarlandı. Aralık: {CLEANUP_INTERVAL} saniye')
    log_and_alert(f'Engellenen IP\'ler temizleme zamanlayıcısı ayarlandı. Aralık: {CLEANUP_INTERVAL/60} dakika', level='info')

# Tehdit Engelleme Fonksiyonu
def block_threat(packet, src_ip, dst_ip, sport, dport, threat_type):
    """Tespit edilen tehdide göre IP'yi engeller."""
    policy = BLOCK_POLICIES.get(threat_type, {'duration': 3600, 'rule': 'INPUT -j DROP'})
    duration = policy['duration']
    rule = policy['rule']
    reason = f'{threat_type} Saldırısı Tespit Edildi'
    if block_ip(src_ip, dst_ip, sport, dport, reason, threat_type, duration, rule):
        logger.info(f'Tehdit engellendi: {src_ip}, Sebep: {reason}, Tehdit Türü: {threat_type}')
        log_and_alert(f'Tehdit engellendi: {src_ip}, Tehdit Türü: {threat_type}', level='critical')
        return True
    return False

# Engellenen IP'lerin Listesini Görüntüleme
def list_blocked_ips():
    """Engellenen IP'lerin listesini döndürür."""
    cleanup_blocked_ips()
    if not BLOCKED_IPS:
        log_and_alert('Engellenmiş IP bulunmamaktadır.', level='info')
        return []
    data = []
    for ip, info in BLOCKED_IPS.items():
        remaining_time = info.get('duration', 0) - (time.time() - info.get('block_time', 0))
        if remaining_time > 0:
            data.append([
                ip,
                info.get('threat_type', 'Bilinmiyor'),
                info.get('reason', 'Bilinmiyor'),
                f'{remaining_time/60:.2f} dakika'
            ])
        else:
            unblock_ip(ip)  # Süresi dolmuşsa engeli kaldır
    if data:
        if TABULATE_AVAILABLE:
            log_and_alert(tabulate(data, headers=['IP Adresi', 'Tehdit Türü', 'Sebep', 'Kalan Süre'], tablefmt='grid'), level='info')
        else:
            log_and_alert('Engellenen IP\'ler:', level='info')
            for row in data:
                log_and_alert(f'- IP: {row[0]}, Tehdit Türü: {row[1]}, Sebep: {row[2]}, Kalan Süre: {row[3]}', level='info')
    return list(BLOCKED_IPS.keys())

# İlk yüklemede engellenen IP'leri dosyadan yükle
load_blocked_ips()
# Otomatik temizleme zamanlayıcısını başlat
schedule_cleanup()
