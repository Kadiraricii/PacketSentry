from scapy.all import *
import logging
import os
import re
import urllib.parse
import sys
import argparse
import platform
import subprocess
import json
import threading
import queue
from datetime import datetime
try:
    import psutil
    PSUTIL_AVAILABLE = True
except ImportError:
    PSUTIL_AVAILABLE = False
    logger.warning('psutil kütüphanesi bulunamadı. Bazı sistem bilgileri alınamayabilir.')
    print('Uyarı: psutil kütüphanesi bulunamadı. Bazı sistem bilgileri alınamayabilir.')
try:
    import requests
    REQUESTS_AVAILABLE = True
except ImportError:
    REQUESTS_AVAILABLE = False
    logger.warning('requests kütüphanesi bulunamadı. HTTP bağlantı testi yapılamayacak.')
    print('Uyarı: requests kütüphanesi bulunamadı. HTTP bağlantı testi yapılamayacak.')

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

def setup_logging():
    """Loglama sistemini başlatır ve başlangıç mesajı yazar."""
    logger.info('IDS/IPS sistemi başlatılıyor...')
    print('Loglama başlatıldı. Detaylar için ids.log dosyasına bakabilirsiniz.')

def get_all_interfaces():
    """Sistemdeki tüm ağ arayüzlerini döndürür."""
    try:
        interfaces = get_if_list()
        logger.info('Tüm ağ arayüzleri taranıyor...')
        return interfaces
    except Exception as e:
        logger.error(f'Arayüz listesi alınamadı: {str(e)}')
        print(f'Hata: Arayüz listesi alınamadı. Detaylar için log dosyasına bakın.')
        return []

def is_interface_up(iface):
    """Arayüzün fiziksel olarak UP durumda olup olmadığını kontrol eder (platforma özgü)."""
    system = platform.system()
    try:
        if PSUTIL_AVAILABLE:
            for nic, info in psutil.net_if_stats().items():
                if nic == iface:
                    return info.isup
            return False
        else:
            if system == 'Linux':
                result = subprocess.run(['ip', 'link', 'show', iface], capture_output=True, text=True)
                if 'state UP' in result.stdout:
                    return True
            elif system == 'Darwin':  # macOS
                result = subprocess.run(['ifconfig', iface], capture_output=True, text=True)
                if 'status: active' in result.stdout:
                    return True
            elif system == 'Windows':
                result = subprocess.run(['netsh', 'interface', 'show', 'interface', iface], capture_output=True, text=True)
                if 'Admin State: Enabled' in result.stdout or 'Connect state: Connected' in result.stdout:
                    return True
            return False
    except Exception as e:
        logger.warning(f'Arayüz UP durumu kontrol hatası ({iface}): {str(e)}')
        return False

def get_active_interfaces():
    """Sistemdeki ağ arayüzlerini tarar ve aktif olanları döndürür (loopback, sanal arayüzleri hariç tutar ve UP durumunu kontrol eder)."""
    interfaces = get_all_interfaces()
    active_interfaces = []
    logger.info('Aktif ağ arayüzleri taranıyor...')
    print('Aktif ağ arayüzleri taranıyor...')
    
    for iface in interfaces:
        # Loopback arayüzlerini hariç tut
        if iface.startswith(('lo', 'lo0')):
            continue
        # Sanal arayüzleri hariç tut (docker, vmnet, vboxnet gibi)
        if any(prefix in iface for prefix in ['docker', 'vboxnet', 'vmnet']):
            continue
        try:
            # Arayüzün IP adresini kontrol ederek aktif olup olmadığını anlamaya çalışıyoruz
            conf.iface = iface
            ip_addr = get_if_addr(iface)
            if ip_addr and ip_addr != '0.0.0.0':
                # Arayüzün UP durumunda olup olmadığını kontrol et
                if is_interface_up(iface):
                    active_interfaces.append((iface, ip_addr))
                    logger.info(f'Aktif arayüz bulundu: {iface} (IP: {ip_addr})')
                    print(f'Aktif arayüz bulundu: {iface} (IP: {ip_addr})')
                else:
                    logger.warning(f'Arayüz UP durumda değil: {iface}')
                    print(f'Uyarı: Arayüz UP durumda değil: {iface}')
        except Exception as e:
            logger.warning(f'Arayüz kontrol hatası ({iface}): {str(e)}')
            continue
    
    return active_interfaces

def select_interface():
    """Arayüz seçimini yapar: Komut satırı argümanı, otomatik seçim veya manuel seçim."""
    # Adım 1: Komut satırı argümanını kontrol et
    parser = argparse.ArgumentParser(description='IDS/IPS Sistemi - Arayüz Seçimi')
    parser.add_argument('-i', '--interface', type=str, help='Kullanılacak ağ arayüzü adı')
    args = parser.parse_args()
    
    if args.interface:
        logger.info(f'Komut satırı argümanı ile arayüz belirtilmiş: {args.interface}')
        print(f'Komut satırı argümanı ile arayüz belirtilmiş: {args.interface}')
        all_interfaces = get_all_interfaces()
        if args.interface in all_interfaces:
            try:
                conf.iface = args.interface
                ip_addr = get_if_addr(args.interface)
                if ip_addr and ip_addr != '0.0.0.0':
                    logger.info(f'Belirtilen arayüz aktif: {args.interface} (IP: {ip_addr})')
                    print(f'Belirtilen arayüz aktif: {args.interface} (IP: {ip_addr})')
                    return args.interface
                else:
                    logger.warning(f'Belirtilen arayüz aktif değil: {args.interface}')
                    print(f'Uyarı: Belirtilen arayüz aktif değil. Otomatik seçime geçiliyor.')
            except Exception as e:
                logger.error(f'Belirtilen arayüz kontrol hatası: {str(e)}')
                print(f'Hata: Belirtilen arayüz kontrol edilirken bir sorun oluştu. Otomatik seçime geçiliyor.')
        else:
            logger.error(f'Belirtilen arayüz bulunamadı: {args.interface}')
            print(f'Hata: Belirtilen arayüz bulunamadı. Otomatik seçime geçiliyor.')
    
    # Adım 2: Otomatik arayüz tespiti
    active_interfaces = get_active_interfaces()
    config_file = 'interface_config.json'
    recommended_iface = None
    
    # Önbellekten arayüzü kontrol et
    try:
        if os.path.exists(config_file):
            with open(config_file, 'r') as f:
                config = json.load(f)
                cached_iface = config.get('selected_interface')
                if cached_iface:
                    for iface, ip_addr in active_interfaces:
                        if iface == cached_iface:
                            logger.info(f'Önbellekten arayüz yüklendi: {cached_iface}')
                            print(f'Önbellekten arayüz yüklendi: {cached_iface}')
                            return cached_iface
                    logger.warning(f'Önbellekteki arayüz bulunamadı: {cached_iface}. Yeni seçim yapılacak.')
                    print(f'Önbellekteki arayüz bulunamadı: {cached_iface}. Yeni seçim yapılacak.')
    except Exception as e:
        logger.warning(f'Önbellek dosyasını okuma hatası: {str(e)}')
        print(f'Önbellek dosyasını okuma hatası. Yeni seçim yapılacak.')
    
    if len(active_interfaces) == 1:
        iface, ip_addr = active_interfaces[0]
        logger.info(f'Tek aktif arayüz bulundu ve otomatik seçildi: {iface} (IP: {ip_addr})')
        print(f'Tek aktif arayüz bulundu ve otomatik seçildi: {iface} (IP: {ip_addr})')
        # Seçilen arayüzü önbelleğe kaydet
        try:
            with open(config_file, 'w') as f:
                json.dump({'selected_interface': iface}, f)
            logger.info(f'Arayüz önbelleğe kaydedildi: {iface}')
        except Exception as e:
            logger.warning(f'Arayüz önbelleğe kaydedilemedi: {str(e)}')
        return iface
    elif len(active_interfaces) > 1:
        logger.info(f'Birden fazla aktif arayüz bulundu. Dış ağ testi yapılıyor...')
        print(f'Birden fazla aktif arayüz bulundu. Dış ağ testi yapılıyor...')
        recommended_iface = None
        targets = ["8.8.8.8", "1.1.1.1", "google.com"]
        result_queue = queue.Queue()
        threads = []

        def ping_test(iface, target, result_queue):
            try:
                conf.iface = iface
                ans, unans = sr(IP(dst=target)/ICMP(), timeout=2, verbose=False)
                if ans:
                    result_queue.put((iface, target))
            except Exception as e:
                logger.warning(f'Ping testi hatası ({iface}, Hedef: {target}): {str(e)}')

        # Paralel ping testi
        for iface, ip_addr in active_interfaces:
            for target in targets:
                t = threading.Thread(target=ping_test, args=(iface, target, result_queue))
                t.start()
                threads.append(t)

        # Tüm thread'lerin bitmesini bekle (maksimum süre sınırı ile)
        for t in threads:
            t.join(timeout=3)

        # Sonuçları kontrol et
        try:
            while not result_queue.empty():
                iface, target = result_queue.get_nowait()
                recommended_iface = iface
                logger.info(f'İnternete bağlı arayüz bulundu: {iface} (Hedef: {target})')
                print(f'İnternete bağlı arayüz bulundu: {iface} (Hedef: {target})')
                break
        except queue.Empty:
            pass

        # Eğer ping testi başarısız olduysa HTTP testi yap
        if not recommended_iface and REQUESTS_AVAILABLE:
            logger.info('Ping testleri başarısız oldu. HTTP testi yapılıyor...')
            print('Ping testleri başarısız oldu. HTTP testi yapılıyor...')
            for iface, ip_addr in active_interfaces:
                conf.iface = iface
                try:
                    response = requests.get('https://www.google.com', timeout=3)
                    if response.status_code == 200:
                        recommended_iface = iface
                        logger.info(f'İnternete bağlı arayüz bulundu (HTTP): {iface}')
                        print(f'İnternete bağlı arayüz bulundu (HTTP): {iface}')
                        break
                except requests.exceptions.RequestException as e:
                    logger.warning(f'HTTP testi hatası ({iface}): {str(e)}')
                    continue

        if recommended_iface:
            logger.info(f'Önerilen arayüz: {recommended_iface}. Kullanıcı seçimi gerekiyor.')
            print(f'Önerilen arayüz: {recommended_iface}. Kullanıcı seçimi gerekiyor.')
            # Önerilen arayüzü listenin başına taşı
            active_interfaces = [(iface, ip) for iface, ip in active_interfaces if iface == recommended_iface] + \
                               [(iface, ip) for iface, ip in active_interfaces if iface != recommended_iface]
        else:
            logger.warning(f'Dış ağ testi başarısız oldu. Kullanıcı seçimi gerekiyor.')
            print(f'Dış ağ testi başarısız oldu. Kullanıcı seçimi gerekiyor.')
    else:
        logger.warning(f'Hiçbir aktif arayüz bulunamadı. Kullanıcı seçimi gerekiyor.')
        print(f'Hiçbir aktif arayüz bulunamadı. Kullanıcı seçimi gerekiyor.')
    
    # Adım 3: Kullanıcıya listeyi sun ve seçim yaptır
    interfaces_to_show = active_interfaces if active_interfaces else [(iface, 'Bilinmiyor') for iface in get_all_interfaces()]
    if not interfaces_to_show:
        logger.error('Seçilebilecek hiçbir ağ arayüzü bulunamadı. Program sonlandırılıyor.')
        print('Hata: Seçilebilecek hiçbir ağ arayüzü bulunamadı. Program sonlandırılıyor.')
        return None
    
    print('\nMevcut arayüzler:')
    for i, (iface, ip_addr) in enumerate(interfaces_to_show, 1):
        print(f'{i}. {iface} (IP: {ip_addr})')
    
    max_attempts = 3
    attempt = 0
    while attempt < max_attempts:
        try:
            choice = int(input(f'Bir arayüz seçin (1-{len(interfaces_to_show)}): ')) - 1
            if 0 <= choice < len(interfaces_to_show):
                selected_iface = interfaces_to_show[choice][0]
                # Seçilen arayüzün loopback veya sanal olup olmadığını kontrol et
                if selected_iface.startswith(('lo', 'lo0')) or any(prefix in selected_iface for prefix in ['docker', 'vboxnet', 'vmnet']):
                    logger.warning(f'Seçilen arayüz loopback veya sanal: {selected_iface}. Lütfen başka bir arayüz seçin.')
                    print(f'Hata: Seçilen arayüz loopback veya sanal: {selected_iface}. Lütfen başka bir arayüz seçin.')
                    attempt += 1
                    if attempt < max_attempts:
                        print(f'Kalan deneme hakkı: {max_attempts - attempt}')
                    continue
                # Seçilen arayüzün dış ağa bağlı olup olmadığını kontrol et
                conf.iface = selected_iface
                is_connected = False
                targets = ["8.8.8.8", "1.1.1.1", "google.com"]
                for target in targets:
                    try:
                        ans, unans = sr(IP(dst=target)/ICMP(), timeout=2, verbose=False)
                        if ans:
                            is_connected = True
                            # Removed break statement
                    except Exception as e:
                        logger.warning(f'Dış ağ testi hatası ({selected_iface}, Hedef: {target}): {str(e)}')
                        continue
                if not is_connected and REQUESTS_AVAILABLE:
                    try:
                        response = requests.get('https://www.google.com', timeout=3)
                        if response.status_code == 200:
                            is_connected = True
                    except requests.exceptions.RequestException as e:
                        logger.warning(f'HTTP testi hatası ({selected_iface}): {str(e)}')
                if not is_connected:
                    logger.warning(f'Seçilen arayüz dış ağa bağlı değil: {selected_iface}. Başka bir arayüz seçilmesi önerilir.')
                    print(f'Uyarı: Seçilen arayüz dış ağa bağlı değil: {selected_iface}. Başka bir arayüz seçilmesi önerilir.')
                    retry = input('Başka bir arayüz seçmek ister misiniz? (e/h): ').lower()
                    if retry == 'e':
                        attempt += 1
                        if attempt < max_attempts:
                            print(f'Kalan deneme hakkı: {max_attempts - attempt}')
                        continue
                logger.info(f'Kullanıcı tarafından seçilen arayüz: {selected_iface}')
                print(f'Seçilen arayüz: {selected_iface}')
                # Seçilen arayüzü önbelleğe kaydet
                try:
                    config_file = 'interface_config.json'
                    with open(config_file, 'w') as f:
                        json.dump({'selected_interface': selected_iface}, f)
                    logger.info(f'Arayüz önbelleğe kaydedildi: {selected_iface}')
                except Exception as e:
                    logger.warning(f'Arayüz önbelleğe kaydedilemedi: {str(e)}')
                return selected_iface
            else:
                logger.warning(f'Geçersiz seçim: {choice+1}. Tekrar deneyin.')
                print(f'Hata: Geçersiz seçim. Lütfen 1 ile {len(interfaces_to_show)} arasında bir sayı girin.')
        except (ValueError, IndexError):
            logger.warning('Geçersiz giriş. Sayı girilmesi gerekiyor.')
            print('Hata: Geçersiz giriş. Lütfen bir sayı girin.')
        attempt += 1
        if attempt < max_attempts:
            print(f'Kalan deneme hakkı: {max_attempts - attempt}')
    
    logger.error(f'Maksimum deneme sayısına ulaşıldı. Program sonlandırılıyor.')
    print(f'Hata: Maksimum deneme sayısına ulaşıldı. Program sonlandırılıyor.')
    print('Sorun devam ederse, lütfen log dosyasını ({}) inceleyin veya geliştiriciye bildirin.'.format(LOG_FILE))
    print('Ayrıca, ağ ayarlarınızı kontrol edin veya sistem yöneticinize danışın.')
    # Hata raporu dosyası oluştur
    try:
        error_report_file = 'error_report.txt'
        with open(error_report_file, 'w') as f:
            f.write(f'Hata Raporu - {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}\n')
            f.write(f'Log Dosyası: {LOG_FILE}\n')
            f.write('Sistem Bilgileri:\n')
            system_info = platform.uname()
            f.write(f'Sistem: {system_info.system} {system_info.release} {system_info.version}\n')
            f.write(f'Makine: {system_info.machine}\n')
            if PSUTIL_AVAILABLE:
                cpu_info = psutil.cpu_count()
                mem_info = psutil.virtual_memory()
                f.write(f'CPU Sayısı: {cpu_info}\n')
                f.write(f'Bellek: Toplam {mem_info.total / (1024**3):.2f} GB, Kullanılabilir {mem_info.available / (1024**3):.2f} GB\n')
            f.write('Arayüz Listesi:\n')
            for iface, ip in interfaces_to_show:
                f.write(f'- {iface} (IP: {ip})\n')
            f.write('Hata Mesajı: Maksimum deneme sayısına ulaşıldı. Arayüz seçilemedi.\n')
        logger.info(f'Hata raporu oluşturuldu: {error_report_file}')
        print(f'Hata raporu oluşturuldu: {error_report_file}. Lütfen bu dosyayı geliştiriciye gönderin.')
    except Exception as e:
        logger.error(f'Hata raporu oluşturma hatası: {str(e)}')
        print(f'Hata raporu oluşturma sırasında bir sorun oluştu.')
    return None

def packet_callback(packet):
    """Gelen paketleri analiz eder, loglar ve SQL Injection gibi şüpheli aktiviteleri tespit eder."""
    if packet.haslayer(IP):
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        log_msg = f'Kaynak IP: {src_ip} -> Hedef IP: {dst_ip}'
        logger.info(log_msg)
        print(log_msg)
        
        if packet.haslayer(TCP):
            sport = packet[TCP].sport
            dport = packet[TCP].dport
            if dport == 80 or dport == 443:
                proto = 'HTTP' if dport == 80 else 'HTTPS'
                log_msg = f'{proto} Paketi: Port {sport} -> {dport}'
                logger.info(log_msg)
                print(log_msg)
                if packet.haslayer(Raw):
                    payload = packet[Raw].load
                    log_msg = f'Payload: {payload[:50]}...'
                    logger.info(log_msg)
                    print(log_msg)
                    # SQL Injection tespiti için genişletilmiş desen kontrolü
                    try:
                        # Payload'u string'e çevirip URL kod çözme yap (çoklu kodlama denemeleri)
                        payload_str = None
                        try:
                            payload_str = payload.decode('utf-8')
                        except UnicodeDecodeError:
                            try:
                                payload_str = payload.decode('latin-1')
                            except UnicodeDecodeError:
                                payload_str = payload.decode('utf-8', errors='ignore')
                        if payload_str:
                            decoded_payload = urllib.parse.unquote(payload_str)
                            # Genişletilmiş SQL Injection desenleri (regex ile)
                            sql_injection_regexes = [
                                r'(?i)UNION\s*SELECT',  # Case-insensitive UNION SELECT
                                r'(?i)UNION\s*/\*.*\*/\s*SELECT',  # UNION/**/SELECT gibi yorumlu desenler
                                r'(?i)OR\s*1\s*=\s*1',  # OR 1=1
                                r'(?i)AND\s*1\s*=\s*1',  # AND 1=1
                                r'--',  # SQL yorum satırı
                                r';\s*DROP\s*TABLE',  # DROP TABLE gibi tehlikeli komutlar
                                r'(?i)EXEC\s+xp_',  # EXEC xp_ ile başlayan stored procedures
                                r'(?i)EXEC\s+sp_',  # EXEC sp_ ile başlayan stored procedures
                                r'%27',  # Kodlanmış tek tırnak (')
                                r'%22',  # Kodlanmış çift tırnak (")
                                r'%3B'   # Kodlanmış noktalı virgül (;)
                            ]
                            threat_score = 0
                            matched_patterns = []
                            for regex in sql_injection_regexes:
                                if re.search(regex, decoded_payload):
                                    threat_score += 1
                                    matched_patterns.append(regex)
                                    break # Desen bulunduğunda döngüden çık

                            # Döngü bittikten sonra tehdit puanını kontrol et
                            if threat_score > 0:
                                alert_msg = f'!!! ŞÜPHELİ SQL INJECTION TESPİT EDİLDİ !!! Kaynak IP: {src_ip}, Hedef IP: {dst_ip}, Port: {sport}->{dport}, Tehdit Puanı: {threat_score}, Eşleşen Kalıplar: {", ".join(matched_patterns)}, Payload Özeti: {decoded_payload[:100]}...'
                                logger.warning(alert_msg)
                                # Terminalde renkli çıktı (sadece terminal ortamında)
                                try:
                                    if os.isatty(1):  # Terminalde mi çalışıyoruz?
                                        print(f'\033[91m[!!] UYARI: {alert_msg}\033[0m')  # Kırmızı renkte uyarı
                                    else:
                                        print(f'[!!] UYARI: {alert_msg}')
                                except:
                                    print(f'[!!] UYARI: {alert_msg}')
                                if threat_score >= 2:  # Eşik: En az 2 desen eşleşirse daha ciddi bir uyarı
                                    logger.critical(f'YÜKSET TEHDİT SEVİYESİ: SQL Injection tespit edildi. Tehdit Puanı: {threat_score}')
                                    print(f'\033[91m[!!] KRİTİK UYARI: Yüksek tehdit seviyesi tespit edildi. Tehdit Puanı: {threat_score}\033[0m')
                            ## break # Bu break dışarıdaki if bloğunun sonundaydı, kaldırıldı.
                    except Exception as e:
                        logger.warning(f'Payload çözümleme hatası: {str(e)}')
                        # Bayt bazlı basit kontrol (yedek)
                        sql_injection_patterns = [
                            b'UNION SELECT',
                            b'1=1',
                            b'OR 1=1',
                            b'--',
                            b'; DROP TABLE',
                            b'EXEC xp_',
                            b'EXEC sp_'
                        ]
                        for pattern in sql_injection_patterns:
                            if pattern in payload:
                                alert_msg = f'!!! ŞÜPHELİ SQL INJECTION TESPİT EDİLDİ (Bayt Kontrolü) !!! Kaynak IP: {src_ip}, Hedef IP: {dst_ip}, Port: {sport}->{dport}, Kalıp: {pattern.decode("utf-8", errors="ignore")}'
                                logger.warning(alert_msg)
                                try:
                                    if os.isatty(1):
                                        print(f'\033[91m[!!] UYARI: {alert_msg}\033[0m')
                                    else:
                                        print(f'[!!] UYARI: {alert_msg}')
                                except:
                                    print(f'[!!] UYARI: {alert_msg}')
                                break
        elif packet.haslayer(UDP):
            sport = packet[UDP].sport
            dport = packet[UDP].dport
            log_msg = f'UDP Paketi: Port {sport} -> {dport}'
            logger.info(log_msg)
            print(log_msg)

def check_permissions(iface):
    """Paket yakalama için gerekli izinleri kontrol eder."""
    try:
        logger.info('Paket yakalama izinleri kontrol ediliyor...')
        print('Paket yakalama izinleri kontrol ediliyor...')
        sniff(iface=iface, count=1, timeout=0.1, store=0)
        logger.info('Paket yakalama izinleri doğrulandı.')
        print('Paket yakalama izinleri doğrulandı.')
        return True
    except PermissionError:
        logger.error('Hata: Paket yakalama için yönetici (root/sudo) yetkileri gerekiyor.')
        print('Hata: Paket yakalama için yönetici (root/sudo) yetkileri gerekiyor. Lütfen programı sudo ile çalıştırın.')
        return False
    except Exception as e:
        logger.error(f'İzin kontrolü sırasında hata oluştu: {str(e)}')
        print(f'Hata: İzin kontrolü sırasında bir sorun oluştu. Detaylar için log dosyasına bakın.')
        return False

def main():
    """Ana fonksiyon: Loglama, izin kontrolü, arayüz seçimi yapar, ardından paket dinlemeyi başlatır."""
    setup_logging()
    iface = select_interface()
    
    if iface is None:
        logger.error('Paket dinleme başlatılamadı: Arayüz seçilemedi.')
        print('Paket dinleme başlatılamadı: Arayüz seçilemedi.')
        return
    
    # İzin kontrolü yap
    if not check_permissions(iface):
        logger.error('Program sonlandırılıyor: Gerekli izinler sağlanamadı.')
        print('Program sonlandırılıyor: Gerekli izinler sağlanamadı.')
        return
    
    try:
        logger.info(f'Paket dinleme başlatılıyor. Arayüz: {iface}')
        print(f'Paket dinleme başlatılıyor. Arayüz: {iface}')
        # HTTP, HTTPS ve UDP için genişletilmiş filtre
        sniff(iface=iface, prn=packet_callback, filter='tcp port 80 or tcp port 443 or udp', store=0)
    except Exception as e:
        logger.error(f'Paket dinleme hatası: {str(e)}')
        print(f'Hata: Paket dinleme sırasında bir sorun oluştu. Detaylar için log dosyasına bakın.')

if __name__ == '__main__':
    main()
