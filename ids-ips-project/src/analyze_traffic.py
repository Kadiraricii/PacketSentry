from scapy.all import *
import logging
import os
import re
import urllib.parse
from datetime import datetime

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

def get_active_interfaces():
    """Sistemdeki ağ arayüzlerini tarar ve aktif olanları döndürür."""
    interfaces = get_if_list()
    active_interfaces = []
    logger.info('Ağ arayüzleri taranıyor...')
    print('Ağ arayüzleri taranıyor...')
    
    for iface in interfaces:
        try:
            # Arayüzün IP adresini kontrol ederek aktif olup olmadığını anlamaya çalışıyoruz
            conf.iface = iface
            if get_if_addr(iface) != '0.0.0.0':
                active_interfaces.append(iface)
                logger.info(f'Aktif arayüz bulundu: {iface}')
                print(f'Aktif arayüz bulundu: {iface}')
        except Exception as e:
            logger.warning(f'Arayüz kontrol hatası ({iface}): {str(e)}')
            continue
    
    return active_interfaces

def select_interface():
    """Aktif arayüzleri bulur ve otomatik/manuel seçim yapar."""
    active_interfaces = get_active_interfaces()
    
    if not active_interfaces:
        logger.error('Hiçbir aktif ağ arayüzü bulunamadı.')
        print('Hata: Hiçbir aktif ağ arayüzü bulunamadı.')
        return None
    
    # Otomatik seçim: İlk aktif arayüzü seç
    selected_interface = active_interfaces[0]
    logger.info(f'Otomatik seçilen arayüz: {selected_interface}')
    print(f'Otomatik seçilen arayüz: {selected_interface}')
    return selected_interface

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
                        # Payload'u string'e çevirip URL kod çözme yap
                        payload_str = payload.decode('utf-8', errors='ignore')
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
                            r'(?i)EXEC\s+sp_'   # EXEC sp_ ile başlayan stored procedures
                        ]
                        for regex in sql_injection_regexes:
                            if re.search(regex, decoded_payload):
                                alert_msg = f'!!! ŞÜPHELİ SQL INJECTION TESPİT EDİLDİ !!! Kaynak IP: {src_ip}, Hedef IP: {dst_ip}, Port: {sport}->{dport}, Kalıp: {regex}, Payload Özeti: {decoded_payload[:100]}...'
                                logger.warning(alert_msg)
                                # Terminalde renkli çıktı (sadece terminal ortamında)
                                try:
                                    if os.isatty(1):  # Terminalde mi çalışıyoruz?
                                        print(f'\033[91m{alert_msg}\033[0m')  # Kırmızı renkte uyarı
                                    else:
                                        print(alert_msg)
                                except:
                                    print(alert_msg)
                                break
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
                                        print(f'\033[91m{alert_msg}\033[0m')
                                    else:
                                        print(alert_msg)
                                except:
                                    print(alert_msg)
                                break
        elif packet.haslayer(UDP):
            sport = packet[UDP].sport
            dport = packet[UDP].dport
            log_msg = f'UDP Paketi: Port {sport} -> {dport}'
            logger.info(log_msg)
            print(log_msg)

def main():
    """Ana fonksiyon: Loglama ve arayüz seçimi yapar, ardından paket dinlemeyi başlatır."""
    setup_logging()
    iface = select_interface()
    
    if iface is None:
        logger.error('Paket dinleme başlatılamadı: Arayüz seçilemedi.')
        print('Paket dinleme başlatılamadı: Arayüz seçilemedi.')
        # Manuel seçim alternatifi
        interfaces = get_if_list()
        if interfaces:
            print('Mevcut arayüzler:')
            for i, inf in enumerate(interfaces):
                print(f'{i+1}. {inf}')
            try:
                choice = int(input(f'Bir arayüz seçin (1-{len(interfaces)}): ')) - 1
                if 0 <= choice < len(interfaces):
                    iface = interfaces[choice]
                    logger.info(f'Manuel seçilen arayüz: {iface}')
                    print(f'Manuel seçilen arayüz: {iface}')
                else:
                    logger.error('Geçersiz seçim. Program sonlandırılıyor.')
                    print('Geçersiz seçim. Program sonlandırılıyor.')
                    return
            except (ValueError, IndexError):
                logger.error('Geçersiz giriş. Program sonlandırılıyor.')
                print('Geçersiz giriş. Program sonlandırılıyor.')
                return
        else:
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
