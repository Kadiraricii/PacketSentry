import os
import sys
import time
import psutil
import argparse
from datetime import datetime
from scapy.all import rdpcap, sniff
import threading
import queue
import logging

# Proje modüllerini import etmek için src dizinine path ekleme
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '../src')))
from analyze_traffic import packet_callback
from detect_attacks import detect_attacks
from detect_and_block import block_threat

# Loglama ayarları
LOG_FILE = '../data/performance_test.log'
log_dir = os.path.dirname(LOG_FILE)
if not os.path.exists(log_dir):
    os.makedirs(log_dir)

logging.basicConfig(
    filename=LOG_FILE,
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)

logger = logging.getLogger(__name__)

# Performans metrikleri
global_packet_count = 0
global_start_time = 0
global_end_time = 0
cpu_usages = []
memory_usages = []

# Root yetkisi kontrolü ve uyarı
def check_privileges():
    if os.geteuid() != 0:
        print("\n⚠️  UYARI: Bu program root yetkileri gerektiriyor!")
        print("Çözüm seçenekleri:")
        print("1. Sudo ile çalıştırın: sudo python3 performance_test.py")
        print("2. Sadece .pcap dosyası testi için root yetkisi gerekmez")
        print("3. Canlı trafik yakalama için root yetkisi zorunludur\n")
        return False
    return True

# Güvenli ağ arayüzü listesi alma (MacOS ve Linux uyumlu)
def get_available_interfaces():
    try:
        import netifaces
        interfaces = netifaces.interfaces()
        return [iface for iface in interfaces if iface != 'lo']
    except ImportError:
        # netifaces yoksa alternatif yöntemler
        import platform
        system = platform.system().lower()
        
        try:
            import subprocess
            if system == 'darwin':  # MacOS
                # MacOS için ifconfig kullan
                result = subprocess.run(['ifconfig', '-l'], capture_output=True, text=True)
                if result.returncode == 0:
                    interfaces = result.stdout.strip().split()
                    return [iface for iface in interfaces if iface != 'lo0']
                else:
                    # networksetup ile deneme
                    result = subprocess.run(['networksetup', '-listallhardwareports'], capture_output=True, text=True)
                    interfaces = []
                    for line in result.stdout.split('\n'):
                        if 'Device:' in line:
                            device = line.split('Device:')[1].strip()
                            if device and device != 'lo0':
                                interfaces.append(device)
                    return interfaces if interfaces else ['en0', 'en1', 'en2']
            else:  # Linux
                result = subprocess.run(['ip', 'link', 'show'], capture_output=True, text=True)
                interfaces = []
                for line in result.stdout.split('\n'):
                    if ':' in line and 'state' in line.lower():
                        iface = line.split(':')[1].strip()
                        if iface != 'lo':
                            interfaces.append(iface)
                return interfaces
        except:
            # Son çare: sistem tipine göre varsayılan arayüzler
            if system == 'darwin':  # MacOS
                return ['en0', 'en1', 'en2', 'bridge0']
            else:  # Linux
                return ['eth0', 'wlan0', 'enp0s3']

# Zaman damgalı ve renkli terminal çıktıları
def log_and_alert(msg, level='info'):
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

# Sistem kaynaklarını ölçme fonksiyonu
def measure_resources(process):
    try:
        cpu_percent = process.cpu_percent(interval=1)
        memory_info = process.memory_info()
        memory_usage = memory_info.rss / (1024 * 1024)  # MB cinsinden
        return cpu_percent, memory_usage
    except Exception as e:
        logger.error(f'Kaynak ölçüm hatası: {str(e)}')
        return 0.0, 0.0

# Performans testi için paket işleme fonksiyonu
def performance_packet_callback(packet):
    global global_packet_count
    global_packet_count += 1
    try:
        if packet.haslayer('IP'):
            src_ip = packet['IP'].src
            dst_ip = packet['IP'].dst
            sport = packet['TCP'].sport if packet.haslayer('TCP') else (packet['UDP'].sport if packet.haslayer('UDP') else 0)
            dport = packet['TCP'].dport if packet.haslayer('TCP') else (packet['UDP'].dport if packet.haslayer('UDP') else 0)
            threat_types = detect_attacks(packet, src_ip, dst_ip, sport, dport)
            if threat_types:
                for threat_type in threat_types:
                    block_threat(packet, src_ip, dst_ip, sport, dport, threat_type)
    except Exception as e:
        logger.error(f'Paket işleme hatası: {str(e)}')

# .pcap dosyasından performans testi
def test_pcap_performance(pcap_file, duration):
    global global_start_time, global_end_time
    try:
        log_and_alert(f'.pcap dosyası ile performans testi başlatılıyor: {pcap_file}', level='info')
        packets = rdpcap(pcap_file)
        log_and_alert(f'Toplam {len(packets)} paket yüklendi.', level='info')
        
        process = psutil.Process()
        global_start_time = time.time()
        start_time = global_start_time
        
        for i, packet in enumerate(packets):
            performance_packet_callback(packet)
            if i % 100 == 0:  # Her 100 pakette bir kaynak kullanımı ölç
                cpu, mem = measure_resources(process)
                cpu_usages.append(cpu)
                memory_usages.append(mem)
            if duration and time.time() - start_time > duration:
                log_and_alert(f'Süre sınırı ({duration} saniye) aşıldı, test durduruluyor.', level='warning')
                break
        
        global_end_time = time.time()
        log_and_alert(f'.pcap dosyası testi tamamlandı.', level='success')
    except Exception as e:
        logger.error(f'.pcap performans testi hatası: {str(e)}')
        log_and_alert(f'Hata: .pcap performans testi başarısız oldu: {str(e)}', level='critical')

# Güvenli canlı trafik testi
def test_live_traffic_performance(iface, duration):
    global global_start_time, global_end_time
    
    # Root yetkisi kontrolü
    if not check_privileges():
        log_and_alert('Canlı trafik yakalama için root yetkileri gerekiyor!', level='critical')
        print("Alternatif: --pcap parametresi ile .pcap dosyası kullanarak test yapabilirsiniz")
        return False
    
    try:
        log_and_alert(f'Canlı trafik ile performans testi başlatılıyor. Arayüz: {iface}', level='info')
        
        # Arayüz kontrolü
        available_interfaces = get_available_interfaces()
        if iface not in available_interfaces:
            log_and_alert(f'Uyarı: {iface} arayüzü bulunamadı. Mevcut arayüzler: {", ".join(available_interfaces)}', level='warning')
            if available_interfaces:
                iface = available_interfaces[0]
                log_and_alert(f'Varsayılan arayüz kullanılıyor: {iface}', level='info')
            else:
                log_and_alert('Kullanılabilir ağ arayüzü bulunamadı!', level='critical')
                return False
        
        process = psutil.Process()
        global_start_time = time.time()
        start_time = global_start_time
        
        def resource_monitor():
            while time.time() - start_time <= duration:
                cpu, mem = measure_resources(process)
                cpu_usages.append(cpu)
                memory_usages.append(mem)
                time.sleep(1)
        
        monitor_thread = threading.Thread(target=resource_monitor)
        monitor_thread.daemon = True
        monitor_thread.start()
        
        sniff(iface=iface, prn=performance_packet_callback, store=0, timeout=duration)
        global_end_time = time.time()
        log_and_alert(f'Canlı trafik testi tamamlandı.', level='success')
        return True
    except Exception as e:
        logger.error(f'Canlı trafik performans testi hatası: {str(e)}')
        log_and_alert(f'Hata: Canlı trafik performans testi başarısız oldu: {str(e)}', level='critical')
        return False

# Performans sonuçlarını raporlama (EKLEYİCİ OLARAK)
def report_performance_results():
    global global_packet_count, global_start_time, global_end_time
    try:
        total_time = global_end_time - global_start_time if global_end_time > global_start_time else 1
        packets_per_second = global_packet_count / total_time if total_time > 0 else 0
        avg_cpu = sum(cpu_usages) / len(cpu_usages) if cpu_usages else 0.0
        avg_mem = sum(memory_usages) / len(memory_usages) if memory_usages else 0.0
        max_cpu = max(cpu_usages) if cpu_usages else 0.0
        max_mem = max(memory_usages) if memory_usages else 0.0
        
        current_time = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        
        report = f"""
========================================
Performans Testi Sonuçları - {current_time}
========================================
Toplam İşlenen Paket: {global_packet_count}
Toplam Süre: {total_time:.2f} saniye
Paket İşleme Hızı: {packets_per_second:.2f} paket/saniye
Ortalama CPU Kullanımı: {avg_cpu:.2f}%
Maksimum CPU Kullanımı: {max_cpu:.2f}%
Ortalama Bellek Kullanımı: {avg_mem:.2f} MB
Maksimum Bellek Kullanımı: {max_mem:.2f} MB
========================================
"""
        logger.info(report)
        log_and_alert(report, level='info')
        
        # Sonuçları dosyaya EKLEYİCİ olarak kaydet (öncekiler silinmesin)
        test_results_path = os.path.join(os.path.dirname(__file__), 'test_results.md')
        
        # Dosya varsa sonuna ekle, yoksa yeni oluştur
        mode = 'a' if os.path.exists(test_results_path) else 'w'
        with open(test_results_path, mode, encoding='utf-8') as md_f:
            if mode == 'w':
                md_f.write("# IDS/IPS Performans Test Sonuçları\n\n")
            md_f.write(f"## Test Sonuçları - {current_time}\n")
            md_f.write("```\n")
            md_f.write(report)
            md_f.write("```\n\n")
            md_f.write("---\n\n")
        
        log_and_alert('Performans sonuçları test_results.md dosyasına EKLENDİ (önceki sonuçlar korundu).', level='success')
        
        # Ayrıca JSON formatında da kaydet
        import json
        json_results = {
            'timestamp': current_time,
            'total_packets': global_packet_count,
            'total_time': total_time,
            'packets_per_second': packets_per_second,
            'avg_cpu': avg_cpu,
            'max_cpu': max_cpu,
            'avg_memory': avg_mem,
            'max_memory': max_mem
        }
        
        json_results_path = os.path.join(os.path.dirname(__file__), 'performance_results.json')
        
        # JSON dosyasını da ekleyici olarak kaydet
        if os.path.exists(json_results_path):
            with open(json_results_path, 'r', encoding='utf-8') as f:
                existing_results = json.load(f)
            existing_results.append(json_results)
        else:
            existing_results = [json_results]
        
        with open(json_results_path, 'w', encoding='utf-8') as f:
            json.dump(existing_results, f, indent=2, ensure_ascii=False)
        
        log_and_alert('Sonuçlar JSON formatında da kaydedildi.', level='info')
        
    except Exception as e:
        logger.error(f'Raporlama hatası: {str(e)}')
        log_and_alert(f'Hata: Performans sonuçları raporlanamadı: {str(e)}', level='critical')

def main():
    parser = argparse.ArgumentParser(description='IDS/IPS Performans Testi')
    parser.add_argument('--pcap', type=str, help='Test için kullanılacak .pcap dosyası yolu')
    parser.add_argument('--interface', type=str, help='Canlı trafik testi için ağ arayüzü')
    parser.add_argument('--duration', type=int, default=60, help='Test süresi (saniye)')
    parser.add_argument('--list-interfaces', action='store_true', help='Mevcut ağ arayüzlerini listele')
    args = parser.parse_args()
    
    # Mevcut arayüzleri listele
    if args.list_interfaces:
        interfaces = get_available_interfaces()
        print("\nMevcut ağ arayüzleri:")
        for i, iface in enumerate(interfaces, 1):
            print(f"{i}. {iface}")
        print("\nCanlı trafik testi için: --interface ARAYUZ_ADI")
        print("Örnek: python3 performance_test.py --interface eth0 --duration 30")
        return
    
    log_and_alert('Performans testi başlatılıyor...', level='info')
    
    if args.pcap:
        if not os.path.exists(args.pcap):
            log_and_alert(f'Hata: .pcap dosyası bulunamadı: {args.pcap}', level='critical')
            return
        test_pcap_performance(args.pcap, args.duration)
    elif args.interface:
        if not test_live_traffic_performance(args.interface, args.duration):
            log_and_alert('Canlı trafik testi başarısız oldu.', level='critical')
            return
    else:
        print("\nKullanım örnekleri:")
        print("1. .pcap dosyası ile test: python3 performance_test.py --pcap dosya.pcap")
        print("2. Canlı trafik testi: sudo python3 performance_test.py --interface eth0")
        print("3. Arayüzleri listele: python3 performance_test.py --list-interfaces")
        log_and_alert('Hata: Test türü belirtilmedi. Lütfen --pcap veya --interface argümanını kullanın.', level='critical')
        return
    
    report_performance_results()
    log_and_alert('Performans testi tamamlandı.', level='success')

if __name__ == '__main__':
    main()