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

# Canlı trafik ile performans testi
def test_live_traffic_performance(iface, duration):
    global global_start_time, global_end_time
    try:
        log_and_alert(f'Canlı trafik ile performans testi başlatılıyor. Arayüz: {iface}', level='info')
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
    except Exception as e:
        logger.error(f'Canlı trafik performans testi hatası: {str(e)}')
        log_and_alert(f'Hata: Canlı trafik performans testi başarısız oldu: {str(e)}', level='critical')

# Performans sonuçlarını raporlama
def report_performance_results():
    global global_packet_count, global_start_time, global_end_time
    try:
        total_time = global_end_time - global_start_time if global_end_time > global_start_time else 1
        packets_per_second = global_packet_count / total_time if total_time > 0 else 0
        avg_cpu = sum(cpu_usages) / len(cpu_usages) if cpu_usages else 0.0
        avg_mem = sum(memory_usages) / len(memory_usages) if memory_usages else 0.0
        max_cpu = max(cpu_usages) if cpu_usages else 0.0
        max_mem = max(memory_usages) if memory_usages else 0.0
        
        report = f"""
Performans Testi Sonuçları
--------------------------
Toplam İşlenen Paket: {global_packet_count}
Toplam Süre: {total_time:.2f} saniye
Paket İşleme Hızı: {packets_per_second:.2f} paket/saniye
Ortalama CPU Kullanımı: {avg_cpu:.2f}%
Maksimum CPU Kullanımı: {max_cpu:.2f}%
Ortalama Bellek Kullanımı: {avg_mem:.2f} MB
Maksimum Bellek Kullanımı: {max_mem:.2f} MB
"""
        logger.info(report)
        log_and_alert(report, level='info')
        
        with open('../tests/test_results.md', 'a') as md_f:
            md_f.write(f"## Yeni Test Sonuçları - {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            md_f.write(report + '\n\n')
        log_and_alert('Performans sonuçları test_results.md dosyasına kaydedildi.', level='info')
    except Exception as e:
        logger.error(f'Raporlama hatası: {str(e)}')
        log_and_alert(f'Hata: Performans sonuçları raporlanamadı: {str(e)}', level='critical')

def main():
    parser = argparse.ArgumentParser(description='IDS/IPS Performans Testi')
    parser.add_argument('--pcap', type=str, help='Test için kullanılacak .pcap dosyası yolu')
    parser.add_argument('--interface', type=str, help='Canlı trafik testi için ağ arayüzü')
    parser.add_argument('--duration', type=int, default=60, help='Test süresi (saniye)')
    args = parser.parse_args()
    
    log_and_alert('Performans testi başlatılıyor...', level='info')
    
    if args.pcap:
        if not os.path.exists(args.pcap):
            log_and_alert(f'Hata: .pcap dosyası bulunamadı: {args.pcap}', level='critical')
            return
        test_pcap_performance(args.pcap, args.duration)
    elif args.interface:
        test_live_traffic_performance(args.interface, args.duration)
    else:
        log_and_alert('Hata: Test türü belirtilmedi. Lütfen --pcap veya --interface argümanını kullanın.', level='critical')
        return
    
    report_performance_results()
    log_and_alert('Performans testi tamamlandı.', level='success')

if __name__ == '__main__':
    main()
