# Araştırma Notları: Trafik Analizi Script’i

## Script Özeti
- **Dosya:** `src/analyze_traffic.py`
- **Amaç:** Gerçek zamanlı ağ trafiğini analiz etmek, HTTP (port 80), HTTPS (port 443) ve UDP trafiğini yakalamak, konsola yazdırmak ve log dosyasına kaydetmek. Script, Snort’un HTTP kuralıyla (`alert tcp any any -> any 80`) uyumlu çalışarak IDS/IPS analizi için temel oluşturur.
- **Proje Bağlamı:** Modül 2 kapsamında, Ubuntu 22.04 (UTM sanal makinesi) üzerinde ağ trafiği analizi ve kural tabanlı tespit hedeflenir.

## Özellikler
- **Loglama:**
  - Trafik verileri `../data/ids.log`’a kaydedilir.
  - Format: `%(asctime)s - %(levelname)s - %(message)s` (örneğin, `2025-05-24 01:00:00,123 - INFO - HTTP Paketi: Port 12345 -> 80`).
  - Log dizini (`../data`) otomatik oluşturulur.
- **Arayüz Seçimi:**
  - Aktif ağ arayüzlerini otomatik tarar ve ilk aktif arayüzü seçer (örneğin, `enp0s1`, IP: 192.168.64.14).
  - Hata durumunda manuel arayüz seçimi sunar.
- **Paket Analizi:**
  - **IP Katmanı:** Kaynak ve hedef IP adresleri.
  - **TCP Katmanı:** HTTP/HTTPS (port 80/443) için kaynak/hedef portlar ve payload (ilk 50 bayt).
  - **UDP Katmanı:** Kaynak/hedef portlar.
- **Filtre:** `tcp port 80 or tcp port 443 or udp`, sadece ilgili trafiği yakalar, performansı optimize eder.
- **Hata Yönetimi:** Arayüz hataları, paket dinleme sorunları loglanır ve kullanıcıya bildirilir.
- **Performans:** `store=0` ile bellek kullanımı minimumda tutulur.

## Bağımlılıklar
- **Python Paketleri:**
  - `scapy==2.5.0` (ağ analizi).
  - `logging` (Python standart kütüphanesi, loglama).
- **requirements.txt:**