# Araştırma Notları: Trafik Analizi Script’i

## Script Özeti
- **Dosya:** `src/analyze_traffic.py`
- **Amaç:** Gerçek zamanlı ağ trafiğini analiz etmek, HTTP (port 80), HTTPS (port 443) ve UDP trafiğini yakalamak, konsola yazdırmak ve log dosyasına kaydetmek. Script, Snort’un HTTP kuralıyla (`alert tcp any any -> any 80`) uyumlu çalışarak IDS/IPS analizi için temel oluşturur.
- **Proje Bağlamı:** Modül 2 kapsamında, Ubuntu 22.04 (UTM sanal makinesi) üzerinde ağ trafiği analizi ve kural tabanlı tespit hedeflenir.

## Özellikler (Başlangıç Sürümü)
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

## Geliştirmeler ve İyileştirmeler (Güncel Sürüm)
Script, başlangıç sürümünden bu yana önemli ölçüde geliştirilmiştir. Aşağıda yapılan temel iyileştirmeler ve yeni özellikler detaylı bir şekilde açıklanmıştır:

- **Gelişmiş Arayüz Seçimi:**
  - **Komut Satırı Desteği:** Kullanıcılar, `-i` veya `--interface` argümanı ile doğrudan bir arayüz belirtebilir.
  - **Otomatik Filtreleme:** Loopback (`lo`, `lo0`) ve sanal arayüzler (`docker`, `vboxnet`, `vmnet`) hariç tutularak yalnızca IP adresi olan ve fiziksel olarak "UP" durumda olan arayüzler seçilir.
  - **Akıllı Dış Ağ Testi:** Birden fazla aktif arayüz varsa, `8.8.8.8`, `1.1.1.1` ve `google.com` gibi hedeflere paralel ping testi yapılır. Ayrıca, ping başarısız olursa HTTP isteği (`requests` kütüphanesi ile) testi devreye girer.
  - **Önbellekleme:** Seçilen arayüz, `interface_config.json` dosyasına kaydedilir ve sonraki çalıştırmalarda varsayılan olarak kullanılır.
  - **Kullanıcı Doğrulaması:** Kullanıcı tarafından seçilen arayüzün loopback veya sanal olup olmadığı kontrol edilir; dış ağ bağlantısı test edilir ve bağlı değilse kullanıcıya başka bir seçim yapma seçeneği sunulur.

- **İzin Kontrolü:**
  - Program başlangıcında kısa süreli bir test `sniff` işlemi ile paket yakalama izinleri kontrol edilir. `PermissionError` durumunda kullanıcıya yönetici (root/sudo) yetkileriyle çalıştırması gerektiği bildirilir.

- **SQL Injection Tespiti:**
  - HTTP ve HTTPS paketlerinde SQL Injection kalıpları için genişletilmiş regex kontrolü eklendi (`UNION SELECT`, `OR 1=1`, kodlanmış ifadeler gibi).
  - Tehdit puanı sistemi ile yanlış pozitifler azaltıldı; birden fazla desen eşleşirse tehdit puanı artar ve eşik (2 desen) aşılırsa ciddi uyarı verilir.

- **Payload Kodlama Toleransı:**
  - Payload decode işlemi için UTF-8, Latin-1 ve `errors='ignore'` seçenekleri sırayla denenir, böylece farklı kodlamalardaki veriler analiz edilebilir.

- **Hata Yönetimi ve Raporlama:**
  - Maksimum deneme sayısı aşıldığında bir `error_report.txt` dosyası oluşturulur. Bu dosya sistem bilgilerini, arayüz listesini ve hata mesajlarını içerir.
  - Kullanıcıya ağ ayarlarını kontrol etme ve sistem yöneticisine danışma gibi rehberlik sağlanır.

- **Performans Optimizasyonu:**
  - Paralel ping testi ile dış ağ kontrolü hızlandırıldı.
  - Arayüz seçimi önbelleklemesi ile tekrarlanan seçim süreçleri önlendi.

- **Platform Desteği:**
  - `psutil` kütüphanesi ile arayüz durumu kontrolü platformdan bağımsız hale getirildi. Eğer `psutil` yoksa, Linux, macOS ve Windows için platforma özgü komutlar kullanılır.

- **Terminal Çıktısı Esnekliği:**
  - Renkli uyarı mesajları (`os.isatty(1)` kontrolü ile) terminal dışı ortamlarda standart metne dönüştürülür (`[!!] UYARI: ...`).

## Bağımlılıklar
- **Python Paketleri:**
  - `scapy>=2.4.5` (ağ analizi).
  - `psutil>=5.9.0` (sistem bilgileri ve arayüz durumu kontrolü).
  - `requests>=2.28.1` (HTTP bağlantı testi).
  - `logging`, `threading`, `queue`, `json`, `subprocess` (Python standart kütüphaneleri, loglama ve performans optimizasyonu).
- **requirements.txt:**
```
# PacketSentry IDS/IPS Projesi için Gerekli Kütüphaneler

# Temel paket yakalama ve ağ analizi için
scapy>=2.4.5

# Sistem bilgileri ve arayüz durumu kontrolü için
psutil>=5.9.0

# HTTP bağlantı testi için
requests>=2.28.1
```
