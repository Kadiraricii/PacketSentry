<div align="center">
  <img src="https://img.shields.io/github/languages/count/kadirarici/PacketSentry?style=flat-square&color=blueviolet" alt="Language Count">
  <img src="https://img.shields.io/badge/Language-Python-1e90ff?style=flat-square" alt="Top Language">
  <img src="https://img.shields.io/github/last-commit/kadirarici/PacketSentry?date-today&style=flat-square&color=ff69b4" alt="Last Commit">
  <img src="https://img.shields.io/badge/License-MIT-yellow?style=flat-square" alt="License">
  <img src="https://img.shields.io/badge/Status-Active-green?style=flat-square" alt="Status">
  <img src="https://img.shields.io/badge/Contributions-Welcome-brightgreen?style=flat-square" alt="Contributions">
  <img src="https://img.shields.io/badge/Version-1.0-blueviolet?style=flat-square" alt="Version">
</div>

# PacketSentry
*PacketSentry: Gelişmiş Ağ Tespit ve Önleme Sistemi*

A state-of-the-art, real-time intrusion detection and prevention system (IDS/IPS) designed to safeguard networks with precision and efficiency.  
*Gerçek zamanlı ağ tehditlerini hassasiyet ve verimlilikle koruyan, son teknoloji bir saldırı tespit ve önleme sistemi (IDS/IPS).*

---

## Features / *Özellikler*

- **Real-Time Threat Detection**  
  Instantly identifies and mitigates threats like SQL Injection, XSS, and Brute Force attacks using state-of-the-art algorithms for robust security.  
  *Gerçek Zamanlı Tehdit Tespiti: SQL Injection, XSS ve Brute Force gibi tehditleri son teknoloji algoritmalarla anında tespit eder ve önler.*

- **Cross-Platform Compatibility**  
  Seamlessly operates on Linux, macOS, and Windows, ensuring smooth integration and optimal performance across diverse environments.  
  *Çapraz Platform Uyumluluğu: Linux, macOS ve Windows ortamlarında sorunsuz entegrasyon ve optimize performans sunar.*

- **Performance Monitoring**  
  Monitors key metrics like packets per second (PPS), CPU, and memory usage, enabling fine-tuned performance optimization.  
  *Performans İzleme: Saniyede işlenen paket (PPS), CPU ve bellek kullanımını izleyerek performansı en üst düzeye çıkarır.*

- **Enhanced Logging System**  
  Provides timestamped, color-coded logs for comprehensive threat analysis and streamlined monitoring.  
  *Gelişmiş Loglama Sistemi: Zaman damgalı ve renk kodlu loglarla kapsamlı tehdit analizi ve kolay izleme sağlar.*

- **Scalable & Modular Design**  
  Adapts effortlessly to expanding network demands with a flexible, modular architecture for future-proof scalability.  
  *Ölçeklenebilir ve Modüler Tasarım: Esnek ve modüler yapısıyla büyüyen ağ ihtiyaçlarına kolayca uyum sağlar.*

- **Advanced Threat Coverage**  
  Detects a wide range of threats, including Command Injection, Directory Traversal, and more, for comprehensive protection.  
  *Gelişmiş Tehdit Kapsamı: Command Injection, Directory Traversal ve daha birçok tehdidi tespit ederek tam koruma sağlar.*

- **Future-Ready**  
  Continuously evolving with new features and enhancements to stay ahead of emerging threats.  
  *Geleceğe Hazır: Yeni özellikler ve geliştirmelerle sürekli evrilerek yeni tehditlere karşı hazır olur.*

---

## Team / *Ekip*

- **Kadir Arıcı** (*2420*********5*)  
  *Lead Developer & Security Architect*  
  Leads the project with a strong focus on building innovative software and advanced security solutions.  
  *Baş Geliştirici ve Güvenlik Mimarı*  
  Yenilikçi yazılım ve gelişmiş güvenlik çözümleri geliştirme odaklı olarak projeye liderlik eder.

---

## Roadmap / *Yol Haritası*

See our detailed plans in [ROADMAP.md](ROADMAP.md).  
*Detaylı planları görmek için [ROADMAP.md](ROADMAP.md) dosyasına göz atın.*

---

## Research / *Araştırmalar*

| Topic / *Başlık*        | Link                                    | Description / *Açıklama*                        |
|-------------------------|-----------------------------------------|------------------------------------------------|
| Network Traffic Analysis | [researchs/traffic_analysis.md](ids-ips-project/docs/Network Traffic Analysis.md) | In-depth study of packet analysis techniques and tools. / *Paket analiz tekniklerinin ve araçlarının derinlemesine incelenmesi.* |
| Threat Detection Methods | [researchs/threat_detection.md](ids-ips-project/docs/Threat Detection Methods.md) | Comprehensive analysis of modern IDS/IPS strategies. / *Modern IDS/IPS stratejilerinin kapsamlı analizi.* |
| Security Optimization    | [researchs/optimization.md](ids-ips-project/docs/Security Optimization.md) | Techniques to minimize false positives in intrusion detection. / *Saldırı tespitinde yanlış pozitifleri azaltma teknikleri.* |
| Emerging Threats         | [researchs/emerging_threats.md](ids-ips-project/docs/Emerging Threats.md) | Exploration of new vulnerabilities like Zero-day exploits. / *Zero-day gibi yeni tehditlerin incelenmesi.* |

---

## Installation / *Kurulum*

1. **Clone the Repository / *Depoyu Klonlayın***:  
   ```bash
   git clone https://github.com/kadirarici/PacketSentry.git
   cd PacketSentry
   ```

2. **Set Up Virtual Environment / *Sanal Ortam Kurulumu*** (Recommended):  
   ```bash
   python -m venv venv
   source venv/bin/activate  # On Windows: venv\Scripts\activate
   ```

3. **Install Dependencies / *Bağımlılıkları Yükleyin***:  
   ```bash
   pip install -r requirements.txt
   ```

---


## Usage / Kullanım

### 1. Traffic Analysis / Trafik Analizi
To analyze network traffic / Ağ trafiğini analiz etmek için:
```bash
sudo python3 src/analyze_traffic.py
```

### 2. Attack Detection / Saldırı Tespiti
To detect potential attacks / Potansiyel saldırıları tespit etmek için:
```bash
sudo python3 src/detect_attacks.py
```

### 3. Attack Detection and Blocking / Saldırı Tespiti ve Engelleme
To detect and automatically block attacks / Saldırıları tespit edip otomatik engellemek için:
```bash
sudo python3 src/detect_and_block.py
```

### 4. Easy Network Monitoring / Kolay Ağ İzleme
For simplified network monitoring / Basitleştirilmiş ağ izleme için:
```bash
sudo python3 src/easy_network_monitoring.py
```

### 5. Performance Testing / Performans Testi
To test system performance / Sistem performansını test etmek için:
```bash
sudo python3 tests/performance_test.py
```

## Important Notes / Önemli Notlar

- All commands require `sudo` privileges as root access is needed to capture network packets  
  *Tüm komutlar `sudo` yetkisi gerektirir çünkü ağ paketlerini yakalamak için root erişimi gereklidir*

- Run commands from the project root directory (`PacketSentry/ids-ips-project/`)  
  *Komutları projenin ana dizininden (`PacketSentry/ids-ips-project/`) çalıştırın*

- Make sure required Python packages are installed before first run  
  *İlk çalıştırmadan önce gerekli Python paketlerinin yüklendiğinden emin olun*

## Requirements / Gereksinimler

- Python 3.x
- Root/Administrator privileges / Root/Administrator yetkileri
- Required Python libraries (specified in requirements.txt) / Gerekli Python kütüphaneleri (requirements.txt dosyasında belirtilmiştir)

## Security Warning / Güvenlik Uyarısı

This tool is developed for network security purposes. Use only on your own network or authorized systems.  
*Bu araç ağ güvenliği amacıyla geliştirilmiştir. Yalnızca kendi ağınızda veya izinli sistemlerde kullanın.*

<!---

## Contributing / *Katkıda Bulunma*

We welcome contributions! To help:  
1. Fork the repository.  
2. Clone your fork (`git clone git@github.com:YOUR_USERNAME/PacketSentry.git`).  
3. Create a branch (`git checkout -b feature/your-feature`).  
4. Commit changes with clear, descriptive messages.  
5. Push to your fork (`git push origin feature/your-feature`).  
6. Open a Pull Request.  

Follow our coding standards (see [CONTRIBUTING.md](CONTRIBUTING.md)).  
*Topluluk katkilerini memnuniyetle karşılıyoruz! Katkıda bulunmak için yukarıdaki adımları izleyin ve kodlama standartlarımıza uyun.*
-->
---

## License / *Lisans*

Licensed under the [MIT License](LICENSE).  
*MIT Lisansı altında lisanslanmıştır.*

---

<!--## Acknowledgements / *Teşekkürler* (Optional)

Thanks to:  
- 
-  

*Teşekkürler: İstinye Üniversitesi’ne yenilikçi akademik ortamı için, Scapy ve Psutil kütüphanelerine güçlü ve güvenilir destekleri için, açık kaynak topluluğuna ilham ve iş birliği için.*

---

## Contact / *İletişim* (Optional)

Project Maintainer: Kadir Arıcı - [kadir.arici@istinye.edu.tr](mailto:kadir.arici@istinye.edu.tr)  
Found a bug? Open an issue.  

*Proje Sorumlusu: Kadir Arıcı - [kadir.arici@istinye.edu.tr](mailto:kadir.arici@istinye.edu.tr). Hata bulursanız bir sorun bildirin.*
### -->
