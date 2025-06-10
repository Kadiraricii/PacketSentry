<div align="center">
  <img src="https://img.shields.io/badge/Roadmap-2025-blueviolet?style=flat-square" alt="Roadmap 2025">
  <img src="https://img.shields.io/badge/Status-In%20Progress-1e90ff?style=flat-square" alt="Status">
  <img src="https://img.shields.io/badge/Version-1.0-ff69b4?style=flat-square" alt="Version">
</div>

# PacketSentry Roadmap
*PacketSentry Yol Haritası*

This roadmap outlines the planned development phases and milestones for PacketSentry, an advanced network intrusion detection and prevention system (IDS/IPS). It includes detailed tasks, progress updates, risks, and community contribution opportunities.  
*Bu yol haritası, gelişmiş bir ağ saldırı tespit ve önleme sistemi (IDS/IPS) olan PacketSentry’nin planlanan geliştirme aşamalarını ve kilometre taşlarını özetler. Detaylı görevler, ilerleme güncellemeleri, riskler ve topluluk katkı fırsatlarını içerir.*

---

## Development Phases / *Geliştirme Aşamaları*

### Phase 1: Foundation (Completed - Q1 2025)
*1. Aşama: Temel Yapı (Tamamlandı - 2025 1. Çeyrek)*
- **Objective:** Establish core detection algorithms and cross-platform compatibility.  
  *Amaç: Temel tespit algoritmalarını oluşturmak ve çapraz platform uyumluluğunu sağlamak.*
- **Milestones:**  
  - Implemented rule-based detection for SQL Injection and XSS using predefined patterns.  
    *SQL Injection ve XSS için kural tabanlı tespit, önceden tanımlı desenlerle uygulandı.*
  - Set up basic logging system with timestamped entries in `data/ids.log`.  
    *Zaman damgalı girişlerle temel loglama sistemi `data/ids.log`’da kuruldu.*
  - Added support for Linux environment (tested on Ubuntu 20.04).  
    *Linux ortamı desteği eklendi (Ubuntu 20.04 üzerinde test edildi).*
- **Risks Encountered:** Limited rule coverage led to some false negatives; addressed by expanding rule sets.  
  *Karşılaşılan Riskler: Sınırlı kural kapsamı bazı yanlış negatiflere yol açtı; kural setleri genişletilerek çözüldü.*

### Phase 2: Expansion (In Progress - Q2 2025)
*2. Aşama: Genişletme (Devam Ediyor - 2025 2. Çeyrek)*
- **Objective:** Enhance threat detection and add performance monitoring features.  
  *Amaç: Tehdit tespitini geliştirmek ve performans izleme özelliklerini eklemek.*
- **Milestones:**  
  - Add Brute Force detection using rate-limiting analysis (completed).  
    *Hız sınırlama analizi ile Brute Force tespiti eklendi (tamamlandı).*
  - Implement Command Injection detection using pattern matching (in progress, 70% complete).  
    *Desen eşleştirme ile Command Injection tespiti uygulanıyor (devam ediyor, %70 tamamlandı).*
  - Integrate PPS, CPU, and memory usage tracking with Psutil library (completed).  
    *Psutil kütüphanesi ile PPS, CPU ve bellek kullanım izleme entegre edildi (tamamlandı).*
  - Extend support to macOS (completed) and Windows (in progress, testing phase).  
    *macOS desteği eklendi (tamamlandı), Windows desteği devam ediyor (test aşamasında).*
- **Risks & Challenges:** Windows compatibility issues due to varying network stack behaviors; requires additional testing on Windows 10/11.  
  *Riskler ve Zorluklar: Windows ağ yığını davranış farklılıkları nedeniyle uyumluluk sorunları; Windows 10/11 üzerinde ek test gerekiyor.*
- **Priorities:** Completing Command Injection detection and ensuring Windows support are critical for this phase.  
  *Öncelikler: Command Injection tespiti tamamlanması ve Windows desteği sağlanması bu aşama için kritik.*

### Phase 3: Optimization (Planned - Q3 2025)
*3. Aşama: Optimizasyon (Planlanmış - 2025 3. Çeyrek)*
- **Objective:** Optimize performance and reduce false positives for a more reliable system.  
  *Amaç: Performansı optimize etmek ve daha güvenilir bir sistem için yanlış pozitifleri azaltmak.*
- **Milestones:**  
  - Refine detection algorithms by integrating machine learning models (e.g., anomaly detection).  
    *Makine öğrenimi modelleri (örneğin, anomali tespiti) entegre edilerek tespit algoritmaları iyileştirilecek.*
  - Reduce false positives by implementing a scoring system for threat confidence levels.  
    *Tehdit güven seviyeleri için bir puanlama sistemi ile yanlış pozitifler azaltılacak.*
  - Introduce advanced logging with color-coded outputs and filters for severity levels.  
    *Renk kodlu çıktılar ve önem seviyesi filtreleriyle gelişmiş loglama tanıtılacak.*
  - Conduct performance benchmarks to achieve at least 10,000 PPS on mid-tier hardware.  
    *Orta seviye donanımda en az 10.000 PPS elde etmek için performans benchmark’ları yapılacak.*
- **Risks & Challenges:** Machine learning integration may increase resource usage; optimization will be key.  
  *Riskler ve Zorluklar: Makine öğrenimi entegrasyonu kaynak kullanımını artırabilir; optimizasyon kritik olacak.*
- **Priorities:** Reducing false positives and ensuring performance scalability are top priorities.  
  *Öncelikler: Yanlış pozitifleri azaltmak ve performans ölçeklenebilirliği en yüksek öncelikler.*

### Phase 4: Scalability & Future (Planned - Q4 2025)
*4. Aşama: Ölçeklenebilirlik ve Gelecek (Planlanmış - 2025 4. Çeyrek)*
- **Objective:** Scale the system for larger networks and integrate emerging threat detection.  
  *Amaç: Sistemi daha büyük ağlar için ölçeklendirmek ve yeni tehdit tespitini entegre etmek.*
- **Milestones:**  
  - Develop a modular architecture to allow easy addition of new detection modules.  
    *Yeni tespit modüllerinin kolayca eklenmesi için modüler bir mimari geliştirilecek.*
  - Add detection for Directory Traversal using file path analysis and Zero-day exploits via behavior-based detection.  
    *Dosya yolu analizi ile Directory Traversal ve davranış tabanlı tespit ile Zero-day exploit tespiti eklenecek.*
  - Plan for cloud integration with AWS/Google Cloud for distributed network monitoring.  
    *Dağıtılmış ağ izleme için AWS/Google Cloud ile bulut entegrasyonu planlanacak.*
  - Explore API support for third-party integrations (e.g., SIEM systems).  
    *Üçüncü taraf entegrasyonları (örneğin, SIEM sistemleri) için API desteği araştırılacak.*
- **Risks & Challenges:** Cloud integration may introduce latency; careful design of distributed architecture required.  
  *Riskler ve Zorluklar: Bulut entegrasyonu gecikme yaratabilir; dağıtılmış mimari dikkatli tasarlanmalı.*
- **Priorities:** Building a scalable architecture and integrating Zero-day exploit detection are critical.  
  *Öncelikler: Ölçeklenebilir bir mimari oluşturmak ve Zero-day exploit tespiti entegrasyonu kritik.*

---

## Key Milestones / *Ana Kilometre Taşları*
- **Q1 2025:** Core functionality completed with Linux support.  
  *2025 1. Çeyrek: Temel işlevsellik ve Linux desteği tamamlandı.*
- **Q2 2025:** Multi-platform support (Linux, macOS, Windows) and performance tracking implemented.  
  *2025 2. Çeyrek: Çoklu platform desteği (Linux, macOS, Windows) ve performans izleme uygulandı.*
- **Q3 2025:** Optimized system with machine learning detection and advanced logging released.  
  *2025 3. Çeyrek: Makine öğrenimi tespiti ve gelişmiş loglama ile optimize sistem yayınlandı.*
- **Q4 2025:** Scalable solution with cloud integration and Zero-day detection deployed.  
  *2025 4. Çeyrek: Bulut entegrasyonu ve Zero-day tespiti ile ölçeklenebilir çözüm devreye alındı.*

---

## Community Contributions / *Topluluk Katkıları*
We encourage community involvement to accelerate development. Areas where you can help:  
- Suggest new detection rules for emerging threats.  
- Improve logging formats or add visualization tools.  
- Test and provide feedback on Windows/macOS compatibility.  
- Contribute to documentation or translation efforts.  

*Topluluk katılımını teşvik ediyoruz. Yardım edebileceğiniz alanlar:*  
- *Yeni tehditler için tespit kuralları önerin.*  
- *Loglama formatlarını geliştirin veya görselleştirme araçları ekleyin.*  
- *Windows/macOS uyumluluğu için test yapın ve geri bildirim sağlayın.*  
- *Dokümantasyon veya çeviri çalışmalarına katkıda bulunun.*

---

## Notes / *Notlar*
- Timelines are subject to change based on research progress, testing outcomes, and community feedback.  
  *Zaman çizelgeleri, araştırma ilerlemesi, test sonuçları ve topluluk geri bildirimlerine bağlı olarak değişebilir.*
- Regular updates will be provided in this roadmap to reflect progress.  
  *İlerlemeyi yansıtmak için bu yol haritası düzenli olarak güncellenecek.*
- Check [ROADMAP.md](ROADMAP.md) for the latest updates.  
  *En son güncellemeler için [ROADMAP.md](ROADMAP.md)’yi kontrol edin.*

---
