# Ağ Trafik Analizi: Paket İncelemesi ve Araçları

## 2. Ağ Trafik Analizi: Teknikler, Araçlar ve Prensipler

### 2.1. Paket Analizi ve Ağ Adli Bilişimin Temelleri

Ağ Trafik Analizi (NTA), ağ sorunlarını gidermek, güvenlik tehditlerini tespit etmek ve performansı optimize etmek için hayati öneme sahiptir.[4, 5] Ağ adli bilişimi, izinsiz girişleri izlemek, güvenlik açıklarını belirlemek ve gelecekteki olayları önlemek için ihlalleri analiz etmek amacıyla paket verilerini ve trafik akışlarını incelemeyi içerir.[6] NTA, ağ etkinliğinin gerçek zamanlı ve geçmiş kaydını sağlayarak görünürlüğü artırır ve kör noktaları ortadan kaldırır.[5]

#### Akış Verileri vs Paket Verileri

Akış verileri ve paket verileri arasındaki ayrım, ağ görünürlüğünde kritik bir dengeyi ortaya koymaktadır:

- **Akış Verileri**: Trafik hacimleri ve paketlerin ağdaki yolculuğunu haritalama konusunda geniş bilgiler sunar
- **Paket Verileri**: Özellikle Derin Paket İncelemesi (DPI) aracılığıyla derin siber güvenlik soruşturmaları ve adli analiz için gerekli olan ayrıntılı bilgiyi sağlar

Akış verileri, siber güvenlik sorunlarını derinlemesine incelemek için zengin ayrıntı ve bağlamdan yoksun kalabilirken, paket verileri %100 görünürlük sunar. Bu durum, kapsamlı bir NTA stratejisinin, bütünsel görünürlük ve eyleme geçirilebilir istihbarat için her ikisini de entegre etmesi gerektiğini göstermektedir.

**Siber güvenlik amaçları için önemli nokta**: Özellikle tehdit tespiti ve adli bilişimde, paket düzeyinde analiz, sağladığı ayrıntı düzeyi nedeniyle üstündür. Bu, yalnızca akış verilerine güvenmenin yetersiz olduğu anlamına gelir; sağlam bir NTA programının, daha yüksek maliyet ve karmaşıklığına rağmen tam paket verilerini yakalama ve analiz etme yeteneğini gerektirdiği sonucuna varır.

### 2.2. Temel Paket Analizi Teknikleri ve Metodolojileri

Paket analizi teknikleri şunları içerir:

- Protokollerin nasıl çalıştığını anlamak
- "Normal" trafik modellerini belirleme
- İhlal göstergelerini arama
- Saldırganların faaliyetlerini nasıl gizlediğini tespit etme

#### Temel Teknikler

- **Derin Paket İncelemesi (DPI)**: Ağ paketlerindeki en küçük ayrıntıları incelemek için temel bir tekniktir
- **Filtreleme**: Hedeflenen analiz için belirli veri akışlarını izole etmek için esastır
- **Oturum Yeniden Yapılandırma**: Ağ oturumlarını (örneğin, TCP akışları) yeniden yapılandırmak, uygulama katmanı veri alışverişlerini analiz etmek için hayati öneme sahiptir

### 2.3. Temel Ağ Trafik Analiz Araçları: Derinlemesine Bir Bakış

#### Wireshark
Paket analizi için "altın standart" olarak kabul edilen güçlü, açık kaynaklı bir paket analizcisidir.

**Özellikler:**
- Gerçek zamanlı trafik yakalama ve inceleme
- Yüzlerce ağ protokolü için derinlemesine paket incelemesi
- Protokol analizi ve detaylı paket denetimi
- Belirli veri akışlarını izole etmek için filtreleme seçenekleri
- Birden fazla işletim sistemiyle uyumluluk
- Görselleştirme ve kapsamlı raporlama için dışa aktarma seçenekleri

**En İyi Kullanım Alanları:** Derinlemesine paket analizi, protokol sorun giderme ve ağ adli bilişimi

#### Tcpdump
Basitliği ve ağ adli bilişimindeki etkinliği ile bilinen bir komut satırı paket analiz aracıdır.

**Özellikler:**
- Ağ trafiğini gerçek zamanlı olarak yakalama
- Şüpheli etkinliği belirlemek için belirli paketleri inceleme
- Filtreleme özelliği
- Verimli ve esnek yapı

**En İyi Kullanım Alanları:** Linux ve Unix tabanlı sistemlerde hızlı, gerçek zamanlı trafik analizi ve hata ayıklama

#### Tshark
Wireshark'ın komut satırı arayüzü (CLI) versiyonudur. Metin tabanlı bir ortamda benzer paket yakalama ve analiz özellikleri sunar.

**En İyi Kullanım Alanları:** Otomasyon, betikleme ve uzaktan ağ izleme

#### Tcpick
TCP akışı takibinde uzmanlaşmış bir paket koklayıcıdır. Ağ oturumlarını yeniden yapılandırır.

**En İyi Kullanım Alanları:** HTTP veya FTP trafiği gibi uygulama katmanı veri alışverişlerini analiz etmek

#### NGrep (Network Grep)
Unix grep komutu gibi çalışır, ancak ağ paketleri için tasarlanmıştır.

**En İyi Kullanım Alanları:** HTTP isteklerindeki anahtar kelimeler veya oturum açma girişimleri gibi ağ trafiğindeki belirli kalıpları aramak

#### Elastic Packetbeat
Elastic Stack'in bir bileşenidir ve gerçek zamanlı bir ağ trafik göndericisi olarak işlev görür.

**Özellikler:**
- Ağ verilerini Elasticsearch'e yakalama ve gönderme
- Kibana'da gelişmiş görselleştirme ve analiz

**En İyi Kullanım Alanları:** Uygulama katmanı izleme, güvenlik analizi ve SIEM entegrasyonu

#### Network Taps (Donanım)
Ağ trafiğini izleme amacıyla yansıtan donanım cihazlarıdır.

**Avantajlar:**
- SPAN portlarının aksine, ağ performansını etkilemeden %100 paket görünürlüğü
- Yüksek güvenilirlik

**En İyi Kullanım Alanları:** Pasif trafik izleme, güvenlik adli bilişimi ve uyumluluk denetimi

#### SPAN Portları (Yazılım)
Port yansıtma olarak da bilinen bir anahtar özelliğidir.

**Avantajlar:**
- Uygun maliyetli
- Kolay kurulum

**En İyi Kullanım Alanları:** Genel ağ izleme ve sorun giderme

#### SANS Adli Bilişim Araç Kiti (SIFT)
Dijital adli soruşturmalar için tasarlanmış kapsamlı bir açık kaynak araç paketidir.

**Özellikler:**
- Ubuntu üzerine inşa edilmiş
- Dosya sistemi analizinden ağ adli bilişimine kadar geniş uygulama yelpazesi
- Wireshark ve Network Miner gibi araçlarla entegrasyon

## Araç Karşılaştırma Tablosu

| Araç Adı | Tür | Temel Özellikler | En İyi Kullanım Alanları | Avantajlar | Dezavantajlar |
|----------|-----|------------------|-------------------------|------------|---------------|
| **Wireshark** | Paket Analizci | Derin paket incelemesi, yüzlerce protokol analizi, filtreleme, görselleştirme, OS uyumluluğu | Derinlemesine paket analizi, protokol sorun giderme, ağ adli bilişimi | Kapsamlı, açık kaynak, yaygın kullanım | Öğrenme eğrisi, yoğun trafik için kaynak tüketimi |
| **Tcpdump** | Komut Satırı (CLI) | Gerçek zamanlı yakalama ve filtreleme, düşük kaynak kullanımı, çoklu arayüz desteği | Hızlı, gerçek zamanlı trafik analizi, sorun giderme, Linux/Unix hata ayıklama | Hafif, hızlı, betiklenebilir | GUI yok, ham veri çıktısı |
| **Tshark** | Komut Satırı (CLI) | Wireshark'ın CLI versiyonu, paket yakalama ve analiz | Otomasyon, betikleme, uzaktan ağ izleme | Otomasyon için ideal, esnek | GUI yok, Wireshark'a kıyasla daha az görselleştirme |
| **Tcpick** | Paket Koklayıcı | TCP akış takibi, ağ oturumlarını yeniden yapılandırma | TCP bağlantılarını izleme, veri akışlarını yeniden yapılandırma (HTTP/FTP) | Uygulama katmanı analizi için özel | Sadece TCP odaklı |
| **NGrep** | Ağ Grep | Ağ trafiğinde belirli kalıpları arama (düzenli ifadelerle) | Ağ trafiğini düzenli ifadelerle filtreleme, anahtar kelime arama | Hızlı kalıp eşleştirme | Yalnızca metin tabanlı, derin protokol analizi yok |
| **Elastic Packetbeat** | Gerçek Zamanlı İzleme | Gerçek zamanlı ağ verisi gönderimi, Elasticsearch/Kibana entegrasyonu | Uygulama katmanı izleme, güvenlik analizi, SIEM entegrasyonu | Ölçeklenebilir görselleştirme, SIEM ile entegre | Elastic Stack bağımlılığı |
| **Network Taps** | Donanım | %100 paket görünürlüğü, ağ performansını etkilemez | Pasif trafik izleme, güvenlik adli bilişimi, uyumluluk denetimi | Yüksek doğruluk, tam görünürlük | Donanım maliyeti, fiziksel kurulum gereksinimi |
| **SPAN Portları** | Yazılım Tabanlı | Port yansıtma, anahtar üzerinden trafik kopyalama | Genel ağ izleme, sorun giderme | Uygun maliyetli, kolay kurulum | Güvenilirlik TAPs'tan düşük, anahtar performansı etkilenebilir |
| **SIFT** | Adli Bilişim Paketi | Merkezi platform, dosya sistemi/bellek/ağ analizi, Wireshark entegrasyonu | Kapsamlı dijital adli soruşturmalar | Geniş araç yelpazesi, açık kaynak | Ubuntu tabanlı, kurulum ve yapılandırma gerektirir |

### 2.4. Modern Siber Güvenlikte NTA'nın Prensipleri ve Stratejik Uygulamaları

#### Temel Uygulamalar

NTA aşağıdaki kritik alanlarda kullanılır:

- **Kötü Amaçlı Yazılım Tespiti**: TCP port 445'i tarayan WannaCry gibi fidye yazılımları
- **Güvenlik Açıkları**: Savunmasız protokolleri/şifreleri belirlemek
- **Ağ Sorun Giderme**: Performans ve bağlantı sorunlarını çözmek
- **Cihaz Görünürlüğü**: IoT cihazları da dahil olmak üzere ağa bağlanan tüm cihazlar
- **Uyumluluk**: Düzenleyici gereksinimlerin karşılanması

#### Kritik Güvenlik Konuları

**Çevre İzleme**: NTA, ağ çevresini ve güvenlik duvarlarının dahili arayüzlerini izlemek için kritik öneme sahiptir, çünkü kullanıcılar tünelleme veya VPN'ler aracılığıyla kuralları atlayabilir.

**Şifrelenmemiş Protokol Tespiti**: Şifrelenmemiş yönetim protokolleriyle (Telnet, HTTP, SNMP, Cisco Smart Install) ilişkili şüpheli etkinliğin tespiti önemli bir uygulamadır.

**Güvenilir Adli Bilgi**: NTA, bir saldırı sırasında tehlikeye girebilecek güvenlik duvarı günlüklerinden daha güvenilir adli bilgi sunar.

#### Stratejik Önemi

Şifrelenmemiş protokollerin izlenmesine ve saldırılar sırasında güvenlik duvarı günlüklerinin güvenilmezliğine yapılan vurgu, saldırganların görünürlük ve yapılandırma zayıflıklarını kullandığı temel bir prensibi işaret etmektedir. NTA, ağ etkinliği hakkında bağımsız, daha derin ve daha esnek bir doğru kaynak sağlayarak bu boşlukları doldurur.

Bu yaklaşım:
- Geleneksel çevre savunmalarının kaçırabileceği yanal hareketleri belirleme
- İhlal sonrası faaliyetleri tespit etme
- Birincil günlükler tehlikeye girdiğinde diğer güvenlik kontrollerini doğrulama
- Adli soruşturmalar için hayati veri sağlama

konularında kritik öneme sahiptir.

---

## Sonuç

Temel araçlar olan Wireshark ve Tcpdump'ın, Packetbeat ve Network Taps gibi gelişmiş çözümlerle birlikte devam eden önemi, etkili NTA'nın katmanlı bir araç setine dayandığını göstermektedir. Temel, ayrıntılı paket analizi, derinlemesine incelemeler ve adli bilişim için vazgeçilmezliğini korurken, daha üst düzey, entegre araçlar operasyonel verimlilik için gerçek zamanlı izleme ve daha geniş görünürlük sağlamaktadır.

Bu durum, tek bir aracın her derde deva olmadığını; sağlam bir NTA yeteneğinin, farklı amaçlar için özel araçların birleşimini gerektirdiğini göstermektedir.
