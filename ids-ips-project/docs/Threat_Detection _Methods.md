# Tehdit Tespit Yöntemleri: IDS/IPS Stratejileri ve Ötesi

## 3. Modern Tehdit Tespit Yöntemleri: IDS/IPS ve Ötesi

### 3.1. Saldırı Tespit ve Önleme Sistemlerinin (IDS/IPS) Evrimi ve Önemi

Hem Saldırı Tespit Sistemleri (IDS) hem de Saldırı Önleme Sistemleri (IPS), bir kuruluşa yönelik tehditlere karşı koruma sağlamak üzere tasarlanmıştır, ancak operasyonel modelleri farklılık gösterir.[8]

#### IDS (Intrusion Detection System)
- **Pasif İzleme**: Siber güvenlik tehditlerini tespit etmek için pasif bir izleme çözümüdür
- **Uyarı Sistemi**: Potansiyel bir izinsiz giriş tespit edildiğinde, güvenlik personeline olayı araştırmaları ve düzeltici önlem almaları için bir uyarı oluşturur
- **Reaktif Yaklaşım**: Saldırı gerçekleştikten sonra tespit eder

#### IPS (Intrusion Prevention System)
- **Aktif Koruma**: Aktif bir koruma sistemidir
- **Tespit ve Önleme**: IDS gibi potansiyel tehditleri belirlemeye çalışır, ancak belirlenen bir tehdidi engellemek veya düzeltmek için de harekete geçer
- **Proaktif Yaklaşım**: İzinsiz girişin gerçekleşmesini önlemeye yardımcı olur

#### Seçim Kriterleri
IDS ve IPS arasındaki seçim, dağıtım senaryosuna ve sistem kullanılabilirliği ile koruma ihtiyacı arasındaki dengeye bağlıdır.

### 3.2. IDS/IPS Sınıflandırması: İmza Tabanlı, Anomali Tabanlı ve Hibrit Yaklaşımlar

IDS/IPS sistemleri, tehditleri nasıl algıladıklarına göre temel olarak üç ana kategoriye ayrılır:

#### İmza Tabanlı IDS
Kötü amaçlı etkinlikle bağlantılı benzersiz kalıplar olan önceden tanımlanmış saldırı imzaları veritabanına dayanır.

**Çalışma Prensibi:**
- Ağ trafiğini sürekli olarak izler
- Bilinen imzalarla eşleştirir
- Eşleşme durumunda uyarılar tetikler

**Avantajları:**
- Bilinen tehditlerin hızlı tespiti
- Bilinen kalıplar için genellikle daha düşük yanlış pozitifler

**Sınırlamaları:**
- Yeni veya değiştirilmiş saldırı yöntemlerine karşı etkisizdir
- Zero-day saldırılarına karşı savunmasızdır

#### Anomali Tabanlı IDS
Geçmiş verileri ve makine öğrenimi modellerini kullanarak "normal" davranışın bir temelini oluşturur.

**Çalışma Prensibi:**
- Normal davranış temelini oluşturur
- Bu temelden sapmaları tespit eder
- Önemli anomalileri potansiyel izinsiz giriş olarak işaretler

**Avantajları:**
- Yeni, bilinmeyen veya zero-day saldırılarını tanımlayabilir
- Gelişen tehditlere uyum sağlayabilir

**Sınırlamaları:**
- Meşru etkinliği şüpheli olarak yanlış tanıması nedeniyle daha yüksek yanlış pozitif oranları
- Kaynak yoğundur
- Etkinliği doğru şekilde oluşturulmuş temellere bağlıdır

#### Hibrit IDS
Her bir yaklaşımın sınırlamalarını gidermek için hem imza tabanlı hem de anomali tabanlı tespit yöntemlerini birleştirir.

**Özellikler:**
- Bilinen tehditler için imza tabanlı tespit
- Yeni saldırılar için anomali tabanlı tespit
- Saldırı tespitinin genel etkinliğini artırır

## Tespit Metodolojileri Karşılaştırma Tablosu

| Tespit Metodu | Kullanılan Teknoloji | Güçlü Yönler | Sınırlamalar | En İyi Senaryolar |
|---------------|---------------------|---------------|--------------|-------------------|
| **İmza Tabanlı** | Saldırı imzaları veritabanı | Bilinen tehditlerin hızlı tespiti, düşük yanlış pozitifler | Zero-day saldırılarına karşı etkisiz, yeni tehditleri kaçırır | Bilinen kötü amaçlı yazılımlara ve saldırılara karşı koruma |
| **Anomali Tabanlı** | Sezgisel yöntemler, YZ, veri madenciliği | Yeni ve bilinmeyen tehditleri tespit eder, gelişen tehditlere uyum sağlar | Yüksek yanlış pozitif oranları, kaynak yoğun, temel doğruluğuna bağımlı | Zero-day saldırılarının tespiti, ağdaki normal dışı davranışların belirlenmesi |
| **Hibrit** | İmza tabanlı ve Anomali tabanlı kombinasyonu | Hem bilinen hem de yeni tehditleri tespit eder, kapsamlı güvenlik | Her iki yöntemin de bazı sınırlamalarını miras alabilir | Dinamik ve karmaşık tehdit ortamlarında en iyi genel koruma |

### Hibrit Yaklaşımın Gerekliliği

İmza tabanlı sistemlerin doğal sınırlamaları (zero-day saldırılarını kaçırma) ve anomali tabanlı sistemlerin zorlukları (daha yüksek yanlış pozitifler, kaynak yoğunluğu), hibrit bir yaklaşımın gerekliliğini vurgulamaktadır. Bu evrim, hem bilinen hem de bilinmeyen tehditlerin bir arada bulunduğu dinamik bir tehdit ortamıyla mücadele etmek için gereken adaptif doğayı yansıtmaktadır.

### 3.3. IDS/IPS'nin Operasyonel Modelleri (NIDS, HIDS) ve Dağıtım Hususları

IDS/IPS sistemleri, dağıtım konumlarına ve veri kaynaklarına göre de sınıflandırılır:

#### Ağ Tabanlı Saldırı Tespit Sistemi (NIDS)
**Özellikler:**
- Ağ içinde stratejik noktalara dağıtılır
- Belirli bir ağ segmenti üzerindeki tüm ağ trafiği verilerini (promiscuous modda) sürekli olarak yakalar ve analiz eder
- Hem imza tabanlı hem de anomali tabanlı tespiti kullanır

**Avantajlar:**
- Geniş ağ görünürlüğü
- Merkezi izleme
- Ağ genelindeki saldırıları tespit etme

#### Ana Bilgisayar Tabanlı Saldırı Tespit Sistemi (HIDS)
**Özellikler:**
- Sunucular veya iş istasyonları gibi bireysel ana bilgisayarlardaki etkinlikleri izler
- Günlükler, dosya erişim girişimleri ve çalışan süreçleri kapsar
- Öncelikle anomali tabanlı tespiti kullanır

**Avantajlar:**
- Belirli ana bilgisayar etkinliklerine ilişkin daha derin bilgiler
- Sistem düzeyinde detaylı analiz
- Yerel saldırıları tespit etme

#### Dağıtım Takasları
Seçim, görünürlük derinliği ile sistemin aldığı kapsam ve bağlam arasında bir denge kurmayı içerir:
- **NIDS**: Geniş ağ görünürlüğü sunar
- **HIDS**: Belirli ana bilgisayar etkinliklerine ilişkin daha derin bilgiler sağlar

### 3.4. Tehdit Tespitindeki Gelişmeler: NDR ve YZ/ML Entegrasyonunun Yükselişi

Tehdit tespit teknolojileri, hızla gelişen siber tehdit ortamına ayak uydurmak için önemli ilerlemeler kaydetmektedir.

#### Ağ Tespit ve Yanıt (NDR)

Modern Güvenlik Operasyon Merkezleri (SOC'ler) için vazgeçilmez bir altyapı olarak ortaya çıkmaktadır.

**Temel Özellikler:**
- **Sürekli İzleme**: Doğu-batı (yanal) ve kuzey-güney trafiğini sürekli olarak izler
- **Gelişmiş Tespit**: Geleneksel güvenlik cihazlarının (IDS/IPS dahil) kaçırabileceği tehditleri etkili bir şekilde tespit eder
- **Saldırgan Merkezli Yetenekler**: Doğru tespit, otomatik yanıt ve bulut avantajları sunar

**Otomatik Yanıt Özellikleri:**
- Trafik engelleme
- Ana bilgisayar izolasyonu
- SOAR/SIEM ile bağlantı kurarak kapalı döngü bertarafı
- Yanıt sürelerini önemli ölçüde kısaltma

**Modern Adaptasyonlar:**
- Bulut yerel adaptasyon (IaaS/SaaS dağıtımı, çoklu bulut hibrit ortamları)
- Hassas kimlik bilgisi sızıntısını yakalama
- Gartner'ın Magic Quadrant raporunda olgunluğa ulaşmış teknoloji olarak tanınma

#### YZ ve Makine Öğrenimi Entegrasyonu

**Temel Roller:**
- Kalıpları belirleme
- Anomalileri tanıma
- Yeni tehditlere uyum sağlama
- Modelleri gelişen davranışlara göre sürekli iyileştirme
- Yanlış pozitifleri azaltma ve hassasiyeti artırma

**Pratik Uygulamalar:**

**Büyük Dil Modelleri (LLM'ler):**
- Güvenlik analizinde yanlış pozitif tespitini önemli ölçüde iyileştirebilir
- Geleneksel SAST araçlarını tamamlayabilir
- Yanlış pozitifleri azaltma prensibi, daha geniş güvenlik analizine uygulanabilir

**Gelişmiş IPS Çözümleri:**
- Davranışsal analiz yoluyla zero-day tehditlerini önlemek için YZ/ML'den yararlanır

**Modern IDS Çözümleri:**
- Normal etkinlik ile potansiyel tehditler arasındaki farkı ayırt etmek için makine öğrenimi ve kalıp tanımaya giderek daha fazla güvenir

### 3.5. Paradigma Değişimi: Reaktif'ten Proaktif Savunmaya

#### Teknolojik Evrim
NDR'nin yükselişi ve YZ/ML'nin tehdit tespitine yaygın entegrasyonu, imza odaklı, reaktif güvenlikten daha proaktif, davranışsal ve otomatik bir savunma duruşuna temel bir geçişi işaret etmektedir.

#### Değişimi Yönlendiren Faktörler
- **Artan Tehdit Hacmi ve Karmaşıklığı**: İnsan analistler tek başına uyarı hacimlerine ve yeni saldırı tekniklerine ayak uyduramamaktadır
- **Ölçeklenebilirlik İhtiyacı**: YZ/ML ve NDR, ölçeklenebilirlik sağlamak için kritik öneme sahiptir
- **Alarm Yorgunluğu**: Yanlış pozitifleri azaltmak için otomatik sistemler gereklidir
- **Gerçek Zamanlı Yanıt**: Bağlama duyarlı, anında yanıtlar gereklidir

#### Modern Savunmanın Anahtarları
**NDR'nin Kapsamlı Trafik İzlemesi + YZ/ML'nin Analitik Gücü = Paradigma Değişiminin Anahtarı**

Bu sinerji şunları sağlar:
- Statik, imza tabanlı tespitten dinamik, davranışsal analize geçiş
- Pasif savunmadan aktif operasyona dönüşüm
- Otomatik, akıllı sistemler ile etkili savunmanın sürdürül
