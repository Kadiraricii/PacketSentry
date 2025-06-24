# Gelişen Tehditler: Zero-Day Açıklarının Ortamı ve Yeni Trendler

## 5.1. Zero-Day Güvenlik Açıkları, İstismarları ve Saldırılarını Tanımlama

### Zero-Day
Güvenlik ekiplerinin bir yazılım güvenlik açığından haberdar olmadığı ve bir yama geliştirmek için "0" günleri olduğu durumlarda kullanılan terimdir.

### Zero-Day Güvenlik Açığı
Yazılım, donanım veya bellenimdeki satıcı veya geliştiriciler tarafından bilinmeyen gizli bir zayıflık, kodlama hatası veya tasarım hatasıdır. Bu, "gizli tünel" veya "kilidi açık arka kapı" olarak tanımlanır.

### Zero-Day İstismarı
Bir saldırganın bir zero-day güvenlik açığından yararlanmak için oluşturduğu yöntem veya koddur. Bu, "özel yapım araç" veya özel olarak hazırlanmış "anahtar"dır.

### Zero-Day Saldırısı
Bir saldırganın bir hedef sisteme zarar vermek, veri çalmak veya yetkisiz kontrol elde etmek için bir zero-day istismarını kullandığı gerçek olaydır.

### Zero-Day ve N-Day İstismarı
Bir zero-day, satıcı tarafından bilinmezken istismar edilir; bir N-day güvenlik açığı ise genellikle bir yama mevcutken kamuya açıklanmıştır, ancak mağdur yamayı zamanında uygulamamıştır.

## 5.2. Zero-Day Tehditlerinin Özellikleri ve Gerçek Dünya Örnekleri

### Özellikleri
Bilinmeyen doğaları, özellikle bulut iş yükleri için onları son derece tehlikeli ve tespit etmesi zor hale getirir. Kayıt dışı varlıklar, yanlış yapılandırmalar veya diğer güvenlik sorunları nedeniyle uzun süre "gizli tehditler" veya "kör noktalar" olarak var olabilirler.

### Karmaşıklık Nedenleri

#### Modern Yazılımın Karmaşıklığı
Tescilli kod, açık kaynak kütüphaneler ve üçüncü taraf entegrasyonları içeren katmanlı mimariler, gizli güvenlik açıkları oluşturma olasılığını artırır.

#### Genişleyen Saldırı Yüzeyleri
Bulut öncelikli stratejiler, SaaS araçları, uzaktan altyapı, IoT cihazları ve gölge BT, dijital ayak izlerini katlanarak büyütür ve saldırganlar için daha fazla potansiyel giriş noktası sunar.

#### Becerikli Saldırganlar
Tehdit aktörleri, istismarlar için gelişen bir yeraltı piyasası ile yüksek düzeyde organize ve etkilidir.

Modern yazılımın artan karmaşıklığı ve saldırı yüzeylerinin genişlemesi, zero-day güvenlik açıklarının çoğalmasının ve kalıcılığının doğrudan itici güçleridir. Bu durum, bilinmeyen kusurlar sorununun azalmadığını, aksine çağdaş BT ekosistemlerine yapısal olarak yerleştiğini ve bu nedenle proaktif ve adaptif savunma stratejilerinin (yalnızca reaktif yamalamanın aksine) kesinlikle gerekli olduğunu göstermektedir.

### Gerçek Dünya Örnekleri

#### Stuxnet
İran nükleer santrifüjlerini fiziksel olarak yok etmek için dört ayrı zero-day kullanan dönüm noktası niteliğinde bir solucan örneğidir.

#### Log4Shell
Apache Log4j kütüphanesindeki milyonlarca uygulamayı ve hizmeti küresel olarak etkileyen yaygın bir güvenlik açığıdır.

#### Yakın Tarihli 2025 Örnekleri
- Apple Cihaz Zero-Day Saldırıları (Nisan 2025)
- Microsoft CLFS Zero-day Tehdit Açığı (Nisan 2025)
- Linux Çekirdek Zero-Day İstismarları (Şubat 2025)

#### CVE-2025-0282
Ivanti Connect Secure için CISA Azaltma Talimatları: Tehdit avcılığı, fabrika ayarlarına sıfırlama ve kimlik bilgilerinin iptali dahil olmak üzere acil eylem gerektiren kritik bir güvenlik açığının belirli bir örneğidir.

## 5.3. Mevcut Siber Tehdit Ortamı ve Gelişen Trendler

Siber tehdit ortamı sürekli evrim geçirmekte ve yeni eğilimler ortaya çıkmaktadır:

### Girişimci Saldırganlar
Siber suç, otomasyon, YZ ve gelişmiş sosyal mühendislik kullanarak saldırıları ölçeklendiren son derece verimli bir iş haline gelmektedir. Ortalama e-suç yayılma süresi 48 dakikadır.

### Kötü Amaçlı Yazılım İçermeyen Tespitler
Tespitlerin %79'u kötü amaçlı yazılım içermemektedir, bu da dosyasız saldırılara ve "living-off-the-land" tekniklerine doğru bir kaymayı göstermektedir.

### Saldırgan Operasyonlarında YZ
Üretken YZ, sahte profiller, YZ tarafından oluşturulan e-postalar/web siteleri için saldırganlar (örn. FAMOUS CHOLLIMA) tarafından kullanılmakta, içeriden tehditleri ve sosyal mühendisliği güçlendirmektedir.

### Hedef ve Teknik Çeşitlendirmesi
DDoS saldırıları gelişmekte, çeşitli uygulama katmanı protokollerini (HTTP/2, SIP, DNS, IoT protokolleri) istismar etmektedir.

### En Büyük Tehditler (ENISA)
- Fidye yazılımı (çoklu gasp)
- Kötü amaçlı yazılım
- Sosyal mühendislik (kimlik avı, vishing, smishing)
- Verilere yönelik tehditler (ihlaller/sızıntılar)
- Kullanılabilirliğe yönelik tehditler (DDoS)
- Bilgi manipülasyonu (FIMI)

### Jeopolitik Etki
Çin bağlantılı faaliyetlerde artış (150% artış) gözlemlenmektedir.

"Girişimci saldırganların" "Üretken YZ'den" yararlanması ile "modern yazılımın karmaşıklığı" ve "genişleyen saldırı yüzeylerinin" birleşimi, bileşik bir tehdit oluşturmaktadır. YZ, saldırganların sofistike sosyal mühendislik ve keşif faaliyetlerini ölçeklendirmesine olanak tanıyarak ilk erişim olasılığını artırırken, genişleyen saldırı yüzeyi zero-day'ler için daha fazla giriş noktası sağlamaktadır.

## 5.4. Zero-Day İstismarlarına Karşı Kapsamlı Azaltma ve Savunma Stratejileri

Zero-day istismarlarına karşı korunmak için kapsamlı ve çok katmanlı bir savunma stratejisi benimsemek zorunludur:

### Paradigma Değişimi
Önleme merkezli güvenlikten proaktif esnekliğe geçiş, uzlaşma varsayımı altında faaliyet gösterme.

### Çok Katmanlı, Proaktif Strateji

#### Yama Yönetimi
Bilinen güvenlik açıkları için esastır. Yazılım güncellemelerinin zamanında belirlenmesi, önceliklendirilmesi, test edilmesi ve dağıtılması kritik öneme sahiptir.

#### Güvenlik Açığı Yönetimi
Tüm varlıklardaki siber güvenlik açıklarını sürekli olarak belirleme, değerlendirme, raporlama, yönetme ve düzeltme sürecidir. Tehdit istihbaratıyla riskleri önceliklendirir. Sürekli güvenlik açığı taraması hayati öneme sahiptir.

#### Web Uygulama Güvenlik Duvarı (WAF)
HTTP/HTTPS trafiğini filtreleyerek uygulama düzeyinde koruma sağlar, uygulamaları kötü amaçlı isteklerden korur. "Sanal yamalama" olarak işlev görebilir.

#### Davranış Tabanlı Tehdit Tespiti (EDR/XDR)
Bilinmeyen tehditler için bile, normal davranıştan sapmaları belirleyerek kötü amaçlı etkinliği gerçek zamanlı olarak tespit etmek için kritik öneme sahiptir. Gelişmiş IPS çözümleri de bunu kullanır.

#### Sıfır Güven Mimarisi
Katı erişim kontrolleri ve sürekli doğrulama uygulayarak bir ihlalin "patlama yarıçapını" sınırlar.

#### Uygulama Beyaz Listeleme
Yalnızca önceden onaylanmış uygulamaların/IP'lerin/donanımların bir ortamda çalışmasına izin verir, ilk erişim sağlansa bile kötü amaçlı yüklerin başlatılmasını kısıtlar.

#### Ayrıcalıklı Erişimi Sınırlama ve Ağları Bölümlendirme
Hasarı sınırlamak ve kuruluş çapında saldırıları önlemek için en az ayrıcalık, mikro segmentasyon ve tam zamanında (JIT) erişim uygulayın.

#### Giden Trafiği İzleme
Zero-day'ler genellikle veri sızdırma başlayana kadar tespit edilmediği için, büyük veri aktarımları, yetkisiz hedef IP'ler veya bilinen komuta ve kontrol (C2) sunucularıyla şifreli iletişim gibi olağandışı davranışları yakından izleyin.

#### Hızlı Olay Yanıt (IR) Planı
Kritik bir savunmadır. Gerçek bir zero-day saldırısı sırasında kusursuz yürütme sağlamak için düzenli tatbikatlar ve simülasyonlar gereklidir. Etkiyi en aza indirmek için hızlı tespit, izolasyon ve yanıta odaklanın.

#### Sürekli Saldırı Yüzeyi Analizi
Gizli tehditleri ve kör noktaları proaktif olarak belirleyin.

"Önleme merkezli" güvenlikten "proaktif esnekliğe" geçiş ve "uzlaşmayı varsayma" vurgusu, siber güvenliğe ilişkin olgun bir anlayışı temsil etmektedir. Bu, kuruluşların yalnızca ilk ihlalleri önlemeye değil, aynı zamanda sağlam tespit, izolasyon ve kurtarma yeteneklerine de eşit derecede yatırım yapması gerektiğini ima etmektedir. Bu, zero-day tehditlerinin tam önlemeyi gerçekçi olmayan bir hedef haline getirdiğini kabul etmektedir.
