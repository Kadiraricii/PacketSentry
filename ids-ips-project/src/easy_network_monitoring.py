import subprocess
import json
import time
import threading
from datetime import datetime
import re

class KolayAgIzleme:
    def __init__(self):
        self.calisir_mi = True
        print("🔍 Kolay Ağ İzleme Sistemi başlatılıyor...")
        print("📌 Bu sistem root yetkisi gerektirmez!")
    
    def ag_baglantilari_getir(self):
        """
        netstat komutuyla mevcut ağ bağlantılarını getirir
        Root yetkisi gerektirmez
        """
        try:
            # netstat komutuyla bağlantı bilgilerini al
            result = subprocess.run(['netstat', '-an'], 
                                  capture_output=True, text=True, timeout=10)
            
            baglanti_listesi = []
            for satir in result.stdout.split('\n'):
                # TCP ve UDP bağlantılarını filtrele
                if 'tcp' in satir.lower() or 'udp' in satir.lower():
                    parcalar = satir.split()
                    if len(parcalar) >= 4:
                        protokol = parcalar[0]
                        yerel_adres = parcalar[3]
                        uzak_adres = parcalar[4] if len(parcalar) > 4 else 'Bilinmiyor'
                        durum = parcalar[5] if len(parcalar) > 5 else 'Bilinmiyor'
                        
                        # Sadece ilginç bağlantıları kaydet (port 80, 443, vb.)
                        if ':80' in uzak_adres or ':443' in uzak_adres or ':53' in uzak_adres:
                            baglanti_listesi.append({
                                'zaman': datetime.now().strftime("%H:%M:%S"),
                                'protokol': protokol,
                                'yerel_adres': yerel_adres,
                                'uzak_adres': uzak_adres,
                                'durum': durum
                            })
            
            return baglanti_listesi
        except Exception as e:
            print(f"❌ Ağ bağlantıları alınırken hata: {e}")
            return []
    
    def dns_sorgulari_izle(self):
        """
        DNS sorgularını sistem loglarından izler
        macOS için özel komut
        """
        try:
            print("🔍 DNS sorguları izleniyor...")
            # Son 1 dakikadaki DNS loglarını al
            result = subprocess.run([
                'log', 'show', 
                '--predicate', 'subsystem == "com.apple.network.dns"',
                '--style', 'compact', 
                '--last', '1m'
            ], capture_output=True, text=True, timeout=15)
            
            if result.stdout:
                dns_sayisi = len(result.stdout.split('\n'))
                if dns_sayisi > 1:
                    print(f"📊 Son 1 dakikada {dns_sayisi} DNS sorgusu tespit edildi")
                    
                    # İlginç domain'leri bul
                    for satir in result.stdout.split('\n')[:5]:  # Sadece ilk 5 tanesini göster
                        if satir.strip():
                            print(f"   🌐 DNS: {satir[:100]}...")
            else:
                print("📊 DNS aktivitesi bulunamadı")
                
        except Exception as e:
            print(f"⚠️  DNS izleme hatası (normal): {e}")
    
    def guvenlik_duvari_logları_kontrol_et(self):
        """
        Güvenlik duvarı (firewall) loglarını kontrol eder
        Engellenen bağlantıları gösterir
        """
        try:
            print("🛡️  Güvenlik duvarı logları kontrol ediliyor...")
            # Firewall loglarını al
            result = subprocess.run([
                'log', 'show', 
                '--predicate', 'subsystem == "com.apple.pf"',
                '--style', 'compact',
                '--last', '10m'
            ], capture_output=True, text=True, timeout=15)
            
            if result.stdout:
                engellenen_sayisi = 0
                for satir in result.stdout.split('\n'):
                    if 'block' in satir.lower() or 'deny' in satir.lower():
                        engellenen_sayisi += 1
                        if engellenen_sayisi <= 3:  # Sadece ilk 3 tanesini göster
                            print(f"   🚫 Engellendi: {satir[:80]}...")
                
                if engellenen_sayisi > 0:
                    print(f"📊 Toplam {engellenen_sayisi} engelleme tespit edildi")
                else:
                    print("✅ Güvenlik duvarı engelleme bulunamadı")
            else:
                print("📊 Güvenlik duvarı aktivitesi bulunamadı")
                
        except Exception as e:
            print(f"⚠️  Güvenlik duvarı kontrolü hatası (normal): {e}")
    
    def sureksiz_izleme_baslat(self):
        """
        Ana izleme döngüsü - her 10 saniyede bir çalışır
        """
        print("\n🚀 Sürekli ağ izleme başlatıldı!")
        print("⏹️  Durdurmak için Ctrl+C basın\n")
        
        dongu_sayisi = 0
        
        try:
            while self.calisir_mi:
                dongu_sayisi += 1
                print(f"\n--- 📊 İzleme Raporu #{dongu_sayisi} - {datetime.now().strftime('%H:%M:%S')} ---")
                
                # Ağ bağlantılarını kontrol et
                baglanti_listesi = self.ag_baglantilari_getir()
                if baglanti_listesi:
                    print(f"🌐 {len(baglanti_listesi)} aktif internet bağlantısı:")
                    for baglanti in baglanti_listesi[:5]:  # Sadece ilk 5 tanesini göster
                        print(f"   📡 {baglanti['yerel_adres']} → {baglanti['uzak_adres']} ({baglanti['protokol']})")
                else:
                    print("📶 Aktif internet bağlantısı bulunamadı")
                
                # Her 3. döngüde DNS ve firewall kontrolü yap
                if dongu_sayisi % 3 == 0:
                    self.dns_sorgulari_izle()
                    self.guvenlik_duvari_logları_kontrol_et()
                
                print(f"⏰ 10 saniye bekleniyor... (#{dongu_sayisi})")
                time.sleep(10)
                
        except KeyboardInterrupt:
            print("\n\n🛑 İzleme durduruldu!")
            self.calisir_mi = False
        except Exception as e:
            print(f"\n❌ İzleme hatası: {e}")

def main():
    """
    Ana fonksiyon - programı başlatır
    """
    print("=" * 60)
    print("🔍 KOLAY AĞ İZLEME SİSTEMİ")
    print("=" * 60)
    print("📌 Bu program root yetkisi gerektirmez")
    print("🔍 Ağ bağlantılarını, DNS sorgularını ve güvenlik duvarını izler")
    print("⚡ Hafif ve güvenli bir alternatif çözümdür")
    print("=" * 60)
    
    izleyici = KolayAgIzleme()
    
    # İlk kontrolleri yap
    print("\n🔍 İlk sistem kontrolü yapılıyor...")
    izleyici.ag_baglantilari_getir()
    izleyici.dns_sorgulari_izle()
    izleyici.guvenlik_duvari_logları_kontrol_et()
    
    # Sürekli izlemeyi başlat
    izleyici.sureksiz_izleme_baslat()

if __name__ == "__main__":
    main()