# 🚀 Network Optimizer Pro

**Gelişmiş USB Tethering & TTL Değiştirme Aracı**

---

## 📋 İçindekiler 

- [Genel Bakış](#-genel-bakış)
- [TTL Nedir?](#-ttl-nedir)
- [Nasıl Çalışır?](#-nasıl-çalışır)
- [Uygulama Görüntüsü](#-uygulama-görünümü)
- [Sistem Gereksinimleri](#-sistem-gereksinimleri)
- [Kurulum](#-kurulum)
- [Kullanım Kılavuzu](#-kullanım-kılavuzu)
- [Özellikler](#-özellikler)
- [Güvenlik Notları](#-güvenlik-notları)
- [Sorun Giderme](#-sorun-giderme)
- [Sık Sorulan Sorular](#-sık-sorulan-sorular)

---

## 🎯 Genel Bakış

Network Optimizer Pro, Windows sistemlerde USB tethering optimizasyonu ve TTL (Time To Live) değiştirme işlemlerini otomatikleştiren gelişmiş bir araçtır. Bu uygulama, mobil internet bağlantılarının performansını artırır ve servis sağlayıcı kısıtlamalarını aşmaya yardımcı olur.

### 🌟 Ana Özellikler

- **USB Tethering Optimizasyonu**: Windows'u USB tethering için optimize eder
- **TTL Değiştirme**: Gerçek zamanlı TTL değeri manipülasyonu
- **DNS Optimizasyonu**: Cloudflare DNS (1.1.1.1) yapılandırması
- **Ağ Adaptörü Ayarları**: Optimal MTU ve performans ayarları
- **Otomatik Geri Yükleme**: Değişiklikleri geri alma scripti
- **Modern Arayüz**: Kullanıcı dostu futuristik tasarım

---

## 🔍 TTL Nedir?

### Time To Live (Yaşam Süresi)

**TTL**, ağ paketlerinin internetde kalabileceği maksimum süreyi belirleyen bir değerdir. Her paket bir TTL değeri ile gönderilir ve her router'dan geçtiğinde bu değer 1 azalır. TTL 0'a ulaştığında paket atılır.

### 📱 Farklı Cihazlarda TTL Değerleri

| Cihaz Türü | Varsayılan TTL |
|------------|----------------|
| **Windows** | 128 |
| **Android** | 64 |
| **iOS** | 64 |
| **Linux** | 64 |
| **macOS** | 64 |

### 🏢 Servis Sağlayıcıları Nasıl Tespit Eder?

Servis sağlayıcıları, aşağıdaki yöntemlerle cihaz türünü tespit edebilir:

1. **TTL Analizi**: Gelen paketlerin TTL değerlerini kontrol eder
2. **HTTP Header Analizi**: User-Agent ve diğer başlık bilgileri
3. **Paket Boyutu Analizi**: Farklı cihazların paket boyutu desenleri
4. **Deep Packet Inspection (DPI)**: Trafik içeriği analizi

#### 🎯 TTL Tespit Mantığı

```
Telefon → Router → ISP
   64  →   63   → 62  (ISP: "Bu Android/iOS")

Bilgisayar → Router → ISP  
    128   →   127  → 126 (ISP: "Bu Windows")

Optimize Edilmiş:
Telefon → Bilgisayar(TTL=65) → Router → ISP
   64   →        65         →   64   → 63 (ISP: "Bu tek cihaz")
```


## 🖼️ Uygulama Görünümü

![Image](https://github.com/user-attachments/assets/8a321c7f-dc09-496e-8842-b0dc3f435f89)


## 🖼️ Uygulama Görünümü
![Image](https://github.com/user-attachments/assets/8a321c7f-dc09-496e-8842-b0dc3f435f89)

## 💻 Sistem Gereksinimleri

### Minimum Gereksinimler

- **İşletim Sistemi**: Windows 10 (64-bit)
- **RAM**: 4 GB
- **Depolama**: 100 MB boş alan
- **Ağ**: USB Tethering destekli mobil cihaz
- **Yetki**: Administrator hakları

### Önerilen Gereksinimler

- **İşletim Sistemi**: Windows 10/11 (64-bit)
- **RAM**: 8 GB
- **Depolama**: 500 MB boş alan
- **Ağ**: 4G/5G destekli mobil cihaz

---

## 📦 Kurulum

### 1. İndirme

- [Son sürümü buradan indirin](https://github.com/ademcck/NetworkOptimizerPro/releases/download/v1.0/NetworkOptimizerPro.zip)
- `NetworkOptimizerPro.exe` dosyasını indirin

### 2. Yükleme

```bash
# Geliştirici için
git clone https://github.com/ademcck/NetworkOptimizerPro.git
cd NetworkOptimizerPro
```

### 3. Gerekli Kütüphaneler

```txt
tkinter (Python ile birlikte gelir)
scapy>=2.4.5
```

**Scapy Kurulumu:**
```bash
pip install scapy
```

---

## 📖 Kullanım Kılavuzu

### 🔧 Adım 1: USB Tethering Kurulumu

1. **Telefonu Bağlayın**
   - USB kablosu ile telefonu bilgisayara bağlayın
   - Telefonda USB Tethering'i etkinleştirin

2. **Windows Ayarları**
   - `Ayarlar → Ağ ve İnternet → Mobil etkin nokta`
   - **Mobil etkin noktayı AÇIK** yapın

### 🚀 Adım 2: İlk Optimizasyon

1. **Uygulamayı Administrator Olarak Çalıştırın**
   ```
   NetworkOptimizerPro.exe → Sağ Tık → "Yönetici olarak çalıştır"
   ```

2. **USB Tethering Sekmesine Gidin**
   - `📱 USB Tethering` sekmesini açın

3. **Optimizasyonu Başlatın**
   - `🚀 START OPTIMIZATION` butonuna tıklayın
   - İşlemin tamamlanmasını bekleyin

4. **Bilgisayarı Yeniden Başlatın**
   - Değişikliklerin geçerli olması için restart gereklidir

### 🛡️ Adım 3: TTL Monitoring

1. **Uygulamayı Tekrar Administrator Olarak Çalıştırın**

2. **TTL Modifier Sekmesine Gidin**
   - `🛡️ TTL Modifier` sekmesini açın

3. **Ağ Arayüzünü Seçin**
   - Dropdown menüden USB Tethering arayüzünü seçin
   - Genellikle "Local Area Connection" veya benzer

4. **TTL Değerini Ayarlayın**
   - Önerilen değer: **65**
   - Bu değer optimize edilmiş trafik için idealdir

5. **Monitoring'i Başlatın**
   - `🚀 START MONITORING` butonuna tıklayın
   - Artık tüm trafik TTL=65 ile gönderilecek

### 📊 Adım 4: İzleme

- **Packet Monitor**: Gerçek zamanlı paket trafiği
- **Statistics**: İşlem istatistikleri
- **System Status**: Ağ durumu bilgileri

---

## ⚡ Özellikler

### 🔧 USB Tethering Optimizasyonu

- **TTL Ayarları**: Sistem TTL'ini 65'e ayarlar
- **DNS Optimizasyonu**: Cloudflare DNS (1.1.1.1, 1.0.0.1)
- **Registry Ayarları**: TCP/IP optimizasyonları
- **MTU Ayarları**: Optimal paket boyutu
- **Ağ Profili**: Performans odaklı profil

### 🛡️ TTL Modifier

- **Gerçek Zamanlı İzleme**: Paket seviyesi TTL değiştirme
- **Çoklu Protokol**: TCP, UDP, ICMP desteği
- **İstatistik Takibi**: Paket sayıları ve cihaz tespiti
- **Arayüz Seçimi**: Birden fazla ağ adaptörü desteği

### 📊 Monitoring & Logging

- **Paket İzleme**: Gerçek zamanlı trafik görüntüleme
- **Performans İstatistikleri**: Throughput ve latency metrikleri
- **Cihaz Tespiti**: Ağdaki cihazları otomatik tespit
- **Rapor Oluşturma**: Detaylı kullanım raporları

---

## 🔒 Güvenlik Notları

### ⚠️ Önemli Uyarılar

1. **Administrator Hakları**: Uygulama sistem ayarlarını değiştirir
2. **Güvenlik Duvarı**: Bazı güvenlik yazılımları uygulamayı engelleyebilir
3. **Geri Yükleme**: Değişiklikleri geri almak için restore scripti kullanın
4. **Yasal Sorumluluk**: Servis sağlayıcı sözleşmenizi kontrol edin

### 🛡️ Güvenlik Önlemleri

- **Otomatik Restore**: Sistem ayarlarını otomatik geri yükleme
- **Backup Oluşturma**: Orijinal ayarları yedekleme
- **Güvenli Çıkış**: Uygulama kapatılırken temizlik işlemleri

---

## 🔧 Sorun Giderme

### ❌ Yaygın Sorunlar

#### 1. "Administrator Privileges Required" Hatası

**Çözüm:**
```
Uygulama simgesine sağ tıklayın → "Yönetici olarak çalıştır"
```

#### 2. "Scapy Library Not Found" Hatası

**Çözüm:**
```bash
pip install scapy
```

#### 3. TTL Monitoring Çalışmıyor

**Çözüm:**
- Doğru ağ arayüzünü seçtiğinizden emin olun
- Windows Defender'ı geçici olarak devre dışı bırakın
- Uygulamayı administrator olarak çalıştırın

#### 4. USB Tethering Bağlantı Sorunu

**Çözüm:**
1. USB kablosunu kontrol edin
2. Telefonda USB Tethering'i yeniden etkinleştirin
3. Windows'ta mobil etkin noktayı açın
4. Ağ adaptörlerini yenileyin

### 🔄 Ayarları Geri Yükleme

Sorun yaşarsanız:

1. **Uygulama İçinden:**
   - `🔄 RESTORE SETTINGS` butonunu kullanın

2. **Manuel Geri Yükleme:**
   - `restore_settings.bat` dosyasını administrator olarak çalıştırın

3. **Komut Satırından:**
   ```cmd
   netsh int ipv4 set global defaultcurhoplimit=128
   netsh int ipv6 set global defaultcurhoplimit=128
   ```

---

## ❓ Sık Sorulan Sorular

### Q: TTL değiştirme yasal mı?

**A:** TTL değiştirme teknik olarak yasal bir işlemdir, ancak servis sağlayıcı sözleşmenizi kontrol etmeniz önerilir. Çoğu sağlayıcı tethering kısıtlamaları koyar.

### Q: Hangi TTL değerini kullanmalıyım?

**A:** Önerilen değer **65**'tir. Bu değer çoğu senaryo için optimize edilmiştir ve tespit edilme riskini minimize eder.

### Q: İnternet hızım düşer mi?

**A:** Hayır, aksine optimizasyon sayesinde daha stabil ve hızlı bağlantı elde edebilirsiniz. DNS ayarları ve TCP optimizasyonları performansı artırır.

### Q: Birden fazla cihaz bağlayabilir miyim?

**A:** Evet, TTL monitoring aktif olduğunda tüm cihazların trafiği optimize edilir. WiFi hotspot veya Ethernet paylaşımı da desteklenir.

### Q: Uygulama arka planda çalışır mı?

**A:** TTL monitoring'i başlattıktan sonra uygulama minimize edilebilir. Sistem tepsisinde çalışmaya devam eder.

### Q: Antivirüs uyarısı veriyor?

**A:** Ağ ayarlarını değiştirdiği için bazı antivirüs yazılımları uyarı verebilir. Güvenilir kaynaklardan indirdiğiniz uygulamayı beyaz listeye ekleyin.

---

## 📞 Destek

### 🐛 Hata Bildirimi

Sorun yaşıyorsanız:

1. **Sistem Bilgilerini Toplayın**
2. **GitHub Issues'a Bildirin**

### 💬 İletişim

- **GitHub**: [Issues](https://github.com/ademcck/NetworkOptimizerPro/issues)
- **Email**: support@snipcore.com

---

## 📝 Lisans

Bu proje MIT lisansı altında dağıtılmaktadır.

---

## 🙏 Katkıda Bulunma

Katkılarınızı bekliyoruz! 

### 🔄 Güncellemeler

- **v1.0.0**: İlk stabil sürüm
- **v1.0.0**: TTL monitoring iyileştirmeleri
- **v1.0.0**: GUI geliştirmeleri

---

**⚡ Network Optimizer Pro ile internet bağlantınızı optimize edin!** 🚀
