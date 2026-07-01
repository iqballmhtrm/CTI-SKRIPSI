# Panduan Setup VPN Privat (Tailscale) antar VPS

Untuk memastikan keamanan aliran data log dari VPS A (Honeypot) ke VPS B (SOC Server), kita tidak boleh mengirim log mentah melalui IP Publik. Kita akan menggunakan **Tailscale**, sebuah layanan VPN berbasis WireGuard yang sangat mudah dikonfigurasi.

## Langkah 1: Pendaftaran Tailscale
1. Kunjungi [tailscale.com](https://tailscale.com/) dan buat akun (gratis).
2. Anda akan diarahkan ke *Admin Console*. Biarkan halaman tersebut terbuka.

## Langkah 2: Instalasi di VPS B (SOC Server)
Jalankan perintah berikut di terminal VPS B:
```bash
# Mengunduh dan menginstal Tailscale
curl -fsSL https://tailscale.com/install.sh | sh

# Mengautentikasi dan menyambungkan server ke jaringan Tailscale
sudo tailscale up
```
Setelah menjalankan `tailscale up`, akan muncul sebuah tautan URL di terminal. *Copy* tautan tersebut dan buka di *browser* Anda untuk memberikan otorisasi mesin ini masuk ke akun Anda.

Setelah terhubung, cek IP Privat Tailscale VPS B:
```bash
tailscale ip -4
```
**Catat IP ini sebagai `<SOC_SERVER_VPN_IP>` (Misal: 100.x.x.x). IP ini akan dipakai oleh Filebeat di VPS A.**

## Langkah 3: Instalasi di VPS A (Honeypot)
Jalankan perintah yang sama di terminal VPS A:
```bash
curl -fsSL https://tailscale.com/install.sh | sh
sudo tailscale up
```
Buka tautan autentikasi di *browser*. 

Cek IP Privat Tailscale VPS A:
```bash
tailscale ip -4
```
**Catat IP ini sebagai `<HONEYPOT_VPN_IP>`. IP ini akan dipakai oleh Logstash dan SOAR Dashboard di VPS B.**

## Langkah 4: Verifikasi Konektivitas
Dari VPS B (SOC Server), coba *ping* ke IP VPN VPS A:
```bash
ping <HONEYPOT_VPN_IP>
```
Dari VPS A (Honeypot), coba *ping* ke IP VPN VPS B:
```bash
ping <SOC_SERVER_VPN_IP>
```

Jika keduanya membalas dengan sukses, jaringan VPN privat Anda telah siap. Seluruh komunikasi yang melewati IP 100.x.x.x ini dienkripsi dengan standar WireGuard yang sangat tangguh.
