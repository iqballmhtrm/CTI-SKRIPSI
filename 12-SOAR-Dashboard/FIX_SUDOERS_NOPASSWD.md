# PANDUAN SETUP NOPASSWD SUDO DI VICTIM-NODE
**Tujuan:** Mengamankan eksekusi SSH remote dari SOAR ke VICTIM-NODE agar tidak memerlukan pengiriman password secara hardcode (plain-text).

Sebagai solusi keamanan tingkat lanjut, kita akan menggunakan fitur `sudoers.d` yang memberikan hak eksekusi perintah spesifik (seperti `iptables` dan `passwd`) secara *passwordless* (NOPASSWD) bagi pengguna `iqbal` (atau `korban`).

## Langkah-Langkah (Kerjakan Manual)

1. **Login ke VICTIM-NODE:**
   Buka terminal di mesin Anda dan jalankan perintah SSH ke VICTIM-NODE:
   ```bash
   ssh iqbal@192.168.56.106
   ```
   *(Masukkan password saat ini jika diminta).*

2. **Buka Editor Visudo yang Aman:**
   Jangan mengedit file `/etc/sudoers` secara langsung. Gunakan `visudo` untuk memvalidasi sintaks sebelum menyimpan agar tidak mengunci diri Anda keluar dari sistem:
   ```bash
   sudo visudo -f /etc/sudoers.d/soar-nopasswd
   ```

3. **Tambahkan Aturan NOPASSWD:**
   Pastikan letak *binary* dari perintah tersebut benar (`/sbin/iptables` dan `/usr/bin/passwd`). Tambahkan baris berikut di dalam file yang baru saja terbuka:
   ```text
   iqbal ALL=(root) NOPASSWD: /sbin/iptables, /usr/bin/passwd, /bin/ps, /usr/bin/ss
   ```
   *(Catatan: Tambahkan juga `/bin/ps` dan `/usr/bin/ss` karena modul SOAR Forensics membutuhkannya).*

4. **Simpan dan Keluar:**
   - Jika menggunakan `nano`: Tekan `Ctrl+X`, lalu ketik `Y`, kemudian tekan `Enter`.
   - Jika menggunakan `vi` atau `vim`: Tekan `Esc`, lalu ketik `:wq` dan tekan `Enter`.

5. **Lakukan Uji Coba (Verifikasi):**
   Uji apakah aturan berhasil dengan mencoba mengeksekusi perintah tersebut dari luar tanpa password. Keluar dari VICTIM-NODE (`exit`) lalu jalankan perintah ini dari terminal SOC-SERVER:
   ```bash
   ssh iqbal@192.168.56.106 "sudo iptables -L"
   ```
   *Keberhasilan ditandai dengan perintah `iptables` yang langsung tereksekusi dan menampilkan aturan firewall tanpa prompt password sama sekali.*

Setelah panduan ini selesai Anda lakukan, modul keamanan kode yang baru (di mana password hardcode telah saya buang) akan dapat beroperasi dengan aman dan lancar!
