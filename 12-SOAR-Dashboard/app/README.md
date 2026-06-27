# CTI SOAR Dashboard

Dashboard SOAR (Security Orchestration, Automation, and Response) sederhana berbasis Flask untuk memfasilitasi pelaporan log secara real-time dari Logstash dan melakukan respons aktif (Active Response) ke Victim Node.

## Cara Instalasi (di SOC Server 192.168.56.10)

1. Pastikan Python 3 sudah terinstal.
2. Install dependency:
   ```bash
   pip3 install -r requirements.txt
   ```
3. Jalankan aplikasi:
   ```bash
   python3 soar_app.py
   ```
4. Akses Web UI di browser Anda melalui `http://192.168.56.10:5000/`.

## Integrasi Logstash
Konfigurasi Logstash agar melempar HTTP POST ke web ini. Lihat file `../soc-pipeline-webhook-output.conf` untuk konfigurasinya.

## Known Limitations (Peringatan Keamanan)
- **TIDAK ADA AUTENTIKASI / RBAC:** Endpoint `/webhook` dan semua endpoint aksi mitigasi (`/action/block-ip`, dll.) saat ini terbuka lebar tanpa login atau Role-Based Access Control. 
- Implementasi ini sengaja disederhanakan dan HANYA AMAN dijalankan di dalam lingkungan Lab (Host-Only Network) untuk keperluan demonstrasi Skripsi. 
- Untuk penggunaan tingkat *Production*, wajib ditambahkan layer otentikasi seperti JWT, API Key, atau session login.
