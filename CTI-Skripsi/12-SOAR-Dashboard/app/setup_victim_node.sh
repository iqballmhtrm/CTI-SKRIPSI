#!/bin/bash
# =========================================================================
# SCRIPT SETUP: SSH Passwordless & Sudoers di Victim Node
# =========================================================================
# CATATAN: Script ini HANYA UNTUK DOKUMENTASI. Jangan jalankan file ini 
# secara otomatis. Silakan jalankan command di bawah ini secara manual 
# di masing-masing VM.

# ---------------------------------------------------------
# LANGKAH 1: Di SOC Server (192.168.56.10)
# ---------------------------------------------------------
# Generate SSH key jika belum ada (tekan enter saja untuk semua pertanyaan):
# ssh-keygen -t rsa -b 4096

# Copy public key ke Victim Node (masukkan password user 'korban' saat diminta):
# ssh-copy-id korban@192.168.56.106

# Test login tanpa password:
# ssh korban@192.168.56.106 "echo Berhasil Login Passwordless!"


# ---------------------------------------------------------
# LANGKAH 2: Di Victim Node (192.168.56.106)
# ---------------------------------------------------------
# Login ke Victim Node sebagai root, lalu buka visudo:
# sudo visudo -f /etc/sudoers.d/korban-soar

# Tambahkan persis baris berikut di dalam file yang terbuka:
# korban ALL=(root) NOPASSWD: /sbin/iptables, /usr/bin/passwd, /usr/bin/ps, /bin/netstat

# PERHATIAN: 
# - Pastikan path command benar (/sbin/iptables atau /usr/sbin/iptables tergantung OS).
#   Anda bisa mengeceknya dengan command: which iptables
# - Penggunaan 'visudo -f' sangat penting karena akan memvalidasi sintaks 
#   sudoers. Jika ada typo, visudo akan memperingatkan sebelum disimpan
#   sehingga mencegah sistem sudo Anda rusak.
