#!/bin/bash
# Script untuk menjalankan 30 iterasi pengujian MTTR via Dashboard
echo "Memulai 30 Iterasi Pengujian (Dashboard Mode) - Attack: hydra"

for i in {1..30}; do
    echo "======================================"
    echo "Menjalankan Iterasi ke-$i dari 30..."
    /home/iqbal/eksperimen/run-iteration.sh $i dashboard hydra
    echo "Istirahat 10 detik sebelum iterasi berikutnya..."
    sleep 10
done

echo "30 Iterasi Selesai!"
