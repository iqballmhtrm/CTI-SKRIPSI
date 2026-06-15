#!/bin/bash
# CTI-Skripsi System Health Check

echo "--- Kibana Status & Logs ---"
sudo systemctl status kibana --no-pager
echo "--- Last 10 lines of Kibana log ---"
sudo journalctl -u kibana -n 10 --no-pager

echo -e "\n--- Elasticsearch Status ---"
sudo systemctl status elasticsearch --no-pager

echo -e "\n--- System Memory ---"
free -h

echo -e "\n--- Checking for OOM Killer activity ---"
sudo dmesg -T | grep -i "killed process" || echo "No OOM killer messages found in dmesg."

echo -e "\nHealth check complete."