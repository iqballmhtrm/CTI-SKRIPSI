#!/usr/bin/env python3
# =====================================================================
# patch_filebeat_ar.py  — Tambah input Filebeat untuk Wazuh active-responses.log
# ke /etc/filebeat/filebeat.yml DI VICTIM (idempotent, indentasi YAML benar).
# Jalankan DI VICTIM: sudo python3 /tmp/patch_fb.py
# =====================================================================
import sys, shutil, datetime

P = "/etc/filebeat/filebeat.yml"
s = open(P, encoding="utf-8").read()

if "wazuh-ar-victim" in s:
    print("ALREADY PATCHED (id 'wazuh-ar-victim' ditemukan) — tidak ada perubahan")
    sys.exit(0)

BLOCK = """
# 3. Wazuh Active Response log (firewall-drop / MTTR T2)
- type: filestream
  id: wazuh-ar-victim
  enabled: true
  paths:
    - /var/ossec/logs/active-responses.log
  fields:
    log_type: wazuh-ar
  fields_under_root: true

"""

lines = s.splitlines(keepends=True)

# Anchor: baris komentar bagian "Processors" (akhir daftar filebeat.inputs)
anchor = None
for i, l in enumerate(lines):
    if l.strip().startswith("#") and "Processors" in l:
        anchor = i
        break
if anchor is None:
    for i, l in enumerate(lines):
        if l.strip() == "processors:":
            anchor = i
            break

if anchor is None:
    print("ANCHOR NOT FOUND (bagian Processors) — BATAL, tidak ada perubahan")
    sys.exit(1)

bak = P + ".bak_ar_" + datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
shutil.copy(P, bak)
lines.insert(anchor, BLOCK)
open(P, "w", encoding="utf-8").write("".join(lines))
print("PATCHED OK — input 'wazuh-ar-victim' ditambahkan sebelum bagian Processors.")
print("Backup: " + bak)
