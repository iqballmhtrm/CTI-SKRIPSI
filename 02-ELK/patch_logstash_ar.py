#!/usr/bin/env python3
# =====================================================================
# patch_logstash_ar.py  — Sisipkan filter WAZUH ACTIVE-RESPONSE (T2/MTTR)
# ke /etc/logstash/conf.d/soc-pipeline.conf (idempotent, whitespace-robust).
# Jalankan DI SOC: sudo python3 /tmp/patch_ar.py
# Tujuan: entri active-responses.log victim (command:"add") ditandai
#   rule.description = "Host Blocked by firewall-drop Active Response"
#   data.srcip + source.ip = IP yang diblokir, @timestamp = waktu eksekusi.
# =====================================================================
import sys, shutil, datetime

P = "/etc/logstash/conf.d/soc-pipeline.conf"
s = open(P, encoding="utf-8").read()

if "wazuh-ar" in s:
    print("ALREADY PATCHED (token 'wazuh-ar' ditemukan) — tidak ada perubahan")
    sys.exit(0)

BLOCK = r'''
  ### >>> WAZUH ACTIVE-RESPONSE (firewall-drop) -> T2/MTTR <<<
  if [log_type] == "wazuh-ar" {
    grok {
      match => { "message" => "^(?<ar_exec_time>%{YEAR}/%{MONTHNUM}/%{MONTHDAY} %{TIME}) %{NOTSPACE:ar_prog}: %{GREEDYDATA:ar_json}" }
      tag_on_failure => ["_ar_grokfail"]
    }
    if [ar_json] and [ar_json] =~ /"command":"add"/ {
      json { source => "ar_json" target => "ar" }
      mutate {
        add_field => {
          "[rule][description]" => "Host Blocked by firewall-drop Active Response"
          "[data][srcip]" => "%{[ar][parameters][alert][data][srcip]}"
          "[source][ip]" => "%{[ar][parameters][alert][data][srcip]}"
          "[event_type]" => "active_response"
        }
      }
      date {
        match => [ "ar_exec_time", "yyyy/MM/dd HH:mm:ss" ]
        timezone => "Asia/Jakarta"
        target => "@timestamp"
      }
      mutate { remove_field => [ "message", "ar_json", "ar", "ar_prog", "ar_exec_time" ] }
    } else {
      drop {}
    }
  }
  ### <<< END WAZUH ACTIVE-RESPONSE >>>

'''

lines = s.splitlines(keepends=True)
anchor = None
for i, l in enumerate(lines):
    if l.strip().startswith('if [service][type] == "wazuh"'):
        anchor = i
        break

if anchor is None:
    print("ANCHOR NOT FOUND (baris 'if [service][type] == \"wazuh\"') — BATAL, tidak ada perubahan")
    sys.exit(1)

bak = P + ".bak_ar_" + datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
shutil.copy(P, bak)
lines.insert(anchor, BLOCK)
open(P, "w", encoding="utf-8").write("".join(lines))
print("PATCHED OK — blok wazuh-ar disisipkan sebelum 'WAZUH JSON PARSER'.")
print("Backup: " + bak)
