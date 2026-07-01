# Pilar 4 — Pemetaan Pola Ancaman & Threat Intelligence

> **Tujuan Penelitian**: Mengidentifikasi dan memetakan pola ancaman dari data honeypot
> ke framework MITRE ATT&CK, membangun kapabilitas threat intelligence lokal,
> dan mengelola siklus hidup data secara berkelanjutan.

---

## Daftar Isi

1. [Threat Intel IOC — Ekstraksi & Feed Lokal](#1-threat-intel-ioc--ekstraksi--feed-lokal)
2. [Attack Discovery — AI-Powered Correlation](#2-attack-discovery--ai-powered-correlation)
3. [MITRE ATT&CK Mapping](#3-mitre-attck-mapping)
4. [ILM + Data Streams — Manajemen Siklus Hidup Data](#4-ilm--data-streams--manajemen-siklus-hidup-data)
5. [Ringkasan Pemetaan Tujuan Penelitian](#5-ringkasan-pemetaan-tujuan-penelitian)

---

## 1. Threat Intel IOC — Ekstraksi & Feed Lokal

> **Tujuan Penelitian yang Dipetakan**: Membangun kapabilitas CTI mandiri
> dengan mengekstrak Indicator of Compromise (IOC) dari data honeypot
> dan membagikannya dalam format standar industri (STIX 2.1).

### 1.1 Apa Itu IOC?

IOC (Indicator of Compromise) adalah artefak forensik yang mengindikasikan
potensi intrusi. Dalam konteks honeypot, IOC yang bisa diekstrak meliputi:

| Tipe IOC | Sumber | Contoh |
|---|---|---|
| IP Address | Semua log honeypot | `203.0.113.50` |
| Domain / URL | Cowrie download log, Dionaea | `malware.evil-domain.com` |
| File Hash (MD5/SHA256) | Cowrie file download | `d41d8cd98f00b204e9800998ecf8427e` |
| SSH Key Fingerprint | Cowrie SSH log | `SHA256:abc123...` |
| Username/Password | Cowrie auth log | `root:admin123` |
| User-Agent String | HTTP honeypot | `Mozilla/5.0 (compatible; Nmap Scripting Engine)` |

### 1.2 Mengekstrak IOC dari Elasticsearch

#### 1.2.1 Top Malicious IPs (ES|QL)

```esql
FROM honeypot-*
| WHERE @timestamp >= NOW() - 7 days
| STATS attack_count = COUNT(*),
        unique_tactics = COUNT_DISTINCT(mitre.tactic.keyword),
        ports_targeted = COUNT_DISTINCT(destination.port)
  BY source.ip
| WHERE attack_count > 50
| SORT attack_count DESC
| LIMIT 100
```

#### 1.2.2 Downloaded Malware Hashes (ES|QL)

```esql
FROM cowrie-*
| WHERE event.action == "file_download" AND file.hash.sha256 IS NOT NULL
| STATS download_count = COUNT(*),
        first_seen = MIN(@timestamp),
        last_seen = MAX(@timestamp)
  BY file.hash.sha256, file.name, url.original
| SORT download_count DESC
| LIMIT 50
```

#### 1.2.3 Suspicious Domains (ES|QL)

```esql
FROM honeypot-*
| WHERE dns.question.name IS NOT NULL OR url.domain IS NOT NULL
| EVAL domain = COALESCE(dns.question.name, url.domain)
| STATS hit_count = COUNT(*),
        unique_sources = COUNT_DISTINCT(source.ip)
  BY domain
| WHERE hit_count > 10
| SORT hit_count DESC
| LIMIT 50
```

### 1.3 Format STIX 2.1

STIX (Structured Threat Information Expression) versi 2.1 adalah standar OASIS
untuk berbagi threat intelligence. Berikut adalah contoh lengkap:

#### 1.3.1 STIX 2.1 Bundle — IOC dari Honeypot

```json
{
  "type": "bundle",
  "id": "bundle--a1b2c3d4-e5f6-7890-abcd-ef1234567890",
  "objects": [
    {
      "type": "identity",
      "spec_version": "2.1",
      "id": "identity--f1a2b3c4-d5e6-7890-abcd-111111111111",
      "created": "2026-06-16T13:00:00.000Z",
      "modified": "2026-06-16T13:00:00.000Z",
      "name": "CTI Honeypot Research Lab",
      "description": "Threat intelligence generated from honeypot infrastructure for academic research (Skripsi CTI Project)",
      "identity_class": "organization",
      "sectors": ["education"],
      "contact_information": "cti-lab@university.ac.id"
    },
    {
      "type": "indicator",
      "spec_version": "2.1",
      "id": "indicator--b2c3d4e5-f6a7-8901-bcde-222222222222",
      "created": "2026-06-16T13:00:00.000Z",
      "modified": "2026-06-16T13:00:00.000Z",
      "created_by_ref": "identity--f1a2b3c4-d5e6-7890-abcd-111111111111",
      "name": "Malicious IP - SSH Brute Force Actor",
      "description": "IP address melakukan brute force SSH terhadap honeypot Cowrie. Terdeteksi 847 percobaan login gagal dalam 1 jam. Username yang dicoba: root, admin, ubuntu, test.",
      "indicator_types": ["malicious-activity"],
      "pattern": "[ipv4-addr:value = '203.0.113.50']",
      "pattern_type": "stix",
      "pattern_version": "2.1",
      "valid_from": "2026-06-16T13:00:00.000Z",
      "valid_until": "2026-07-16T13:00:00.000Z",
      "kill_chain_phases": [
        {
          "kill_chain_name": "mitre-attack",
          "phase_name": "credential-access"
        }
      ],
      "labels": ["brute-force", "ssh", "honeypot-derived"],
      "confidence": 85,
      "lang": "id",
      "external_references": [
        {
          "source_name": "mitre-attack",
          "url": "https://attack.mitre.org/techniques/T1110/",
          "external_id": "T1110"
        }
      ]
    },
    {
      "type": "indicator",
      "spec_version": "2.1",
      "id": "indicator--c3d4e5f6-a7b8-9012-cdef-333333333333",
      "created": "2026-06-16T13:00:00.000Z",
      "modified": "2026-06-16T13:00:00.000Z",
      "created_by_ref": "identity--f1a2b3c4-d5e6-7890-abcd-111111111111",
      "name": "Malicious File Hash - Downloaded Malware",
      "description": "File malware yang diunduh penyerang ke honeypot Cowrie setelah berhasil login. File terdeteksi sebagai cryptominer.",
      "indicator_types": ["malicious-activity"],
      "pattern": "[file:hashes.'SHA-256' = 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855']",
      "pattern_type": "stix",
      "pattern_version": "2.1",
      "valid_from": "2026-06-16T13:00:00.000Z",
      "valid_until": "2026-09-16T13:00:00.000Z",
      "kill_chain_phases": [
        {
          "kill_chain_name": "mitre-attack",
          "phase_name": "execution"
        }
      ],
      "labels": ["malware", "cryptominer", "honeypot-derived"],
      "confidence": 95
    },
    {
      "type": "indicator",
      "spec_version": "2.1",
      "id": "indicator--d4e5f6a7-b8c9-0123-defa-444444444444",
      "created": "2026-06-16T13:00:00.000Z",
      "modified": "2026-06-16T13:00:00.000Z",
      "created_by_ref": "identity--f1a2b3c4-d5e6-7890-abcd-111111111111",
      "name": "Malicious Domain - C2 Server",
      "description": "Domain yang digunakan sebagai Command & Control server. Terdeteksi dari outbound connection honeypot setelah eksploitasi berhasil.",
      "indicator_types": ["malicious-activity"],
      "pattern": "[domain-name:value = 'c2.evil-domain.example']",
      "pattern_type": "stix",
      "pattern_version": "2.1",
      "valid_from": "2026-06-16T13:00:00.000Z",
      "valid_until": "2026-08-16T13:00:00.000Z",
      "kill_chain_phases": [
        {
          "kill_chain_name": "mitre-attack",
          "phase_name": "command-and-control"
        }
      ],
      "labels": ["c2", "domain", "honeypot-derived"],
      "confidence": 75
    },
    {
      "type": "attack-pattern",
      "spec_version": "2.1",
      "id": "attack-pattern--e5f6a7b8-c9d0-1234-efab-555555555555",
      "created": "2026-06-16T13:00:00.000Z",
      "modified": "2026-06-16T13:00:00.000Z",
      "name": "Brute Force: Password Guessing",
      "description": "Penyerang mencoba banyak kombinasi password secara berurutan untuk mendapatkan akses SSH.",
      "kill_chain_phases": [
        {
          "kill_chain_name": "mitre-attack",
          "phase_name": "credential-access"
        }
      ],
      "external_references": [
        {
          "source_name": "mitre-attack",
          "url": "https://attack.mitre.org/techniques/T1110/001/",
          "external_id": "T1110.001"
        }
      ]
    },
    {
      "type": "relationship",
      "spec_version": "2.1",
      "id": "relationship--f6a7b8c9-d0e1-2345-fabc-666666666666",
      "created": "2026-06-16T13:00:00.000Z",
      "modified": "2026-06-16T13:00:00.000Z",
      "relationship_type": "indicates",
      "source_ref": "indicator--b2c3d4e5-f6a7-8901-bcde-222222222222",
      "target_ref": "attack-pattern--e5f6a7b8-c9d0-1234-efab-555555555555",
      "description": "IP 203.0.113.50 teridentifikasi melakukan serangan brute force SSH"
    },
    {
      "type": "sighting",
      "spec_version": "2.1",
      "id": "sighting--a7b8c9d0-e1f2-3456-abcd-777777777777",
      "created": "2026-06-16T13:00:00.000Z",
      "modified": "2026-06-16T13:00:00.000Z",
      "first_seen": "2026-06-15T02:30:00.000Z",
      "last_seen": "2026-06-16T12:45:00.000Z",
      "count": 847,
      "sighting_of_ref": "indicator--b2c3d4e5-f6a7-8901-bcde-222222222222",
      "where_sighted_refs": ["identity--f1a2b3c4-d5e6-7890-abcd-111111111111"],
      "summary": true
    }
  ]
}
```

### 1.4 Mengimpor IOC ke Elastic Security Threat Intelligence

#### 1.4.1 Menggunakan Filebeat Threat Intel Module

1. Aktifkan modul Threat Intel di Filebeat:

```yaml
# filebeat.yml
filebeat.modules:
  - module: threatintel
    custom:
      enabled: true
      var.input: file
      var.paths:
        - /opt/honeypot-ioc/stix-feed/*.json
      var.data_stream.dataset: ti_custom.honeypot_ioc
```

2. Restart Filebeat:

```bash
sudo systemctl restart filebeat
```

#### 1.4.2 Menggunakan Indicator Match Rule

Setelah IOC terindeks, buat detection rule yang mencocokkan traffic masuk
dengan IOC feed:

1. **Security → Rules → Create new rule → Indicator Match**.
2. Konfigurasi:
   - **Source index**: `honeypot-*`, `suricata-*`
   - **Indicator index**: `filebeat-threatintel-*` atau `logs-ti_custom.honeypot_ioc-*`
   - **Indicator mapping**:
     - `source.ip` → `threat.indicator.ip`
     - `url.domain` → `threat.indicator.url.domain`
     - `file.hash.sha256` → `threat.indicator.file.hash.sha256`
3. **About**:
   - **Name**: `[CTI] IOC Match - Honeypot Threat Intel Feed`
   - **Severity**: `High`
   - **Tags**: `cti-pilar4`, `threat-intel`, `ioc-match`

### 1.5 Automasi Ekstraksi IOC

Script Python untuk mengekstrak IOC dari Elasticsearch dan membuat STIX bundle:

```python
#!/usr/bin/env python3
"""
extract_ioc.py — Mengekstrak IOC dari Elasticsearch dan membuat STIX 2.1 bundle.
Dijalankan harian via cron job.
"""

from elasticsearch import Elasticsearch
from datetime import datetime, timezone, timedelta
import json
import uuid
import hashlib

es = Elasticsearch(['http://localhost:9200'])

IDENTITY_ID = "identity--f1a2b3c4-d5e6-7890-abcd-111111111111"
OUTPUT_DIR = "/opt/honeypot-ioc/stix-feed"


def generate_stix_id(prefix, seed):
    """Membuat STIX ID deterministik dari seed string."""
    ns = uuid.UUID('6ba7b810-9dad-11d1-80b4-00c04fd430c8')
    return f"{prefix}--{uuid.uuid5(ns, seed)}"


def extract_malicious_ips(days=7, min_attacks=50):
    """Mengekstrak IP yang melakukan serangan di atas ambang batas."""
    query = {
        "size": 0,
        "query": {
            "range": {
                "@timestamp": {
                    "gte": f"now-{days}d"
                }
            }
        },
        "aggs": {
            "top_ips": {
                "terms": {
                    "field": "source.ip",
                    "size": 500,
                    "min_doc_count": min_attacks
                },
                "aggs": {
                    "tactics": {
                        "terms": {
                            "field": "mitre.tactic.keyword",
                            "size": 10
                        }
                    },
                    "countries": {
                        "terms": {
                            "field": "source.geo.country_name.keyword",
                            "size": 1
                        }
                    }
                }
            }
        }
    }

    result = es.search(index="honeypot-*", body=query)
    indicators = []

    for bucket in result['aggregations']['top_ips']['buckets']:
        ip = bucket['key']
        count = bucket['doc_count']
        tactics = [t['key'] for t in bucket['tactics']['buckets']]
        country = (bucket['countries']['buckets'][0]['key']
                   if bucket['countries']['buckets'] else 'Unknown')

        indicator = {
            "type": "indicator",
            "spec_version": "2.1",
            "id": generate_stix_id("indicator", f"ip-{ip}"),
            "created": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000Z"),
            "modified": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000Z"),
            "created_by_ref": IDENTITY_ID,
            "name": f"Malicious IP - {ip}",
            "description": (
                f"IP {ip} ({country}) melakukan {count} serangan "
                f"dalam {days} hari terakhir. "
                f"Taktik MITRE: {', '.join(tactics)}."
            ),
            "indicator_types": ["malicious-activity"],
            "pattern": f"[ipv4-addr:value = '{ip}']",
            "pattern_type": "stix",
            "pattern_version": "2.1",
            "valid_from": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000Z"),
            "valid_until": (
                datetime.now(timezone.utc) + timedelta(days=30)
            ).strftime("%Y-%m-%dT%H:%M:%S.000Z"),
            "confidence": min(95, 50 + (count // 10)),
            "labels": ["honeypot-derived", country.lower().replace(' ', '-')]
        }
        indicators.append(indicator)

    return indicators


def build_stix_bundle(indicators):
    """Membuat STIX 2.1 Bundle dari daftar indikator."""
    bundle = {
        "type": "bundle",
        "id": generate_stix_id("bundle", datetime.now().isoformat()),
        "objects": indicators
    }
    return bundle


def main():
    print("[*] Mengekstrak IOC dari Elasticsearch...")
    indicators = extract_malicious_ips(days=7, min_attacks=50)
    print(f"[+] Ditemukan {len(indicators)} IOC IP malicious")

    bundle = build_stix_bundle(indicators)

    filename = f"honeypot-ioc-{datetime.now().strftime('%Y%m%d')}.json"
    filepath = f"{OUTPUT_DIR}/{filename}"

    with open(filepath, 'w') as f:
        json.dump(bundle, f, indent=2)

    print(f"[+] STIX bundle disimpan: {filepath}")
    print(f"[+] Total objects dalam bundle: {len(bundle['objects'])}")


if __name__ == '__main__':
    main()
```

---

## 2. Attack Discovery — AI-Powered Correlation

> **Tujuan Penelitian yang Dipetakan**: Memanfaatkan fitur AI bawaan Elastic Security
> untuk mengorelasikan alert menjadi narasi serangan yang koheren.

> [!NOTE]
> **Attack Discovery** adalah fitur yang memerlukan lisensi **Enterprise** atau **Trial**.
> Fitur ini menggunakan LLM (Large Language Model) untuk menganalisis alert dan
> menggabungkannya menjadi *attack narrative*.

### 2.1 Apa Itu Attack Discovery?

Attack Discovery secara otomatis:
1. **Menganalisis** ratusan alert yang dihasilkan detection rules.
2. **Mengelompokkan** alert yang berkaitan menjadi satu insiden.
3. **Menghasilkan narasi** serangan dalam bahasa natural.
4. **Memetakan** ke MITRE ATT&CK framework.
5. **Memberikan rekomendasi** langkah investigasi dan mitigasi.

### 2.2 Mengaktifkan Attack Discovery

1. **Pastikan AI Assistant terkonfigurasi**:
   - **Management → Stack Management → AI Assistants → Elastic AI Assistant**.
   - Konfigurasi LLM connector (OpenAI, Azure OpenAI, atau Bedrock).

2. Contoh konfigurasi connector OpenAI:

```json
POST _connector
{
  "name": "OpenAI GPT-4",
  "connector_type_id": ".gen-ai",
  "config": {
    "apiProvider": "OpenAI",
    "apiUrl": "https://api.openai.com/v1/chat/completions",
    "defaultModel": "gpt-4"
  },
  "secrets": {
    "apiKey": "<YOUR_OPENAI_API_KEY>"
  }
}
```

### 2.3 Menggunakan Attack Discovery

1. **Kibana → Security → Attack Discovery**.
2. Pilih rentang waktu (misal: 24 jam terakhir).
3. Klik **Generate** atau **Discover Attacks**.
4. Sistem akan menganalisis alert dan menampilkan:

**Contoh output Attack Discovery**:

```
📌 Attack Narrative #1: SSH Brute Force Campaign

RINGKASAN:
Terdeteksi kampanye brute force SSH terorganisir dari 15 IP
di subnet 203.0.113.0/24 (Rusia) yang menargetkan port 22
honeypot antara 02:00-06:00 UTC.

TIMELINE:
1. 02:15 UTC - Recon: Port scan dari 203.0.113.10 (Suricata alert)
2. 02:22 UTC - Brute force dimulai dari 203.0.113.50 (847 attempts)
3. 02:45 UTC - IP tambahan bergabung: .51, .52, .53
4. 03:10 UTC - Login berhasil di Cowrie (honeypot) dari .50
5. 03:12 UTC - Download malware: cryptominer binary
6. 03:15 UTC - Outbound connection ke c2.evil-domain.example

MITRE ATT&CK:
├── Reconnaissance (T1595) - Port Scanning
├── Credential Access (T1110) - Brute Force
├── Execution (T1059) - Command Execution
├── Command & Control (T1071) - C2 Communication
└── Impact (T1496) - Resource Hijacking (Cryptominer)

REKOMENDASI:
1. Block subnet 203.0.113.0/24 di perimeter firewall
2. Tambahkan hash malware ke IOC feed
3. Block domain c2.evil-domain.example di DNS
4. Review honeypot logs untuk credential yang dicoba
```

### 2.4 Integrasi dengan Cases

Dari Attack Discovery, Anda bisa langsung:
1. Klik **Create case** untuk membuat case investigasi.
2. Semua alert terkait akan otomatis di-attach ke case.
3. Narasi serangan menjadi deskripsi awal case.

---

## 3. MITRE ATT&CK Mapping

> **Tujuan Penelitian yang Dipetakan**: Memetakan setiap serangan yang terdeteksi
> ke framework MITRE ATT&CK untuk klasifikasi dan pelaporan terstandar.

### 3.1 Pipeline Logstash — SID ke MITRE Technique

Pemetaan dilakukan di pipeline Logstash menggunakan file lookup (YAML/CSV)
yang menghubungkan Suricata SID ke MITRE ATT&CK technique ID.

#### 3.1.1 File Lookup: `sid-to-mitre.yml`

```yaml
# /etc/logstash/lookups/sid-to-mitre.yml
# Format: SID -> {tactic, technique_id, technique_name}

"2001219":
  tactic: "Initial Access"
  technique_id: "T1190"
  technique_name: "Exploit Public-Facing Application"

"2002910":
  tactic: "Credential Access"
  technique_id: "T1110"
  technique_name: "Brute Force"

"2002911":
  tactic: "Credential Access"
  technique_id: "T1110.001"
  technique_name: "Brute Force: Password Guessing"

"2010935":
  tactic: "Reconnaissance"
  technique_id: "T1595.002"
  technique_name: "Active Scanning: Vulnerability Scanning"

"2010936":
  tactic: "Reconnaissance"
  technique_id: "T1595.001"
  technique_name: "Active Scanning: Scanning IP Blocks"

"2013028":
  tactic: "Command and Control"
  technique_id: "T1071.001"
  technique_name: "Application Layer Protocol: Web Protocols"

"2024792":
  tactic: "Discovery"
  technique_id: "T1046"
  technique_name: "Network Service Discovery"

"2100366":
  tactic: "Initial Access"
  technique_id: "T1190"
  technique_name: "Exploit Public-Facing Application"

"2210000":
  tactic: "Execution"
  technique_id: "T1059"
  technique_name: "Command and Scripting Interpreter"

"2210044":
  tactic: "Impact"
  technique_id: "T1496"
  technique_name: "Resource Hijacking"
```

#### 3.1.2 Konfigurasi Logstash Pipeline

```ruby
# /etc/logstash/conf.d/30-mitre-enrichment.conf

filter {
  # Hanya proses event Suricata dengan alert
  if [event][module] == "suricata" and [alert][signature_id] {

    # Muat file lookup
    translate {
      source => "[alert][signature_id]"
      target => "[@metadata][mitre_lookup]"
      dictionary_path => "/etc/logstash/lookups/sid-to-mitre.yml"
      fallback => '{"tactic":"Unknown","technique_id":"N/A","technique_name":"Unmapped"}'
    }

    # Parse hasil lookup (JSON string → field)
    json {
      source => "[@metadata][mitre_lookup]"
      target => "[@metadata][mitre]"
    }

    # Set field MITRE ATT&CK
    mutate {
      add_field => {
        "[mitre][tactic]" => "%{[@metadata][mitre][tactic]}"
        "[mitre][technique][id]" => "%{[@metadata][mitre][technique_id]}"
        "[mitre][technique][name]" => "%{[@metadata][mitre][technique_name]}"
      }
    }

    # Mapping ECS-compatible untuk Elastic Security
    mutate {
      add_field => {
        "[threat][framework]" => "MITRE ATT&CK"
        "[threat][tactic][name]" => "%{[@metadata][mitre][tactic]}"
        "[threat][technique][id]" => "%{[@metadata][mitre][technique_id]}"
        "[threat][technique][name]" => "%{[@metadata][mitre][technique_name]}"
      }
    }
  }

  # Enrichment untuk Wazuh alerts
  if [event][module] == "wazuh" and [rule][groups] {

    # Wazuh rule group → MITRE tactic (simplified mapping)
    if "authentication_failed" in [rule][groups] {
      mutate {
        add_field => {
          "[mitre][tactic]" => "Credential Access"
          "[mitre][technique][id]" => "T1110"
          "[mitre][technique][name]" => "Brute Force"
          "[threat][framework]" => "MITRE ATT&CK"
          "[threat][tactic][name]" => "Credential Access"
          "[threat][technique][id]" => "T1110"
          "[threat][technique][name]" => "Brute Force"
        }
      }
    }

    if "web_scan" in [rule][groups] or "web_attack" in [rule][groups] {
      mutate {
        add_field => {
          "[mitre][tactic]" => "Initial Access"
          "[mitre][technique][id]" => "T1190"
          "[mitre][technique][name]" => "Exploit Public-Facing Application"
          "[threat][framework]" => "MITRE ATT&CK"
          "[threat][tactic][name]" => "Initial Access"
          "[threat][technique][id]" => "T1190"
          "[threat][technique][name]" => "Exploit Public-Facing Application"
        }
      }
    }

    if "rootcheck" in [rule][groups] {
      mutate {
        add_field => {
          "[mitre][tactic]" => "Persistence"
          "[mitre][technique][id]" => "T1547"
          "[mitre][technique][name]" => "Boot or Logon Autostart Execution"
          "[threat][framework]" => "MITRE ATT&CK"
          "[threat][tactic][name]" => "Persistence"
          "[threat][technique][id]" => "T1547"
          "[threat][technique][name]" => "Boot or Logon Autostart Execution"
        }
      }
    }
  }
}
```

### 3.2 Visualisasi MITRE ATT&CK Matrix di Elastic Security

Elastic Security menyediakan tampilan matriks MITRE ATT&CK bawaan.

#### 3.2.1 Langkah-Langkah

1. **Kibana → Security → Overview**.
2. Scroll ke bagian **MITRE ATT&CK** (atau klik tab khusus jika tersedia).
3. Matriks akan menampilkan:
   - **Kolom**: Taktik MITRE (Reconnaissance, Initial Access, ..., Impact).
   - **Baris**: Teknik spesifik di bawah setiap taktik.
   - **Warna sel**: intensitas berdasarkan jumlah alert.
4. Klik sel untuk melihat alert spesifik yang terpeta ke teknik tersebut.

#### 3.2.2 Filter Matriks

- Gunakan **time picker** untuk memfilter berdasarkan rentang waktu.
- Gunakan **KQL bar** untuk memfilter berdasarkan sumber:

```kql
event.module: "suricata" AND mitre.tactic: *
```

#### 3.2.3 Membuat Panel Dashboard dari Matriks

1. Di **Dashboard**, klik **Create panel → Lens**.
2. Konfigurasi:
   - **Visualization type**: **Heat map** (termal).
   - **Rows**: `threat.tactic.name.keyword`
   - **Columns**: `threat.technique.name.keyword`
   - **Color**: Count
3. Simpan sebagai **"MITRE ATT&CK Heatmap Coverage"**.

### 3.3 Coverage Gap Analysis

Gunakan query ES|QL untuk mengidentifikasi taktik MITRE yang belum ter-cover
oleh detection rules:

```esql
FROM .internal.alerts-security.alerts-default-*
| WHERE @timestamp >= NOW() - 30 days
| STATS alert_count = COUNT(*),
        unique_rules = COUNT_DISTINCT(kibana.alert.rule.name)
  BY threat.tactic.name
| SORT alert_count DESC
```

Bandingkan hasilnya dengan 14 taktik MITRE ATT&CK Enterprise:

| Taktik | Alert Count | Status |
|---|---|---|
| Credential Access | 1,245 | ✅ Covered |
| Initial Access | 892 | ✅ Covered |
| Reconnaissance | 456 | ✅ Covered |
| Execution | 234 | ✅ Covered |
| Command and Control | 89 | ⚠️ Low coverage |
| Persistence | 12 | ⚠️ Low coverage |
| Privilege Escalation | 0 | ❌ Not covered |
| Defense Evasion | 0 | ❌ Not covered |
| Lateral Movement | 0 | ❌ Not covered |
| Collection | 0 | ❌ Not covered |
| Exfiltration | 0 | ❌ Not covered |
| Impact | 45 | ✅ Covered |
| Resource Development | 0 | ❌ Not covered |
| Discovery | 78 | ✅ Covered |

> [!TIP]
> Taktik yang bertanda ❌ menunjukkan area di mana detection rules perlu
> ditambahkan. Ini normal untuk honeypot karena beberapa taktik lebih relevan
> untuk environment internal (misal: Lateral Movement, Exfiltration).

---

## 4. ILM + Data Streams — Manajemen Siklus Hidup Data

> **Tujuan Penelitian yang Dipetakan**: Mengelola volume data honeypot yang terus bertambah
> melalui kebijakan retensi otomatis agar infrastruktur tetap efisien.

### 4.1 Konsep ILM (Index Lifecycle Management)

ILM mengotomatiskan transisi index melalui fase-fase:

```
┌──────────┐    7 hari    ┌──────────┐   30 hari    ┌──────────┐   90 hari    ┌──────────┐
│   HOT    │ ──────────►  │   WARM   │ ──────────►  │   COLD   │ ──────────►  │  DELETE  │
│          │              │          │              │          │              │          │
│ Primary  │              │ Read-only│              │ Frozen   │              │ Dihapus  │
│ Indexing │              │ Shrink   │              │ Snapshot │              │          │
│ Search   │              │ Force    │              │ Jarang   │              │          │
│          │              │ merge    │              │ diakses  │              │          │
└──────────┘              └──────────┘              └──────────┘              └──────────┘
```

### 4.2 Membuat ILM Policy via Dev Tools

```json
PUT _ilm/policy/honeypot-ilm-policy
{
  "policy": {
    "phases": {
      "hot": {
        "min_age": "0ms",
        "actions": {
          "rollover": {
            "max_primary_shard_size": "10gb",
            "max_age": "7d",
            "max_docs": 5000000
          },
          "set_priority": {
            "priority": 100
          }
        }
      },
      "warm": {
        "min_age": "7d",
        "actions": {
          "shrink": {
            "number_of_shards": 1
          },
          "forcemerge": {
            "max_num_segments": 1
          },
          "allocate": {
            "number_of_replicas": 0
          },
          "set_priority": {
            "priority": 50
          }
        }
      },
      "cold": {
        "min_age": "30d",
        "actions": {
          "allocate": {
            "number_of_replicas": 0
          },
          "set_priority": {
            "priority": 0
          },
          "freeze": {}
        }
      },
      "delete": {
        "min_age": "90d",
        "actions": {
          "delete": {}
        }
      }
    }
  }
}
```

**Penjelasan setiap fase**:

| Fase | `min_age` | Aksi | Tujuan |
|---|---|---|---|
| **Hot** | 0 (langsung) | Rollover ketika ≥10GB atau ≥7 hari atau ≥5M docs | Performa tulis & baca optimal |
| **Warm** | 7 hari | Shrink ke 1 shard, force merge, 0 replika | Hemat storage, masih bisa di-query |
| **Cold** | 30 hari | Freeze, 0 replika | Sangat hemat storage, query lambat |
| **Delete** | 90 hari | Hapus index | Bersihkan data lama |

### 4.3 Membuat Index Template dengan ILM

```json
PUT _index_template/honeypot-template
{
  "index_patterns": ["honeypot-*"],
  "data_stream": {},
  "template": {
    "settings": {
      "index.lifecycle.name": "honeypot-ilm-policy",
      "number_of_shards": 1,
      "number_of_replicas": 0,
      "index.codec": "best_compression"
    },
    "mappings": {
      "properties": {
        "@timestamp": { "type": "date" },
        "source": {
          "properties": {
            "ip": { "type": "ip" },
            "geo": {
              "properties": {
                "location": { "type": "geo_point" },
                "country_name": { "type": "keyword" },
                "country_iso_code": { "type": "keyword" },
                "city_name": { "type": "keyword" },
                "continent_name": { "type": "keyword" }
              }
            }
          }
        },
        "destination": {
          "properties": {
            "ip": { "type": "ip" },
            "port": { "type": "integer" }
          }
        },
        "event": {
          "properties": {
            "kind": { "type": "keyword" },
            "category": { "type": "keyword" },
            "action": { "type": "keyword" },
            "module": { "type": "keyword" },
            "severity": { "type": "integer" },
            "outcome": { "type": "keyword" }
          }
        },
        "mitre": {
          "properties": {
            "tactic": { "type": "keyword" },
            "technique": {
              "properties": {
                "id": { "type": "keyword" },
                "name": { "type": "keyword" }
              }
            }
          }
        },
        "threat": {
          "properties": {
            "framework": { "type": "keyword" },
            "tactic": {
              "properties": {
                "name": { "type": "keyword" }
              }
            },
            "technique": {
              "properties": {
                "id": { "type": "keyword" },
                "name": { "type": "keyword" }
              }
            }
          }
        },
        "rule": {
          "properties": {
            "name": { "type": "keyword" },
            "category": { "type": "keyword" }
          }
        },
        "alert": {
          "properties": {
            "signature": { "type": "text" },
            "signature_id": { "type": "keyword" },
            "severity": { "type": "integer" }
          }
        }
      }
    }
  },
  "priority": 200
}
```

### 4.4 Membuat Data Stream

Data Streams adalah abstraksi di atas time-series index yang otomatis
menggunakan ILM policy:

```json
PUT _data_stream/honeypot-suricata
```

```json
PUT _data_stream/honeypot-cowrie
```

```json
PUT _data_stream/honeypot-wazuh
```

Verifikasi:

```json
GET _data_stream/honeypot-*
```

Respons:

```json
{
  "data_streams": [
    {
      "name": "honeypot-suricata",
      "timestamp_field": { "name": "@timestamp" },
      "indices": [
        {
          "index_name": ".ds-honeypot-suricata-2026.06.16-000001",
          "index_uuid": "abc123..."
        }
      ],
      "generation": 1,
      "status": "GREEN",
      "template": "honeypot-template",
      "ilm_policy": "honeypot-ilm-policy",
      "next_generation_managed_by": "Index Lifecycle Management"
    }
  ]
}
```

### 4.5 Monitoring ILM Status

#### 4.5.1 Via API

```json
GET honeypot-*/_ilm/explain
```

Contoh respons:

```json
{
  ".ds-honeypot-suricata-2026.06.10-000001": {
    "index": ".ds-honeypot-suricata-2026.06.10-000001",
    "managed": true,
    "policy": "honeypot-ilm-policy",
    "phase": "warm",
    "phase_time_millis": 1718496000000,
    "age": "6.2d",
    "action": "complete",
    "step": "complete"
  },
  ".ds-honeypot-suricata-2026.06.16-000002": {
    "index": ".ds-honeypot-suricata-2026.06.16-000002",
    "managed": true,
    "policy": "honeypot-ilm-policy",
    "phase": "hot",
    "age": "0.5d",
    "action": "rollover",
    "step": "check-rollover-ready"
  }
}
```

#### 4.5.2 Via UI

1. **Management → Stack Management → Index Management**.
2. Klik tab **Data Streams**.
3. Pilih data stream untuk melihat backing indices dan status ILM.

### 4.6 Manual Rollover (Jika Diperlukan)

```json
POST honeypot-suricata/_rollover
{
  "conditions": {
    "max_age": "1d",
    "max_docs": 1000000
  }
}
```

### 4.7 Snapshot untuk Backup Fase Cold

Sebelum data dihapus di fase delete, pastikan snapshot aktif:

```json
PUT _snapshot/honeypot-backup
{
  "type": "fs",
  "settings": {
    "location": "/mnt/backup/elasticsearch/honeypot",
    "compress": true
  }
}
```

Buat SLM (Snapshot Lifecycle Management) policy:

```json
PUT _slm/policy/honeypot-daily-snapshot
{
  "schedule": "0 0 2 * * ?",
  "name": "<honeypot-snap-{now/d}>",
  "repository": "honeypot-backup",
  "config": {
    "indices": ["honeypot-*"],
    "ignore_unavailable": true,
    "include_global_state": false
  },
  "retention": {
    "expire_after": "180d",
    "min_count": 5,
    "max_count": 50
  }
}
```

---

## 5. Ringkasan Pemetaan Tujuan Penelitian

| Komponen | Tujuan Penelitian | Output Utama |
|---|---|---|
| IOC Extraction + STIX 2.1 | Membangun kapabilitas CTI mandiri | Feed IOC lokal standar industri |
| Indicator Match Rule | Deteksi berdasarkan threat intel | Alert saat IOC cocok dengan traffic baru |
| Attack Discovery (AI) | Korelasi otomatis alert → narasi | Laporan insiden terstruktur |
| MITRE ATT&CK Mapping | Klasifikasi serangan terstandar | Coverage matrix & gap analysis |
| ILM + Data Streams | Manajemen siklus hidup data | Retensi otomatis: 7d hot → 30d warm → 90d delete |
| SLM Snapshot | Backup data cold phase | Retensi backup 180 hari |

---

> **Catatan Arsitektural**: Data stream `honeypot-*` digunakan sebagai sumber tunggal
> untuk semua pilar. Pastikan ILM policy tidak menghapus data yang masih diperlukan
> untuk analisis jangka panjang (misal: tren MTTD bulanan). Sesuaikan `min_age`
> fase delete jika diperlukan.

---

*Dokumen ini merupakan bagian dari Pilar 4 — Proyek Riset CTI Skripsi.*
*Terakhir diperbarui: 16 Juni 2026*
