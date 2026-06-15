# Validasi MITRE ATT&CK Mapping (Kibana)

Berdasarkan pengujian nyata dan injeksi yang tertangkap di dalam `eve.json` dan kemudian diteruskan melalui Logstash ke Elasticsearch / Kibana:

| SID | Technique ID | Technique Name | Tactic |
|---|---|---|---|
| 1000010 | T1046 | Network Service Scanning | Discovery |
| 1000020 | T1110 | Brute Force | Credential Access |
| 1000030 | T1595 | Active Scanning | Reconnaissance |

Ketiga event tersebut telah terverifikasi secara sempurna memiliki *fields* berikut pada Kibana:
- `mitre.technique_id`
- `mitre.technique_name`
- `mitre.tactic_name`
