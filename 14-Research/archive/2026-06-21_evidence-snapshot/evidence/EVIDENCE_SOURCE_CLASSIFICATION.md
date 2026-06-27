# EVIDENCE SOURCE CLASSIFICATION AUDIT
**AUDIT DATE:** 21 Juni 2026  
**PURPOSE:** Classify all claims as REPOSITORY vs RUNTIME evidence  
**METHODOLOGY:** Systematic verification of evidence sources  

---

## CLASSIFICATION TABLE

| # | Claim | Value | Source Type | Repository File | Runtime System | Verified | Confidence | Notes |
|---|-------|-------|-------------|-----------------|----------------|----------|------------|-------|
| 1 | Incident Count (606) | 606 incidents | REPOSITORY | `AUDIT_REPORT_GROUND_TRUTH.md` Line 102 | incidents.db query (NOT ACCESSIBLE) | ⚠️ PARTIAL | MEDIUM | Audit dated 20 Juni 2026; Database NOT queryable from current environment |
| 2 | Incident Count (~9020) | ~9020 incidents | UNKNOWN | NOT FOUND in repository | UNKNOWN | ❌ NO | NONE | Mentioned in master context but NO EVIDENCE in repository or runtime |
| 3 | MTTD Manual Mode | 1.70 seconds | REPOSITORY | `11-Bab4/laporan_implementasi_lengkap.md` Line 296 | Elasticsearch index `cti-mttd-mttr-iqbal` (NOT ACCESSIBLE) | ✅ YES | HIGH | Calculated from 5 iterations; Raw data in implementation report |
| 4 | MTTD Dashboard Mode | 3.36 seconds | REPOSITORY | `11-Bab4/laporan_implementasi_lengkap.md` Line 297 | Elasticsearch index `cti-mttd-mttr-iqbal` (NOT ACCESSIBLE) | ✅ YES | HIGH | Calculated from 5 iterations; Raw data in implementation report |
| 5 | MTTR Manual Mode | 56.86 seconds | REPOSITORY | `11-Bab4/laporan_implementasi_lengkap.md` Line 296 | Elasticsearch index `cti-mttd-mttr-iqbal` (NOT ACCESSIBLE) | ✅ YES | HIGH | Calculated from 5 iterations; Raw data in implementation report |
| 6 | MTTR Dashboard Mode | 60.51 seconds | REPOSITORY | `11-Bab4/laporan_implementasi_lengkap.md` Line 297 | Elasticsearch index `cti-mttd-mttr-iqbal` (NOT ACCESSIBLE) | ✅ YES | HIGH | Calculated from 5 iterations; Raw data in implementation report |
| 7 | MITRE Mapped Count | 1 | UNKNOWN | NOT FOUND | NOT FOUND | ❌ NO | NONE | Mentioned in master context; NO EVIDENCE in repository |
| 8 | MITRE Unmapped Count | 151 | UNKNOWN | NOT FOUND | NOT FOUND | ❌ NO | NONE | Mentioned in master context; NO EVIDENCE in repository |
| 9 | Dataset Noise % | 95% | ESTIMATED | NOT FOUND | NOT FOUND | ❌ NO | NONE | Mentioned in master context; NO ACTUAL MEASUREMENT |
| 10 | Research Data % | 2-5% | ESTIMATED | NOT FOUND | NOT FOUND | ❌ NO | NONE | Mentioned in master context; NO ACTUAL MEASUREMENT |
| 11 | Nmap Validation | PASS (T1046) | REPOSITORY | `07-Testing/Nmap/nmap_validation_success.txt` | NOT APPLICABLE | ✅ YES | HIGH | Validation marker file exists |
| 12 | Hydra Validation | PASS (T1110.001) | REPOSITORY | `07-Testing/Hydra/hydra_validation_success.txt` | NOT APPLICABLE | ✅ YES | HIGH | Validation marker file exists |
| 13 | Nikto Validation | PASS (T1595.002) | REPOSITORY | `07-Testing/Nikto/nikto_validation_success.txt` | NOT APPLICABLE | ✅ YES | HIGH | Validation marker file exists |
| 14 | SOAR Database Schema | See schema | REPOSITORY | `AUDIT_REPORT_GROUND_TRUTH.md` Lines 87-101 | incidents.db (NOT ACCESSIBLE) | ✅ YES | HIGH | Schema documented in audit; Code verified in `soar_app.py` |
| 15 | SOAR Execution Mode | Manual/Nohup | REPOSITORY | `AUDIT_REPORT_GROUND_TRUTH.md` Line 104 | systemd check (NOT PERFORMED) | ⚠️ PARTIAL | MEDIUM | No systemd service found in audit |
| 16 | Hardcoded Password | "123123" | REPOSITORY | `AUDIT_REPORT_GROUND_TRUTH.md` Line 82 | soar_app.py (CONTRADICTS) | ⚠️ CONFLICT | LOW | Audit claims hardcode exists; Current soar_app.py has NOPASSWD comment |
| 17 | Elasticsearch Index | cti-logs-iqbal-* | REPOSITORY | Multiple files | NOT ACCESSIBLE | ✅ YES | HIGH | Consistent across all configuration files |
| 18 | SOAR Webhook Endpoint | /webhook | REPOSITORY | `12-SOAR-Dashboard/app/soar_app.py` Line 102 | NOT ACCESSIBLE | ✅ YES | HIGH | Verified in source code |
| 19 | MTTD Iteration Count | 10 total | REPOSITORY | `11-Bab4/laporan_implementasi_lengkap.md` Table | Elasticsearch (NOT ACCESSIBLE) | ✅ YES | HIGH | 5 Manual + 5 Dashboard mode |
| 20 | Attacker IP | 192.168.56.105 | REPOSITORY | Multiple files | Ping result: UNREACHABLE | ⚠️ PARTIAL | MEDIUM | IP documented but node unreachable per audit |
| 21 | Victim IP | 192.168.56.106 | REPOSITORY | Multiple files | Ping result: REACHABLE | ✅ YES | HIGH | Verified in audit report |
| 22 | SOC IP | 192.168.56.10 | REPOSITORY | Multiple files | Active per audit | ✅ YES | HIGH | Verified in audit report |
| 23 | System Readiness | 98% Ready | REPOSITORY | `09-Evidence/final-readiness-report.md` | NOT VERIFIED | ⚠️ PARTIAL | MEDIUM | Self-reported readiness; No independent validation |
| 24 | Threat Score Transform | EXISTS | REPOSITORY | `11-Bab4/laporan_implementasi_lengkap.md` | NOT ACCESSIBLE | ⚠️ PARTIAL | MEDIUM | Documented but not directly verified |
| 25 | Threat Score Index | cti-threat-score-iqbal | REPOSITORY | `11-Bab4/laporan_implementasi_lengkap.md` | NOT ACCESSIBLE | ⚠️ PARTIAL | MEDIUM | Documented with sample data (3 IPs) |
| 26 | Dashboard Visualizations | 6 created | REPOSITORY | `11-Bab4/laporan_implementasi_lengkap.md` | NOT ACCESSIBLE | ⚠️ PARTIAL | MEDIUM | Documented but Kibana not accessible |
| 27 | MITRE Mapping File | EXISTS | REPOSITORY | `05-MITRE/mitre-mapping.yml` | /etc/logstash/dictionaries/ (NOT ACCESSIBLE) | ✅ YES | HIGH | File exists in repo; Runtime location documented |
| 28 | PAM/Session Events | EXISTS (noise) | ESTIMATED | NOT FOUND | NOT FOUND | ❌ NO | NONE | Assumed noise type; NO ACTUAL SAMPLES |
| 29 | Suricata Invalid ACK | EXISTS (noise) | ESTIMATED | NOT FOUND | NOT FOUND | ❌ NO | NONE | Assumed noise type; NO ACTUAL SAMPLES |
| 30 | CSV Export Files | NOT FOUND | NOT FOUND | NOT FOUND | NOT FOUND | ❌ NO | NONE | Script generates CSV but NO FILES in repository |

---

## CRITICAL FINDINGS

### ✅ REPOSITORY VERIFIED (High Confidence)

1. **MTTD/MTTR Metrics (10 iterations)**
   - Source: `11-Bab4/laporan_implementasi_lengkap.md`
   - Data: Complete table with timestamps
   - Confidence: HIGH
   - Status: Can be used for thesis

2. **Attack Validation (3 types)**
   - Source: `07-Testing/{Nmap,Hydra,Nikto}/validation_success.txt`
   - Confidence: HIGH
   - Status: Proven detection capability

3. **MITRE Mapping Dictionary**
   - Source: `05-MITRE/mitre-mapping.yml`
   - Contains: ~25 SID → Technique mappings
   - Confidence: HIGH
   - Status: Implementation verified

4. **SOAR Application Schema**
   - Source: `12-SOAR-Dashboard/app/soar_app.py`
   - Verified: Complete schema with MTTD/MTTR fields
   - Confidence: HIGH
   - Status: Implementation correct

5. **Network Topology**
   - Source: Multiple configuration files + `AUDIT_REPORT_GROUND_TRUTH.md`
   - IPs: 192.168.56.10 (SOC), 192.168.56.106 (Victim), 192.168.56.105 (Attacker)
   - Confidence: HIGH
   - Status: Lab environment verified

### ❌ NOT VERIFIED (No Evidence)

1. **Incident Count: ~9020**
   - Source: Master context claim only
   - Repository: NO MENTION
   - Runtime: NOT ACCESSIBLE
   - Status: **UNVERIFIED CLAIM**

2. **MITRE Coverage: 1 mapped vs 151 unmapped**
   - Source: Master context claim only
   - Repository: NO EVIDENCE
   - Runtime: NOT ACCESSIBLE
   - Status: **UNVERIFIED CLAIM**

3. **Noise Composition: 95% / 2-5%**
   - Source: Master context claim only
   - Repository: NO MEASUREMENTS
   - Runtime: NOT ACCESSIBLE
   - Status: **UNVERIFIED ESTIMATE**

4. **PAM Login/Session Events (noise samples)**
   - Source: Master context assumption
   - Repository: NO ACTUAL SAMPLES
   - Runtime: NOT ACCESSIBLE
   - Status: **UNVERIFIED ASSUMPTION**

5. **Suricata Stream Invalid ACK (noise samples)**
   - Source: Master context assumption
   - Repository: NO ACTUAL SAMPLES
   - Runtime: NOT ACCESSIBLE
   - Status: **UNVERIFIED ASSUMPTION**

6. **CSV Export Files**
   - Expected: `hasil_uji_mttd_10_iterasi.csv`
   - Repository: NOT FOUND
   - Runtime: NOT ACCESSIBLE
   - Status: **MISSING EVIDENCE**

### ⚠️ PARTIAL / CONFLICTING

1. **Incident Count: 606**
   - Source: `AUDIT_REPORT_GROUND_TRUTH.md` (20 Juni 2026)
   - Runtime: NOT CURRENTLY ACCESSIBLE
   - Confidence: MEDIUM (dated snapshot, not current)
   - Status: HISTORICAL DATA

2. **Hardcoded Password "123123"**
   - Audit Claims: Present in soar_app.py
   - Current Code: Comments indicate NOPASSWD migration in progress
   - Status: **CONFLICTING EVIDENCE** (code may have been updated after audit)

3. **SOAR Execution Mode**
   - Audit Claims: Manual/Nohup (no systemd service)
   - Priority List: Convert to systemd service (Priority 3)
   - Status: Known limitation, migration planned

---

## MISSING INFORMATION FOR DATASET HEALTH ASSESSMENT

### Critical Data Gaps (Cannot Be Determined from Repository)

1. **Current Actual Incident Count**
   - Need: `sqlite3 incidents.db "SELECT COUNT(*) FROM incidents;"`
   - Status: NOT ACCESSIBLE (SSH to SOC required)

2. **Current Attack Type Distribution**
   - Need: `sqlite3 incidents.db "SELECT attack_type, COUNT(*) FROM incidents GROUP BY attack_type;"`
   - Status: NOT ACCESSIBLE

3. **Current MITRE Status Distribution**
   - Need: `sqlite3 incidents.db "SELECT mitre_technique, COUNT(*) FROM incidents GROUP BY mitre_technique;"`
   - Status: NOT ACCESSIBLE

4. **Actual Noise Sample Events**
   - Need: Query incidents.db for events NOT from 192.168.56.105/108
   - Status: NOT ACCESSIBLE

5. **Event Signature Distribution**
   - Need: `sqlite3 incidents.db "SELECT attack_type, COUNT(*) FROM incidents GROUP BY attack_type ORDER BY COUNT(*) DESC LIMIT 20;"`
   - Status: NOT ACCESSIBLE

6. **Time Range of Dataset**
   - Need: `sqlite3 incidents.db "SELECT MIN(timestamp), MAX(timestamp) FROM incidents;"`
   - Status: NOT ACCESSIBLE

7. **Source IP Distribution**
   - Need: `sqlite3 incidents.db "SELECT src_ip, COUNT(*) FROM incidents GROUP BY src_ip;"`
   - Status: NOT ACCESSIBLE (would reveal noise sources)

8. **Current Elasticsearch MITRE Coverage**
   - Need: Query ES for mapped vs unmapped events
   - Status: NOT ACCESSIBLE

9. **Current Threat Score Index Status**
   - Need: Query `cti-threat-score-iqbal` index
   - Status: NOT ACCESSIBLE

10. **Actual PAM/Wazuh Internal Event Count**
    - Need: Grep/query for "PAM", "session", "wazuh" in attack_type field
    - Status: NOT ACCESSIBLE

---

## VERIFIABLE VS ASSUMED DATA

### ✅ VERIFIABLE FROM REPOSITORY

| Data Type | Evidence Location | Verification Method |
|-----------|-------------------|---------------------|
| MTTD/MTTR (10 iterations) | `11-Bab4/laporan_implementasi_lengkap.md` | Direct read of report table |
| Attack validation status | `07-Testing/*/validation_success.txt` | File existence + content check |
| MITRE mapping dictionary | `05-MITRE/mitre-mapping.yml` | Direct read of YAML file |
| SOAR schema | `12-SOAR-Dashboard/app/soar_app.py` | Code inspection |
| Network topology | Multiple config files | Cross-reference verification |
| System architecture | `11-Bab4/laporan_implementasi_lengkap.md` | Documentation review |

### ❌ CANNOT VERIFY FROM REPOSITORY (Runtime Required)

| Data Type | Requires | Current Status |
|-----------|----------|----------------|
| Current incident count | SSH + SQLite query | NOT ACCESSIBLE |
| Dataset composition | Database analysis | NOT ACCESSIBLE |
| Noise percentage | Database + pattern analysis | NOT ACCESSIBLE |
| MITRE coverage ratio | Elasticsearch query | NOT ACCESSIBLE |
| Threat score data | Elasticsearch query | NOT ACCESSIBLE |
| Dashboard visualization status | Kibana access | NOT ACCESSIBLE |
| Logstash pipeline status | systemctl status | NOT ACCESSIBLE |
| Elasticsearch index size | curl ES API | NOT ACCESSIBLE |

### 🔮 ASSUMPTIONS IN MASTER CONTEXT (No Evidence)

| Claim | Evidence Status | Impact on Conclusions |
|-------|-----------------|----------------------|
| ~9020 incidents | NOT FOUND | Cannot validate scale claim |
| 95% noise | NOT MEASURED | Cannot validate contamination claim |
| 2-5% research data | NOT MEASURED | Cannot validate signal-to-noise ratio |
| MITRE 1:151 ratio | NOT FOUND | Cannot validate mapping coverage claim |
| PAM events are noise | NO SAMPLES | Cannot validate noise classification |

---

## CONCLUSIONS

### What We Know for Certain (Repository Evidence)

1. ✅ **10 MTTD/MTTR iterations were executed** (May 28, 2026)
   - Manual mode: Avg MTTD 1.70s, Avg MTTR 56.86s
   - Dashboard mode: Avg MTTD 3.36s, Avg MTTR 60.51s
   - Source: Implementation report with complete timestamp data

2. ✅ **3 attack types validated** (Nmap T1046, Hydra T1110.001, Nikto T1595)
   - Source: Validation marker files in 07-Testing/

3. ✅ **MITRE mapping implemented** with 25+ SID entries
   - Source: mitre-mapping.yml file

4. ✅ **SOAR application has correct schema** for MTTD/MTTR tracking
   - Source: soar_app.py code

5. ✅ **Lab network topology documented** (3 VMs, host-only network)
   - Source: Multiple configuration files + audit report

### What We Cannot Determine (No Evidence)

1. ❌ **Current incidents.db composition** - NOT ACCESSIBLE
2. ❌ **Actual noise percentage** - NOT MEASURED
3. ❌ **Current MITRE mapping coverage** - NOT ACCESSIBLE
4. ❌ **Dataset time range** - NOT ACCESSIBLE
5. ❌ **Source IP distribution** - NOT ACCESSIBLE
6. ❌ **Event signature distribution** - NOT ACCESSIBLE
7. ❌ **Actual PAM/Wazuh event samples** - NOT FOUND
8. ❌ **The ~9020 incident claim** - NO EVIDENCE
9. ❌ **The 1 mapped / 151 unmapped claim** - NO EVIDENCE

### Critical Gap for Dataset Health Assessment

**To determine the TRUE health of the research dataset, we MUST have:**

1. **SSH access to SOC Server (192.168.56.10)** to query:
   - incidents.db directly
   - Elasticsearch indices
   - Logstash pipeline status

2. **SQL queries on incidents.db:**
   ```sql
   -- Basic counts
   SELECT COUNT(*) FROM incidents;
   SELECT status, COUNT(*) FROM incidents GROUP BY status;
   SELECT attack_type, COUNT(*) FROM incidents GROUP BY attack_type;
   
   -- MITRE distribution
   SELECT mitre_technique, COUNT(*) FROM incidents 
   GROUP BY mitre_technique ORDER BY COUNT(*) DESC;
   
   -- Source IP distribution (to identify noise sources)
   SELECT src_ip, COUNT(*) FROM incidents 
   GROUP BY src_ip ORDER BY COUNT(*) DESC;
   
   -- Time range
   SELECT MIN(timestamp), MAX(timestamp) FROM incidents;
   
   -- Sample of attack types (to classify noise)
   SELECT DISTINCT attack_type FROM incidents LIMIT 50;
   ```

3. **Elasticsearch queries:**
   ```bash
   # MITRE coverage
   curl -X GET "https://localhost:9200/cti-logs-iqbal-*/_search" -d '{
     "size": 0,
     "aggs": {
       "mapped": {"filter": {"exists": {"field": "mitre.technique_id"}}},
       "unmapped": {"filter": {"bool": {"must_not": {"exists": {"field": "mitre.technique_id"}}}}}
     }
   }'
   ```

---

## RECOMMENDATION

**CURRENT STATUS:** Cannot make definitive conclusions about dataset health based solely on repository evidence.

**REQUIRED ACTION:** Runtime system access to perform actual queries and measurements.

**ALTERNATIVE:** If runtime access unavailable, rely ONLY on the **verified MTTD/MTTR dataset** (10 iterations) from the implementation report, which IS documented and verifiable from repository evidence.

---

## CONFIDENCE LEVELS

| Evidence Type | Confidence | Can Use for Thesis? |
|---------------|-----------|---------------------|
| MTTD/MTTR (10 iterations) | HIGH ✅ | YES |
| Attack validation (3 types) | HIGH ✅ | YES |
| MITRE mapping implementation | HIGH ✅ | YES |
| SOAR schema | HIGH ✅ | YES |
| Network topology | HIGH ✅ | YES |
| Incident count (606) | MEDIUM ⚠️ | CAUTION (dated) |
| Incident count (~9020) | NONE ❌ | NO |
| Noise percentage (95%) | NONE ❌ | NO |
| MITRE 1:151 ratio | NONE ❌ | NO |

---

**END OF EVIDENCE CLASSIFICATION AUDIT**
