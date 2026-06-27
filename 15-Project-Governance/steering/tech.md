# Technology Stack

## Core Components

### Security Infrastructure
- **Suricata IDS**: Network intrusion detection with custom rule definitions
- **Wazuh**: Host-based intrusion detection and security monitoring
- **Elastic Stack (ELK)**:
  - **Elasticsearch**: Log storage and search engine
  - **Logstash**: Log processing pipeline with MITRE ATT&CK enrichment
  - **Kibana**: Visualization and dashboard interface
- **Filebeat**: Log shipper from Suricata to Logstash

### SOAR Dashboard
- **Flask 3.0.0**: Python web framework for incident response interface
- **Werkzeug 3.0.1**: WSGI utility library
- **SQLite3**: Local database for incident tracking
- **Python 3**: Standard library (ipaddress, subprocess, sqlite3)

### Scripting & Automation
- **Bash**: Primary scripting language for system automation
- **PowerShell**: Dashboard manipulation and Kibana API interactions
- **Python**: Data processing, database queries, and API interactions

## Common Commands

### System Management
```bash
# Start ELK stack services
sudo systemctl start elasticsearch
sudo systemctl start logstash
sudo systemctl restart suricata
sudo systemctl start kibana

# Check system health
sudo systemctl status elasticsearch --no-pager
sudo systemctl status kibana --no-pager
sudo journalctl -u kibana -n 10 --no-pager
```

### Testing & Validation
```bash
# Simulate all attacks (inject test events)
cd 07-Testing
./simulate_all_attacks.sh

# Run MTTD (Mean Time To Detect) measurements
python3 run_10_iterations_mttd.py

# Inject specific payloads
./inject.sh
```

### Elasticsearch Operations
```bash
# Query Elasticsearch
curl -k -u elastic:PASSWORD https://localhost:9200/cti-logs-*/_search

# Check mappings
curl -k -u elastic:PASSWORD https://localhost:9200/cti-logs-*/_mapping

# Cleanup snapshots
./cleanup_snapshots.sh
```

### MITRE Mapping Management
```bash
# Apply MITRE mapping updates
cd 05-MITRE
./patch_mitre.sh

# Validate MITRE mappings
./tmp_mitre_check.sh

# Reset MITRE mapping to defaults
./reset_mitre_mapping.sh
```

### SOAR Dashboard
```bash
# Start SOAR application (on SOC Server)
cd 12-SOAR-Dashboard/app
python3 soar_app.py

# Install dependencies
pip3 install -r requirements.txt

# Database operations
python3 query_db.py
python3 schema.py
```

## Configuration Files

### Key Locations
- Elasticsearch config: `02-ELK/elasticsearch.yml`
- Logstash pipeline: `02-ELK/logstash.conf` or `12-SOAR-Dashboard/soc-pipeline.conf`
- Filebeat config: `02-ELK/filebeat.yml`
- Kibana config: `02-ELK/kibana.yml`
- Suricata rules: `03-Suricata/custom.rules`
- Wazuh config: `04-Wazuh/ossec.conf`
- MITRE mapping: `05-MITRE/mitre-mapping.yml`

### Naming Conventions
- Index pattern: `cti-logs-iqbal-*` or `cti-logs-*`
- Dashboard exports: `.ndjson` format (Kibana saved objects)
- Evidence files: JSON format with descriptive names
- Scripts: Descriptive names with `.sh` (Bash) or `.ps1` (PowerShell) extensions

## Development Patterns

### Script Structure
- Use `#!/bin/bash` or `#!/usr/bin/env bash` shebars
- Include `set -euo pipefail` for error handling in Bash
- Add descriptive comments for complex operations
- Use sudo for system service operations

### Security Considerations
- **SSL verification disabled** in Python scripts (lab environment only)
- **No authentication** on SOAR endpoints (lab environment only)
- Hardcoded credentials in scripts (acceptable for research, NOT for production)
- Host-only network isolation (192.168.56.0/24)

### Testing Approach
- Simulation-based: Inject synthetic events into Suricata eve.json log
- Validation: Query Elasticsearch for enriched events with MITRE fields
- Evidence collection: Save raw JSON responses for documentation
- Iterative testing: Run multiple iterations for MTTD metrics
