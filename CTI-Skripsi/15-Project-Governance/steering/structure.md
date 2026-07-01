# Project Structure

## Directory Organization

The repository follows a numbered folder structure that represents the logical flow of the CTI system implementation:

### Configuration & Infrastructure

- **`01-Topologi/`**: Network topology diagrams and architecture documentation
  - DrawIO diagrams showing SOC, victim, and attacker node relationships
  - DOCX files describing network setup

- **`02-ELK/`**: Elastic Stack configuration and management scripts
  - Service configuration files (elasticsearch.yml, logstash.conf, kibana.yml, filebeat.yml)
  - Startup and health check scripts
  - Pipeline patching and mapping cleanup utilities
  - Elasticsearch snapshot rotation scripts

- **`03-Suricata/`**: Suricata IDS custom rules
  - `custom.rules`: Detection signatures for CTI-LAB scenarios

- **`04-Wazuh/`**: Wazuh HIDS configuration
  - `ossec.conf`: Agent and manager configuration

- **`05-MITRE/`**: MITRE ATT&CK framework integration
  - `mitre-mapping.yml`: SID to MITRE technique ID dictionary
  - Patching and validation scripts for mapping updates
  - Validation output files

- **`06-Dashboard/`**: Kibana dashboard development
  - `.ndjson` exports of dashboard configurations (versioned)
  - PowerShell scripts for dashboard assembly and index pattern validation
  - Field mapping verification utilities

### Testing & Validation

- **`07-Testing/`**: Attack simulation and validation
  - Subdirectories for each attack type (Hydra/, Nikto/, Nmap/)
  - Simulation scripts (`simulate_all_attacks.sh`, `inject.sh`)
  - MTTD measurement scripts (`run_10_iterations_mttd.py`)
  - Payload JSON files for manual injection

- **`08-Screenshots/`**: Visual evidence organized by component
  - Subdirectories: Attacker/, Dashboard/, ELK/, SOC/, Victim/, Wazuh/, Repair-Validation/

- **`09-Evidence/`**: Raw data artifacts and validation reports
  - JSON dumps from Elasticsearch queries
  - Markdown reports (audit, validation, root cause analysis)
  - Backup configurations
  - Shell scripts for evidence collection

### Documentation

- **`10-Bab3/`**: Chapter 3 - System Design (Perancangan)
  - DOCX thesis chapter files
  - Markdown design documentation

- **`11-Bab4/`**: Chapter 4 - Implementation & Testing (Implementasi dan Pengujian)
  - DOCX thesis chapter files
  - Markdown implementation reports

### Utilities & Extensions

- **`12-Scripts_and_Dumps/`**: General-purpose utilities
  - Elasticsearch dump and export scripts
  - Dashboard fixing utilities
  - Query testing scripts
  - Scratch workspace for experimental code

- **`12-SOAR-Dashboard/`**: Flask-based SOAR application
  - `app/`: Main application code
    - `soar_app.py`: Flask application entry point
    - `requirements.txt`: Python dependencies
    - `templates/`: HTML templates for web UI
    - `forensics/`: Incident analysis modules
    - `.env.example`: Environment configuration template
  - `migrations/`: Database schema migrations
  - `tests/`: Test suites
  - `screenshots/`: Application screenshots
  - Pipeline configuration files for Logstash integration

- **`13-Audit/`**: Research audit tools and reports
  - `tools/`: Python and shell scripts for dataset analysis
    - `audit_dataset.py`: Main dataset audit script
    - `check_db.py`, `check_db_stats.py`: Database validation tools
    - `query_db.py`: Database query utilities
    - `reset_db.py`: Database reset utility
    - `run_audit.sh`, `run_audit2.sh`: Audit execution scripts
    - `SYSTEM_PROMPT_AUDITOR_CTI_ELK.md`: Auditor AI configuration
  - `reports/`: Audit findings and analysis reports
    - `EVIDENCE_SOURCE_CLASSIFICATION.md`: Evidence source verification

- **`13-Honeypot-Migration/`**: Cloud deployment preparation
  - `docs/`: Migration documentation
  - `elk-exploration/`: ELK configuration for cloud
  - `vpn-setup/`: VPN configuration for secure access
  - `vps-a-honeypot/`: Honeypot server setup
  - `vps-b-soc-server/`: SOC server cloud configuration

- **`14-Research/`**: Official research datasets and protocols
  - `datasets/`: Clean research datasets (30 controlled iterations)
  - `protocols/`: Testing protocols and methodologies

- **`15-Project-Governance/`**: Project management and AI governance
  - `prompts/`: AI assistant configuration prompts
    - `MASTER_PROMPT_CTI_ELK.md`: Main research context
    - `MASTER_PROMPT_FULL_LIFECYCLE_CTI.md`: Full lifecycle guidelines
  - `roadmaps/`: Project planning and roadmaps
    - `roadmap_master_final_cti_elk.html`: Master project roadmap
  - `steering/`: AI steering rules (also in `.kiro/steering/`)
    - `product.md`: Product overview and capabilities
    - `structure.md`: Project structure documentation
    - `tech.md`: Technology stack and commands

### Root Level Files

- **`README.md`**: Repository overview and structure explanation
- **`AUDIT_REPORT_GROUND_TRUTH.md`**: System validation and ground truth documentation
- **`test-clock-sync-v2.sh`**: Time synchronization testing script
- **`draft-text.txt`**: Working notes and draft content
- **`DRAFT-SKRIPSI-FINAL-IQBAL.docx`**: Complete thesis document

## File Naming Patterns

### Scripts
- Descriptive names with action verbs: `apply_`, `fix_`, `check_`, `validate_`, `simulate_`
- Version suffixes when iterating: `_v2`, `_v3`, `_v4`
- Unix variants: `_unix` suffix for cross-platform compatibility

### Configuration Files
- Standard names: `elasticsearch.yml`, `logstash.conf`, `kibana.yml`
- Component-specific prefixes: `soc-pipeline.conf`, `mitre-mapping.yml`

### Evidence & Exports
- Descriptive prefixes indicating content: `final-`, `dashboard-`, `mitre-`, `nmap-`, `hydra-`, `nikto-`
- Format suffixes: `.json`, `.ndjson`, `.md`, `.txt`
- Versioning: `-v2`, `-v3`, `-final`, `-after-fix`

## Development Workflow Patterns

1. **Configuration changes**: Edit in numbered folders (02-ELK, 05-MITRE)
2. **Testing**: Run simulations from 07-Testing, collect evidence in 09-Evidence
3. **Dashboard updates**: Develop in 06-Dashboard, export `.ndjson` versions
4. **Audit & Analysis**: Use tools in 13-Audit/tools/, save reports in 13-Audit/reports/
5. **Research datasets**: Store clean controlled datasets in 14-Research/datasets/
6. **Documentation**: Update thesis chapters in 10-Bab3, 11-Bab4
7. **SOAR development**: Work in 12-SOAR-Dashboard/app/
8. **Governance**: Maintain AI prompts and steering rules in 15-Project-Governance/

## Important Paths

### On SOC Server (Linux)
- Suricata log: `/var/log/suricata/eve.json`
- Logstash dictionaries: `/etc/logstash/dictionaries/mitre-mapping.yml`
- SOAR database: `/home/iqbal/soar-dashboard/app/incidents.db`
- Elasticsearch index: `cti-logs-iqbal-*`

### In Repository (Windows)
- Audit tools: `13-Audit/tools/`
- Audit reports: `13-Audit/reports/`
- Research datasets: `14-Research/datasets/`
- AI governance: `15-Project-Governance/`
- Kiro steering: `.kiro/steering/` (mirrored in `15-Project-Governance/steering/`)
