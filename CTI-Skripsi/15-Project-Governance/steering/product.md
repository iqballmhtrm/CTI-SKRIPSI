# Product Overview

This is a Cyber Threat Intelligence (CTI) research project (Skripsi/Thesis) implementing a Security Operations Center (SOC) system for threat detection and response.

## Core Capabilities

- **Threat Detection**: Suricata IDS with custom rules for detecting reconnaissance, brute force, and web vulnerability scanning attacks
- **Log Aggregation**: Elastic Stack (ELK) pipeline for collecting, enriching, and analyzing security events
- **Threat Intelligence**: MITRE ATT&CK framework integration for mapping detected attacks to known adversary techniques
- **Visualization**: Kibana dashboards for SOC analysts to monitor and investigate threats
- **Automated Response**: SOAR dashboard (Flask-based) for incident management and active response actions

## Validated Attack Scenarios

1. **Nmap Reconnaissance** → MITRE T1046 (Network Service Discovery)
2. **Hydra SSH Brute Force** → MITRE T1110.001 (Brute Force - Password Guessing)  
3. **Nikto Web Vulnerability Scan** → MITRE T1595.002 (Gather Victim Host Information)

## Environment

- **Language**: Mixed (Bash scripts, Python, configuration files)
- **Documentation**: Indonesian (Bahasa Indonesia) with English technical terms
- **Deployment**: VirtualBox lab environment with host-only network (192.168.56.0/24)
- **Purpose**: Academic research and demonstration (NOT production-ready)
