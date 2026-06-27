with open(r'C:\Users\mohiq\VirtualBox VMs\CTI-Skripsi\12-SOAR-Dashboard\soc-pipeline.conf.bak', 'r') as f:
    text = f.read()

sig_target = '''  if [wazuh][data][alert][signature_id] {

    mutate {
      add_field => {
        "[@metadata][sig_id_str]" => "%{[wazuh][data][alert][signature_id]}"
      }
    }

  } else if [suricata][eve][alert][signature_id] {'''
sig_replace = '''  if [wazuh][data][alert][signature_id] {
    mutate { add_field => { "[@metadata][sig_id_str]" => "%{[wazuh][data][alert][signature_id]}" } }
  } else if [rule][id] {
    mutate { add_field => { "[@metadata][sig_id_str]" => "%{[rule][id]}" } }
  } else if [alert][signature_id] {
    mutate { add_field => { "[@metadata][sig_id_str]" => "%{[alert][signature_id]}" } }
  } else if [suricata][eve][alert][signature_id] {'''
text = text.replace(sig_target, sig_replace)

soar_norm_target = '''    if [wazuh][data][alert][signature] {
      mutate { replace => { "[soar][attack_type]" => "%{[wazuh][data][alert][signature]}" } }
    } else if [alert][signature] {
      mutate { replace => { "[soar][attack_type]" => "%{[alert][signature]}" } }
    } else if [suricata][eve][alert][signature] {
      mutate { replace => { "[soar][attack_type]" => "%{[suricata][eve][alert][signature]}" } }
    }
    
    if [wazuh][data][rule][level] {
      mutate { replace => { "[soar][severity]" => "%{[wazuh][data][rule][level]}" } }
    } else if [alert][severity] {
      mutate { replace => { "[soar][severity]" => "%{[alert][severity]}" } }
    } else if [suricata][eve][alert][severity] {
      mutate { replace => { "[soar][severity]" => "%{[suricata][eve][alert][severity]}" } }
    }'''

soar_norm_replace = '''    if [wazuh][data][alert][signature] {
      mutate { replace => { "[soar][attack_type]" => "%{[wazuh][data][alert][signature]}" } }
    } else if [rule][description] {
      mutate { replace => { "[soar][attack_type]" => "%{[rule][description]}" } }
    } else if [alert][signature] {
      mutate { replace => { "[soar][attack_type]" => "%{[alert][signature]}" } }
    } else if [suricata][eve][alert][signature] {
      mutate { replace => { "[soar][attack_type]" => "%{[suricata][eve][alert][signature]}" } }
    }
    
    if [wazuh][data][rule][level] {
      mutate { replace => { "[soar][severity]" => "%{[wazuh][data][rule][level]}" } }
    } else if [rule][level] {
      mutate { replace => { "[soar][severity]" => "%{[rule][level]}" } }
    } else if [alert][severity] {
      mutate { replace => { "[soar][severity]" => "%{[alert][severity]}" } }
    } else if [suricata][eve][alert][severity] {
      mutate { replace => { "[soar][severity]" => "%{[suricata][eve][alert][severity]}" } }
    }

    if [mitre][technique_name] and [mitre][technique_name] != "Unmapped" {
      mutate {
        replace => { 
          "[soar][mitre_technique]" => "%{[mitre][technique_name]}" 
          "[soar][mitre_status]" => "Mapped"
        }
      }
    }'''
text = text.replace(soar_norm_target, soar_norm_replace)

fallback_target = '''        "[soar][attack_type]" => "Unknown Signature"
        "[soar][severity]" => "0"
        "[soar][mitre_technique]" => "Unmapped"'''
fallback_replace = '''        "[soar][attack_type]" => "Unknown Signature"
        "[soar][severity]" => "0"
        "[soar][mitre_technique]" => "Unmapped"
        "[soar][mitre_status]" => "Unmapped"'''
text = text.replace(fallback_target, fallback_replace)

http_target = '''  # --- SOAR HTTP WEBHOOK ---
  if [@metadata][sig_id_str] {
    http {
      url => "http://127.0.0.1:5000/webhook"
      http_method => "post"
      format => "json"
      mapping => {
        "timestamp_alert" => "%{@timestamp}"
        "src_ip" => "%{[source][ip]}"
        "attack_type" => "%{[soar][attack_type]}"
        "severity" => "%{[soar][severity]}"
        "mitre_technique" => "%{[soar][mitre_technique]}"
        "pipeline_source" => "logstash_http"
      }
    }
  }'''
http_replace = '''  # --- SOAR HTTP WEBHOOK ---
  if [@metadata][sig_id_str] {
    http {
      url => "http://127.0.0.1:5000/webhook"
      http_method => "post"
      format => "json"
      mapping => {
        "timestamp_alert" => "%{[@timestamp]}"
        "src_ip" => "%{[source][ip]}"
        "attack_type" => "%{[soar][attack_type]}"
        "severity" => "%{[soar][severity]}"
        "mitre_technique" => "%{[soar][mitre_technique]}"
        "mitre_status" => "%{[soar][mitre_status]}"
        "pipeline_source" => "logstash_http"
      }
    }
  }'''
text = text.replace(http_target, http_replace)

with open(r'C:\Users\mohiq\VirtualBox VMs\CTI-Skripsi\12-SOAR-Dashboard\soc-pipeline.conf', 'w') as f:
    f.write(text)
