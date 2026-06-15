import json

with open('/var/log/suricata/eve.json', 'r') as f:
    for line in f:
        try:
            d = json.loads(line)
            if d.get("event_type") == "alert":
                print(json.dumps(d))
                break
        except:
            pass
