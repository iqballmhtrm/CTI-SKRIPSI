# MITRE mapping changes — 2026-06-15

Added mapping entries for SIDs discovered during audit and retro-enrichment:

- `2013504` -> `T1105`
- `2033966` -> `T1102`
- `2033967` -> `T1102`

Deployment and PR instructions:

1. Create a branch and commit the files:

```
git checkout -b add/mitre-mappings-2026-06-15
git add "CTI-Skripsi/05-MITRE/mitre-mapping.yml" "CTI-Skripsi/05-MITRE/mitre-mapping-changes.md"
git commit -m "feat(mitre): add mappings for SIDs 2013504, 2033966, 2033967"
```

2. Push and open PR (example using GitHub CLI):

```
git remote add origin <git-remote-url>
git push -u origin add/mitre-mappings-2026-06-15
gh pr create --title "Add MITRE mappings" --body "Add MITRE mapping entries and deployment guidance." --base main --head add/mitre-mappings-2026-06-15
```

3. To deploy directly to SOC server (example):

```
scp "CTI-Skripsi/05-MITRE/mitre-mapping.yml" iqbal@192.168.56.10:/tmp/mitre-mapping.yml
ssh iqbal@192.168.56.10 'sudo mv /tmp/mitre-mapping.yml /etc/logstash/dictionaries/mitre-mapping.yml && sudo chown root:logstash /etc/logstash/dictionaries/mitre-mapping.yml && sudo chmod 640 /etc/logstash/dictionaries/mitre-mapping.yml && sudo systemctl restart logstash'
```

4. After deployment, run `_update_by_query` for each SID to retro-apply the MITRE enrichment (example below).

Example `_update_by_query` for SID `2013504`:

```
curl -s -k -u elastic 'https://localhost:9200/cti-logs-iqbal-*/_update_by_query?conflicts=proceed' -H 'Content-Type: application/json' -d '{
  "script": {
    "source": "if (ctx._source.mitre == null) ctx._source.mitre = new HashMap(); ctx._source.mitre.put(\"technique_id\", params.tech);",
    "lang": "painless",
    "params": {"tech":"T1105"}
  },
  "query": {"term": {"alert.signature_id": 2013504}}
}'
```

Notes:
- Use numeric `term` queries when `signature_id` is stored as an integer.
- Take an ES snapshot before mass `_update_by_query`.
