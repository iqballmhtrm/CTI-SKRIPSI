[System.Net.ServicePointManager]::SecurityProtocol = [System.Net.SecurityProtocolType]::Tls12
[System.Net.ServicePointManager]::ServerCertificateValidationCallback = { $true }

$es = 'https://192.168.56.10:9200'
$auth = 'elastic:lflqgBlynmWIBHgzvN17lvZ1Lz34qAxn'
$basic = [System.Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($auth))
$headers = @{ Authorization = "Basic $basic" }

Function DoCount($bodyObj, $label) {
    $body = $bodyObj | ConvertTo-Json -Depth 10
    try {
        $r = Invoke-RestMethod -Uri "$es/cti-logs-iqbal-*/_count" -Method Post -Headers $headers -ContentType 'application/json' -Body $body -ErrorAction Stop
        Write-Output "$label => $($r.count)"
    } catch {
        Write-Output "$label => ERROR: $($_ | Out-String)"
    }
}

Write-Output "=== Total documents (all time) ==="
try { $total = Invoke-RestMethod -Uri "$es/cti-logs-iqbal-*/_count" -Method Get -Headers $headers -ErrorAction Stop; Write-Output ("total => " + $total.count) } catch { Write-Output ("total => ERROR: " + ($_ | Out-String)) }

Write-Output "=== Counts by time window ==="
DoCount @{ query = @{ range = @{ "@timestamp" = @{ gte = "now-24h" } } } } "last24h"
DoCount @{ query = @{ range = @{ "@timestamp" = @{ gte = "now-7d" } } } } "last7d"
DoCount @{ query = @{ range = @{ "@timestamp" = @{ gte = "now-30d" } } } } "last30d"

Write-Output "=== Indices matching cti-logs-iqbal-* (index, docs.count, store.size) ==="
try {
    $idxs = Invoke-RestMethod -Uri "$es/_cat/indices/cti-logs-iqbal-*?h=index,docs.count,store.size&s=index&format=json" -Method Get -Headers $headers -ErrorAction Stop
    $idxs | ForEach-Object { Write-Output ("$($_.index)  docs:$($_.'docs.count')  size:$($_.'store.size')") }
} catch { Write-Output ("index list ERROR: " + ($_ | Out-String)) }

$fieldsToCheck = @('mitre.technique_id','alert_count','unique_techniques','source.ip','destination.port','suricata.eve.alert.signature_id')
Write-Output "=== Field existence counts ==="
foreach ($f in $fieldsToCheck) {
    $body = @{ query = @{ exists = @{ field = $f } } }
    DoCount $body "$f"
}

Write-Output "=== Sample docs with mitre.technique_id (size=3) ==="
try {
    $sample = Invoke-RestMethod -Uri "$es/cti-logs-iqbal-*/_search?size=3&sort=@timestamp:desc" -Method Get -Headers $headers -ErrorAction Stop
    if ($sample.hits.hits.Count -gt 0) {
        $sample.hits.hits | ForEach-Object { $_._source | ConvertTo-Json -Depth 10 | Write-Output }
    } else {
        Write-Output "No sample hits"
    }
} catch { Write-Output ("sample ERROR: " + ($_ | Out-String)) }

Write-Output "Done."
