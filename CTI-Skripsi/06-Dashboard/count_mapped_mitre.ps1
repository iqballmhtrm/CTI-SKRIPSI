$es = 'https://192.168.56.10:9200'
[System.Net.ServicePointManager]::SecurityProtocol = [System.Net.SecurityProtocolType]::Tls12
[System.Net.ServicePointManager]::ServerCertificateValidationCallback = { $true }
$auth = 'elastic:lflqgBlynmWIBHgzvN17lvZ1Lz34qAxn'
$basic = [System.Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($auth))
$headers = @{ Authorization = "Basic $basic" }
$body = @{
    query = @{
        bool = @{
            must = @(
                @{ exists = @{ field = 'mitre.technique_id' } },
                @{ bool = @{ must_not = @(@{ term = @{ 'mitre.technique_id.keyword' = 'Unmapped' } }) } }
            )
        }
    }
}
$b = $body | ConvertTo-Json -Depth 10
$r = Invoke-RestMethod -Uri "$es/cti-logs-iqbal-*/_count" -Method Post -Headers $headers -ContentType 'application/json' -Body $b
Write-Output ("mapped_count=" + $r.count)
