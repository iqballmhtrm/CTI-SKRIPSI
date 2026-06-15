$auth = 'elastic:lflqgBlynmWIBHgzvN17lvZ1Lz34qAxn'
$kibana = 'http://192.168.56.10:5601'
$ids = @('7afca9a4-6f1e-4e1c-81e0-b82fd03711b3','ba3ea9c0-2add-4700-b0e9-ebc444ef41ec')
foreach ($id in $ids) {
    $url = "$kibana/api/saved_objects/index-pattern/$id"
    $respRaw = & curl.exe -sS -u $auth -k $url | Out-String
    try { $j = $respRaw | ConvertFrom-Json } catch { Write-Output "PARSE_FAIL $id"; continue }
    $fields = $j.attributes.fields
    $found = $false
    if ($fields -match '"name"\s*:\s*"mitre.technique_id"') { $found = $true }
    if ($found) { $status = 'FOUND' } else { $status = 'NOTFOUND' }
    Write-Output ($id + ': ' + $status + ' (fields length: ' + $fields.Length + ')')
}
