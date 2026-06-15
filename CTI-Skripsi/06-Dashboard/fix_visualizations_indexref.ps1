param (
    [Parameter(Mandatory=$true, HelpMessage="Password for the 'elastic' user")]
    [string]$ElasticPassword
)

[System.Net.ServicePointManager]::SecurityProtocol = [System.Net.SecurityProtocolType]::Tls12
[System.Net.ServicePointManager]::ServerCertificateValidationCallback = { $true }

$kibana = 'http://192.168.56.10:5601'
$auth = "elastic:$ElasticPassword"
$basic = [System.Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($auth))
$headers = @{ 'kbn-xsrf' = 'true'; Authorization = "Basic $basic" }

Write-Output "Fetching visualizations list from Kibana..."
$find = Invoke-RestMethod -Uri "$kibana/api/saved_objects/_find?type=visualization&per_page=1000" -Headers $headers -Method Get

foreach ($so in $find.saved_objects) {
    $id = $so.id
    Write-Output ("Checking visualization: " + $id)
    try {
        $full = Invoke-RestMethod -Uri "$kibana/api/saved_objects/visualization/$id" -Headers $headers -Method Get -ErrorAction Stop
    } catch {
        Write-Warning (("Failed to fetch full object for " + $id + ": ") + ($_ | Out-String))
        continue
    }

    $attrs = $full.attributes
    if (-not $attrs.kibanaSavedObjectMeta) { Write-Output ($id + ': no kibanaSavedObjectMeta, skipping'); continue }
    $searchJSON = $attrs.kibanaSavedObjectMeta.searchSourceJSON
    if (-not $searchJSON) { Write-Output ($id + ': no searchSourceJSON, skipping'); continue }

    try {
        $searchObj = $searchJSON | ConvertFrom-Json
    } catch {
        Write-Warning (($id + ': cannot parse searchSourceJSON, skipping') + " -- " + ($_ | Out-String))
        continue
    }

    if ($searchObj.PSObject.Properties.Name -contains 'index' -or $searchObj.PSObject.Properties.Name -contains 'indexRefName') {
        Write-Output ($id + ': already has index/indexRefName')
        continue
    }

    $refs = $full.references
    $hasIndexRef = $false
    foreach ($r in $refs) {
        if ($r.name -eq 'kibanaSavedObjectMeta.searchSourceJSON.index') { $hasIndexRef = $true; break }
    }
    if (-not $hasIndexRef) { Write-Output ($id + ': no index ref in references, skipping'); continue }

    Write-Output ($id + ': adding indexRefName to searchSourceJSON')
    # build a fresh object with existing properties + indexRefName to avoid SetValue issues
    $newObj = @{}
    foreach ($prop in $searchObj.PSObject.Properties) { $newObj[$prop.Name] = $prop.Value }
    $newObj['indexRefName'] = 'kibanaSavedObjectMeta.searchSourceJSON.index'
    $newSearchJSON = $newObj | ConvertTo-Json -Depth 50

    # assign back as string
    $attrs.kibanaSavedObjectMeta.searchSourceJSON = $newSearchJSON

    # prepare payload: include all existing attributes to avoid losses
    $payload = @{ attributes = $attrs } | ConvertTo-Json -Depth 100

    try {
        $updateResp = Invoke-RestMethod -Uri "$kibana/api/saved_objects/visualization/$id" -Method Put -Headers $headers -ContentType 'application/json' -Body $payload -ErrorAction Stop
        Write-Output ($id + ': updated')
    } catch {
        Write-Warning (("'" + $id + "': update failed: ") + ($_ | Out-String))
    }
}

Write-Output 'Done.'
