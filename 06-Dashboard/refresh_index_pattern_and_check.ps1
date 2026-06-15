param (
    [Parameter(Mandatory=$true, HelpMessage="Password for the 'elastic' user")]
    [string]$ElasticPassword
)

[System.Net.ServicePointManager]::SecurityProtocol = [System.Net.SecurityProtocolType]::Tls12
[System.Net.ServicePointManager]::ServerCertificateValidationCallback = { $true }

$kibana = 'http://192.168.56.10:5601'
$es = 'https://192.168.56.10:9200'
$auth = "elastic:$ElasticPassword"

$fieldsFile = 'C:\Users\mohiq\VirtualBox VMs\CTI-Skripsi\06-Dashboard\cti-fields.json'
$pattern = [System.Uri]::EscapeDataString('cti-logs-iqbal-*')
$metaFields = [System.Uri]::EscapeDataString('@timestamp')
$uri = "$kibana/api/index_patterns/_fields_for_wildcard?pattern=$pattern&meta_fields=$metaFields"

$headers = @{ 'kbn-xsrf' = 'true' }
$basic = [System.Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($auth))
$headers['Authorization'] = "Basic $basic"
$esHeaders = @{ Authorization = "Basic $basic" }

Write-Output "Fetching fields from Kibana: $uri"
try {
    $resp = Invoke-RestMethod -Uri $uri -Headers $headers -Method GET -ErrorAction Stop
    $resp | ConvertTo-Json -Depth 50 | Out-File -Encoding UTF8 $fieldsFile
    Write-Output "Saved fields to $fieldsFile"
} catch {
    Write-Warning ("Failed fetching fields from Kibana: " + ($_ | Out-String) + " - continuing to ES checks without refreshing index-pattern.")
}

$fieldsString = $null
if (Test-Path $fieldsFile) {
    $json = Get-Content -Raw -Path $fieldsFile | ConvertFrom-Json
    if ($json.fields) {
        $fieldsString = $json.fields | ConvertTo-Json -Depth 50
    } else {
        Write-Warning "No fields returned from Kibana; skipping index-pattern update."
    }
} else {
    Write-Warning "Fields file $fieldsFile not found; skipping index-pattern update."
}

$indexPatternIds = @('7afca9a4-6f1e-4e1c-81e0-b82fd03711b3','ba3ea9c0-2add-4700-b0e9-ebc444ef41ec')

if (-not $fieldsString) {
    Write-Output "Attempting to build fields from Elasticsearch mapping for pattern cti-logs-iqbal-*"
    $mapUri = "$es/cti-logs-iqbal-*/_mapping"
    try {
        $mapResp = Invoke-RestMethod -Uri $mapUri -Headers $esHeaders -Method Get -ErrorAction Stop
    } catch {
        Write-Warning ("Failed fetching mapping from ES via Invoke-RestMethod: " + ($_ | Out-String))
        $mapResp = $null
        try {
            Write-Output "Attempting curl fallback to fetch ES mapping..."
            $mapJson = & curl.exe -sS -u $auth -k $mapUri
            if ($mapJson) { $mapResp = $mapJson | ConvertFrom-Json }
        } catch {
            Write-Warning ("curl fallback failed: " + ($_ | Out-String))
        }
    }

    if ($mapResp) {
        $fieldDict = @{}

        function Process-Props($props, $prefix) {
            foreach ($prop in $props.PSObject.Properties) {
                $pname = $prop.Name
                if ($prefix -and $prefix -ne '') { $fullname = "$prefix.$pname" } else { $fullname = $pname }
                $val = $prop.Value
                if ($val.type) {
                    if (-not $fieldDict.ContainsKey($fullname)) { $fieldDict[$fullname] = @() }
                    $fieldDict[$fullname] += $val.type
                }
                if ($val.properties) {
                    Process-Props $val.properties $fullname
                }
                if ($val.fields) {
                    foreach ($sub in $val.fields.PSObject.Properties) {
                        $subname = "$fullname.$($sub.Name)"
                        $subval = $sub.Value
                        if ($subval.type) {
                            if (-not $fieldDict.ContainsKey($subname)) { $fieldDict[$subname] = @() }
                            $fieldDict[$subname] += $subval.type
                        }
                        if ($subval.properties) { Process-Props $subval.properties $subname }
                    }
                }
            }
        }

        foreach ($idx in $mapResp.PSObject.Properties) {
            $mappingRoot = $null
            if ($idx.Value.mappings) { $mappingRoot = $idx.Value.mappings }
            elseif ($idx.Value.mappings -eq $null -and $idx.Value.properties) { $mappingRoot = $idx.Value }
            if ($mappingRoot) {
                if ($mappingRoot.properties) { $startProps = $mappingRoot.properties } else { $startProps = $mappingRoot }
                if ($startProps -and $startProps.PSObject.Properties.Count -gt 0) { Process-Props $startProps "" }
            }
        }

        $fieldsArray = @()
        foreach ($k in $fieldDict.Keys | Sort-Object) {
            $group = $fieldDict[$k] | Group-Object | Sort-Object Count -Descending
            $esType = $group[0].Name
            switch ($esType) {
                'keyword' { $kt = 'string' }
                'text' { $kt = 'string' }
                'date' { $kt = 'date' }
                'boolean' { $kt = 'boolean' }
                'long' { $kt = 'number' }
                'integer' { $kt = 'number' }
                'short' { $kt = 'number' }
                'byte' { $kt = 'number' }
                'double' { $kt = 'number' }
                'float' { $kt = 'number' }
                'half_float' { $kt = 'number' }
                'scaled_float' { $kt = 'number' }
                'ip' { $kt = 'ip' }
                'geo_point' { $kt = 'geo_point' }
                default { $kt = 'string' }
            }

            $searchable = $true
            $aggregatable = $false
            if ($esType -in @('keyword','long','integer','short','byte','double','float','half_float','scaled_float','date','ip')) { $aggregatable = $true }
            if ($esType -eq 'text') { $aggregatable = $false }
            $readFromDocValues = $aggregatable

            $entry = @{ name = $k; type = $kt; searchable = $searchable; aggregatable = $aggregatable; count = 0; scripted = $false; esTypes = @($esType); readFromDocValues = $readFromDocValues }
            $fieldsArray += $entry
        }

        $fieldsString = $fieldsArray | ConvertTo-Json -Depth 20
        Write-Output ("Built fields JSON with $($fieldsArray.Count) fields from ES mapping.")
    } else {
        Write-Warning "Could not build fields from ES mapping; proceeding without updating index-patterns."
    }
}

if ($fieldsString) {
    $payloadObj = @{ attributes = @{ fields = $fieldsString } }
    $payloadJson = $payloadObj | ConvertTo-Json -Depth 50
    foreach ($id in $indexPatternIds) {
        $updateUri = "$kibana/api/saved_objects/index-pattern/$id"
        Write-Output "Updating index-pattern $id..."
        try {
            $updateResp = Invoke-RestMethod -Method Put -Uri $updateUri -Headers $headers -ContentType 'application/json' -Body $payloadJson -ErrorAction Stop
            Write-Output ("Updated index-pattern: " + $updateResp.id + " (" + $updateResp.attributes.title + ")")
        } catch {
            Write-Error ("Failed updating index-pattern " + $id + ": " + ($_ | Out-String))
        }
    }
} else {
    Write-Output "Skipping index-pattern update because fields could not be built."
}

# Query Elasticsearch for top mitre.technique_id
$searchUri = "$es/cti-logs-iqbal-*/_search?size=0"
$aggBody = @{
    aggs = @{
        by_mitre = @{
            terms = @{ field = "mitre.technique_id.keyword"; size = 10 }
        }
    }
} | ConvertTo-Json -Depth 10

$esHeaders = @{ Authorization = "Basic $basic" }

Write-Output "Querying Elasticsearch for top mitre.technique_id (terms on mitre.technique_id.keyword)"
try {
    $esResp = Invoke-RestMethod -Uri $searchUri -Method Post -Headers $esHeaders -ContentType 'application/json' -Body $aggBody -ErrorAction Stop
} catch {
    Write-Error ("First attempt failed; trying GET with body fallback: " + ($_ | Out-String))
    try {
        $esResp = Invoke-RestMethod -Uri $searchUri -Method Get -Headers $esHeaders -ContentType 'application/json' -Body $aggBody -ErrorAction Stop
    } catch {
        Write-Error ("Elasticsearch query failed: " + ($_ | Out-String))
        exit 4
    }
}

if ($esResp.aggregations -and $esResp.aggregations.by_mitre.buckets) {
    Write-Output "Top MITRE technique buckets:"
    $esResp.aggregations.by_mitre.buckets | ForEach-Object { Write-Output ("$($_.key) : $($_.doc_count)") }
} else {
    Write-Output "No aggregation buckets returned; check field name or data presence."
}

# Show one sample document with mitre.technique_id
$sampleQuery = '{"query":{"exists":{"field":"mitre.technique_id"}},"size":1}'
try {
    $sample = Invoke-RestMethod -Uri "$es/cti-logs-iqbal-*/_search" -Method Post -Headers $esHeaders -ContentType 'application/json' -Body $sampleQuery -ErrorAction Stop
    if ($sample.hits.hits.Count -gt 0) {
        Write-Output "Sample document (source):"
        $sample.hits.hits[0]._source | ConvertTo-Json -Depth 10 | Write-Output
    } else {
        Write-Output "No sample documents with mitre.technique_id found."
    }
} catch {
    Write-Error ("Failed to fetch sample doc: " + ($_ | Out-String))
}

Write-Output "Done."
