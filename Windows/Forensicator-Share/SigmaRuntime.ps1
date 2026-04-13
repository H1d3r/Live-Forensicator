if(-not $script:sigmaBundlePath){
    $script:sigmaBundlePath = Join-Path $PSScriptRoot "sigma-rules-precompiled.json"
}

function Get-SigmaSeverityValue {
    param([string]$Level)

    $levelMap = @{
        "critical"      = 5
        "high"          = 4
        "medium"        = 3
        "low"           = 2
        "informational" = 1
    }

    return ($levelMap[$Level.ToLowerInvariant()] ?? 0)
}

function Get-SigmaRuleBundle {
    param([string]$BundlePath = $script:sigmaBundlePath)

    if(-not (Test-Path $BundlePath)){
        Write-ForensicLog "Precompiled Sigma bundle missing — skipping detection" -Level WARN -Section "SIGMA" -Detail "Bundle not found at $BundlePath."
        return $null
    }

    try{
        return (Get-Content $BundlePath -Raw -ErrorAction Stop | ConvertFrom-Json -Depth 100)
    }
    catch{
        Write-ForensicLog "Failed to load Sigma bundle: $($_.Exception.Message)" -Level ERROR -Section "SIGMA"
        return $null
    }
}

function ConvertTo-SigmaWildcardRegex {
    param(
        [string]$Value,
        [ValidateSet("exact","contains","startswith","endswith")]
        [string]$Mode
    )

    $escaped = [regex]::Escape($Value) -replace '\\\*', '.*' -replace '\\\?', '.'

    switch($Mode){
        "exact"      { return "^$escaped$" }
        "contains"   { return "^.*$escaped.*$" }
        "startswith" { return "^$escaped.*$" }
        "endswith"   { return "^.*$escaped$" }
    }
}

function Get-SigmaComparableValues {
    param(
        [string]$Value,
        [bool]$Windash
    )

    $values = [System.Collections.Generic.List[string]]::new()
    $values.Add($Value)

    if($Windash){
        if($Value.Contains('-')){
            $values.Add($Value -replace '-', '/')
        }
        if($Value.Contains('/')){
            $values.Add($Value -replace '/', '-')
        }
    }

    return $values | Where-Object { $_ } | Select-Object -Unique
}

function Test-SigmaCidrMatch {
    param(
        [string]$Address,
        [string]$Cidr
    )

    try{
        $parts = $Cidr.Split('/', 2)
        if($parts.Count -ne 2){ return $false }

        $ipAddress    = [System.Net.IPAddress]::Parse($Address)
        $network      = [System.Net.IPAddress]::Parse($parts[0])
        $prefixLength = [int]$parts[1]

        if($ipAddress.AddressFamily -ne $network.AddressFamily){
            return $false
        }

        $ipBytes      = $ipAddress.GetAddressBytes()
        $networkBytes = $network.GetAddressBytes()
        $remaining    = $prefixLength

        for($index = 0; $index -lt $ipBytes.Length; $index++){
            if($remaining -le 0){ break }

            if($remaining -ge 8){
                if($ipBytes[$index] -ne $networkBytes[$index]){
                    return $false
                }
                $remaining -= 8
                continue
            }

            $mask = [byte]((([int]0xFF) -shl (8 - $remaining)) -band 0xFF)
            if(($ipBytes[$index] -band $mask) -ne ($networkBytes[$index] -band $mask)){
                return $false
            }
            $remaining = 0
        }

        return $true
    }
    catch{
        return $false
    }
}

function Test-SigmaScalarMatch {
    param(
        [string]$Actual,
        [string]$Expected,
        [string]$Operator,
        [bool]$IgnoreCase
    )

    if($null -eq $Actual){
        return $false
    }

    if($Operator -eq "cidr"){
        return (Test-SigmaCidrMatch -Address $Actual -Cidr $Expected)
    }

    if($Operator -eq "re"){
        try{
            $options = [System.Text.RegularExpressions.RegexOptions]::None
            if($IgnoreCase){
                $options = $options -bor [System.Text.RegularExpressions.RegexOptions]::IgnoreCase
            }
            return [regex]::IsMatch($Actual, $Expected, $options)
        }
        catch{
            return $false
        }
    }

    $pattern = ConvertTo-SigmaWildcardRegex -Value $Expected -Mode $Operator
    $options = [System.Text.RegularExpressions.RegexOptions]::None
    if($IgnoreCase){
        $options = $options -bor [System.Text.RegularExpressions.RegexOptions]::IgnoreCase
    }

    return [regex]::IsMatch($Actual, $pattern, $options)
}

function Test-SigmaFieldMatcher {
    param(
        $Matcher,
        $Context
    )

    $fieldName = [string]$Matcher.field
    $actual    = [string]($Context.Fields[$fieldName] ?? "")
    $operator  = [string]$Matcher.operator

    if($operator -eq "is_null"){
        return [string]::IsNullOrWhiteSpace($actual)
    }

    $perValueResults = foreach($rawValue in @($Matcher.values)){
        $valueMatched = $false
        foreach($candidate in Get-SigmaComparableValues -Value ([string]$rawValue) -Windash ([bool]$Matcher.windash)){
            if(Test-SigmaScalarMatch -Actual $actual -Expected $candidate -Operator $operator -IgnoreCase ([bool]$Matcher.ignore_case)){
                $valueMatched = $true
                break
            }
        }
        $valueMatched
    }

    if([string]$Matcher.match -eq "all"){
        return (-not ($perValueResults -contains $false))
    }

    return ($perValueResults -contains $true)
}

function Test-SigmaRawMatcher {
    param(
        $Matcher,
        $Context
    )

    $perValueResults = foreach($rawValue in @($Matcher.values)){
        Test-SigmaScalarMatch -Actual ([string]$Context.RawText) -Expected ([string]$rawValue) -Operator ([string]$Matcher.operator) -IgnoreCase ([bool]$Matcher.ignore_case)
    }

    if([string]$Matcher.match -eq "all"){
        return (-not ($perValueResults -contains $false))
    }

    return ($perValueResults -contains $true)
}

function Test-SigmaExpression {
    param(
        $Expression,
        $Context,
        [hashtable]$ItemResults
    )

    if($null -eq $Expression){ return $false }

    switch([string]$Expression.type){
        "all" {
            foreach($child in @($Expression.children)){
                if(-not (Test-SigmaExpression -Expression $child -Context $Context -ItemResults $ItemResults)){
                    return $false
                }
            }
            return $true
        }
        "any" {
            foreach($child in @($Expression.children)){
                if(Test-SigmaExpression -Expression $child -Context $Context -ItemResults $ItemResults){
                    return $true
                }
            }
            return $false
        }
        "not" {
            return (-not (Test-SigmaExpression -Expression $Expression.child -Context $Context -ItemResults $ItemResults))
        }
        "field" {
            return (Test-SigmaFieldMatcher -Matcher $Expression -Context $Context)
        }
        "raw" {
            return (Test-SigmaRawMatcher -Matcher $Expression -Context $Context)
        }
        "item_ref" {
            return [bool]($ItemResults[[string]$Expression.name] ?? $false)
        }
        "wildcard_ref" {
            $pattern = [string]$Expression.pattern
            $keys = if($pattern.ToLowerInvariant() -eq "them"){
                @($ItemResults.Keys)
            }
            else{
                @($ItemResults.Keys | Where-Object { $_ -like $pattern })
            }

            if($keys.Count -eq 0){
                return $false
            }

            if([string]$Expression.mode -eq "all"){
                foreach($key in $keys){
                    if(-not [bool]$ItemResults[$key]){
                        return $false
                    }
                }
                return $true
            }

            foreach($key in $keys){
                if([bool]$ItemResults[$key]){
                    return $true
                }
            }
            return $false
        }
        default {
            return $false
        }
    }
}

function ConvertTo-SigmaEventContext {
    param(
        $Event,
        $Source
    )

    $xml = [xml]$Event.ToXml()
    $eventData = @{}

    if($xml.Event.EventData -and $xml.Event.EventData.Data){
        foreach($node in @($xml.Event.EventData.Data)){
            if($node.Name){
                $eventData[[string]$node.Name] = [string]$node.'#text'
            }
        }
    }

    $systemValues = @{
        EventID      = [string]$Event.Id
        Channel      = [string]$Event.LogName
        ProviderName = [string]$xml.Event.System.Provider.Name
    }

    $fields = @{}
    foreach($property in $Source.field_map.PSObject.Properties){
        $fieldName = [string]$property.Name
        $mapping   = $property.Value
        $value     = $null

        switch([string]$mapping.kind){
            "eventdata" { $value = $eventData[[string]$mapping.name] }
            "system"    { $value = $systemValues[[string]$mapping.name] }
        }

        if($null -ne $value){
            $fields[$fieldName] = [string]$value
        }
    }

    $rawText = ""
    try{
        $rawText = [string]$Event.Message
    }
    catch{
        $rawText = ""
    }

    if([string]::IsNullOrWhiteSpace($rawText)){
        $rawText = $xml.OuterXml
    }
    else{
        $rawText = $rawText + "`n" + $xml.OuterXml
    }

    return @{
        Event     = $Event
        Fields    = $fields
        EventData = $eventData
        RawText   = $rawText
    }
}

function Test-SigmaRuleMatch {
    param(
        $Rule,
        $Context
    )

    $itemResults = @{}
    foreach($property in $Rule.items.PSObject.Properties){
        $itemResults[[string]$property.Name] = Test-SigmaExpression -Expression $property.Value -Context $Context -ItemResults $itemResults
    }

    return (Test-SigmaExpression -Expression $Rule.condition -Context $Context -ItemResults $itemResults)
}

function ConvertTo-SigmaFilterXml {
    param(
        $Source,
        [int]$DaysBack
    )

    $logName = [string]$Source.log_name
    $safeLogName = [System.Security.SecurityElement]::Escape($logName)
    $startTimeUtc = (Get-Date).AddDays(-$DaysBack).ToUniversalTime().ToString("o", [System.Globalization.CultureInfo]::InvariantCulture)

    $systemClauses = [System.Collections.Generic.List[string]]::new()
    $eventIdClauses = @($Source.event_ids | ForEach-Object { "EventID=$([int]$_)" })
    if($eventIdClauses.Count -gt 0){
        $systemClauses.Add("(" + ($eventIdClauses -join " or ") + ")")
    }
    $systemClauses.Add("TimeCreated[@SystemTime&gt;='$startTimeUtc']")

    $systemFilter = $systemClauses -join " and "

    return [xml]@"
<QueryList>
  <Query Id="0" Path="$safeLogName">
    <Select Path="$safeLogName">*[System[$systemFilter]]</Select>
  </Query>
</QueryList>
"@
}

function Invoke-SigmaScan {
    param(
        [string]$BundlePath = $script:sigmaBundlePath,
        [int]   $DaysBack   = 30,
        [ValidateSet("critical","high","medium","low","informational")]
        [string]$MinLevel   = "medium"
    )

    $results     = [System.Collections.Generic.List[PSCustomObject]]::new()
    $bundle      = Get-SigmaRuleBundle -BundlePath $BundlePath
    $seenMatches = [System.Collections.Generic.HashSet[string]]::new()

    if($null -eq $bundle){
        return ,$results
    }

    Write-ForensicLog "Loaded precompiled Sigma bundle" -Level INFO -Section "SIGMA" -Detail "Generated: $($bundle.metadata.generated_at_utc) | Compiled rules: $($bundle.metadata.compiled_rule_count) | Skipped at build time: $($bundle.metadata.skipped_rule_count)"

    $minLevelNum = Get-SigmaSeverityValue -Level $MinLevel
    $rules = @($bundle.rules | Where-Object { (Get-SigmaSeverityValue -Level ([string]$_.level)) -ge $minLevelNum })

    if($rules.Count -eq 0){
        Write-ForensicLog "No Sigma rules met the selected severity threshold" -Level WARN -Section "SIGMA" -Detail "Minimum level: $MinLevel"
        return ,$results
    }

    $sourceMap = @{}
    foreach($source in @($bundle.sources)){
        $sourceMap[[string]$source.id] = $source
    }

    $rulesBySource = @{}
    foreach($rule in $rules){
        foreach($sourceId in @($rule.sources)){
            if(-not $rulesBySource.ContainsKey([string]$sourceId)){
                $rulesBySource[[string]$sourceId] = [System.Collections.Generic.List[object]]::new()
            }
            $rulesBySource[[string]$sourceId].Add($rule)
        }
    }

    $sourceIds = @($rulesBySource.Keys | Sort-Object)
    $sourceIndex = 0

    foreach($sourceId in $sourceIds){
        $sourceIndex++
        $source = $sourceMap[$sourceId]
        if($null -eq $source){ continue }

        Write-Progress -Activity "Running Sigma Rules" `
                       -Status "[$sourceIndex/$($sourceIds.Count)] $([string]$source.log_name)" `
                       -PercentComplete ([Math]::Round(($sourceIndex / $sourceIds.Count) * 100))

        try{
            Get-WinEvent -ListLog ([string]$source.log_name) -ErrorAction Stop | Out-Null
        }
        catch{
            Write-ForensicLog "Skipping Sigma source — log not available" -Level WARN -Section "SIGMA" -Detail "$([string]$source.log_name)"
            continue
        }

        $filterXml = ConvertTo-SigmaFilterXml -Source $source -DaysBack $DaysBack

        try{
            foreach($event in Get-WinEvent -FilterXml $filterXml -ErrorAction Stop){
                $context = ConvertTo-SigmaEventContext -Event $event -Source $source

                foreach($rule in $rulesBySource[$sourceId]){
                    if(-not (Test-SigmaRuleMatch -Rule $rule -Context $context)){
                        continue
                    }

                    $recordId = [string]($event.RecordId ?? $event.Id)
                    $matchKey = "$sourceId|$([string]$rule.rule_file)|$recordId"
                    if(-not $seenMatches.Add($matchKey)){
                        continue
                    }

                    $results.Add([PSCustomObject]@{
                        RuleTitle   = [string]$rule.title
                        RuleLevel   = [string]$rule.level
                        RuleTags    = (@($rule.tags) -join ", ")
                        EventId     = $event.Id
                        LogName     = [string]$event.LogName
                        TimeCreated = $event.TimeCreated.ToLocalTime().ToString("yyyy-MM-dd HH:mm:ss")
                        User        = [string]($context.Fields["User"] ?? $context.EventData["SubjectUserName"] ?? $context.EventData["TargetUserName"] ?? "N/A")
                        CommandLine = [string]($context.Fields["CommandLine"] ?? $context.Fields["ScriptBlockText"] ?? $context.Fields["Payload"] ?? "N/A")
                        Process     = [string]($context.Fields["Image"] ?? $context.Fields["ImageLoaded"] ?? "N/A")
                        RuleFile    = [string]$rule.rule_file
                    })

                    Write-ForensicLog "SIGMA HIT: $([string]$rule.title)" `
                                      -Level FINDING `
                                      -Section "SIGMA" `
                                      -Detail "Level: $([string]$rule.level) | EventId: $($event.Id) | Time: $($event.TimeCreated)"
                }
            }
        }
        catch{
            Write-ForensicLog "Failed Sigma query for $([string]$source.log_name): $($_.Exception.Message)" -Level WARN -Section "SIGMA"
        }
    }

    Write-Progress -Activity "Running Sigma Rules" -Completed
    return ,$results
}
