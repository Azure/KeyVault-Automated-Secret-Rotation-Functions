param([object]$EventGridEvent, [object]$TriggerMetadata)

$MAX_RETRY_ATTEMPTS = 30
$MAX_JSON_DEPTH = 10
$DATA_PLANE_API_VERSION = "7.6-preview.1"
$AZURE_FUNCTION_NAME = "AkvStorageAccountConnectionStringConnector"

$EXPECTED_FUNCTION_APP_SUBSCRIPTION_ID = $env:WEBSITE_OWNER_NAME.Substring(0, 36)
$EXPECTED_FUNCTION_APP_RG_NAME = $env:WEBSITE_RESOURCE_GROUP
$EXPECTED_FUNCTION_APP_NAME = $env:WEBSITE_SITE_NAME
$EXPECTED_FUNCTION_RESOURCE_ID = "/subscriptions/$EXPECTED_FUNCTION_APP_SUBSCRIPTION_ID/resourceGroups/$EXPECTED_FUNCTION_APP_RG_NAME/providers/Microsoft.Web/sites/$EXPECTED_FUNCTION_APP_NAME/functions/$AZURE_FUNCTION_NAME"

function Get-InactiveCredentialId([string]$ActiveCredentialId) {
    $inactiveCredentialId = switch ($ActiveCredentialId) {
        "key1" { "key2" }
        "key2" { "key1" }
        default { throw "The active credential ID '$ActiveCredentialId' didn't match the expected pattern. Expected 'key1' or 'key2'." }
    }
    return $inactiveCredentialId
}

function Get-CredentialValue([string]$ActiveCredentialId, [string]$ProviderAddress) {
    if (-not ($ActiveCredentialId)) {
        return @($null, "The active credential ID is missing.")
    }
    if ($ActiveCredentialId -notin @("key1", "key2")) {
        return @($null, "The active credential ID '$ActiveCredentialId' didn't match the expected pattern. Expected 'key1' or 'key2'.")
    }
    if (-not ($ProviderAddress)) {
        return @($null, "The provider address is missing.")
    }
    if (-not ($ProviderAddress -match "/subscriptions/([^/]+)/resourceGroups/([^/]+)/providers/Microsoft.Storage/storageAccounts/([^/]+)")) {
        return @($null, "The provider address '$ProviderAddress' didn't match the expected pattern.")
    }
    $subscriptionId = $Matches[1]
    $resourceGroupName = $Matches[2]
    $storageAccountName = $Matches[3]

    $null = Select-AzSubscription -SubscriptionId $subscriptionId
    try {
        $accountKey = (Get-AzStorageAccountKey -ResourceGroupName $resourceGroupName -AccountName $storageAccountName | Where-Object KeyName -eq $ActiveCredentialId).value
        $credentialValue = "DefaultEndpointsProtocol=https;AccountName=$storageAccountName;AccountKey=$accountKey"
        return @($credentialValue, $null)
    } catch [Microsoft.Rest.Azure.CloudException] {
        $httpStatusCode = $_.Exception.Response.StatusCode
        $httpStatusCodeDescription = "$([int]$httpStatusCode) ($httpStatusCode)"
        $requestUri = $_.Exception.Request.RequestUri
        $requestId = $_.Exception.RequestId
        $errorCode = $_.Exception.Body.Code
        $errorMessage = $_.Exception.Body.Message
        Write-Host "  httpStatusCode: '$httpStatusCodeDescription'"
        Write-Host "  requestUri: '$requestUri'"
        Write-Host "  x-ms-request-id: '$requestId'"
        Write-Host "  errorCode: '$errorCode'"
        Write-Host "  errorMessage: '$errorMessage'"
        throw "Encountered unexpected exception during Get-CredentialValue. Throwing."
    }
}

function Invoke-CredentialRegeneration([string]$InactiveCredentialId, [string]$ProviderAddress) {
    if (-not ($ProviderAddress)) {
        return @($null, "The provider address is missing.")
    }
    if (-not ($ProviderAddress -match "/subscriptions/([^/]+)/resourceGroups/([^/]+)/providers/Microsoft.Storage/storageAccounts/([^/]+)")) {
        return @($null, "The provider address '$ProviderAddress' didn't match the expected pattern.")
    }
    $subscriptionId = $Matches[1]
    $resourceGroupName = $Matches[2]
    $storageAccountName = $Matches[3]

    $null = Select-AzSubscription -SubscriptionId $subscriptionId
    try {
        $null = New-AzStorageAccountKey -ResourceGroupName $resourceGroupName -Name $storageAccountName -KeyName $InactiveCredentialId
        $accountKey = (Get-AzStorageAccountKey -ResourceGroupName $resourceGroupName -AccountName $storageAccountName | Where-Object KeyName -eq $InactiveCredentialId).value
        $credentialValue = "DefaultEndpointsProtocol=https;AccountName=$storageAccountName;AccountKey=$accountKey"
        return @($credentialValue, $null)
    } catch [Microsoft.Rest.Azure.CloudException] {
        $httpStatusCode = $_.Exception.Response.StatusCode
        $httpStatusCodeDescription = "$([int]$httpStatusCode) ($httpStatusCode)"
        $requestUri = $_.Exception.Request.RequestUri
        $requestId = $_.Exception.RequestId
        $errorCode = $_.Exception.Body.Code
        $errorMessage = $_.Exception.Body.Message
        Write-Host "  httpStatusCode: '$httpStatusCodeDescription'"
        Write-Host "  requestUri: '$requestUri'"
        Write-Host "  x-ms-request-id: '$requestId'"
        Write-Host "  errorCode: '$errorCode'"
        Write-Host "  errorMessage: '$errorMessage'"
        throw "Encountered unexpected exception during Invoke-CredentialRegeneration. Throwing."
    }
}

function Get-CurrentSecret(
    [string]$UnversionedSecretId,
    [string]$ExpectedSecretId,
    [string]$ExpectedLifecycleState,
    [string]$CallerName) {
    $secret = $null
    $actualSecretId = $null
    $actualLifecycleState = $null
    $actualFunctionResourceId = $null

    $token = (Get-AzAccessToken -ResourceTypeName KeyVault -AsSecureString).Token

    # In rare cases, this handler might receive the published event before AKV has finished committing to storage.
    # To mitigate this, poll the current secret for up to 30s until its current lifecycle state matches that of the published event.
    foreach ($i in 1..$MAX_RETRY_ATTEMPTS) {
        $clientRequestId = [Guid]::NewGuid().ToString()
        Write-Host "  Attempt #$i with x-ms-client-request-id: '$clientRequestId'"
        $headers = @{
            "User-Agent"             = "$AZURE_FUNCTION_NAME/1.0 ($CallerName; Step 1; Attempt $i)"
            "x-ms-client-request-id" = $clientRequestId
        }
        $response = Invoke-WebRequest -Uri "${UnversionedSecretId}?api-version=$DATA_PLANE_API_VERSION" `
            -Method "GET" `
            -Authentication OAuth `
            -Token $token `
            -ContentType "application/json" `
            -Headers $headers
        $secret = $response.Content | ConvertFrom-Json
        $actualSecretId = $secret.id
        $actualLifecycleState = $secret.attributes.lifecycleState
        $actualFunctionResourceId = $secret.providerConfig.functionResourceId
        if (
            ($actualSecretId -eq $ExpectedSecretId) -and
            ($actualLifecycleState -eq $ExpectedLifecycleState) -and
            ($actualFunctionResourceId -eq $EXPECTED_FUNCTION_RESOURCE_ID)
        ) {
            break
        }
        Start-Sleep -Seconds 1
    }
    if (-not ($actualSecretId -eq $ExpectedSecretId)) {
        return @($null, "The secret '$actualSecretId' did not transition to '$ExpectedSecretId' after approximately $MAX_RETRY_ATTEMPTS seconds. Exiting.")
    }
    if (-not ($actualLifecycleState -eq $ExpectedLifecycleState)) {
        return @($null, "The secret '$actualSecretId' still has a lifecycle state of '$actualLifecycleState' and did not transition to '$ExpectedLifecycleState' after approximately $MAX_RETRY_ATTEMPTS seconds. Exiting.")
    }
    if (-not ($actualFunctionResourceId -eq $EXPECTED_FUNCTION_RESOURCE_ID)) {
        return @($null, "Expected function resource ID to be '$EXPECTED_FUNCTION_RESOURCE_ID', but found '$actualFunctionResourceId'. Exiting.")
    }
    $lifecycleDescription = $secret.attributes.lifecycleDescription
    $validityPeriod = $secret.rotationPolicy.validityPeriod
    $activeCredentialId = $secret.providerConfig.activeCredentialId
    $providerAddress = $secret.providerConfig.providerAddress
    $functionResourceId = $secret.providerConfig.functionResourceId
    Write-Host "  lifecycleDescription: '$lifecycleDescription'"
    Write-Host "  validityPeriod: '$validityPeriod'"
    Write-Host "  activeCredentialId: '$activeCredentialId'"
    Write-Host "  providerAddress: '$providerAddress'"
    Write-Host "  functionResourceId: '$functionResourceId'"

    return @($secret, $null)
}

function Update-PendingSecret(
    [string]$UnversionedSecretId,
    [string]$UpdatePendingSecretRequestBody,
    [string]$CallerName) {
    $clientRequestId = [Guid]::NewGuid().ToString()
    Write-Host "  x-ms-client-request-id: '$clientRequestId'"
    $token = (Get-AzAccessToken -ResourceTypeName KeyVault -AsSecureString).Token
    $headers = @{
        "User-Agent"             = "$AZURE_FUNCTION_NAME/1.0 ($CallerName; Step 3)"
        "x-ms-client-request-id" = $clientRequestId
    }
    try {
        $response = Invoke-WebRequest -Uri "${UnversionedSecretId}/pending?api-version=$DATA_PLANE_API_VERSION" `
            -Method "PUT" `
            -Authentication OAuth `
            -Token $token `
            -ContentType "application/json" `
            -Headers $headers `
            -Body $UpdatePendingSecretRequestBody
        $updatedSecret = $response.Content | ConvertFrom-Json
        $lifecycleState = $updatedSecret.attributes.lifecycleState
        $lifecycleDescription = $updatedSecret.attributes.lifecycleDescription
        $activeCredentialId = $updatedSecret.providerConfig.activeCredentialId
        Write-Host "  lifecycleState: '$lifecycleState'"
        Write-Host "  lifecycleDescription: '$lifecycleDescription'"
        Write-Host "  activeCredentialId: '$activeCredentialId'"
        return @($updatedSecret, $null)
    } catch {
        $httpStatusCode = $_.Exception.Response.StatusCode
        $httpStatusCodeDescription = "$([int]$httpStatusCode) ($httpStatusCode)"
        $errorBody = $_.ErrorDetails.Message | ConvertFrom-Json
        $requestUri = $_.Exception.Response.RequestMessage.RequestUri
        $requestId = $_.Exception.Response.Headers.GetValues("x-ms-request-id") -join ","
        $errorCode = $errorBody.error.code
        $errorMessage = $errorBody.error.message
        Write-Host "  httpStatusCode: '$httpStatusCodeDescription'"
        Write-Host "  requestUri: '$requestUri'"
        Write-Host "  x-ms-request-id: '$requestId'"
        Write-Host "  errorCode: '$errorCode'"
        Write-Host "  errorMessage: '$errorMessage'"
        if (($httpStatusCode -ge 400) -and ($httpStatusCode -lt 500)) {
            return @($null, "Classifying $httpStatusCodeDescription as non-retriable. Exiting.")
        }
        throw "Classifying $httpStatusCodeDescription as retriable. Throwing."
    }
}

function Invoke-PendingSecretImport([string]$VersionedSecretId, [string]$UnversionedSecretId) {
    $expectedLifecycleState = "ImportPending"
    $callerName = "Invoke-PendingSecretImport"

    Write-Host "Step 1: Get the current secret for validation and the ground truth."
    $secret, $nonRetriableError = Get-CurrentSecret -UnversionedSecretId $UnversionedSecretId `
        -ExpectedSecretId $VersionedSecretId `
        -ExpectedLifecycleState $expectedLifecycleState `
        -CallerName $callerName
    if ($nonRetriableError) {
        Write-Host $nonRetriableError
        return
    }

    Write-Host "Step 2: Import the secret from the provider and prepare the new secret in-memory."
    $activeCredentialId = $secret.providerConfig.activeCredentialId
    $providerAddress = $secret.providerConfig.providerAddress
    $activeCredentialValue, $nonRetriableError = Get-CredentialValue -ActiveCredentialId $activeCredentialId `
        -ProviderAddress $providerAddress
    if ($nonRetriableError) {
        Write-Host $nonRetriableError
        return
    }
    $secret | Add-Member -NotePropertyName "value" -NotePropertyValue $activeCredentialValue -Force
    $secret.providerConfig.activeCredentialId = $activeCredentialId
    $updatePendingSecretRequestBody = ConvertTo-Json $secret -Depth $MAX_JSON_DEPTH -Compress

    Write-Host "Step 3: Update the pending secret."
    $updatedSecret, $nonRetriableError = Update-PendingSecret -UnversionedSecretId $UnversionedSecretId `
        -UpdatePendingSecretRequestBody $updatePendingSecretRequestBody `
        -CallerName $callerName
    if ($nonRetriableError) {
        Write-Host $nonRetriableError
        return
    }
}

function Invoke-PendingSecretRotation([string]$VersionedSecretId, [string]$UnversionedSecretId) {
    $expectedLifecycleState = "RotationPending"
    $callerName = "Invoke-PendingSecretRotation"

    Write-Host "Step 1: Get the current secret for validation and the ground truth."
    $secret, $nonRetriableError = Get-CurrentSecret -UnversionedSecretId $UnversionedSecretId `
        -ExpectedSecretId $VersionedSecretId `
        -ExpectedLifecycleState $expectedLifecycleState `
        -CallerName $callerName
    if ($nonRetriableError) {
        Write-Host $nonRetriableError
        return
    }

    Write-Host "Step 2: Regenerate the inactive credential via the provider and prepare the new secret in-memory."
    $activeCredentialId = $secret.providerConfig.activeCredentialId
    $providerAddress = $secret.providerConfig.providerAddress
    $inactiveCredentialId = Get-InactiveCredentialId -ActiveCredentialId $activeCredentialId
    $inactiveCredentialValue, $nonRetriableError = Invoke-CredentialRegeneration -InactiveCredentialId $inactiveCredentialId `
        -ProviderAddress $providerAddress
    if ($nonRetriableError) {
        Write-Host $nonRetriableError
        return
    }
    $secret | Add-Member -NotePropertyName "value" -NotePropertyValue $inactiveCredentialValue -Force
    $secret.providerConfig.activeCredentialId = $inactiveCredentialId
    $updatePendingSecretRequestBody = ConvertTo-Json $secret -Depth $MAX_JSON_DEPTH -Compress

    Write-Host "Step 3: Update the pending secret."
    $updatedSecret, $nonRetriableError = Update-PendingSecret -UnversionedSecretId $UnversionedSecretId `
        -UpdatePendingSecretRequestBody $updatePendingSecretRequestBody `
        -CallerName $callerName
    if ($nonRetriableError) {
        Write-Host $nonRetriableError
        return
    }
}

$ErrorActionPreference = "Stop"

$EventGridEvent | ConvertTo-Json -Depth $MAX_JSON_DEPTH -Compress | Write-Host
$eventType = $EventGridEvent.eventType
$versionedSecretId = $EventGridEvent.data.Id
if (-not ($versionedSecretId -match "(https://[^/]+/[^/]+/[^/]+)/[0-9a-f]{32}")) {
    throw "The versioned secret ID '$versionedSecretId' didn't match the expected pattern."
}
$unversionedSecretId = $Matches[1]

switch ($eventType) {
    "Microsoft.KeyVault.SecretImportPending" {
        Invoke-PendingSecretImport -VersionedSecretId $versionedSecretId -UnversionedSecretId $unversionedSecretId
    }
    "Microsoft.KeyVault.SecretRotationPending" {
        Invoke-PendingSecretRotation -VersionedSecretId $versionedSecretId -UnversionedSecretId $unversionedSecretId
    }
    default {
        throw "The Event Grid event '$eventType' is unsupported. Expected 'Microsoft.KeyVault.SecretImportPending' or 'Microsoft.KeyVault.SecretRotationPending'."
    }
}