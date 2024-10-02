<# 
This PowerShell script is designed for Azure Functions that automatically handles the rotation and import of credentials (storage account keys) stored in Azure Key Vault by responding to Event Grid events. 
It ensures that secrets are updated and synchronized with their associated storage accounts, helping automate secret management using Key Vault data plane APIs..
#>

# Parameters for the Azure Function triggered by an Event Grid Event
param([object]$EventGridEvent, [object]$TriggerMetadata)

# Constants
$MAX_RETRY_ATTEMPTS = 30  # Maximum number of retry attempts to poll for a secret update
$MAX_JSON_DEPTH = 10      # Maximum JSON depth allowed when serializing objects
$DATA_PLANE_API_VERSION = "7.6-preview.1"  # The API version for Key Vault data plane operations
$AZURE_FUNCTION_NAME = "AkvStorageAccountConnectionStringConnector" # Name of the Azure Function

# Extract subscription ID, resource group name, and app name from environment variables to construct the expected function resource ID.
# These environment variables are set by the Azure Function App runtime.
$EXPECTED_FUNCTION_APP_SUBSCRIPTION_ID = $env:WEBSITE_OWNER_NAME.Substring(0, 36)
$EXPECTED_FUNCTION_APP_RG_NAME = $env:WEBSITE_RESOURCE_GROUP
$EXPECTED_FUNCTION_APP_NAME = $env:WEBSITE_SITE_NAME

# Construct the expected Azure Function resource ID
$EXPECTED_FUNCTION_RESOURCE_ID = "/subscriptions/$EXPECTED_FUNCTION_APP_SUBSCRIPTION_ID/resourceGroups/$EXPECTED_FUNCTION_APP_RG_NAME/providers/Microsoft.Web/sites/$EXPECTED_FUNCTION_APP_NAME/functions/$AZURE_FUNCTION_NAME"

# Function to get the inactive credential ID based on the currently active credential (either 'key1' or 'key2').
# Azure Storage Accounts typically have two access keys, and this function switches between them.
function Get-InactiveCredentialId([string]$ActiveCredentialId) {
    $inactiveCredentialId = switch ($ActiveCredentialId) {
        "key1" { "key2" }
        "key2" { "key1" }
        default { throw "The active credential ID '$ActiveCredentialId' didn't match the expected pattern. Expected 'key1' or 'key2'." }
    }
    return $inactiveCredentialId
}

# Function to retrieve the value of the active credential (storage account key) from Azure.
# It checks for valid inputs and retrieves the specified key from the storage account.
function Get-CredentialValue([string]$ActiveCredentialId, [string]$ProviderAddress) {
    # Validate if the active credential ID is provided
    if (-not ($ActiveCredentialId)) {
        return @($null, "The active credential ID is missing.")
    }
    # Ensure the credential ID matches the expected pattern ('key1' or 'key2')
    if ($ActiveCredentialId -notin @("key1", "key2")) {
        return @($null, "The active credential ID '$ActiveCredentialId' didn't match the expected pattern. Expected 'key1' or 'key2'.")
    }
    # Validate if the provider address (resource ID of the storage account) is provided
    if (-not ($ProviderAddress)) {
        return @($null, "The provider address is missing.")
    }
    # Ensure the provider address matches the expected Azure Storage Account resource format
    if (-not ($ProviderAddress -match "/subscriptions/([^/]+)/resourceGroups/([^/]+)/providers/Microsoft.Storage/storageAccounts/([^/]+)")) {
        return @($null, "The provider address '$ProviderAddress' didn't match the expected pattern.")
    }

    # Extract details from the provider address (subscription ID, resource group, storage account name)
    $subscriptionId = $Matches[1]
    $resourceGroupName = $Matches[2]
    $storageAccountName = $Matches[3]

    # Select the subscription to operate on
    $null = Select-AzSubscription -SubscriptionId $subscriptionId

    # Retrieve the specified storage account key (credential) from the storage account
    try {
        $accountKey = (Get-AzStorageAccountKey -ResourceGroupName $resourceGroupName -AccountName $storageAccountName | Where-Object KeyName -eq $ActiveCredentialId).value
        $credentialValue = "DefaultEndpointsProtocol=https;AccountName=$storageAccountName;AccountKey=$accountKey"
        return @($credentialValue, $null)
    } catch [Microsoft.Rest.Azure.CloudException] {
        # Handle any exceptions by logging detailed information and re-throwing the exception
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

# Function to regenerate a storage account key (credential).
# This function generates a new inactive credential, which can later be made active.
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

    # Attempt to regenerate the inactive credential (storage account key) and return it
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

# Function to get the current secret from Azure Key Vault for validation purposes.
# This function ensures that the secret is in the expected state before proceeding with further actions.
function Get-CurrentSecret(
    [string]$UnversionedSecretId,
    [string]$ExpectedSecretId,
    [string]$ExpectedLifecycleState,
    [string]$CallerName) {
    $secret = $null
    $actualSecretId = $null
    $actualLifecycleState = $null
    $actualFunctionResourceId = $null

    # Get the auth token for authenticating requests to Key Vault
    $token = (Get-AzAccessToken -ResourceTypeName KeyVault -AsSecureString).Token

    # In rare cases, this handler might receive the published event before AKV has finished committing to storage.
    # To mitigate this, poll the current secret for up to 30s until its current lifecycle state matches that of the published event.
    foreach ($i in 1..$MAX_RETRY_ATTEMPTS) {
        $clientRequestId = [Guid]::NewGuid().ToString()
        Write-Host "  Attempt #$i with x-ms-client-request-id: '$clientRequestId'"

         # Define HTTP headers for the request
        $headers = @{
            "User-Agent"             = "$AZURE_FUNCTION_NAME/1.0 ($CallerName; Step 1; Attempt $i)"
            "x-ms-client-request-id" = $clientRequestId
        }

        # Perform a GET request to fetch the current secret from Key Vault
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

        # Check if the actual lifecycle state matches the expected state, stop polling if so.
        if (
            ($actualSecretId -eq $ExpectedSecretId) -and
            ($actualLifecycleState -eq $ExpectedLifecycleState) -and
            ($actualFunctionResourceId -eq $EXPECTED_FUNCTION_RESOURCE_ID)
        ) {
            break
        }
        Start-Sleep -Seconds 1
    }

    # Check if the secret did not reach the expected state after retries, return an error message.
    if (-not ($actualSecretId -eq $ExpectedSecretId)) {
        return @($null, "The secret '$actualSecretId' did not transition to '$ExpectedSecretId' after approximately $MAX_RETRY_ATTEMPTS seconds. Exiting.")
    }
    if (-not ($actualLifecycleState -eq $ExpectedLifecycleState)) {
        return @($null, "The secret '$actualSecretId' still has a lifecycle state of '$actualLifecycleState' and did not transition to '$ExpectedLifecycleState' after approximately $MAX_RETRY_ATTEMPTS seconds. Exiting.")
    }
    if (-not ($actualFunctionResourceId -eq $EXPECTED_FUNCTION_RESOURCE_ID)) {
        return @($null, "Expected function resource ID to be '$EXPECTED_FUNCTION_RESOURCE_ID', but found '$actualFunctionResourceId'. Exiting.")
    }

    # Output detailed secret properties for logging purposes.
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

# Function to update a secret in Azure Key Vault with the 'Pending' lifecycle state.
# It updates the secret's attributes based on the provided request body.
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

    # Perform an HTTP PUT request to update the secret's state to 'Pending'.
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

        # If the error is in the 400 range, classify it as non-retriable and return.
        if (($httpStatusCode -ge 400) -and ($httpStatusCode -lt 500)) {
            return @($null, "Classifying $httpStatusCodeDescription as non-retriable. Exiting.")
        }

        # If the error is outside the 400 range, throw a retriable error.
        throw "Classifying $httpStatusCodeDescription as retriable. Throwing."
    }
}

# Function to handle the pending import of a secret.
# Validates the current secret state, fetches its credentials, and updates it with imported data.
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

    # Import the secret from the provider and prepare the new secret in-memory for update.
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

    # Call the update function to store the pending secret.
    Write-Host "Step 3: Update the pending secret."
    $updatedSecret, $nonRetriableError = Update-PendingSecret -UnversionedSecretId $UnversionedSecretId `
        -UpdatePendingSecretRequestBody $updatePendingSecretRequestBody `
        -CallerName $callerName
    if ($nonRetriableError) {
        Write-Host $nonRetriableError
        return
    }
}

# Function to handle pending secret rotation in Azure Key Vault.
# This function rotates the secret by regenerating an inactive credential and updating the secret's lifecycle state.
function Invoke-PendingSecretRotation([string]$VersionedSecretId, [string]$UnversionedSecretId) {
    $expectedLifecycleState = "RotationPending"
    $callerName = "Invoke-PendingSecretRotation"

    # Step 1: Validate the current secret state and ensure it's in the correct lifecycle state (RotationPending).
    Write-Host "Step 1: Get the current secret for validation and the ground truth."
    $secret, $nonRetriableError = Get-CurrentSecret -UnversionedSecretId $UnversionedSecretId `
        -ExpectedSecretId $VersionedSecretId `
        -ExpectedLifecycleState $expectedLifecycleState `
        -CallerName $callerName
    if ($nonRetriableError) {
        Write-Host $nonRetriableError
        return
    }

    # Step 2: Regenerate the inactive credential for the secret.
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

    # Update the secret object to mark the newly regenerated inactive credential as the active credential.
    $secret.providerConfig.activeCredentialId = $inactiveCredentialId
    $updatePendingSecretRequestBody = ConvertTo-Json $secret -Depth $MAX_JSON_DEPTH -Compress

    # Step 3: Update the pending secret in Azure Key Vault with the newly regenerated credential information.
    Write-Host "Step 3: Update the pending secret."
    $updatedSecret, $nonRetriableError = Update-PendingSecret -UnversionedSecretId $UnversionedSecretId `
        -UpdatePendingSecretRequestBody $updatePendingSecretRequestBody `
        -CallerName $callerName
    if ($nonRetriableError) {
        Write-Host $nonRetriableError
        return
    }
}

# Set the error action preference to "Stop" to halt script execution on errors.
$ErrorActionPreference = "Stop"

# Extract the event type and versioned secret ID for further operations
$EventGridEvent | ConvertTo-Json -Depth $MAX_JSON_DEPTH -Compress | Write-Host
$eventType = $EventGridEvent.eventType
$versionedSecretId = $EventGridEvent.data.Id
if (-not ($versionedSecretId -match "(https://[^/]+/[^/]+/[^/]+)/[0-9a-f]{32}")) {
    throw "The versioned secret ID '$versionedSecretId' didn't match the expected pattern."
}
$unversionedSecretId = $Matches[1]

# Handle the EventGrid event based on its type.
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