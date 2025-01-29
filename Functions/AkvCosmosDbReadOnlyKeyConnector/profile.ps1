# Azure Functions profile.ps1
#
# This profile.ps1 will get executed every "cold start" of your Function App, which occurs when:
# - A Function App starts up for the very first time.
# - A Function App starts up after being deallocated due to inactivity.
#
# You can define helper functions, run commands, or specify environment variables
# NOTE: any variables defined that are not environment variables will get reset after the first execution

# Authenticate with Azure PowerShell using MSI.
if ($env:MSI_SECRET -and (Get-Module -ListAvailable Az.Accounts)) {
    # To distinguish between different Azure environments, we use an AzureEnvironmentName environment variable, which
    # comes from the appSettings section of your Azure Function App. If you are using an ARM template, then you can
    # populate this using syntax like: "[environment().name]".
    $environmentName = if ($env:AzureEnvironmentName) {$env:AzureEnvironmentName} else {"AzureCloud"}
    Connect-AzAccount -Identity -Environment $environmentName
}

# You can also define functions or aliases that can be referenced in any of your PowerShell functions.