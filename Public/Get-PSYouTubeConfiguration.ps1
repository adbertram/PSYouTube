function Get-PSYouTubeConfiguration {
    [CmdletBinding()]
    param
    (
        [Parameter()]
        [ValidateNotNullOrEmpty()]
        [string]$RefreshToken,

        [Parameter()]
        [ValidateNotNullOrEmpty()]
        [string]$AccessToken,

        [Parameter()]
        [ValidateNotNullOrEmpty()]
        [string]$ClientId,

        [Parameter()]
        [ValidateNotNullOrEmpty()]
        [string]$ClientSecret,

        [Parameter()]
        [ValidateNotNullOrEmpty()]
        [string]$ApiKey,

        [Parameter()]
        [ValidateNotNullOrEmpty()]
        [switch]$Decrypt
    )

    $ErrorActionPreference = 'Stop'

    try {
        function decrypt([string]$TextToDecrypt) {
            $secure = ConvertTo-SecureString $TextToDecrypt
            $hook = New-Object system.Management.Automation.PSCredential("test", $secure)
            $plain = $hook.GetNetworkCredential().Password
            return $plain
        }
    
        $configJsonPath = "$PSScriptRoot\Configuration.json"
        if (-not (Test-Path -Path $configJsonPath)) {
            throw 'The required Configuration.json file could not be found.'
        }

        $encconfig = Get-Content -Path $configJsonPath -Raw | ConvertFrom-Json -AsHashtable
        $decconfig = @{ }
        $encconfig.Keys | ForEach-Object {
            if ($encconfig[$_]) {
                if ($Decrypt.IsPresent) {
                    $decconfig.$_ = decrypt $encconfig[$_]
                } else {
                    $decconfig.$_ = $encconfig[$_]
                }
            } else {
                $decconfig.$_ = ''
            }
        }
        $script:PSYouTubeConfiguration = [pscustomobject]$decconfig
        [pscustomobject]$decconfig
    } catch {
        $PSCmdlet.ThrowTerminatingError($_)
    }
}