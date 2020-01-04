function Request-RefreshToken {
    [CmdletBinding()]
    param
    (
        [Parameter()]
        [ValidateNotNullOrEmpty()]
        [string]$ClientId,

        [Parameter()]
        [ValidateNotNullOrEmpty()]
        [string]$ClientSecret,
        
        [Parameter()]
        [ValidateNotNullOrEmpty()]
        [string]$Prompt = 'consent',

        [Parameter()]
        [ValidateNotNullOrEmpty()]
        [ValidateSet('online', 'offline')]
        [string]$AccessType = 'offline'
    )
	
    $ErrorActionPreference = 'Stop'
    try {
        $config = Get-PSYoutubeConfiguration -Decrypt
        if (-not $PSBoundParameters.ContainsKey('ClientId')) {
            $ClientId = $config.ClientId
        }
        if (-not $PSBoundParameters.ContainsKey('ClientSecret')) {
            $ClientSecret = $config.ClientSecret
        }

        $payload = @{
            'client_id'     = [System.Uri]::EscapeUriString($ClientId)
            'redirect_uri'  = [System.Uri]::EscapeUriString("urn:ietf:wg:oauth:2.0:oob")
            'grant_type'    = 'refresh_token'
            'refresh_token' = $config.AccessToken
            'prompt'        = $Prompt
            'access_type'   = $AccessType
            'client_secret' = [System.Uri]::EscapeUriString($ClientSecret)
        }

        $endpointTokenUri = 'https://www.googleapis.com/oauth2/v4/token'
        $response = Invoke-WebRequest -Uri $endpointTokenUri -Method POST -Body $payload

        ConvertFrom-Json -InputObject $response.Content | Select-Object -ExpandProperty refresh_token
		
    } catch {
        Write-Error $_.Exception.Message
    }
}