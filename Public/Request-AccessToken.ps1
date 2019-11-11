function Request-AccessToken {
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
        [string[]]$Scope = 'youtube'
    )
	
    $ErrorActionPreference = 'Stop'
    try {

        if (-not $PSBoundParameters.ContainsKey('ClientId')) {
            $ClientId = (Get-PSYouTubeConfiguration -Decrypt).ClientId
        }
        if (-not $PSBoundParameters.ContainsKey('ClientSecret')) {
            $ClientSecret = (Get-PSYouTubeConfiguration -Decrypt).ClientSecret
        }

        $payload = @{
            client_id    = [System.Uri]::EscapeUriString($ClientId)
            redirect_uri = [System.Uri]::EscapeUriString("urn:ietf:wg:oauth:2.0:oob")
        }

        $endpointCodeUri = 'https://accounts.google.com/o/oauth2/v2/auth'
    
        $scopes = @()
        foreach ($s in $Scope) {
            $scopes += "https://www.googleapis.com/auth/$s"
        }
        $payload += @{
            'scope'                  = [System.Uri]::EscapeUriString($scopes -join ',')
            'access_type'            = 'offline'
            'include_granted_scopes' = 'true'
            'response_type'          = 'code'
            'state'                  = 'ps_state'
        }

        $keyValues = @()
        $payload.GetEnumerator() | Sort-Object Name | foreach {
            $keyValues += "$($_.Key)=$($_.Value)"
        }
    
        $keyValueString = $keyValues -join '&'
        $authUri = '{0}?{1}' -f $endpointCodeUri, $keyValueString
    
        $code = Read-Host -Prompt "Navigate to $authUri in your browser, allow access and paste the authorization code displayed here."

        $payload += @{
            code          = [System.Uri]::EscapeUriString($code)
            grant_type    = 'authorization_code'
            client_secret = [System.Uri]::EscapeUriString($ClientSecret)
        }

        $endpointTokenUri = 'https://oauth2.googleapis.com/token'
        $response = Invoke-WebRequest -Uri $endpointTokenUri -Method POST -Body $payload

        ConvertFrom-Json -InputObject $response.Content | Select-Object -Property access_token, refresh_token
		
    } catch {
        Write-Error $_.Exception.Message
    }
}