function Get-Channel {
    [OutputType('pscustomobject')]
    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory, ParameterSetName = 'ByUsername')]
        [ValidateNotNullOrEmpty()]
        [string]$Username
    )

    $ErrorActionPreference = 'Stop'

    $payload = @{
        part        = 'snippet,contentDetails'
        forUsername = $Username
    }
	
    Invoke-YouTubeApiCall -Payload $payload -ApiMethod 'channels'
}