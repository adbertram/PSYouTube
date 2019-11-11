function Get-Playlist {
    [OutputType('pscustomobject')]
    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory, ParameterSetName = 'ByChannel')]
        [ValidateNotNullOrEmpty()]
        [string]$ChannelId,

        [Parameter(ParameterSetName = 'ByChannel')]
        [ValidateNotNullOrEmpty()]
        [string[]]$Name
    )

    $ErrorActionPreference = 'Stop'

    $payload = @{
        part      = 'snippet,contentDetails'
        channelId = $ChannelId
    }
	
    $result = Invoke-YouTubeApiCall -Payload $payload -ApiMethod 'playlists'
    if ($PSBoundParameters.ContainsKey('Name')) {
        $result | Where-Object { $_.snippet.title -in $Name }
    } else {
        $result
    }
}