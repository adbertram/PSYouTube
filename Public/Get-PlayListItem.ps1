function Get-PlaylistItem {
    [OutputType('pscustomobject')]
    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$PlaylistId
    )

    $ErrorActionPreference = 'Stop'

    $payload = @{
        part       = 'snippet,id'
        playlistId = $PlaylistId
    }

    Invoke-YouTubeApiCall -Payload $payload -ApiMethod 'playlistItems'
}