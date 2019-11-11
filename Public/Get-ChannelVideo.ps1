function Get-ChannelVideo {
    [OutputType('pscustomobject')]
    [CmdletBinding()]
    param
    ()

    ## NOTE: The API can sometimes take awhile to show newly published videos
    $ErrorActionPreference = 'Stop'

    $payload = @{
        part    = 'snippet'
        type    = 'video'
        forMine = 'true'
    }
    Invoke-YouTubeApiCall -Payload $payload -ApiMethod 'search'
}