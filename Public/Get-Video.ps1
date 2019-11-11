function Get-Video {
    [OutputType('pscustomobject')]
    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string[]]$Id
    )

    $ErrorActionPreference = 'Stop'

    $payload = @{
        part = 'snippet,contentDetails,status'
    }

    ## Split out into groups no larger than 50. 50 is the max at one time
    $i = 0
    do {
        $ids = $Id | Select-Object -First 50 -Skip $i
        $payload.id = $ids -join ','
        Invoke-YouTubeApiCall -Payload $payload -ApiMethod 'videos'
        $i += 50
        $processedIds += $ids
    } while ($processedIds.Count -lt @($Id).Count)
}