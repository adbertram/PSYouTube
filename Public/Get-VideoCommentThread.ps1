function Get-VideoCommentThread {
    [OutputType('pscustomobject')]
    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string[]]$VideoId,

        [Parameter()]
        [ValidateNotNullOrEmpty()]
        [switch]$IncludeReplies
    )

    $ErrorActionPreference = 'Stop'

    $part = @('snippet')
    if ($IncludeReplies.IsPresent) {
        $part += 'replies'
    }
    $payload = @{
        part    = $part -join ','
        videoId = $VideoId
    }
    $VideoId.foreach({
            $payload.videoId = $_
            Invoke-YouTubeApiCall -Payload $payload -ApiMethod 'commentThreads'
        })
}