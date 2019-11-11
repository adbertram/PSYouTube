function Get-VideoAnalytics {
    [OutputType('pscustomobject')]
    [CmdletBinding(DefaultParameterSetName = 'Default')]
    param
    (
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [ValidateSet('estimatedMinutesWatched')]
        [string]$Metric,

        [Parameter()]
        [ValidateNotNullOrEmpty()]
        [string[]]$Id,

        [Parameter(Mandatory, ParameterSetName = 'ByTimeFrame')]
        [ValidateNotNullOrEmpty()]
        [datetime]$StartDate,

        [Parameter(ParameterSetName = 'ByTimeFrame')]
        [ValidateNotNullOrEmpty()]
        [datetime]$EndDate,

        [Parameter()]
        [ValidateNotNullOrEmpty()]
        [int]$StartIndex
    )

    $ErrorActionPreference = 'Stop'

    $payload = @{
        ids        = 'channel==MINE'
        metrics    = $Metric
        dimensions = 'video'
    }

    if (-not $PSBoundParameters.ContainsKey('Id')) {
        $Id = (Get-ChannelVideo).id.videoId
    }
    if ($PSBoundParameters.ContainsKey('StartDate')) {
        $payload.startDate = $StartDate.ToString('yyyy-MM-dd')
    } else {
        $payload.startDate = '2018-01-01'
    }
    if ($PSBoundParameters.ContainsKey('EndDate')) {
        $payload.endDate = $EndDate.ToString('yyyy-MM-dd')
    } else {
        $payload.endDate = (Get-Date -Format 'yyyy-MM-dd')
    }

    $idGroups = Get-Chunk -size 50 -InputObject $Id
    foreach ($idGroup in $idGroups) {
        $payload.filters = 'video=={0}' -f ($idGroup -join ',')
        Write-Verbose -Message "Getting video analytics for video IDs [$(($idGroup -join ','))]..."
        $vids = Invoke-YouTubeApiCall -Payload $payload -ApiMethod 'reports' -ApiName 'Analytics'
        if (@($vids).Count -eq 2) {
            $s = $vids -split ' '
            [pscustomobject]@{
                'videoId' = $s[0]
                $Metric   = $s[1]
            }
        } else {
            foreach ($vid in $vids) {
                [pscustomobject]@{
                    'videoId' = $vid[0]
                    $Metric   = $vid[1]
                }
            }
        }
    }
}