function Remove-Video {
    [OutputType('void')]
    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory, ValueFromPipeline)]
        [ValidateNotNullOrEmpty()]
        [pscustomobject]$Video
    )

    begin {
        $ErrorActionPreference = 'Stop'
    }

    process {
        if ('id' -in $Video.PSObject.Properties.Name) {
            $id = $Video.id	
        } elseif ('videoId' -in $Video.PSObject.Properties.Name) {
            $id = $Video.videoId
        } else {
            throw 'Could not find YouTube video ID!'
        }
        $params = @{
            id = $id
        }
        $null = Invoke-YouTubeApiCall -Parameters $params -ApiMethod 'videos' -HTTPMethod DELETE
    }
}