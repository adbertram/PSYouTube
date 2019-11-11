function Add-Tag {
    [OutputType('void')]
    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory, ValueFromPipeline)]
        [ValidateNotNullOrEmpty()]
        [pscustomobject]$Video,

        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string[]]$Tag,

        [Parameter()]
        [ValidateNotNullOrEmpty()]
        [switch]$Replace,

        [Parameter()]
        [ValidateNotNullOrEmpty()]
        [switch]$PassThru
    )

    begin {
        $ErrorActionPreference = 'Stop'
    }

    process {
        ## Forced to pass the category ID so and the search API won't show it
        $vid = Get-Video -Id $Video.videoId

        ## Ensure there are no dup tags to be set
        $dedupedTags = $Tag | Select-Object -Unique

        if ((@($vid.Tags).Count -gt 0) -and -not $Replace.IsPresent) {
            $existingTags = $vid.Tags
            $tagsToSet = @($dedupedTags) + @($existingTags)
        } else {
            $tagsToSet = @($dedupedTags)
        }

        $payload = @{
            id      = $Video.videoId
            snippet = @{
                'title'      = $Video.title
                'categoryId' = $vid.categoryId
                'tags'       = $tagsToSet
            }
        }

        $result = Invoke-YouTubeApiCall -Payload $payload -ApiMethod 'videos' -HTTPMethod PUT
        if ($PassThru.IsPresent) {
            $result
        }
    }
}