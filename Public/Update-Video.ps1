function Update-Video {
    [OutputType('void')]
    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory, ValueFromPipeline)]
        [ValidateNotNullOrEmpty()]
        [pscustomobject]$Video,

        [Parameter()]
        [ValidateNotNullOrEmpty()]
        [string]$Description,

        [Parameter()]
        [ValidateNotNullOrEmpty()]
        [bool]$EmbeddingAllowed,

        [Parameter()]
        [ValidateNotNullOrEmpty()]
        [string]$Name,

        [Parameter()]
        [ValidateNotNullOrEmpty()]
        [string[]]$Tag,

        [Parameter()]
        [ValidateNotNullOrEmpty()]
        [string]$PrivacyStatus
    )

    begin {
        $ErrorActionPreference = 'Stop'
    }

    process {
        if ($PSBoundParameters.ContainsKey('Description')) {
            $Video.snippet.description = $Description
        }
        if ($PSBoundParameters.ContainsKey('Tag')) {
            if ($Video.snippet.PSObject.Properties.Name -notcontains 'tags') {
                $Video.snippet | Add-Member -NotePropertyName 'tags' -NotePropertyValue $Tag
            } else {
                $Video.snippet.tags = $Tag
            }
        }
        if ($PSBoundParameters.ContainsKey('PrivacyStatus')) {
            $Video.snippet.privacyStatus = $PrivacyStatus
        }
        if ($PSBoundParameters.ContainsKey('EmbeddingAllowed')) {
            $Video.status.embeddable = $EmbeddingAllowed
        }
        if ($PSBoundParameters.ContainsKey('Name')) {
            $Video.snippet.title = $Name
        }
        if ($PSBoundParameters.Keys.Count -gt 1) {
            $payload = @{
                part    = 'snippet,status'
                id      = $Video.id
                kind    = $Video.kind
                snippet = @{
                    title       = $Video.snippet.title
                    categoryId  = $Video.snippet.categoryId
                    description = $Video.snippet.description
                    tags        = $Video.snippet.tags
                }
                status  = @{
                    privacyStatus = $Video.status.privacyStatus
                    embeddable    = $Video.status.embeddable
                }
            }
            $null = Invoke-YouTubeApiCall -Payload $payload -ApiMethod 'videos' -HTTPMethod PUT
        } else {
            Write-Error -Message 'No attributes to change.'
        }
    }
}