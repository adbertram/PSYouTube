function Get-VideoComment {
    [OutputType('pscustomobject')]
    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string[]]$VideoId
    )

    $ErrorActionPreference = 'Stop'

    if ($commentThreads = Get-VideoCommentThread -VideoId $VideoId) {
        $commentThreads.foreach({
                $_.snippet.topLevelComment.snippet | Add-Member -NotePropertyName 'commentId' -NotePropertyValue $_.snippet.topLevelComment.id
                $_.snippet.topLevelComment.snippet | Add-Member -NotePropertyName 'totalVideoReplyCount' -NotePropertyValue $_.snippet.totalReplyCount -PassThru
            })
    }
}