function ConvertTo-Timespan {
    [OutputType('System.TimeSpan')]
    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$VideoDuration
    )

    $ErrorActionPreference = 'Stop'

    try {
        if ($VideoDuration -match 'PT(?<Minutes>\d+)M(?<Seconds>\d+)') {
            New-Timespan -Minutes $matches.Minutes -Seconds $matches.Seconds
        } else {
            throw 'Unable to convert video duration to timespan'
        }
    } catch {
        $PSCmdlet.ThrowTerminatingError($_)
    }
}