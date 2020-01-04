function Invoke-YouTubeApiCall {
    ## Must enable the YouTube Data API on the project you're querying in the Google Developers Console
    [OutputType('pscustomobject')]
    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$ApiMethod,

        [Parameter()]
        [ValidateNotNullOrEmpty()]
        [hashtable]$Payload,

        [Parameter()]
        [ValidateNotNullOrEmpty()]
        [hashtable]$Parameters,

        [Parameter()]
        [ValidateNotNullOrEmpty()]
        [string]$PageToken,

        [Parameter()]
        [ValidateNotNullOrEmpty()]
        [string]$HTTPMethod = 'GET',

        [Parameter()]
        [ValidateNotNullOrEmpty()]
        [ValidateSet('Data', 'Analytics')]
        [string]$ApiName = 'Data',

        [Parameter()]
        [ValidateNotNullOrEmpty()]
        [int]$MaxRetries = 5,

        [Parameter()]
        [ValidateNotNullOrEmpty()]
        [switch]$IsRetryAttempt
    )

    $ErrorActionPreference = 'Stop'

    switch ($ApiName) {
        'Data' {
            $uri = 'https://www.googleapis.com/youtube/v3/{0}' -f $ApiMethod
            break
        }
        'Analytics' {
            $uri = 'https://youtubeanalytics.googleapis.com/v2/{0}' -f $ApiMethod
            break
        }
        default {
            throw "Unrecognized API name: [$_]"
        }
    }

    $invRestParams = @{
        Method      = $HTTPMethod
        ErrorAction = 'Stop'
    }
    $apiPayload = @{ }

    $invRestParams.Headers = @{ 
        'Authorization' = "Bearer $(Get-ActiveToken)" 
    }

    if ($HTTPMethod -eq 'GET') {
        $apiPayload.maxResults = 50	
    } elseif ($PSBoundParameters.ContainsKey('Payload')) {
        $invRestParams.Headers += @{ 
            'Content-Type' = 'application/json'
        }
    }
    $body = $Payload + $apiPayload

    if ($PageToken) {
        $body['pageToken'] = $PageToken
    }
	
    if ($HTTPMethod -ne 'GET') {
        if ($body.ContainsKey('part')) {
            $part = $body.part
            $body.Remove('part')
            $uri = '{0}?part={1}' -f $uri, [uri]::EscapeDataString($part)
        }
        $body = $body | ConvertTo-Json -Depth 5
    }

    $invRestParams.Body = $body

    if ($PSBoundParameters.ContainsKey('Parameters')) {
        $vals = @()
        foreach ($param in $Parameters.GetEnumerator()) {
            $vals += "$($param.Key)=$($param.Value)"
        }
        $queryString = $vals -join '&'
        $uri = "{0}?{1}" -f $uri, $queryString
    }
    $invRestParams.Uri = $uri

    try {
        if ($IsRetryAttempt.IsPresent) {
            $retryAttempts++
            if ($retryAttempts -eq $MaxRetries) {
                throw 'Max API retries met.'
            }
        } else {
            $retryAttempts = 0
        }
        $result = Invoke-RestMethod @invRestParams
    } catch {
        if ($_.Exception.Message -like '*Unauthorized*') {
            Write-Warning -Message "YouTube API returned 401 Unauthorized. Attempting to get refresh token..."
            ## The token may be expired. Grab another one using the refresh token and try again
            $refToken = Request-RefreshToken
            Save-PSYouTubeConfiguration -RefreshToken $refToken -ActiveToken 'Refresh'
            $invParams = @{
                IsRetryAttempt = $true
                Payload        = $Payload
                HTTPMethod     = $HTTPMethod
                ApiMethod      = $ApiMethod
            }
            if ($PageToken) {
                $invParams.PageToken = $PageToken
            }
            Invoke-YouTubeApiCall @invParams
        } elseif ($_.Exception.Message -like '*(403) Forbidden*') {
            throw 'Exceeded API quota'
        } else {
            $PSCmdlet.ThrowTerminatingError($_)
        }
    }

    if ('items' -in $result.PSObject.Properties.Name) {
        $result.items
    } else {
        $result.rows
    }

    if ($result.PSObject.Properties.Name -contains 'nextPageToken') {
        Invoke-YouTubeApiCall -PageToken $result.nextPageToken -Payload $Payload -ApiMethod $ApiMethod -ApiName $ApiName
    }
}