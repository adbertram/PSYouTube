function Request-AccessToken {
    [CmdletBinding(DefaultParameterSetName = 'Default')]
    [OutputType('string')]
    param
    (
        [Parameter()]
        [ValidateNotNullOrEmpty()]
        [string]$ClientId,

        [Parameter()]
        [ValidateNotNullOrEmpty()]
        [string]$ClientSecret,
        
        [Parameter(ParameterSetName = 'Refresh')]
        [ValidateNotNullOrEmpty()]
        [string]$Prompt = 'consent',

        [Parameter(Mandatory, ParameterSetName = 'Refresh')]
        [ValidateNotNullOrEmpty()]
        [string]$RefreshToken,
		
        [Parameter(ParameterSetName = 'NewToken')]
        [ValidateNotNullOrEmpty()]
        [string[]]$Scope = 'youtube',

        [Parameter()]
        [ValidateNotNullOrEmpty()]
        [ValidateSet('online', 'offline')]
        [string]$AccessType = 'online',

        [Parameter(ParameterSetName = 'NewToken')]
        [ValidateSet('code', 'token')]
        [string]$ResponseType = 'code',
	
        [Parameter(ParameterSetName = 'Refresh')]
        [Parameter(ParameterSetName = 'NewToken')]
        [ValidateNotNullOrEmpty()]
        [string]$ApplicationName = 'PSYouTube PowerShell Module'
    )
	
    $ErrorActionPreference = 'Stop'
    try {

        if (-not $PSBoundParameters.ContainsKey('ClientId')) {
            $ClientId = (Get-PSYouTubeApiAuthInfo).ClientId
        }
        if (-not $PSBoundParameters.ContainsKey('ClientSecret')) {
            $ClientSecret = (Get-PSYouTubeApiAuthInfo).ClientSecret
        }

        $payload = @{
            client_id    = [System.Uri]::EscapeUriString($ClientId)
            redirect_uri = [System.Uri]::EscapeUriString("urn:ietf:wg:oauth:2.0:oob")
        }

        if ($PSCmdlet.ParameterSetName -eq 'NewToken') {
            $endpointCodeUri = 'https://accounts.google.com/o/oauth2/v2/auth'
		
            $scopes = @()
            foreach ($s in $Scope) {
                $scopes += "https://www.googleapis.com/auth/$s"
            }
            $payload += @{
                'scope'                  = [System.Uri]::EscapeUriString($scopes -join ',')
                'access_type'            = $AccessType
                'include_granted_scopes' = 'true'
                'response_type'          = 'code'
                'state'                  = 'ps_state'
            }

            $keyValues = @()
            $payload.GetEnumerator() | sort Name | foreach {
                $keyValues += "$($_.Key)=$($_.Value)"
            }
		
            $keyValueString = $keyValues -join '&'
            $authUri = '{0}?{1}' -f $endpointCodeUri, $keyValueString
		
            & start $authUri
		
            $code = Read-Host -Prompt 'Please enter the authorization code displayed in your web browser'

            $payload += @{
                code          = [System.Uri]::EscapeUriString($code)
                grant_type    = 'authorization_code'
                client_secret = [System.Uri]::EscapeUriString($ClientSecret)
            }
        } elseif ($PSCmdlet.ParameterSetName -eq 'Refresh') {
            $payload += @{
                'refresh_token' = $RefreshToken
                'grant_type'    = 'refresh_token'
                'prompt'        = $Prompt
                'access_type'   = $AccessType
                client_secret   = [System.Uri]::EscapeUriString($ClientSecret)
            }
        }

        $endpointTokenUri = 'https://www.googleapis.com/oauth2/v4/token'
        $response = Invoke-WebRequest -Uri $endpointTokenUri -Method POST -Body $payload

        ConvertFrom-Json -InputObject $response.Content | Select-Object -Property access_token, refresh_token
		
    } catch {
        Write-Error $_.Exception.Message
    }
}

function Get-PSYouTubeApiAuthInfo {
    [CmdletBinding()]
    param
    (
        [Parameter()]
        [ValidateNotNullOrEmpty()]
        [string]$RefreshToken,

        [Parameter()]
        [ValidateNotNullOrEmpty()]
        [string]$AccessToken,

        [Parameter()]
        [ValidateNotNullOrEmpty()]
        [string]$ClientId,

        [Parameter()]
        [ValidateNotNullOrEmpty()]
        [string]$ClientSecret,

        [Parameter()]
        [ValidateNotNullOrEmpty()]
        [string]$ApiKey,

        [Parameter()]
        [ValidateNotNullOrEmpty()]
        [string]$RegistryKeyPath = 'HKCU:\Software\PSYouTube'
    )
	
    $ErrorActionPreference = 'Stop'

    function decrypt([string]$TextToDecrypt) {
        $secure = ConvertTo-SecureString $TextToDecrypt
        $hook = New-Object system.Management.Automation.PSCredential("test", $secure)
        $plain = $hook.GetNetworkCredential().Password
        return $plain
    }

    try {
        $PSYouTubeApiInfo = @{ }
		
        'RefreshToken', 'AccessToken', 'ClientId', 'ClientSecret', 'ApiKey' | ForEach-Object {
            if ($PSBoundParameters.ContainsKey($_)) {
                $PSYouTubeApiInfo.$_ = (Get-Variable -Name $_).Value
            }
        }

        if ($PSYouTubeApiInfo.Keys.Count -ne 5) {
            if (Get-Variable -Name PSYouTubeApiInfo -Scope Script -ErrorAction 'Ignore') {
                $script:PSYouTubeApiInfo
            } elseif (-not (Test-Path -Path $RegistryKeyPath)) {
                throw "No PSYouTube API info found in registry!"
            } elseif (-not ($keyValues = Get-ItemProperty -Path $RegistryKeyPath)) {
                throw 'PSYouTube API info not found in registry!'
            } else {
                'RefreshToken', 'AccessToken', 'ClientId', 'ClientSecret', 'ApiKey' | ForEach-Object {
                    $decryptedVal = decrypt $keyValues.$_
                    $PSYouTubeApiInfo.$_ = $decryptedVal
                }
                $script:PSYouTubeApiInfo = [pscustomobject]$PSYouTubeApiInfo
                $script:PSYouTubeApiInfo
            }
			
        } else {
            $script:PSYouTubeApiInfo = [pscustomobject]$PSYouTubeApiInfo
            $script:PSYouTubeApiInfo
        }
    } catch {
        $PSCmdlet.ThrowTerminatingError($_)
    }
}

function Save-PSYoutubeApiAuthInfo {
    [CmdletBinding()]
    param (
        [Parameter()]
        [string]$ClientId,

        [Parameter()]
        [string]$ClientSecret,

        [Parameter(ValueFromPipelineByPropertyName)]
        [Alias('access_token')]
        [string]$AccessToken,
	
        [Parameter(ValueFromPipelineByPropertyName)]
        [Alias('refresh_token')]
        [string]$RefreshToken,

        [Parameter()]
        [string]$APIKey,
	
        [Parameter()]
        [string]$RegistryKeyPath = "HKCU:\Software\PSYouTube"
    )

    begin {
        function encrypt([string]$TextToEncrypt) {
            $secure = ConvertTo-SecureString $TextToEncrypt -AsPlainText -Force
            $encrypted = $secure | ConvertFrom-SecureString
            return $encrypted
        }
    }
	
    process {
        if (-not (Test-Path -Path $RegistryKeyPath)) {
            New-Item -Path ($RegistryKeyPath | Split-Path -Parent) -Name ($RegistryKeyPath | Split-Path -Leaf) | Out-Null
        }
		
        $values = $PSBoundParameters.GetEnumerator().where({ $_.Key -ne 'RegistryKeyPath' -and $_.Value }) | Select-Object -ExpandProperty Key
		
        foreach ($val in $values) {
            Write-Verbose "Creating $RegistryKeyPath\$val"
            New-ItemProperty $RegistryKeyPath -Name $val -Value $(encrypt $((Get-Variable $val).Value)) -Force | Out-Null
        }
    }
}

function Get-Chunk {
    [OutputType("System.Array")]
    [CmdletBinding()]
    param (
        [Parameter(Position = 0)]
        [int]$size = 1,

        [Parameter(ValueFromPipeline = $true)]
        $InputObject
    )

    begin {
        $buf = @()
    }

    process {
        $buf += $InputObject

        if ( $size -gt 0 ) {
            # return chunks
            $start = 0
            $end = $size - 1
            $last = $buf.Count - 1
            while ($end -le $last) {
                , $buf[$start..$end]

                $start = $end + 1
                $end += $size
            }

            # store only items to be used, release unused elements for a Garbage Collection
            if ($start -gt $last) {
                $buf = @()
            } elseif ( $start -ne 0 ) {
                $buf = $buf[$start..$last]
            }
        }
    }

    end {
        if ( $size -lt 0 ) {
            # return a reverse ordered chunks
            $start = -1
            $end = $size
            $last = - $buf.Count
            while ($end -ge $last) {
                , $buf[$start..$end]

                $start = $end - 1
                $end += $size
            }

            if ($start -lt $last) {
                $buf = @()
            } elseif ( $start -ne -1 ) {
                $buf = $buf[$start..$last]
            }
        }

        if ( $buf ) {
            , $buf
            $buf = @()  # release unused elements for a Garbage Collection
        }
    }
}

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
        'Authorization' = "Bearer $((Get-PSYouTubeApiAuthInfo).AccessToken)" 
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
        if ($_.Exception.Message -like '*(401) Unauthorized*') {
            ## The token may be expired. Grab another one using the refresh token and try again
            $apiCred = Get-PSYouTubeApiAuthInfo
            
            $reqParams = @{
                ClientId     = $apiCred.ClientId
                ClientSecret = $apiCred.ClientSecret
                RefreshToken = $apiCred.RefreshToken
                AccessType   = 'offline'
            }

            $tokens = Request-AccessToken @reqParams
            $tokens | Save-PSYoutubeApiAuthInfo
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

function Get-Channel {
    [OutputType('pscustomobject')]
    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory, ParameterSetName = 'ByUsername')]
        [ValidateNotNullOrEmpty()]
        [string]$Username
    )

    $ErrorActionPreference = 'Stop'

    $payload = @{
        part        = 'snippet,contentDetails'
        forUsername = $Username
    }
	
    Invoke-YouTubeApiCall -Payload $payload -ApiMethod 'channels'
}

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

function Get-Playlist {
    [OutputType('pscustomobject')]
    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory, ParameterSetName = 'ByChannel')]
        [ValidateNotNullOrEmpty()]
        [string]$ChannelId,

        [Parameter(ParameterSetName = 'ByChannel')]
        [ValidateNotNullOrEmpty()]
        [string[]]$Name
    )

    $ErrorActionPreference = 'Stop'

    $payload = @{
        part      = 'snippet,contentDetails'
        channelId = $ChannelId
    }
	
    $result = Invoke-YouTubeApiCall -Payload $payload -ApiMethod 'playlists'
    if ($PSBoundParameters.ContainsKey('Name')) {
        $result | Where-Object { $_.snippet.title -in $Name }
    } else {
        $result
    }
}

function Get-PlaylistItem {
    [OutputType('pscustomobject')]
    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$PlaylistId
    )

    $ErrorActionPreference = 'Stop'

    $payload = @{
        part       = 'snippet,id'
        playlistId = $PlaylistId
    }

    Invoke-YouTubeApiCall -Payload $payload -ApiMethod 'playlistItems'
}

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
                    title       = $Video.snippet.title -replace '\\', '\\'
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