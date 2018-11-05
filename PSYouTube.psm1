function Request-AccessToken {
	[CmdletBinding()]
	[OutputType('string')]
	param
	(
		[Parameter(Mandatory)]
		[Parameter(ParameterSetName = 'Refresh')]
		[Parameter(ParameterSetName = 'NewToken')]
		[ValidateNotNullOrEmpty()]
		[string]$ClientId,

		[Parameter(Mandatory)]
		[Parameter(ParameterSetName = 'Refresh')]
		[Parameter(ParameterSetName = 'NewToken')]
		[ValidateNotNullOrEmpty()]
		[string]$ClientSecret,

		[Parameter(Mandatory, ParameterSetName = 'Refresh')]
		[ValidateNotNullOrEmpty()]
		[string]$RefreshToken,
		
		[Parameter(ParameterSetName = 'NewToken')]
		[ValidateNotNullOrEmpty()]
		[string[]]$Scope = 'youtube',

		[Parameter(ParameterSetName = 'NewToken')]
		[ValidateNotNullOrEmpty()]
		[ValidateSet('online', 'offline')]
		[string]$AccessType = 'offline',

		[Parameter(ParameterSetName = 'NewToken')]
		[ValidateSet('code', 'token')]
		[string]$ResponseType = 'code',
	
		[Parameter()]
		[ValidateNotNullOrEmpty()]
		[Parameter(ParameterSetName = 'Refresh')]
		[Parameter(ParameterSetName = 'NewToken')]
		[string]$ApplicationName = 'PSYouTube'
	)
	
	$ErrorActionPreference = 'Stop'
	try {

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

function Get-ApiAuthInfo {
	[CmdletBinding()]
	param
	(
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
		if (-not (Test-Path -Path $RegistryKeyPath)) {
			Write-Warning 'No PSYouTube API info found in registry'
		} else {
			$keys = (Get-Item -Path $RegistryKeyPath).Property
			$ht = @{}
			foreach ($key in $keys) {
				$ht[$key] = decrypt (Get-ItemProperty -Path $RegistryKeyPath).$key
			}
			[pscustomobject]$ht
		}
	} catch {
		Write-Error $_.Exception.Message
	}
}

function Save-ApiAuthInfo {
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
		
		$values = $PSBoundParameters.GetEnumerator().where({ $_.Key -ne 'RegistryKeyPath' -and $_.Value}) | Select-Object -ExpandProperty Key
		
		foreach ($val in $values) {
			Write-Verbose "Creating $RegistryKeyPath\$val"
			New-ItemProperty $RegistryKeyPath -Name $val -Value $(encrypt $((Get-Variable $val).Value)) -Force | Out-Null
		}
	}
}

function Invoke-YouTubeAnalyticsApiCall {
	## Must enable the YouTube Analytics API on the project you're querying in the Google Developers Console
	[OutputType('pscustomobject')]
	[CmdletBinding()]
	param
	(
		[Parameter(Mandatory)]
		[ValidateNotNullOrEmpty()]
		[hashtable]$Payload,

		[Parameter()]
		[ValidateNotNullOrEmpty()]
		[string]$PageToken,

		[Parameter(Mandatory)]
		[ValidateNotNullOrEmpty()]
		[ValidateSet('reports')]
		[string]$ApiMethod
	)

	$ErrorActionPreference = 'Stop'

	$invRestParams = @{
		Method      = 'GET'
		Uri         = 'https://youtubeanalytics.googleapis.com/v2/{0}' -f $ApiMethod		
		Headers     = @{ 
			'Authorization' = "Bearer $((Get-ApiAuthInfo).AccessToken)" 
			'Content-Type'  = 'application/json'
		}
		ErrorAction = 'Stop'
	}
	$apiPayload = @{
		maxResults = 50
		# key        = (Get-ApiAuthInfo).APIKey
	}

	$body = $Payload + $apiPayload

	if ($PageToken) {
		$body['pageToken'] = $PageToken
	}
	
	$invRestParams.Body = $body

	try {
		$result = Invoke-RestMethod @invRestParams
	} catch {
		if ($_.Exception.Message -like '*(401) Unauthorized*') {
			## The token may be expired. Grab another one using the refresh token and try again
			$apiCred = Get-ApiAuthInfo
			$tokens = Request-AccessToken -ClientId $apiCred.ClientId -ClientSecret $apiCred.ClientSecret -RefreshToken $apiCred.RefreshToken
			$tokens | Save-ApiAuthInfo
			$invParams = @{
				Payload   = $Payload
				ApiMethod = $ApiMethod
			}
			if ($PageToken) {
				$invParams.PageToken = $PageToken
			}
			Invoke-YouTubeDataApiCall @invParams
		} else {
			$PSCmdlet.ThrowTerminatingError($_)
		}
	}

	if ('items' -in $result.PSObject.Properties.Name) {
		$output = $result.items
	} else {
		$output = $result
	}
	$output

	if ($result.PSObject.Properties.Name -contains 'nextPageToken') {
		Invoke-YouTubeDataApiCall -PageToken $result.nextPageToken -Payload $Payload -ApiMethod $ApiMethod
	}
}

function Invoke-YouTubeDataApiCall {
	## Must enable the YouTube Data API on the project you're querying in the Google Developers Console
	[OutputType('pscustomobject')]
	[CmdletBinding()]
	param
	(
		[Parameter(Mandatory)]
		[ValidateNotNullOrEmpty()]
		[hashtable]$Payload,

		[Parameter()]
		[ValidateNotNullOrEmpty()]
		[string]$PageToken,

		[Parameter()]
		[ValidateNotNullOrEmpty()]
		[string]$HTTPMethod = 'GET',

		[Parameter(Mandatory)]
		[ValidateNotNullOrEmpty()]
		[ValidateSet('search', 'playlistItems', 'videos', 'playlists', 'channels')]
		[string]$ApiMethod,

		[Parameter()]
		[ValidateNotNullOrEmpty()]
		[string]$Uri
	)

	$ErrorActionPreference = 'Stop'

	if (-not $PSBoundParameters.ContainsKey('Uri')) {
		$uri = 'https://www.googleapis.com/youtube/v3/{0}' -f $ApiMethod	
	}
	
	$invRestParams = @{
		Method      = $HTTPMethod
		ErrorAction = 'Stop'
	}
	$apiPayload = @{}

	if ($HTTPMethod -eq 'GET') {
		$apiPayload.maxResults = 50
		# $apiPayload.key = (Get-ApiAuthInfo).APIKey
		$invRestParams.Headers = @{ 
			'Authorization' = "Bearer $((Get-ApiAuthInfo).AccessToken)" 
		}
	} else {
		$invRestParams.Headers = @{ 
			'Authorization' = "Bearer $((Get-ApiAuthInfo).AccessToken)" 
			'Content-Type'  = 'application/json'
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

	if ($HTTPMethod -ne 'DELETE') {
		$invRestParams.Body = $body
	}
	$invRestParams.Uri = $uri

	try {
		$result = Invoke-RestMethod @invRestParams
	} catch {
		if ($_.Exception.Message -like '*(401) Unauthorized*') {
			## The token may be expired. Grab another one using the refresh token and try again
			$apiCred = Get-ApiAuthInfo
			$tokens = Request-AccessToken -ClientId $apiCred.ClientId -ClientSecret $apiCred.ClientSecret -RefreshToken $apiCred.RefreshToken
			$tokens | Save-ApiAuthInfo
			$invParams = @{
				Payload    = $Payload
				HTTPMethod = $HTTPMethod
				ApiMethod  = $ApiMethod
			}
			if ($PageToken) {
				$invParams.PageToken = $PageToken
			}
			Invoke-YouTubeDataApiCall @invParams
		} else {
			$PSCmdlet.ThrowTerminatingError($_)
		}
	}

	if ('items' -in $result.PSObject.Properties.Name) {
		$output = $result.items
	} else {
		$output = $result
	}
	$output

	if ($result.PSObject.Properties.Name -contains 'nextPageToken') {
		Invoke-YouTubeDataApiCall -PageToken $result.nextPageToken -Payload $Payload -ApiMethod $ApiMethod
	}
}

function Get-Video {
	[OutputType('pscustomobject')]
	[CmdletBinding()]
	param
	(
		[Parameter(Mandatory)]
		[ValidateNotNullOrEmpty()]
		[string[]]$VideoId
	)

	$ErrorActionPreference = 'Stop'

	$payload = @{
		part = 'snippet,contentDetails,status'
	}

	## Split out into groups no larger than 50. 50 is the max at one time
	$i = 0
	do {
		$ids = $VideoId | Select-Object -First 50 -Skip $i
		$payload.id = $ids -join ','
		Invoke-YouTubeDataApiCall -Payload $payload -ApiMethod 'videos'
		$i += 50
		$processedIds += $ids
	} while ($processedIds.Count -lt @($VideoId).Count)
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
	(
		[Parameter(Mandatory)]
		[ValidateNotNullOrEmpty()]
		[string]$ChannelId
	)

	## NOTE: The API can sometimes take awhile to show newly published videos
	$ErrorActionPreference = 'Stop'

	$payload = @{
		part    = 'snippet'
		# channelId = $ChannelId ## this restrict the total videos displayed to 500
		type    = 'video'
		forMine = 'true'
		## These may have to be done once the channel gets over 500. Not sure.
		# order           = 'date'
		# publishedAfter  = '2018-10-01T00:00:00Z'
		# publishedBefore = '2018-10-10T00:00:00Z'
	}

	Invoke-YouTubeDataApiCall -Payload $payload -ApiMethod 'search'
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
	
	Invoke-YouTubeDataApiCall -Payload $payload -ApiMethod 'channels'
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
	
	$result = Invoke-YouTubeDataApiCall -Payload $payload -ApiMethod 'playlists'
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

	Invoke-YouTubeDataApiCall -Payload $payload -ApiMethod 'playlistItems'
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
		if ($PSBoundParameters.ContainsKey('Tags')) {
			$Video.snippet.tags = $Tags
		}
		if ($PSBoundParameters.ContainsKey('PrivacyStatus')) {
			$Video.snippet.privacyStatus = $PrivacyStatus
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
				}
			}
			$null = Invoke-YouTubeDataApiCall -Payload $payload -ApiMethod 'videos' -HTTPMethod PUT
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
		$null = Invoke-YouTubeDataApiCall -Payload $payload -ApiMethod 'videos' -HTTPMethod DELETE -Uri "https://www.googleapis.com/youtube/v3/videos?id=$($Video.id)"
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
		$vid = Get-Video -VideoId $Video.videoId

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

		$result = Invoke-YouTubeDataApiCall -Payload $payload -ApiMethod 'videos' -HTTPMethod PUT
		if ($PassThru.IsPresent) {
			$result
		}
	}
}