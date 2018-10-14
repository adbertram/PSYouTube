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

function ConvertTo-PSYouTubeObject {
	[OutputType('pscustomobject')]
	[CmdletBinding()]
	param
	(
		[Parameter(Mandatory, ValueFromPipeline)]
		[ValidateNotNullOrEmpty()]
		[pscustomobject]$InputObject
	)

	begin {
		$ErrorActionPreference = 'Stop'
	}

	process {
		$output = $InputObject.snippet
		$InputObject.id.PSObject.Properties | foreach {
			$output | Add-Member -MemberType NoteProperty -Name $_.Name -Value $_.Value
		}
		$output
	}
}

function Invoke-YouTubeApiCall {
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
		[ValidateSet('GET', 'POST', 'PUT')]
		[string]$HTTPMethod = 'GET',

		[Parameter(Mandatory)]
		[ValidateNotNullOrEmpty()]
		[ValidateSet('search', 'playlistItems', 'videos', 'playlists', 'channels')]
		[string]$ApiMethod
	)

	$ErrorActionPreference = 'Stop'

	$invRestParams = @{
		Method      = $HTTPMethod
		Uri         = 'https://www.googleapis.com/youtube/v3/{0}?part=snippet' -f $ApiMethod
		ErrorAction = 'Stop'
	}
	$apiPayload = @{}

	if ($HTTPMethod -eq 'GET') {
		$apiPayload.maxResults = 50
		$apiPayload.key = (Get-ApiAuthInfo).APIKey
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
		$body = $body | ConvertTo-Json	
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
				Payload    = $Payload
				HTTPMethod = $HTTPMethod
				ApiMethod  = $ApiMethod
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
		$output = $result.items
	} else {
		$output = $result
	}
	$output | ConvertTo-PSYouTubeObject

	if ($result.PSObject.Properties.Name -contains 'nextPageToken') {
		Invoke-YouTubeApiCall -PageToken $result.nextPageToken -Payload $Payload -ApiMethod $ApiMethod
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
		part = 'snippet,contentDetails'
		id   = $VideoId -join ','
	}

	Invoke-YouTubeApiCall -Payload $payload -ApiMethod 'videos'
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
	## You will only supposedly be able to get up to 500 videos this way.
	$ErrorActionPreference = 'Stop'

	$payload = @{
		channelId = $ChannelId
		type      = 'video'
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

# function AddTo-Playlist {
# 	[OutputType('void')]
# 	[CmdletBinding()]
# 	param
# 	(
# 		[Parameter(Mandatory)]
# 		[ValidateNotNullOrEmpty()]
# 		[string]$PlaylistId,
		
# 		[Parameter()]
# 		[ValidateNotNullOrEmpty()]
# 		[string]$VideoId
# 	)

# 	$ErrorActionPreference = 'Stop'

# 	$payload = @{
# 		part       = 'snippet,id'
# 		playlistId = $PlaylistId
# 		resourceId = $VideoId
# 	}

# 	Invoke-YouTubeApiCall -Payload $payload -ApiMethod 'playlistItems' -HTTPMethod POST
	
# }

function Update-Video {
	[OutputType('void')]
	[CmdletBinding()]
	param
	(
		[Parameter(Mandatory, ValueFromPipeline)]
		[ValidateNotNullOrEmpty()]
		[pscustomobject]$Video,

		[Parameter(Mandatory)]
		[ValidateNotNullOrEmpty()]
		[string]$Description
	)

	begin {
		$ErrorActionPreference = 'Stop'
	}

	process {
		## Forced to pass the category ID so and the search API won't show it
		$vid = Get-Video -VideoId $Video.videoId

		$payload = @{
			id      = $Video.videoId
			snippet = @{
				'title'       = $Video.title
				'categoryId'  = $vid.categoryId
				'description' = $Description
			}
		}

		$null = Invoke-YouTubeApiCall -Payload $payload -ApiMethod 'videos' -HTTPMethod PUT
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

		$result = Invoke-YouTubeApiCall -Payload $payload -ApiMethod 'videos' -HTTPMethod PUT
		if ($PassThru.IsPresent) {
			$result
		}
	}
}