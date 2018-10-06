function Get-ChannelVideo {
	[OutputType('pscustomobject')]
	[CmdletBinding()]
	param
	(
		[Parameter(Mandatory)]
		[ValidateNotNullOrEmpty()]
		[string]$ChannelId,

		[Parameter(Mandatory)]
		[ValidateNotNullOrEmpty()]
		[string]$ApiKey,

		[Parameter()]
		[ValidateNotNullOrEmpty()]
		[string]$PageToken
	)

	$ErrorActionPreference = 'Stop'

	$payload = @{
		part       = 'snippet'
		key        = $ApiKey
		channelId  = $ChannelId
		maxResults = 50
	}

	$baseUri = 'https://www.googleapis.com/youtube/v3/search'

	if ($PageToken) {
		$payload['pageToken'] = $PageToken
	}
	$output = Invoke-RestMethod -Method GET -Body $payload -Uri $baseUri
	$output.items
	if ($output.nextPageToken) {
		Get-ChannelVideo -ChannelId $ChannelId -ApiKey $ApiKey -PageToken $output.nextPageToken
	}
}