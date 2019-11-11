function Save-PSYouTubeConfiguration {
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
        [string]$APIKey
    )

    begin {
        function encrypt([string]$TextToEncrypt) {
            $secure = ConvertTo-SecureString $TextToEncrypt -AsPlainText -Force
            $encrypted = $secure | ConvertFrom-SecureString
            return $encrypted
        }
    }
	
    process {		
        $values = $PSBoundParameters.GetEnumerator().where({ $_.Value })
		
        $config = Get-PSYouTubeConfiguration
        foreach ($val in $values) {
            $config | Add-Member -NotePropertyName $val.Key -NotePropertyValue (encrypt $val.Value) -Force
        }
        $configJsonPath = Join-Path -Path (Split-Path -Path $PSScriptRoot -Parent) -ChildPath 'Configuration.json'
        $config | ConvertTo-Json | Set-Content -Path $configJsonPath
    }
}