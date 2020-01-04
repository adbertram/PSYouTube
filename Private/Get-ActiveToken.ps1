function Get-ActiveToken {
    [CmdletBinding()]
    param
    ()

    $ErrorActionPreference = 'Stop'

    $tokens = Get-PSYouTubeConfiguration -Decrypt
    switch ($tokens.ActiveToken) {
        'Access' {
            $tokens.AccessToken
            break
        }
        'Refresh' {
            $tokens.RefreshToken
            break
        }
        default {
            throw "Unrecognized input: [$_]"
        }
    }
}