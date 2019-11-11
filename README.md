# PSYouTube

## Getting Started

1. Create an API in your Google account.
2. Request an access token and initial token by running `$tokens = Request-AccessToken`.
3. Save the access token and initial refresh token to the local configuration.json file via `Save-PSYouTubeConfiguration -AccessToken $tokens.access_token -RefreshToken $tokens.refresh_token`.
4. Go nuts!
