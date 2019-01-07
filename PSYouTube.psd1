@{
	RootModule        = 'PSYouTube.psm1'
	ModuleVersion     = '0.1'
	GUID              = '6c92d16e-9da5-4f35-8567-11a211f85833'
	Author            = 'Adam Bertram'
	CompanyName       = 'TechSnips, LLC'
	Copyright         = '(c) 2018 TechSnips, LLC. All rights reserved.'
	Description       = 'PSYouTube is a module that allows you to interact with various YouTube APIs in a number of different ways with PowerShell.'
	RequiredModules   = @()
	FunctionsToExport = @('*')
	VariablesToExport = @()
	AliasesToExport   = @()
	PrivateData       = @{
		PSData = @{
			Tags       = @('YouTube', 'REST')
			ProjectUri = 'https://github.com/adbertram/PSYouTube'
		}
	}
}