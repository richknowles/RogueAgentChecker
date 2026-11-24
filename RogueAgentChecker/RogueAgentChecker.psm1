#Requires -Version 5.1
<#
    Rogue Agent Checker - module loader.

    Loads every script in Private\ (internal helpers) and then Public\ (the
    commands you run). Only the Public functions are exported.

    Read-only by design: see docs\ARCHITECTURE.md, and Tests\Safety.Tests.ps1 for
    the tests that enforce it.
#>

$script:RacModuleRoot = $PSScriptRoot
$script:RacVersion = '0.1.1'

foreach ($folder in @('Private', 'Public')) {
    $folderPath = Join-Path -Path $PSScriptRoot -ChildPath $folder
    foreach ($file in @(Get-ChildItem -LiteralPath $folderPath -Filter '*.ps1' | Sort-Object Name)) {
        . $file.FullName
    }
}

$publicFunctions = @(Get-ChildItem -LiteralPath (Join-Path -Path $PSScriptRoot -ChildPath 'Public') -Filter '*.ps1' | ForEach-Object { $_.BaseName })
Export-ModuleMember -Function $publicFunctions
