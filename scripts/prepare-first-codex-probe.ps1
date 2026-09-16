param(
    [ValidateSet("deny", "allow", "malformed", "exit-error")]
    [string]$Mode = "deny",

    [string]$Workspace,

    [string]$CodexCommand = "codex",

    [string]$PythonCommand = "python"
)

$ErrorActionPreference = "Stop"

$RepoRoot = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
$SourceRoot = Join-Path $RepoRoot "src"

if ([string]::IsNullOrWhiteSpace($env:PYTHONPATH)) {
    $env:PYTHONPATH = $SourceRoot
} else {
    $env:PYTHONPATH = $SourceRoot + [IO.Path]::PathSeparator + $env:PYTHONPATH
}

$versionText = (& $CodexCommand --version 2>&1 | Out-String).Trim()
if ($LASTEXITCODE -ne 0 -or [string]::IsNullOrWhiteSpace($versionText)) {
    throw "Could not run '$CodexCommand --version'."
}

Write-Host "Observed Codex: $versionText"
if ($versionText -notmatch '(^|\s)0\.154\.0($|\s)') {
    throw "The first ACV experiment is pinned to Codex CLI 0.154.0. Refusing to prepare publishable evidence for: $versionText"
}

if ([string]::IsNullOrWhiteSpace($Workspace)) {
    $stamp = Get-Date -Format "yyyyMMdd-HHmmss"
    $Workspace = Join-Path ([IO.Path]::GetTempPath()) "acv-codex-$Mode-$stamp"
}
$Workspace = [IO.Path]::GetFullPath($Workspace)

Write-Host "Preparing disposable workspace: $Workspace"
& $PythonCommand -m agent_control_verification codex-prepare $Workspace --mode $Mode
if ($LASTEXITCODE -ne 0) {
    throw "ACV failed to prepare the probe workspace."
}

$manifestPath = Join-Path $Workspace ".acv\codex-probe\manifest.json"
$manifest = Get-Content -Raw -Encoding UTF8 $manifestPath | ConvertFrom-Json

Write-Host ""
Write-Host "Prepared successfully."
Write-Host "Workspace: $Workspace"
Write-Host "Prompt:"
Write-Host $manifest.prompt
Write-Host ""
Write-Host "When Codex usage is available:"
Write-Host "  1. cd `"$Workspace`""
Write-Host "  2. Run Codex and submit the prompt above once."
Write-Host "  3. Review and trust the generated project hook only if Codex asks."
Write-Host "  4. Do not edit acv-marker.txt manually."
Write-Host "  5. Exit Codex after the attempt."
Write-Host "  6. From the ACV checkout, run:"
Write-Host "     acv codex-collect `"$Workspace`""
Write-Host ""
Write-Host "The evidence bundle will be written under .acv\codex-probe\evidence.json."
