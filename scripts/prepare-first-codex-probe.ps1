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

Write-Host "Checking host and ACV provenance before workspace creation..."
& $PythonCommand -m agent_control_verification codex-preflight --codex $CodexCommand
if ($LASTEXITCODE -ne 0) {
    throw "ACV Codex preflight failed."
}

if ([string]::IsNullOrWhiteSpace($Workspace)) {
    $stamp = Get-Date -Format "yyyyMMdd-HHmmss"
    $Workspace = Join-Path ([IO.Path]::GetTempPath()) "acv-codex-$Mode-$stamp"
}
$Workspace = [IO.Path]::GetFullPath($Workspace)

Write-Host ""
Write-Host "Preparing disposable workspace: $Workspace"
& $PythonCommand -m agent_control_verification codex-prepare $Workspace --mode $Mode --python $PythonCommand
if ($LASTEXITCODE -ne 0) {
    throw "ACV failed to prepare the probe workspace."
}

Write-Host ""
Write-Host "Checking prepared workspace..."
& $PythonCommand -m agent_control_verification codex-preflight $Workspace --codex $CodexCommand
if ($LASTEXITCODE -ne 0) {
    throw "Prepared workspace did not pass ACV Codex preflight."
}

$manifestPath = Join-Path $Workspace ".acv\codex-probe\manifest.json"
$manifest = Get-Content -Raw -Encoding UTF8 $manifestPath | ConvertFrom-Json

Write-Host ""
Write-Host "Prepared successfully."
Write-Host "Workspace: $Workspace"
Write-Host "Mode: $Mode"
Write-Host "Prompt:"
Write-Host $manifest.prompt
Write-Host ""
Write-Host "When Codex usage is available:"
Write-Host "  1. cd `"$Workspace`""
Write-Host "  2. Run Codex and submit the prompt above exactly once."
Write-Host "  3. Review and trust the generated project hook only if Codex asks."
Write-Host "  4. Do not edit acv-marker.txt manually."
Write-Host "  5. Exit Codex after the attempt."
Write-Host "  6. From the ACV checkout, collect with:"
Write-Host "     $PythonCommand -m agent_control_verification codex-collect `"$Workspace`" --codex `"$CodexCommand`""
Write-Host "  7. Independently validate the saved bundle with:"
Write-Host "     $PythonCommand -m agent_control_verification render-evidence `"$Workspace\.acv\codex-probe\evidence.json`""
Write-Host ""
Write-Host "Preflight readiness is not evidence that the host enforces the control. The live run and collection establish that separately."
