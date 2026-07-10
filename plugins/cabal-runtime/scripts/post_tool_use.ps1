$ErrorActionPreference = "Stop"

$payload = [Console]::In.ReadToEnd()
$fallback = '{"continue":false,"stopReason":"{\"operation\":\"command\",\"result\":{\"status\":\"unknown\",\"completeness\":\"No structured semantic result is available for this operation.\"}}"}'
if ([string]::IsNullOrWhiteSpace($payload)) {
  Write-Output $fallback
  exit 0
}

$runtime = $env:CABAL_RUNTIME_HOOK_BIN
if ([string]::IsNullOrWhiteSpace($runtime)) {
  $sourceRoot = Resolve-Path (Join-Path $env:PLUGIN_ROOT "..\..") -ErrorAction SilentlyContinue
  if ($sourceRoot) {
    $candidate = Join-Path $sourceRoot "target\debug\cabal-runtime-hook.exe"
    if (Test-Path -LiteralPath $candidate) {
      $runtime = $candidate
    }
  }
}

if ([string]::IsNullOrWhiteSpace($runtime)) {
  $installed = Get-Command "cabal-runtime-hook" -ErrorAction SilentlyContinue
  if ($installed) {
    $runtime = $installed.Source
  }
}

if ([string]::IsNullOrWhiteSpace($runtime) -or -not (Test-Path -LiteralPath $runtime)) {
  Write-Output $fallback
  exit 0
}

$output = $payload | & $runtime 2>$null
if ($LASTEXITCODE -ne 0 -or [string]::IsNullOrWhiteSpace($output)) {
  Write-Output $fallback
  exit 0
}

try {
  $parsed = $output | ConvertFrom-Json -ErrorAction Stop
  if ($parsed.continue -ne $false -or [string]::IsNullOrWhiteSpace([string]$parsed.stopReason)) {
    throw "Invalid projection"
  }
  Write-Output $output
} catch {
  Write-Output $fallback
}

exit 0
