$OmniDir = if ($env:OMNIGUARD_DIR) { $env:OMNIGUARD_DIR } else { Split-Path -Parent $MyInvocation.MyCommand.Path }
$RawArchive = Join-Path $OmniDir "archive/raw"

function Save-RawLogSnapshot {
    param(
        [Parameter(Mandatory)] [string]$SourcePath,
        [Parameter(Mandatory)] [string]$Prefix
    )
    if (-not (Test-Path $SourcePath)) { return $null }
    New-Item -ItemType Directory -Path $RawArchive -Force | Out-Null
    $stamp = Get-Date -Format "yyyyMMdd_HHmmss"
    $ext   = [IO.Path]::GetExtension($SourcePath)
    $dest  = Join-Path $RawArchive "${Prefix}_${stamp}${ext}"
    Copy-Item $SourcePath $dest -Force
    Set-ItemProperty -Path $dest -Name IsReadOnly -Value $true
    return $dest
}
