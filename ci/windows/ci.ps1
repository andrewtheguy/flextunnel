# The steps from the `windows` job of .github/workflows/ci.yml, in the same
# order, with the same flags. When this file and that workflow disagree, the
# workflow is right and this is stale; it exists to say what CI will say before
# CI is asked.
#
# This runs natively on whatever Windows machine it is invoked on: the CI VM
# (see ci/windows/remote.sh) or a dev box. It installs nothing and changes no
# machine state, so running it locally is safe.
#
# Not covered here, on purpose: the release-profile build and the .msi
# packaging, both of which belong to release.yml.
#
# Windows PowerShell 5.1 does not fail on a non-zero exit from a native command,
# whatever $ErrorActionPreference says, so every step checks $LASTEXITCODE by
# hand.
$ErrorActionPreference = 'Stop'

# Invoked over ssh the working directory is the login user's home, not the
# checkout, so anchor to the repo root this script sits in.
Set-Location (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path

function Invoke-Step {
    param(
        [Parameter(Mandatory)][string] $Name,
        [Parameter(Mandatory)][string[]] $Arguments
    )

    Write-Host ''
    Write-Host "== $Name =="
    Write-Host "   cargo $($Arguments -join ' ')"

    & cargo @Arguments
    if ($LASTEXITCODE -ne 0) {
        Write-Host ''
        Write-Host "FAILED: $Name (exit $LASTEXITCODE)"
        exit $LASTEXITCODE
    }
}

Write-Host '== toolchain =='
& cmd /c ver
& rustc --version
& cargo --version
& cargo clippy --version
if ($env:CARGO_TARGET_DIR) { Write-Host "   CARGO_TARGET_DIR=$env:CARGO_TARGET_DIR" }

# The host clippy is what type-checks flextunnel-desktop's Windows backend
# (tray + keychain), which the Linux job never sees.
Invoke-Step 'Clippy' @('clippy', '--workspace', '--all-targets', '--', '-D', 'warnings')

Invoke-Step 'Test' @('test', '-p', 'flextunnel-core', '-p', 'flextunnel-cli', '-p', 'flextunnel-desktop')

Write-Host ''
Write-Host 'all steps passed'
