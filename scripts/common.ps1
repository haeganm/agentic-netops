# Dot-source this to get $py / $cfnLint pointing into the repo venv, on any OS.
# Windows lays a venv out as .venv\Scripts\python.exe; macOS/Linux as .venv/bin/python --
# hardcoding either breaks the other. $IsWindows does not exist on Windows PowerShell 5.1
# (it is $null there), so detect via the env var both editions define.
$repoRoot = Split-Path $PSScriptRoot -Parent
$venvBin = if ($env:OS -eq "Windows_NT") { Join-Path $repoRoot ".venv/Scripts" }
           else { Join-Path $repoRoot ".venv/bin" }
$py = Join-Path $venvBin $(if ($env:OS -eq "Windows_NT") { "python.exe" } else { "python" })
$cfnLint = Join-Path $venvBin $(if ($env:OS -eq "Windows_NT") { "cfn-lint.exe" } else { "cfn-lint" })

# Every entry point is written repo-root-relative, and sam build/deploy require that cwd
# anyway (samconfig.toml, CodeUri src/). Anchoring here makes the scripts work when run
# from any directory instead of failing on the first relative path.
Set-Location $repoRoot
