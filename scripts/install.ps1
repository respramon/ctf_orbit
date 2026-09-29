param(
    [ValidateSet("core", "standard", "full", "dev")]
    [string]$Mode = "standard"
)
$ErrorActionPreference = "Stop"
$OrbitRepo = Split-Path -Parent $PSScriptRoot
Push-Location $OrbitRepo
try {
    & py -3 -c 'import sys; sys.exit(0 if sys.version_info >= (3, 11) else "Butuh Python 3.11+")'
    if ($LASTEXITCODE -ne 0) { throw "Python 3.11+ diperlukan." }
    & py -3 -m venv .venv
    if ($LASTEXITCODE -ne 0) { throw "Pembuatan venv gagal." }
    $OrbitPython = Join-Path $OrbitRepo ".venv\Scripts\python.exe"
    & $OrbitPython -m pip install --upgrade pip
    if ($LASTEXITCODE -ne 0) { throw "Upgrade pip gagal." }
    $OrbitSpec = switch ($Mode) {
        "core" { "." }
        "standard" { ".[image,crypto,reverse]" }
        "full" { ".[full]" }
        "dev" { ".[full,dev]" }
    }
    & $OrbitPython -m pip install -e $OrbitSpec
    if ($LASTEXITCODE -ne 0) { throw "Instalasi gagal. Periksa output pip." }
    & $OrbitPython -m ctf_orbit doctor
    if ($LASTEXITCODE -ne 0) { throw "Doctor gagal." }
    Write-Host "Selesai. CLI: .\.venv\Scripts\ctf-orbit.exe"
    if ($Mode -in @("full", "dev")) {
        Write-Host "Template proses pwntools untuk binary ELF dijalankan melalui Linux/WSL."
    }
} finally {
    Pop-Location
}

