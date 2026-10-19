# Compatible with Windows PowerShell 5.1 and PowerShell 7.
# Creates secrets locally; never displays or overwrites an existing .env.
$ErrorActionPreference = 'Stop'
$projectRoot = Split-Path -Parent $PSScriptRoot
$destination = Join-Path $projectRoot '.env'
$source = Join-Path $projectRoot '.env.example'

if (Test-Path $destination) {
    Write-Host '.env already exists. Preserving your current settings.'
    exit 0
}

function New-RandomHex([int]$ByteCount) {
    $bytes = New-Object byte[] $ByteCount
    $generator = [System.Security.Cryptography.RandomNumberGenerator]::Create()
    try { $generator.GetBytes($bytes) } finally { $generator.Dispose() }
    return ([BitConverter]::ToString($bytes)).Replace('-', '').ToLowerInvariant()
}

$content = [System.IO.File]::ReadAllText($source)
$content = $content.Replace('POSTGRES_PASSWORD=CHANGE_ME_GENERATE_LOCALLY', ('POSTGRES_PASSWORD=' + (New-RandomHex 24)))
$content = $content.Replace('JWT_SECRET_KEY=CHANGE_ME_GENERATE_LOCALLY', ('JWT_SECRET_KEY=' + (New-RandomHex 32)))
# UTF-8 without BOM is compatible with both Docker Compose and Python dotenv.
$encoding = New-Object System.Text.UTF8Encoding($false)
[System.IO.File]::WriteAllText($destination, $content, $encoding)
Write-Host 'Created .env with random local credentials. Keep this file out of Git.'
Write-Host 'Next: docker compose up --build -d --wait --wait-timeout 180'
