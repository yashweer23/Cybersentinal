# Windows PowerShell 5.1 / PowerShell 7. Password is prompted; tokens are never printed.
param(
    [string]$Username = '',
    [string]$FrontendUrl = '',
    [string]$BackendUrl = ''
)
$ErrorActionPreference = 'Stop'
$projectRoot = Split-Path -Parent $PSScriptRoot
$environmentFile = Join-Path $projectRoot '.env'
$login = $null
$session = New-Object Microsoft.PowerShell.Commands.WebRequestSession
$guard = @{ 'X-CSRF-Guard' = '1' }
$signedOut = $false

function Get-ConfiguredPort([string]$Name, [int]$Default) {
    if (Test-Path $environmentFile) {
        $escapedName = [regex]::Escape($Name)
        $found = Select-String -Path $environmentFile -Pattern "^${escapedName}=(\d+)\s*$" | Select-Object -First 1
        if ($found) { return [int]$found.Matches[0].Groups[1].Value }
    }
    return $Default
}
function Assert-HttpStatus([string]$Uri, [hashtable]$Headers, [int]$Expected) {
    $code = 0
    try {
        $result = Invoke-WebRequest -UseBasicParsing -Uri $Uri -Headers $Headers -TimeoutSec 20
        $code = [int]$result.StatusCode
    } catch {
        if (-not $_.Exception.Response) { throw }
        $code = [int]$_.Exception.Response.StatusCode
    }
    if ($code -ne $Expected) { throw "Expected HTTP $Expected at $Uri; received $code" }
}

if (-not $FrontendUrl) { $FrontendUrl = 'http://localhost:' + (Get-ConfiguredPort 'FRONTEND_PORT' 5173) }
if (-not $BackendUrl) { $BackendUrl = 'http://localhost:' + (Get-ConfiguredPort 'BACKEND_PORT' 8000) }
$FrontendUrl = $FrontendUrl.TrimEnd('/')
$BackendUrl = $BackendUrl.TrimEnd('/')

try {
    $phase1Script = Join-Path $PSScriptRoot 'Verify-Phase1.ps1'
    powershell -NoProfile -ExecutionPolicy Bypass -File $phase1Script -FrontendUrl $FrontendUrl -BackendUrl $BackendUrl
    if ($LASTEXITCODE -ne 0) { throw 'Connectivity checks failed' }
    $database = Invoke-RestMethod -Uri "$BackendUrl/api/database/status" -TimeoutSec 20
    if (-not $database.schema_ready -or -not $database.expected_revision -or $database.migration_revision -ne $database.expected_revision) {
        throw 'Run docker compose exec backend alembic upgrade head first.'
    }
    Write-Host "[PASS] Database is ready at $($database.migration_revision)"
    Assert-HttpStatus "$BackendUrl/api/auth/me" @{} 401
    Write-Host '[PASS] Anonymous /auth/me returns 401'
    if (-not $Username) { $Username = Read-Host 'Username (not email)' }
    $securePassword = Read-Host 'Password' -AsSecureString
    $credential = New-Object System.Management.Automation.PSCredential($Username, $securePassword)
    $body = @{ username = $Username; password = $credential.GetNetworkCredential().Password } | ConvertTo-Json
    try {
        $login = Invoke-RestMethod -Method Post -Uri "$BackendUrl/api/auth/login" -Headers $guard -WebSession $session -ContentType 'application/json' -Body $body -TimeoutSec 20
    } finally {
        $body = $null
        $credential = $null
        if ($securePassword) { $securePassword.Dispose() }
    }
    $authorization = @{ Authorization = "Bearer $($login.access_token)" }
    $me = Invoke-RestMethod -Uri "$BackendUrl/api/auth/me" -Headers $authorization -TimeoutSec 20
    if ($me.id -ne $login.user.id -or -not $me.is_active) { throw 'Profile mismatch' }
    if ($me.PSObject.Properties.Name -contains 'hashed_password') { throw 'Password hash leaked' }
    Write-Host "[PASS] Login and profile: $($me.username) / $($me.role)"
    $rules = Invoke-RestMethod -Uri "$FrontendUrl/api/detection-rules" -Headers $authorization -TimeoutSec 20
    if ($rules.Count -ne 10) { throw 'Expected ten seeded detection rules' }
    Write-Host '[PASS] Authenticated rule listing through frontend proxy'
    Assert-HttpStatus "$BackendUrl/api/test/authenticated" $authorization 200
    $analystStatus = if ($me.role -in @('ADMIN', 'ANALYST')) { 200 } else { 403 }
    $adminStatus = if ($me.role -eq 'ADMIN') { 200 } else { 403 }
    Assert-HttpStatus "$BackendUrl/api/test/analyst" $authorization $analystStatus
    Assert-HttpStatus "$BackendUrl/api/test/admin" $authorization $adminStatus
    Assert-HttpStatus "$BackendUrl/api/users" $authorization $adminStatus
    Write-Host '[PASS] Role permissions match the signed-in user'
    $refreshed = Invoke-RestMethod -Method Post -Uri "$BackendUrl/api/auth/refresh" -Headers $guard -WebSession $session -ContentType 'application/json' -Body '{}' -TimeoutSec 20
    if ($refreshed.access_token -eq $login.access_token) { throw 'Refresh did not rotate credentials' }
    $freshHeaders = @{ Authorization = "Bearer $($refreshed.access_token)"; 'X-CSRF-Guard' = '1' }
    Assert-HttpStatus "$BackendUrl/api/auth/me" $freshHeaders 200
    Write-Host '[PASS] Cookie refresh issued a working access token'
    $null = Invoke-WebRequest -UseBasicParsing -Method Post -Uri "$BackendUrl/api/auth/logout" -Headers $freshHeaders -WebSession $session -TimeoutSec 20
    $signedOut = $true
    Assert-HttpStatus "$BackendUrl/api/auth/me" $authorization 401
    Assert-HttpStatus "$BackendUrl/api/auth/me" $freshHeaders 401
    Write-Host '[PASS] Logout invalidates both old and refreshed access tokens'
    Write-Host 'Phase 3 HTTP checks passed. Repeat with each role; verify browser screens separately.'
} catch {
    Write-Host "[FAIL] $($_.Exception.Message)" -ForegroundColor Red
    Write-Host 'Inspect: docker compose ps; docker compose logs --tail=80 backend'
    exit 1
} finally {
    if ($login -and -not $signedOut) {
        try {
            $null = Invoke-WebRequest -UseBasicParsing -Method Post -Uri "$BackendUrl/api/auth/logout" -WebSession $session -Headers @{ 'X-CSRF-Guard' = '1'; Authorization = "Bearer $($login.access_token)" } -TimeoutSec 20
        } catch { Write-Host 'Could not confirm cleanup logout. This verification session may remain valid until expiry.' }
    }
    $login = $null
    $refreshed = $null
    $authorization = $null
    $freshHeaders = $null
    $session = $null
}
