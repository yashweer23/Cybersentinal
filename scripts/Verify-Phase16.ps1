param([string[]]$ComposeFile = @('docker-compose.yml', 'compose.dev.yml'))
$ErrorActionPreference = 'Stop'
$ProjectRoot = Split-Path -Parent $PSScriptRoot
. (Join-Path $PSScriptRoot 'Compose-Helpers.ps1')
Set-ComposeArguments $ComposeFile
$ExitCode = 0
Push-Location $ProjectRoot
try {
    Invoke-ComposeChecked @('up', '--build', '-d', '--wait', '--wait-timeout', '180')
    Invoke-ComposeChecked @('exec', '-T', 'backend', 'alembic', 'upgrade', 'head')
    Invoke-ComposeChecked @('exec', '-T', 'backend', 'python', '-m', 'scripts.seed_detection_rules')
    Invoke-ComposeChecked @('exec', '-T', 'backend', 'python', '-m', 'ruff', 'check', '.')
    Invoke-ComposeChecked @('exec', '-T', 'backend', 'python', '-m', 'scripts.run_database_tests', '--junitxml=data/phase16-pytest.xml', '-ra')
    foreach ($Count in @(1000, 10000)) {
        Invoke-ComposeChecked @('exec', '-T', 'backend', 'python', '-m', 'scripts.validate_system', '--count', "$Count", '--output', "data/phase16-$Count.json")
    }
    Invoke-ComposeChecked @('exec', '-T', 'frontend', 'npm', 'test')
    Invoke-ComposeChecked @('exec', '-T', 'frontend', 'npm', 'run', 'build')
    New-Item -ItemType Directory -Force -Path 'reports/phase16' | Out-Null
    foreach ($File in @('phase16-pytest.xml', 'phase16-1000.json', 'phase16-10000.json')) {
        Invoke-ComposeChecked @('cp', "backend:/app/backend/data/$File", "reports/phase16/$File")
    }
    Write-Host '[PASS] Native database tests, isolated pipelines, lint, frontend tests and build'
    Write-Host '[INFO] Read docs/TESTING.md for production Nginx/browser, JMeter and backup/restore gates.'
} catch {
    Write-Host "[FAIL] $($_.Exception.Message)"
    $ExitCode = 1
} finally { Pop-Location }
exit $ExitCode
