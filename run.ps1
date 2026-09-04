Write-Host "Starting AICTE Cyber Risk Platform + Strix..." -ForegroundColor Green
Write-Host "Location: D:\hackathon\cyber-risk-platform" -ForegroundColor Cyan
Write-Host "NVIDIA endpoint pre-filled in .env - just add NVIDIA_API_KEY" -ForegroundColor Yellow
Write-Host "Strix path: D:\hackathon\strix" -ForegroundColor Cyan
Set-Location -LiteralPath "D:\hackathon\cyber-risk-platform"
if (!(Test-Path ".env")) { Copy-Item ".env.example" ".env" }
Write-Host "Checking .env NVIDIA_API_KEY..."
$envContent = Get-Content ".env" | Select-String "NVIDIA_API_KEY"
Write-Host $envContent
if ($envContent -match "NVIDIA_API_KEY=\s*$") { Write-Host "WARNING: NVIDIA_API_KEY is empty - add your key from https://build.nvidia.com" -ForegroundColor Red }
python -m uvicorn app.main:app --host 127.0.0.1 --port 8000 --reload
