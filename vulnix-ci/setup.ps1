# Windows : crée .env depuis .env.example (si absent) avec un secret agent aléatoire. Ne remplace jamais un .env existant.
$here = Split-Path -Parent $MyInvocation.MyCommand.Path
$envFile = Join-Path $here ".env"
if (Test-Path $envFile) { Write-Host ".env existe déjà : rien changé."; exit 0 }
function New-Secret {
  $bytes = New-Object byte[] 32
  [System.Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($bytes)
  -join ($bytes | ForEach-Object { $_.ToString("x2") })
}
(Get-Content (Join-Path $here ".env.example")) `
  -replace '^WOODPECKER_AGENT_SECRET=$', "WOODPECKER_AGENT_SECRET=$(New-Secret)" `
  -replace '^WOODPECKER_GRPC_SECRET=$', "WOODPECKER_GRPC_SECRET=$(New-Secret)" |
  Set-Content -Encoding utf8 $envFile
New-Item -ItemType Directory -Force (Join-Path $here "data"), (Join-Path $here "agent-config") | Out-Null
Write-Host ".env créé. Remplis WOODPECKER_ADMIN, WOODPECKER_GITHUB_CLIENT et WOODPECKER_GITHUB_SECRET, puis : docker compose up -d"
