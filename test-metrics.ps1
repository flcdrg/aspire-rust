# Test OpenTelemetry Metrics
# This script generates HTTP traffic to demonstrate metrics collection

Write-Host "OpenTelemetry Metrics Test" -ForegroundColor Cyan
Write-Host "==========================" -ForegroundColor Cyan
Write-Host ""

# Check if rustwebapi is running
$process = Get-Process -Name rustwebapi -ErrorAction SilentlyContinue
if (-not $process) {
    Write-Host "❌ rustwebapi is not running" -ForegroundColor Red
    Write-Host ""
    Write-Host "Please start the application with OpenTelemetry enabled:" -ForegroundColor Yellow
    Write-Host "  cd rustwebapi" -ForegroundColor White
    Write-Host "  cargo run -- --otel --port 8000" -ForegroundColor White
    Write-Host ""
    exit 1
}

Write-Host "✅ rustwebapi is running" -ForegroundColor Green
Write-Host ""

$baseUrl = "http://localhost:8000"
$requestCount = 10

Write-Host "Generating $requestCount test requests..." -ForegroundColor Cyan
Write-Host ""

# Generate successful requests
Write-Host "1. Successful requests (200):" -ForegroundColor Yellow
for ($i = 1; $i -le 5; $i++) {
    $name = @("alice", "bob", "charlie", "david", "eve")[$i - 1]
    try {
        $response = Invoke-WebRequest -Uri "$baseUrl/api/$name" -UseBasicParsing
        Write-Host "  ✅ GET /api/$name -> $($response.StatusCode)" -ForegroundColor Green
    } catch {
        Write-Host "  ❌ GET /api/$name -> Error: $_" -ForegroundColor Red
    }
    Start-Sleep -Milliseconds 100
}

Write-Host ""

# Generate bad requests (400)
Write-Host "2. Bad requests (400):" -ForegroundColor Yellow
for ($i = 1; $i -le 2; $i++) {
    try {
        $response = Invoke-WebRequest -Uri "$baseUrl/api/" -UseBasicParsing
    } catch {
        $statusCode = $_.Exception.Response.StatusCode.value__
        Write-Host "  ⚠️  GET /api/ -> $statusCode" -ForegroundColor Yellow
    }
    Start-Sleep -Milliseconds 100
}

Write-Host ""

# Generate not found requests (404)
Write-Host "3. Not found requests (404):" -ForegroundColor Yellow
for ($i = 1; $i -le 3; $i++) {
    try {
        $response = Invoke-WebRequest -Uri "$baseUrl/unknown/path" -UseBasicParsing
    } catch {
        $statusCode = $_.Exception.Response.StatusCode.value__
        Write-Host "  ⚠️  GET /unknown/path -> $statusCode" -ForegroundColor Yellow
    }
    Start-Sleep -Milliseconds 100
}

Write-Host ""
Write-Host "Test completed!" -ForegroundColor Green
Write-Host ""
Write-Host "Expected metrics in Aspire dashboard:" -ForegroundColor Cyan
Write-Host "  - http.server.requests" -ForegroundColor White
Write-Host "    • method=GET, path=/api/*, status=200: 5 requests" -ForegroundColor Gray
Write-Host "    • method=GET, path=/api/, status=400: 2 requests" -ForegroundColor Gray
Write-Host "    • method=GET, path=/unknown/path, status=404: 3 requests" -ForegroundColor Gray
Write-Host ""
Write-Host "  - http.server.request.duration" -ForegroundColor White
Write-Host "    • method=GET, path=/api/*: ~0.001s avg" -ForegroundColor Gray
Write-Host ""
Write-Host "View metrics in Aspire dashboard: https://localhost:17018" -ForegroundColor Cyan
Write-Host ""
