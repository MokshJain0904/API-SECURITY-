# PowerShell script to capture all screenshots autonomously
$edgePath = "C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe"
$screenshotDir = "C:\Users\admin\OneDrive\Desktop\crypto-project\docs\screenshots"

if (!(Test-Path $screenshotDir)) {
    New-Item -ItemType Directory -Force -Path $screenshotDir
}

# Remove temporary test file if present
if (Test-Path "$screenshotDir\test_edge.png") {
    Remove-Item "$screenshotDir\test_edge.png" -Force
}

$tasks = @(
    @{ Name = "00_test_suite_runner.png"; Url = "http://localhost:8000/tests/tests.html"; Budget = 2500 },
    @{ Name = "01_main_ui.png"; Url = "http://localhost:8000/index.html"; Budget = 1500 },
    @{ Name = "02_successful_verification.png"; Url = "http://localhost:8000/index.html?action=verify"; Budget = 2000 },
    @{ Name = "03_attack_payload_tampering.png"; Url = "http://localhost:8000/index.html?action=attack-payload"; Budget = 2000 },
    @{ Name = "04_attack_replay.png"; Url = "http://localhost:8000/index.html?action=attack-replay"; Budget = 2000 },
    @{ Name = "05_attack_expired_timestamp.png"; Url = "http://localhost:8000/index.html?action=attack-expired"; Budget = 2000 },
    @{ Name = "06_attack_wrong_key.png"; Url = "http://localhost:8000/index.html?action=attack-wrongkey"; Budget = 2000 },
    @{ Name = "07_attack_path_tampering.png"; Url = "http://localhost:8000/index.html?action=attack-path"; Budget = 2000 },
    @{ Name = "08_timing_attack_analysis.png"; Url = "http://localhost:8000/index.html?action=timing"; Budget = 2000 },
    @{ Name = "09_light_theme_ui.png"; Url = "http://localhost:8000/index.html?action=light"; Budget = 1500 }
)

foreach ($t in $tasks) {
    $outFile = "$screenshotDir\$($t.Name)"
    Write-Host "Capturing $($t.Name)..."
    Start-Process -FilePath $edgePath -ArgumentList "--headless", "--virtual-time-budget=$($t.Budget)", "--window-size=1400,1050", "--screenshot=$outFile", $t.Url -Wait
    $item = Get-Item $outFile
    Write-Host "  -> Saved: $($t.Name) ($([math]::Round($item.Length / 1KB, 1)) KB)"
}

Write-Host "`nAll screenshots captured successfully!"
