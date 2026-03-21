[CmdletBinding()]
param(
  [ValidateSet("status", "enable-dev", "upload-encrypted")]
  [string]$Action = "status",
  [string]$Port,
  [switch]$SkipCompile,
  [switch]$Yes
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$RepoRoot = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
$BuildDir = Join-Path $RepoRoot "build"
$SketchName = "esp32s3-wifi-kbm.ino"
$Fqbn = "esp32:esp32:esp32s3"

function Find-ArduinoCli {
  $cmd = Get-Command "arduino-cli" -ErrorAction SilentlyContinue
  if ($cmd) { return $cmd.Source }

  $fallback = Join-Path $env:LOCALAPPDATA "Programs\Arduino IDE\resources\app\lib\backend\resources\arduino-cli.exe"
  if (Test-Path $fallback) { return $fallback }

  throw "arduino-cli not found. Install Arduino IDE 2.x or add arduino-cli to PATH."
}

function Find-EspToolExe {
  $root = Join-Path $env:LOCALAPPDATA "Arduino15\packages\esp32\tools\esptool_py"
  if (-not (Test-Path $root)) {
    throw "ESP32 esptool package not found under $root"
  }
  $verDir = Get-ChildItem $root -Directory | Sort-Object Name -Descending | Select-Object -First 1
  if (-not $verDir) {
    throw "No esptool_py version directories found under $root"
  }

  $esptool = Join-Path $verDir.FullName "esptool.exe"
  $espefuse = Join-Path $verDir.FullName "espefuse.exe"
  $espsecure = Join-Path $verDir.FullName "espsecure.exe"
  foreach ($p in @($esptool, $espefuse, $espsecure)) {
    if (-not (Test-Path $p)) { throw "Missing tool: $p" }
  }

  return @{
    esptool = $esptool
    espefuse = $espefuse
    espsecure = $espsecure
  }
}

function Invoke-Tool {
  param(
    [Parameter(Mandatory = $true)][string]$Exe,
    [Parameter(Mandatory = $true)][string[]]$Args
  )
  Write-Host ">> $Exe $($Args -join ' ')"
  & $Exe @Args
  if ($LASTEXITCODE -ne 0) {
    throw "Command failed with exit code ${LASTEXITCODE}: $Exe $($Args -join ' ')"
  }
}

function Invoke-ToolCapture {
  param(
    [Parameter(Mandatory = $true)][string]$Exe,
    [Parameter(Mandatory = $true)][string[]]$Args
  )
  Write-Host ">> $Exe $($Args -join ' ')"
  $out = & $Exe @Args 2>&1
  if ($LASTEXITCODE -ne 0) {
    $text = ($out -join "`n")
    throw "Command failed with exit code ${LASTEXITCODE}: $Exe $($Args -join ' ')`n$text"
  }
  return ($out -join "`n")
}

function Resolve-EspPort {
  param(
    [Parameter(Mandatory = $true)][string]$CliPath,
    [string]$Preferred
  )
  if ($Preferred -and $Preferred.Trim() -ne "") {
    return $Preferred.Trim()
  }

  $list = & $CliPath board list
  if ($LASTEXITCODE -ne 0) {
    throw "Failed to run arduino-cli board list"
  }

  foreach ($line in $list) {
    if ($line -match '^(COM\d+)\s+\w+\s+.+ESP32') {
      return $matches[1]
    }
  }

  throw "Could not auto-detect ESP32 serial port. Pass -Port COMx."
}

function Compile-Sketch {
  param([Parameter(Mandatory = $true)][string]$CliPath)
  Invoke-Tool -Exe $CliPath -Args @("compile", "-b", $Fqbn, "--build-path", $BuildDir, $RepoRoot)
}

function Resolve-HardwarePath {
  $optsPath = Join-Path $BuildDir "build.options.json"
  if (Test-Path $optsPath) {
    try {
      $opts = Get-Content $optsPath -Raw | ConvertFrom-Json
      if ($opts.hardwareFolders) {
        $first = ($opts.hardwareFolders -split ",")[0].Trim()
        if ($first -and (Test-Path $first)) {
          return $first
        }
      }
    } catch {
      # Fall through to package scan below.
    }
  }

  $hwRoot = Join-Path $env:LOCALAPPDATA "Arduino15\packages\esp32\hardware\esp32"
  if (-not (Test-Path $hwRoot)) {
    throw "ESP32 hardware package path not found: $hwRoot"
  }
  $verDir = Get-ChildItem $hwRoot -Directory | Sort-Object Name -Descending | Select-Object -First 1
  if (-not $verDir) {
    throw "No ESP32 hardware version directories found under $hwRoot"
  }
  return $verDir.FullName
}

function Get-FlashArtifacts {
  $bootloader = Join-Path $BuildDir "$SketchName.bootloader.bin"
  $partitions = Join-Path $BuildDir "$SketchName.partitions.bin"
  $app = Join-Path $BuildDir "$SketchName.bin"
  $hardwarePath = Resolve-HardwarePath
  $bootApp0 = Join-Path $hardwarePath "tools\partitions\boot_app0.bin"

  foreach ($p in @($bootloader, $partitions, $app, $bootApp0)) {
    if (-not (Test-Path $p)) {
      throw "Required binary not found: $p"
    }
  }

  return @{
    bootloader = $bootloader
    partitions = $partitions
    bootApp0 = $bootApp0
    app = $app
  }
}

function Get-EfuseSummary {
  param(
    [Parameter(Mandatory = $true)][string]$EspEfuseExe,
    [Parameter(Mandatory = $true)][string]$PortName
  )
  return Invoke-ToolCapture -Exe $EspEfuseExe -Args @("--chip", "esp32s3", "-p", $PortName, "summary")
}

function Test-FlashEncryptionEnabled {
  param([Parameter(Mandatory = $true)][string]$SummaryText)

  if ($SummaryText -match 'SPI_BOOT_CRYPT_CNT[^\r\n]*=\s*Disable') { return $false }
  if ($SummaryText -match 'SPI_BOOT_CRYPT_CNT[^\r\n]*=\s*Enable') { return $true }

  if ($SummaryText -match 'SPI_BOOT_CRYPT_CNT[^\r\n]*\(0b([01]{3})\)') {
    $bits = $matches[1].ToCharArray()
    $ones = ($bits | Where-Object { $_ -eq '1' }).Count
    return (($ones % 2) -eq 1)
  }

  throw "Could not parse SPI_BOOT_CRYPT_CNT from eFuse summary."
}

function Assert-Key0Available {
  param([Parameter(Mandatory = $true)][string]$SummaryText)
  if ($SummaryText -notmatch 'KEY_PURPOSE_0[^\r\n]*=\s*USER') {
    throw "BLOCK_KEY0 is not available for flash encryption (KEY_PURPOSE_0 is not USER)."
  }
}

function Upload-EncryptedImage {
  param(
    [Parameter(Mandatory = $true)][string]$EspToolExe,
    [Parameter(Mandatory = $true)][string]$PortName
  )
  $bins = Get-FlashArtifacts
  Invoke-Tool -Exe $EspToolExe -Args @(
    "--chip", "esp32s3",
    "--port", $PortName,
    "--baud", "921600",
    "--before", "default-reset",
    "--after", "hard-reset",
    "write-flash",
    "--encrypt",
    "-z",
    "--flash-mode", "keep",
    "--flash-freq", "keep",
    "--flash-size", "keep",
    "0x0", $bins.bootloader,
    "0x8000", $bins.partitions,
    "0xe000", $bins.bootApp0,
    "0x10000", $bins.app
  )
}

$arduinoCli = Find-ArduinoCli
$tools = Find-EspToolExe

if ((-not $SkipCompile) -and ($Action -ne "status")) {
  Compile-Sketch -CliPath $arduinoCli
}

$portNow = Resolve-EspPort -CliPath $arduinoCli -Preferred $Port
$summary = Get-EfuseSummary -EspEfuseExe $tools.espefuse -PortName $portNow
$enabled = Test-FlashEncryptionEnabled -SummaryText $summary

if ($Action -eq "status") {
  Write-Host ""
  Write-Host ("Port: " + $portNow)
  Write-Host ("Flash encryption: " + ($(if ($enabled) { "ENABLED" } else { "DISABLED" })))
  exit 0
}

if ($Action -eq "upload-encrypted") {
  if (-not $enabled) {
    throw "Flash encryption is disabled. Run -Action enable-dev first."
  }

  Upload-EncryptedImage -EspToolExe $tools.esptool -PortName $portNow
  Write-Host ""
  Write-Host "Encrypted upload complete."
  exit 0
}

if ($Action -eq "enable-dev") {
  if ($enabled) {
    Write-Host "Flash encryption already enabled; uploading encrypted image."
    Upload-EncryptedImage -EspToolExe $tools.esptool -PortName $portNow
    Write-Host ""
    Write-Host "Encrypted upload complete."
    exit 0
  }

  Assert-Key0Available -SummaryText $summary

  $secretsDir = Join-Path $RepoRoot "secrets"
  New-Item -ItemType Directory -Force -Path $secretsDir | Out-Null
  $stamp = Get-Date -Format "yyyyMMdd-HHmmss"
  $keyFile = Join-Path $secretsDir ("flash_encryption_key_" + $stamp + ".bin")

  Invoke-Tool -Exe $tools.espsecure -Args @("generate-flash-encryption-key", $keyFile)

  if (-not $Yes) {
    Write-Host ""
    Write-Host "WARNING: This burns irreversible eFuses (flash encryption key + SPI_BOOT_CRYPT_CNT)." -ForegroundColor Yellow
    Write-Host "Use development mode only on boards you control." -ForegroundColor Yellow
    $confirm = Read-Host "Type ENABLE to continue"
    if ($confirm -ne "ENABLE") {
      throw "Cancelled by user."
    }
  }

  Invoke-Tool -Exe $tools.espefuse -Args @("--chip", "esp32s3", "-p", $portNow, "--do-not-confirm", "burn-key", "BLOCK_KEY0", $keyFile, "XTS_AES_128_KEY")

  $portNow = Resolve-EspPort -CliPath $arduinoCli -Preferred $Port
  Invoke-Tool -Exe $tools.espefuse -Args @("--chip", "esp32s3", "-p", $portNow, "--do-not-confirm", "burn-efuse", "SPI_BOOT_CRYPT_CNT", "0x1")

  $portNow = Resolve-EspPort -CliPath $arduinoCli -Preferred $Port
  Upload-EncryptedImage -EspToolExe $tools.esptool -PortName $portNow

  $portNow = Resolve-EspPort -CliPath $arduinoCli -Preferred $Port
  $after = Get-EfuseSummary -EspEfuseExe $tools.espefuse -PortName $portNow
  if (-not (Test-FlashEncryptionEnabled -SummaryText $after)) {
    throw "Verification failed: flash encryption still appears disabled."
  }

  Write-Host ""
  Write-Host "Flash encryption enabled (development mode) and encrypted image uploaded."
  Write-Host ("Key file saved to: " + $keyFile)
  exit 0
}

throw "Unhandled action: $Action"
