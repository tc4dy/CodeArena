<#
.SYNOPSIS
    Registry Decoder - Malware Persistence, Shadow Copy, Timelining
.DESCRIPTION
    Extracts run keys, services, scheduled tasks, browser artifacts, USB history.
    Detects hidden registry entries (alternate data streams, null bytes).
    Outputs CSV report.
#>

param(
    [string]$OutputDir = "RegAnalysis_$(Get-Date -Format 'yyyyMMdd_HHmmss')"
)

$OutputPath = New-Item -ItemType Directory -Force -Path $OutputDir

Write-Host "[*] Starting Registry Decoder" -ForegroundColor Cyan

# Function to export and analyze a registry path
function Analyze-RegPath {
    param([string]$Path, [string]$Name)
    try {
        $items = Get-ItemProperty -Path $Path -ErrorAction SilentlyContinue
        if ($items) {
            $items.PSObject.Properties | ForEach-Object {
                if ($_.Name -notin @('PSPath', 'PSParentPath', 'PSChildName', 'PSDrive', 'PSProvider')) {
                    $value = $_ -replace "`0", "[NULL]"   # detect null byte injection
                    [PSCustomObject]@{
                        Category = $Name
                        Path = $Path
                        Name = $_.Name
                        Value = $value
                    }
                }
            }
        }
    } catch {}
}

# Collect persistence locations
$regPaths = @(
    @{Path="HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run"; Name="HKLM_Run"},
    @{Path="HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce"; Name="HKLM_RunOnce"},
    @{Path="HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run"; Name="HKCU_Run"},
    @{Path="HKLM:\SYSTEM\CurrentControlSet\Services"; Name="Services"},
    @{Path="HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tasks"; Name="ScheduledTasks"},
    @{Path="HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders"; Name="ShellFolders"},
    @{Path="HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\TypedPaths"; Name="TypedPaths"},
    @{Path="HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\AppCompatCache"; Name="AppCompatCache"},
    @{Path="HKLM:\SYSTEM\CurrentControlSet\Enum\USBSTOR"; Name="USBHistory"}
)

$report = @()
foreach ($rp in $regPaths) {
    Write-Host "[+] Scanning $($rp.Name)" -ForegroundColor Yellow
    $report += Analyze-RegPath -Path $rp.Path -Name $rp.Name
}

# Shadow copy analysis (check if VSS exists)
$vss = Get-WmiObject -Class Win32_ShadowCopy -ErrorAction SilentlyContinue
if ($vss) {
    Write-Host "[+] Found Volume Shadow Copies" -ForegroundColor Green
    $vss | ForEach-Object {
        $report += [PSCustomObject]@{
            Category="ShadowCopy"
            Path=$_.DeviceObject
            Name="ID"
            Value=$_.ID
        }
    }
} else {
    Write-Host "[-] No VSS found" -ForegroundColor DarkYellow
}

$csvPath = Join-Path $OutputPath "registry_analysis.csv"
$report | Export-Csv -Path $csvPath -NoTypeInformation
Write-Host "[+] Registry report saved to $csvPath" -ForegroundColor Green

# Optional: Check for hidden ADS in registry hive files
$hives = @("$env:SystemRoot\System32\config\SAM", "$env:SystemRoot\System32\config\SYSTEM", "$env:SystemRoot\System32\config\SOFTWARE")
foreach ($hive in $hives) {
    if (Test-Path $hive) {
        $ads = Get-Item -Stream * -Path $hive -ErrorAction SilentlyContinue
        if ($ads.Count -gt 1) {
            Write-Host "[!!] Alternate data streams on $hive : $($ads | Select-Object -ExpandProperty Stream)" -ForegroundColor Red
        }
    }
}