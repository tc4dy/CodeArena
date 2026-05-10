<#
.SYNOPSIS
    Windows Artifact Collector - Fast forensic triage
.DESCRIPTION
    Collects event logs, prefetch, registry, network info, scheduled tasks,
    MFT information (using built-in fsutil), and creates a timestamped folder.
#>

$OutputDir = "WindowsForensics_$(Get-Date -Format 'yyyyMMdd_HHmmss')"
New-Item -ItemType Directory -Force -Path $OutputDir | Out-Null
Write-Host "[+] Collecting artifacts into $OutputDir" -ForegroundColor Cyan

# System info
systeminfo > "$OutputDir\systeminfo.txt"
Get-ComputerInfo > "$OutputDir\computerinfo.txt"
Get-Process | Export-Csv -Path "$OutputDir\processes.csv" -NoTypeInformation
Get-Service | Export-Csv -Path "$OutputDir\services.csv" -NoTypeInformation
Get-ScheduledTask | Export-Csv -Path "$OutputDir\scheduled_tasks.csv" -NoTypeInformation
Get-WmiObject -Class Win32_Product | Select-Object Name, Version, Vendor > "$OutputDir\installed_software.txt"

# Network
ipconfig /all > "$OutputDir\ipconfig.txt"
Get-NetTCPConnection | Export-Csv -Path "$OutputDir\net_tcp.csv" -NoTypeInformation
Get-NetUDPEndpoint | Export-Csv -Path "$OutputDir\net_udp.csv" -NoTypeInformation
arp -a > "$OutputDir\arp.txt"
Get-NetRoute > "$OutputDir\routes.txt"

# User accounts and groups
Get-LocalUser | Export-Csv -Path "$OutputDir\local_users.csv" -NoTypeInformation
Get-LocalGroup | Export-Csv -Path "$OutputDir\local_groups.csv" -NoTypeInformation
Get-LocalGroupMember -Group "Administrators" | Export-Csv -Path "$OutputDir\admin_members.csv" -NoTypeInformation

# Event logs (Security, System, Application) - last 500 events each
$logs = @("Security", "System", "Application")
foreach ($log in $logs) {
    $events = Get-WinEvent -LogName $log -MaxEvents 500 -ErrorAction SilentlyContinue
    $events | Export-Csv -Path "$OutputDir\events_$log.csv" -NoTypeInformation
}

# Prefetch files
$prefetch = "$env:SystemRoot\Prefetch"
if (Test-Path $prefetch) {
    Copy-Item -Path "$prefetch\*.pf" -Destination "$OutputDir\Prefetch\" -ErrorAction SilentlyContinue
}

# Recent documents per user
$users = Get-ChildItem "C:\Users" -Directory
foreach ($user in $users) {
    $recent = "$($user.FullName)\AppData\Roaming\Microsoft\Windows\Recent"
    if (Test-Path $recent) {
        Copy-Item -Path "$recent\*.lnk" -Destination "$OutputDir\Recent_$($user.Name)\" -ErrorAction SilentlyContinue
    }
}

# USB device history
$usb = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Enum\USBSTOR\*\" -ErrorAction SilentlyContinue
$usb | Select-Object PSChildName, FriendlyName, Mfg, Service | Export-Csv -Path "$OutputDir\usb_history.csv" -NoTypeInformation

# Master File Table (MFT) info using fsutil
if ($env:SystemDrive) {
    $drive = $env:SystemDrive[0]
    fsutil volume information $drive`: > "$OutputDir\volume_info.txt"
    fsutil fsinfo ntfsinfo $drive`: > "$OutputDir\ntfs_info.txt"
    # Create a small MFT snapshot (requires admin)
    if ([Security.Principal.WindowsPrincipal]::new([Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        Write-Host "[+] Admin rights detected, dumping MFT metadata..." -ForegroundColor Yellow
        fsutil usn readjournal $drive`: > "$OutputDir\usn_journal.txt" 2>$null
        # MFT is in $MFT file (can copy, but large)
        # Just read first 10 MB
        $mftPath = "\\.\$drive`:"
        $mftPart = Get-Content -Path $mftPath -TotalCount 100000 -ErrorAction SilentlyContinue
        $mftPart | Out-File -FilePath "$OutputDir\MFT_head.txt"
    }
}

# Export registry hives (SAM, SECURITY, SYSTEM, SOFTWARE) - requires admin
if ([Security.Principal.WindowsPrincipal]::new([Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    reg save HKLM\SAM "$OutputDir\SAM.hive"
    reg save HKLM\SECURITY "$OutputDir\SECURITY.hive"
    reg save HKLM\SYSTEM "$OutputDir\SYSTEM.hive"
    reg save HKLM\SOFTWARE "$OutputDir\SOFTWARE.hive"
}

# Compress results (requires .NET)
Write-Host "[+] Compressing artifacts..." -ForegroundColor Green
Add-Type -AssemblyName System.IO.Compression.FileSystem
$compressionLevel = [System.IO.Compression.CompressionLevel]::Optimal
[System.IO.Compression.ZipFile]::CreateFromDirectory($OutputDir, "$OutputDir.zip", $compressionLevel, $false)

Write-Host "[+] Done. Output: $OutputDir and $OutputDir.zip" -ForegroundColor Green