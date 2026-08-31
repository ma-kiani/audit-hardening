$backupPath = "C:\Backup\GPOs"

# check backup directory
if (-not (Test-Path $backupPath)) {
    Write-Host "Creating backup directory at $backupPath"
    New-Item -Path $backupPath -ItemType Directory
}

$gpos = Get-GPO -All
foreach ($gpo in $gpos) {
    try {
        Backup-GPO -Guid $gpo.Id -Path $backupPath -ErrorAction Stop
        Write-Host "Backed up $($gpo.DisplayName)"
    } catch {
        Write-Warning "Failed to back up $($gpo.DisplayName): $_"
    }
}


________________________________________________________________________________
#new Version of script improved by ai


$timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
$backupPath = "C:\Backup\GPOs\$timestamp"

New-Item -Path $backupPath -ItemType Directory -Force | Out-Null

$gpos = Get-GPO -All

foreach ($gpo in $gpos) {
    try {
        Backup-GPO `
            -Guid $gpo.Id `
            -Path $backupPath `
            -ErrorAction Stop |
            Out-Null

        Write-Host "Backed up: $($gpo.DisplayName)"
    }
    catch {
        Write-Warning "Failed: $($gpo.DisplayName) - $($_.Exception.Message)"
    }
}
