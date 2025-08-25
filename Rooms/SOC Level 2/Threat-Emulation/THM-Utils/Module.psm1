function THM-LogStats-All {

Write-Output "`n"
Write-Host "|#|#|#|#|#| Important Log Statistics |#|#|#|#|#|" -ForegroundColor Green
Get-WinEvent -ListLog "Application","Security","System", "Windows PowerShell", "Microsoft-Windows-PowerShell/Operational","Microsoft-Windows-Sysmon/Operational" | Where-Object { $_.RecordCount -gt 0 -or $_.RecordCount -eq 0 } |Select-Object -Property LogName, RecordCount

}

Export-ModuleMember -Function THM-LogStats-All

function THM-LogStats-Application {

Write-Output "`n"
Write-Host "|#|#|#|#|#| APPLICATION Log Statistics (WITHOUT AURORA!) |#|#|#|#|#|" -ForegroundColor Green

$SecurityEvents = Get-WinEvent -FilterHashtable @{ LogName="Application"} | Select-Object Id, TaskDisplayName, ProviderName
$SecuritySummary = $SecurityEvents | Where-Object {$_.ProviderName -ne "AuroraAgent"}| Group-Object Id, TaskDisplayName, ProviderName | Select-Object Count, @{Name='Event ID'; Expression={$_.Group[0].Id}}, @{Name='Task Category'; Expression={$_.Group[0].TaskDisplayName}}, @{Name='Provider'; Expression={$_.Group[0].ProviderName}} | Sort-Object Count -Descending
$SecuritySummary | Format-Table -AutoSize

}

Export-ModuleMember -Function THM-LogStats-Application

function THM-LogStats-Security {

Write-Output "`n"
Write-Host "|#|#|#|#|#| SECURITY Log Statistics |#|#|#|#|#|" -ForegroundColor Green

$SecurityEvents = Get-WinEvent -FilterHashtable @{ LogName="Security" } | Select-Object Id, TaskDisplayName
$SecuritySummary = $SecurityEvents | Group-Object Id, TaskDisplayName | Select-Object Count, @{Name='Event ID'; Expression={$_.Group[0].Id}}, @{Name='Task Category'; Expression={$_.Group[0].TaskDisplayName}} | Sort-Object Count -Descending
$SecuritySummary | Format-Table -AutoSize

}

Export-ModuleMember -Function THM-LogStats-Security

function THM-LogStats-System {

Write-Output "`n"
Write-Host "|#|#|#|#|#| SECURITY Log Statistics |#|#|#|#|#|" -ForegroundColor Green

$SecurityEvents = Get-WinEvent -FilterHashtable @{ LogName="System" } | Select-Object Id, TaskDisplayName
$SecuritySummary = $SecurityEvents | Group-Object Id, TaskDisplayName | Select-Object Count, @{Name='Event ID'; Expression={$_.Group[0].Id}}, @{Name='Task Category'; Expression={$_.Group[0].TaskDisplayName}} | Sort-Object Count -Descending
$SecuritySummary | Format-Table -AutoSize

}

Export-ModuleMember -Function THM-LogStats-System

function THM-LogStats-PowerShell {

Write-Output "`n"
Write-Host "|#|#|#|#|#| Windows POWERSHELL Log Statistics |#|#|#|#|#|" -ForegroundColor Green

$PowershellEvents = Get-WinEvent -FilterHashtable @{ LogName="Windows Powershell" } | Select-Object Id, TaskDisplayName
$PowershellSummary = $PowershellEvents | Group-Object Id, TaskDisplayName | Select-Object Count, @{Name='Event ID'; Expression={$_.Group[0].Id}}, @{Name='Task Category'; Expression={$_.Group[0].TaskDisplayName}} | Sort-Object Count -Descending
$PowershellSummary | Format-Table -AutoSize

}

Export-ModuleMember -Function THM-LogStats-PowerShell

function THM-LogStats-PowerShell-Operational {

Write-Output "`n"

Write-Host "|#|#|#|#|#| Windows POWERSHELL OPERATIONAL Log Statistics |#|#|#|#|#|" -ForegroundColor Green

$PowershellOpEvents = Get-WinEvent -FilterHashtable @{ LogName="Microsoft-Windows-Powershell/Operational" } | Select-Object Id, TaskDisplayName
$PowershellOpSummary = $PowershellOpEvents | Group-Object Id, TaskDisplayName | Select-Object Count, @{Name='Event ID'; Expression={$_.Group[0].Id}}, @{Name='Task Category'; Expression={$_.Group[0].TaskDisplayName}} | Sort-Object Count -Descending
$PowershellOpSummary | Format-Table -AutoSize

}

Export-ModuleMember -Function THM-LogStats-PowerShell-Operational

function THM-LogStats-Aurora {

Write-Output "`n"
Write-Host "|#|#|#|#|#| APPLICATION -> AURORA Log Statistics |#|#|#|#|#|" -ForegroundColor Green

$SecurityEvents = Get-WinEvent -FilterHashtable @{ LogName="Application"; ProviderName='AuroraAgent' } | Select-Object Id, LevelDisplayName, Message
$SecuritySummary = $SecurityEvents | Group-Object Id, LevelDisplayName, Message | Select-Object Count, @{Name='Event ID'; Expression={$_.Group[0].Id}}, @{Name='Task Category'; Expression={$_.Group[0].LevelDisplayName}}, @{Name='Provider'; Expression={$_.Group[0].Message}} | Sort-Object Count -Descending
$SecuritySummary | Format-Table -AutoSize

}

Export-ModuleMember -Function THM-LogStats-Aurora

function THM-LogStats-Sysmon {

Write-Output "`n"
Write-Host "|#|#|#|#|#| SYSMON Log Statistics |#|#|#|#|#|" -ForegroundColor Green

$sysmonEvents = Get-WinEvent -FilterHashtable @{ LogName="Microsoft-Windows-Sysmon/Operational" } | Select-Object Id, TaskDisplayName
$sysmonSummary = $sysmonEvents | Group-Object Id, TaskDisplayName | Select-Object Count, @{Name='Sysmon ID'; Expression={$_.Group[0].Id}}, @{Name='Task Category'; Expression={$_.Group[0].TaskDisplayName}} | Sort-Object Count -Descending
$sysmonSummary | Format-Table -AutoSize

}

Export-ModuleMember -Function THM-LogStats-Sysmon

function THM-LogClear-All {
    $logList = wevtutil el | Where-Object { $_ -notmatch 'Microsoft-Windows-LiveId/(Analytic|Operational)' }
    $totalCount = $logList.Count
    $currentCount = 0

    foreach ($log in $logList) {
        Write-Progress -Activity "Clearing logs..." -Status "Clearing $log..." -PercentComplete (($currentCount / $totalCount) * 100)
        wevtutil cl $log | Out-Null
        $currentCount++
    }

    Write-Progress -Activity "Clearing logs..." -Completed
}

Export-ModuleMember -Function THM-LogClear-All

function THM-LogStats-Flag {

Write-Output "`n"
Write-Host "|#|#|#|#|#| THM{Emulation_is_fun_but_needs_focus_and_exploration} |#|#|#|#|#|" -ForegroundColor Cyan

}

Export-ModuleMember -Function THM-LogStats-Flag
