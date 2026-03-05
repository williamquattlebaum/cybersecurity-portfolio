# CIS Benchmark Remediation Script - Windows 10
# Targets the most common failures from the 32% baseline score
# Run as Administrator in PowerShell

Write-Host "Starting CIS Benchmark Remediation..." -ForegroundColor Green

# 1. Windows Update - Enable automatic updates
Write-Host "[1/10] Configuring Windows Update..." -ForegroundColor Yellow
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" `
  -Name "NoAutoUpdate" -Value 0 -Type DWord -Force -ErrorAction SilentlyContinue
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" `
  -Name "AUOptions" -Value 4 -Type DWord -Force -ErrorAction SilentlyContinue

# 2. Disable Windows Sandbox networking (CIS requirement)
Write-Host "[2/10] Configuring Windows Sandbox policies..." -ForegroundColor Yellow
$sandboxPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Sandbox"
New-Item -Path $sandboxPath -Force -ErrorAction SilentlyContinue | Out-Null
Set-ItemProperty -Path $sandboxPath -Name "AllowNetworking" -Value 0 -Type DWord -Force
Set-ItemProperty -Path $sandboxPath -Name "AllowClipboardRedirection" -Value 0 -Type DWord -Force

# 3. Enable Windows Defender
Write-Host "[3/10] Enabling Windows Defender..." -ForegroundColor Yellow
Set-MpPreference -DisableRealtimeMonitoring $false -ErrorAction SilentlyContinue

# 4. Enable Audit Policy - Logon Events
Write-Host "[4/10] Configuring Audit Policies..." -ForegroundColor Yellow
auditpol /set /subcategory:"Logon" /success:enable /failure:enable
auditpol /set /subcategory:"Account Logon" /success:enable /failure:enable
auditpol /set /subcategory:"Account Management" /success:enable /failure:enable
auditpol /set /subcategory:"Policy Change" /success:enable /failure:enable
auditpol /set /subcategory:"Privilege Use" /success:enable /failure:enable
auditpol /set /subcategory:"System" /success:enable /failure:enable

# 5. User Account Control
Write-Host "[5/10] Hardening UAC settings..." -ForegroundColor Yellow
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" `
  -Name "EnableLUA" -Value 1 -Type DWord -Force
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" `
  -Name "ConsentPromptBehaviorAdmin" -Value 2 -Type DWord -Force
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" `
  -Name "ConsentPromptBehaviorUser" -Value 0 -Type DWord -Force

# 6. Disable Guest Account
Write-Host "[6/10] Disabling Guest account..." -ForegroundColor Yellow
net user guest /active:no

# 7. Account Lockout Policy
Write-Host "[7/10] Setting Account Lockout Policy..." -ForegroundColor Yellow
net accounts /lockoutthreshold:5 /lockoutwindow:30 /lockoutduration:30

# 8. Password Policy
Write-Host "[8/10] Setting Password Policy..." -ForegroundColor Yellow
net accounts /minpwlen:14 /maxpwage:90 /minpwage:1 /uniquepw:24

# 9. Disable AutoRun/AutoPlay
Write-Host "[9/10] Disabling AutoRun..." -ForegroundColor Yellow
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" `
  -Name "NoDriveTypeAutoRun" -Value 255 -Type DWord -Force

# 10. Enable Windows Firewall on all profiles
Write-Host "[10/10] Enabling Windows Firewall..." -ForegroundColor Yellow
Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled True

Write-Host "`nRemediation complete! Rerun Wazuh SCA scan to check new score." -ForegroundColor Green
Write-Host "Expected improvement: 32% -> 55-65%" -ForegroundColor Cyan
