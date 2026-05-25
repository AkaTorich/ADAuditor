<#
    Seed-LabVulns.ps1
    Seeds a deliberately vulnerable Active Directory configuration so that
    AD_AUDITOR findings can be validated end to end.

    TARGET: LAB.LOCAL (NetBIOS LAB), domain controller DC01.
    RUN ON the domain controller, as a Domain Admin, in an elevated PowerShell.

    USAGE:
        .\Seed-LabVulns.ps1            # seed the vulnerabilities
        .\Seed-LabVulns.ps1 -Cleanup   # remove what this script created

    WARNING: for an isolated LAB only. Never run against production.
#>

[CmdletBinding()]
param(
    [string]$NetBios = "LAB",
    [switch]$Cleanup
)

Import-Module ActiveDirectory -ErrorAction Stop

$dn   = (Get-ADDomain).DistinguishedName
$cfg  = (Get-ADRootDSE).configurationNamingContext
$pwd  = ConvertTo-SecureString 'P@ssw0rd1!' -AsPlainText -Force

function Step($msg, [scriptblock]$action) {
    try { & $action; Write-Host ("[+] " + $msg) -ForegroundColor Green }
    catch { Write-Host ("[!] " + $msg + " -> " + $_.Exception.Message) -ForegroundColor Yellow }
}

# Add an ACE to an AD object using the PowerShell AD provider (GUID based,
# locale independent). $right is an ActiveDirectoryRights value.
function Add-Ace($objectDn, $sid, $right, $guid) {
    $path  = "AD:\$objectDn"
    $acl   = Get-Acl $path
    $adr   = [System.DirectoryServices.ActiveDirectoryRights]$right
    $allow = [System.Security.AccessControl.AccessControlType]::Allow
    if ($guid) {
        $rule = [System.DirectoryServices.ActiveDirectoryAccessRule]::new($sid, $adr, $allow, [guid]$guid)
    } else {
        $rule = [System.DirectoryServices.ActiveDirectoryAccessRule]::new($sid, $adr, $allow)
    }
    $acl.AddAccessRule($rule)
    Set-Acl $path $acl
}

# Well-known extended-right / attribute GUIDs
$G_GetChanges    = "1131f6aa-9c07-11d1-f79f-00c04fc2dcd2"
$G_GetChangesAll = "1131f6ad-9c07-11d1-f79f-00c04fc2dcd2"
$G_ForcePwd      = "00299570-246d-11d0-a768-00aa006e0529"
$keyCredGuid = (Get-ADObject -SearchBase (Get-ADRootDSE).schemaNamingContext `
    -Filter "lDAPDisplayName -eq 'msDS-KeyCredentialLink'" -Properties schemaIDGUID `
    -ErrorAction SilentlyContinue).schemaIDGUID
if ($keyCredGuid) { $keyCredGuid = ([guid]$keyCredGuid).ToString() }

# -------------------------------------------------------------------------
if ($Cleanup) {
    Write-Host "=== CLEANUP ===" -ForegroundColor Cyan
    Step "remove seeded users"      { "victim","svc1","da1" | ForEach-Object { Remove-ADUser $_ -Confirm:$false -ErrorAction SilentlyContinue } }
    Step "remove OLDBOX computer"    { Remove-ADComputer OLDBOX -Confirm:$false -ErrorAction SilentlyContinue }
    Step "remove gmsa1"              { Remove-ADServiceAccount gmsa1 -Confirm:$false -ErrorAction SilentlyContinue }
    Step "disable Guest"             { Disable-ADAccount Guest }
    Step "reset dSHeuristics"        { Set-ADObject "CN=Directory Service,CN=Windows NT,CN=Services,$cfg" -Replace @{dSHeuristics='0'} -ErrorAction SilentlyContinue }
    Step "reset reversible-enc pol"  { Set-ADDefaultDomainPasswordPolicy -Identity (Get-ADDomain).DNSRoot -ReversibleEncryptionEnabled $false }
    Step "empty DnsAdmins/Backup Op" {
        Remove-ADGroupMember "DnsAdmins" testuser -Confirm:$false -ErrorAction SilentlyContinue
        Remove-ADGroupMember "Backup Operators" "Domain Users" -Confirm:$false -ErrorAction SilentlyContinue
    }
    Write-Host "Cleanup done. Re-run the audit to confirm a clean baseline." -ForegroundColor Cyan
    return
}

Write-Host "=== SEEDING LAB VULNERABILITIES on $dn ===" -ForegroundColor Cyan

# ---- create test principals ----
Step "create users victim, svc1, da1" {
    "victim","svc1","da1" | ForEach-Object {
        if (-not (Get-ADUser -Filter "sAMAccountName -eq '$_'" -ErrorAction SilentlyContinue)) {
            New-ADUser $_ -AccountPassword $pwd -Enabled $true
        }
    }
}

# ---- Stale objects ----
Step "S-PwdNeverExpires"   { Set-ADUser victim -PasswordNeverExpires $true }
Step "S-PasswdNotReqd"     { Set-ADAccountControl victim -PasswordNotRequired $true }
Step "S-ReversiblePwd"     { Set-ADAccountControl victim -AllowReversiblePasswordEncryption $true }
Step "S-DesOnly"           { Set-ADAccountControl victim -UseDESKeyOnly $true }
Step "S-MustChange"        { Set-ADUser svc1 -ChangePasswordAtLogon $true }   # svc1: victim cannot, it has password-never-expires
Step "S-Expired"           { Set-ADUser victim -AccountExpirationDate (Get-Date).AddDays(-1) }
Step "S-LegacyOS (OLDBOX)" { if (-not (Get-ADComputer -Filter "Name -eq 'OLDBOX'" -ErrorAction SilentlyContinue)) { New-ADComputer OLDBOX -OperatingSystem "Windows Server 2008 R2" } }

# ---- Privileged accounts ----
Step "P-DnsAdmins"         { Add-ADGroupMember "DnsAdmins" testuser -ErrorAction SilentlyContinue }
Step "P-GuestEnabled"      { Enable-ADAccount Guest }
Step "P-BroadInPriv"       { Add-ADGroupMember "Backup Operators" "Domain Users" -ErrorAction SilentlyContinue }
Step "P-PrivKerberoast"    { Add-ADGroupMember "Domain Admins" da1 -ErrorAction SilentlyContinue; setspn -s http/da1.lab.local da1 | Out-Null }
Step "P-PrivNoPreauth"     { Set-ADAccountControl da1 -DoesNotRequirePreAuth $true }

# ---- Kerberos / delegation ----
Step "A-Kerberoast"        { setspn -s http/svc1.lab.local svc1 | Out-Null }
Step "A-AsrepRoast"        { Set-ADAccountControl svc1 -DoesNotRequirePreAuth $true }
Step "A-Unconstrained"     { Set-ADAccountControl -Identity (Get-ADComputer OLDBOX) -TrustedForDelegation $true }
Step "A-Constrained"       { Set-ADUser svc1 -Add @{'msDS-AllowedToDelegateTo'='cifs/DC01.lab.local'} }
Step "A-RBCD"              { Set-ADComputer OLDBOX -PrincipalsAllowedToDelegateToAccount (Get-ADUser svc1) }

# ---- ACL control edges (these light up the Tier 3 graph) ----
$tu = (Get-ADUser testuser).SID
Step "X-AclGenericAll + T3" { Add-Ace "CN=Domain Admins,CN=Users,$dn" $tu "GenericAll" $null }
Step "X-DCSync (get-changes)"     { Add-Ace $dn $tu "ExtendedRight" $G_GetChanges }
Step "X-DCSync (get-changes-all)" { Add-Ace $dn $tu "ExtendedRight" $G_GetChangesAll }
Step "X-AclForceChangePwd" { Add-Ace ((Get-ADUser victim).DistinguishedName) $tu "ExtendedRight" $G_ForcePwd }
Step "X-ShadowCredWrite"   { if ($keyCredGuid) { Add-Ace ((Get-ADUser victim).DistinguishedName) $tu "WriteProperty" $keyCredGuid } }

# ---- Anomalies ----
Step "A-DomainReversible"  { Set-ADDefaultDomainPasswordPolicy -Identity (Get-ADDomain).DNSRoot -ReversibleEncryptionEnabled $true }
Step "A-DescriptionPassword" { Set-ADUser victim -Description "password: P@ssw0rd1!" }
Step "A-WeakEncTypes"      { Set-ADUser victim -Replace @{'msDS-SupportedEncryptionTypes'=4} }
Step "A-AnonymousLdap"     { Set-ADObject "CN=Directory Service,CN=Windows NT,CN=Services,$cfg" -Replace @{dSHeuristics='0000002'} }
Step "A-PreWin2000"        { Add-ADGroupMember "Pre-Windows 2000 Compatible Access" -Members "CN=S-1-5-7,CN=ForeignSecurityPrincipals,$dn" }   # Anonymous Logon FSP
Step "A-Gmsa + X-GmsaRetrievers" {
    if (-not (Get-KdsRootKey -ErrorAction SilentlyContinue)) { Add-KdsRootKey -EffectiveTime ((Get-Date).AddHours(-10)) | Out-Null }
    if (-not (Get-ADServiceAccount -Filter "Name -eq 'gmsa1'" -ErrorAction SilentlyContinue)) {
        New-ADServiceAccount gmsa1 -DNSHostName gmsa1.lab.local -PrincipalsAllowedToRetrieveManagedPassword "Domain Computers"
    }
}

# ---- AD CS (only if a CA / templates exist) ----
Step "C-ESC4 (writable User template)" {
    $tpl = "CN=User,CN=Certificate Templates,CN=Public Key Services,CN=Services,$cfg"
    if (Get-ADObject -Identity $tpl -ErrorAction SilentlyContinue) {
        Add-Ace $tpl ((Get-ADGroup "Domain Users").SID) "WriteProperty" $null
    }
}

Write-Host ""
Write-Host "=== DONE. Now run AD_AUDITOR against LAB.LOCAL / DC01 and review the findings. ===" -ForegroundColor Cyan
Write-Host "Note: SYSVOL GPP cpassword, Restricted Groups and Kerberos-policy findings must be seeded manually via GPO." -ForegroundColor DarkGray
Write-Host "Revert everything with:  .\Seed-LabVulns.ps1 -Cleanup" -ForegroundColor DarkGray
